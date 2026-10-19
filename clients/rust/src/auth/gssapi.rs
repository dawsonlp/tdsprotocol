//! Moving a context into each counted worker makes cancellation revoke the
//! caller's authority without pretending to interrupt a blocking native call.
use super::portable::{AuthFuture, SecurityContext, failure};
use super::{Credentials, GssapiEvidence, Method, Token, WindowsAuth};
use crate::{Error, ErrorKind, Result};
use std::sync::atomic::{AtomicUsize, Ordering};

static WORKERS: AtomicUsize = AtomicUsize::new(0);
struct Running;
impl Drop for Running {
    fn drop(&mut self) {
        WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}
struct Completed<T> {
    // Field drop order keeps this operation counted through result cleanup.
    result: Result<T>,
    _running: Running,
}
async fn blocking_call<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    WORKERS.fetch_add(1, Ordering::AcqRel);
    let running = Running;
    let job = tokio::task::spawn_blocking(move || Completed {
        result: work(),
        _running: running,
    });
    let (send, receive) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        // If the caller was cancelled, failed delivery drops the owned context
        // and tokens. No late result can install itself into a connection.
        let _ = send.send(job.await);
    });
    receive
        .await
        .map_err(|_| failure())?
        .map_err(|_| failure())?
        .result
}

pub(super) struct System {
    context: Option<tds_native_gssapi::Context>,
    method: tds_native_gssapi::Method,
    target: String,
    principal: Option<String>,
    allow_ntlm_fallback: bool,
    evidence: Option<GssapiEvidence>,
    usable: bool,
}
impl System {
    pub fn new(auth: &WindowsAuth, target: String) -> Result<Self> {
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            return Err(Error::new(ErrorKind::Unsupported(
                "system GSSAPI is available on Linux/macOS",
            )));
        }
        let Credentials::SystemCache { principal } = &auth.credentials else {
            return Err(Error::new(ErrorKind::Parameter(
                "system GSSAPI requires system-cache credentials",
            )));
        };
        if auth.kdc_url.is_some() {
            return Err(Error::new(ErrorKind::Parameter(
                "system GSSAPI uses system KDC configuration",
            )));
        }
        if target.is_empty()
            || target.contains('\0')
            || target.len() > super::MAX_TOKEN
            || principal
                .as_ref()
                .is_some_and(|p| p.is_empty() || p.contains('\0') || p.len() > super::MAX_TOKEN)
        {
            return Err(Error::new(ErrorKind::Parameter("invalid GSSAPI principal")));
        }
        let method = match auth.method {
            Method::Kerberos => tds_native_gssapi::Method::Kerberos,
            Method::Negotiate => tds_native_gssapi::Method::Negotiate,
            Method::Ntlm => {
                return Err(Error::new(ErrorKind::Unsupported(
                    "system-cache provider requires Kerberos or Negotiate",
                )));
            }
        };
        Ok(Self {
            context: None,
            method,
            target,
            principal: principal.clone(),
            allow_ntlm_fallback: auth.allow_ntlm_fallback,
            evidence: None,
            usable: true,
        })
    }
}
impl SecurityContext for System {
    fn step<'a>(&'a mut self, challenge: Option<Token>, binding: &'a [u8]) -> AuthFuture<'a> {
        Box::pin(async move {
            if !self.usable {
                return Err(failure());
            }
            // This remains false if the await is cancelled or the provider
            // fails: a context lost to a worker cannot start again implicitly.
            self.usable = false;
            let context = self.context.take();
            let method = self.method;
            let target = self.target.clone();
            let principal = self.principal.clone();
            let fallback = self.allow_ntlm_fallback;
            let binding = binding.to_vec();
            let (context, step) = blocking_call(move || {
                let mut context = match context {
                    Some(context) => context,
                    None => tds_native_gssapi::Context::new(
                        method,
                        &target,
                        principal.as_deref(),
                        fallback,
                    )
                    .map_err(|_| failure())?,
                };
                let step = context
                    .step(challenge.as_ref().map(Token::as_bytes), &binding)
                    .map_err(|_| failure())?;
                Ok((context, step))
            })
            .await?;
            self.evidence = step.evidence;
            self.usable = !step.complete;
            self.context = Some(context);
            // Transfer the zeroizing allocation; do not retain another copy.
            Ok((Token(step.token), step.complete))
        })
    }
    fn gssapi_evidence(&self) -> Option<GssapiEvidence> {
        self.evidence
    }
}

/// Includes outstanding blocking calls and late owned results awaiting cleanup.
pub fn pending_workers() -> usize {
    WORKERS.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;
    static WORKER_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn canceled_worker_drops_late_result_before_retiring_count() {
        let _serial = WORKER_TEST.lock().await;
        #[derive(Debug)]
        struct Owned(tokio::sync::oneshot::Sender<usize>);
        impl Drop for Owned {
            fn drop(&mut self) {
                let (replacement, _) = tokio::sync::oneshot::channel();
                let _ = std::mem::replace(&mut self.0, replacement).send(pending_workers());
            }
        }
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let (cleanup, cleaned) = tokio::sync::oneshot::channel();
        let caller = tokio::spawn(blocking_call(move || {
            let _ = entered.send(());
            wait.recv().unwrap();
            Ok(Owned(cleanup))
        }));
        started.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert!(pending_workers() >= 1);
        release.send(()).unwrap();
        let counted_at_cleanup = tokio::time::timeout(std::time::Duration::from_secs(5), cleaned)
            .await
            .unwrap()
            .unwrap();
        assert!(counted_at_cleanup >= 1);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while pending_workers() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn original_deadline_revokes_waiter_and_late_worker_still_cleans_up() {
        let _serial = WORKER_TEST.lock().await;
        struct Owned(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = self.0.take().unwrap().send(());
            }
        }
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let (cleanup, cleaned) = tokio::sync::oneshot::channel();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(100);
        let caller = tokio::spawn(async move {
            tokio::time::timeout_at(
                deadline,
                blocking_call(move || {
                    let _ = entered.send(());
                    wait.recv().unwrap();
                    Ok(Owned(Some(cleanup)))
                }),
            )
            .await
            .is_err()
        });
        started.await.unwrap();
        assert!(caller.await.unwrap());
        assert!(pending_workers() >= 1);
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), cleaned)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while pending_workers() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn provider_selection_rejects_conflicting_identity_and_kdc_inputs() {
        let mut auth = WindowsAuth::system_cache(Method::Negotiate);
        assert_eq!(
            System::new(&auth, "MSSQLSvc/sql.test:1433".into()).is_ok(),
            cfg!(any(target_os = "linux", target_os = "macos"))
        );
        auth.kdc_url = Some("tcp://kdc.test:88".into());
        assert!(System::new(&auth, "MSSQLSvc/sql.test:1433".into()).is_err());
        auth.kdc_url = None;
        auth.credentials = Credentials::explicit("canary-user", "canary-password");
        let error = System::new(&auth, "MSSQLSvc/sql.test:1433".into())
            .err()
            .unwrap();
        assert!(!format!("{error:?}").contains("canary"));
        auth.credentials = Credentials::SystemCache {
            principal: Some(String::new()),
        };
        assert!(System::new(&auth, "MSSQLSvc/sql.test:1433".into()).is_err());
        auth.credentials = Credentials::SystemCache { principal: None };
        auth.method = Method::Ntlm;
        assert!(System::new(&auth, "MSSQLSvc/sql.test:1433".into()).is_err());
    }
}
