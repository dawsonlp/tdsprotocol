use super::portable::{AuthFuture, SecurityContext, failure};
use super::{Method, Token};
use std::sync::atomic::{AtomicUsize, Ordering};

static WORKERS: AtomicUsize = AtomicUsize::new(0);
struct Running;
impl Drop for Running {
    fn drop(&mut self) {
        WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}
async fn blocking_call<T: Send + 'static>(
    work: impl FnOnce() -> crate::Result<T> + Send + 'static,
) -> crate::Result<T> {
    WORKERS.fetch_add(1, Ordering::AcqRel);
    let running = Running;
    let job = tokio::task::spawn_blocking(move || {
        let _running = running;
        work()
    });
    // The reaper owns work after caller cancellation. Failed delivery drops
    // the complete result, including any native context and token it owns.
    let (send, receive) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = send.send(job.await);
    });
    receive
        .await
        .map_err(|_| failure())?
        .map_err(|_| failure())?
}
pub(super) struct Native {
    context: Option<tds_native_sspi::Context>,
    package: &'static str,
    target: String,
    require_kerberos: bool,
}
impl Native {
    pub fn new(method: Method, target: String, allow_ntlm_fallback: bool) -> Self {
        Self {
            context: None,
            package: match method {
                Method::Ntlm => "NTLM",
                Method::Kerberos => "Kerberos",
                Method::Negotiate => "Negotiate",
            },
            target,
            require_kerberos: method == Method::Kerberos
                || (method == Method::Negotiate && !allow_ntlm_fallback),
        }
    }
}
impl SecurityContext for Native {
    fn step<'a>(&'a mut self, challenge: Option<Token>, binding: &'a [u8]) -> AuthFuture<'a> {
        Box::pin(async move {
            let context = self.context.take();
            let package = self.package;
            let target = self.target.clone();
            let required = self.require_kerberos;
            let binding = binding.to_vec();
            let (context, token, complete) = blocking_call(move || {
                let mut context = match context {
                    Some(context) => context,
                    None => tds_native_sspi::Context::new(package, &target, required)
                        .map_err(|_| failure())?,
                };
                let (token, complete) = context
                    .step(challenge.as_ref().map(Token::as_bytes), &binding)
                    .map_err(|_| failure())?;
                Ok::<_, crate::Error>((context, Token::new(token.to_vec())?, complete))
            })
            .await?;
            self.context = Some(context);
            Ok((token, complete))
        })
    }
}
pub fn pending_workers() -> usize {
    WORKERS.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn canceled_call_reaps_late_owned_result_and_retires_worker() {
        #[derive(Debug)]
        struct OwnedResult(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for OwnedResult {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let (cleanup, cleaned) = tokio::sync::oneshot::channel();
        let caller = tokio::spawn(blocking_call(move || {
            let _ = entered.send(());
            let _ = wait.recv();
            Ok(OwnedResult(Some(cleanup)))
        }));
        started.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert!(pending_workers() >= 1);
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), cleaned)
            .await
            .expect("late result was not destroyed")
            .unwrap();
        assert_eq!(pending_workers(), 0);
    }
}
