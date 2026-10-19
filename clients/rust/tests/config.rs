//! Demand-driven reads: bounded, cancelable and independent of login completion.
#![cfg(feature = "tokio")]
mod support;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use support::Peer;
use tds_client::{
    ConfigError, ConfigPhase, ConfigRead, ConfigService, ConnectionConfig, ConnectionServices,
    ErrorKind, Pool, PoolPolicy, ReleaseOutcome, Step,
};

struct Source {
    value: Mutex<ConnectionConfig>,
    calls: AtomicUsize,
    fail: std::sync::atomic::AtomicBool,
}
impl ConfigService for Source {
    fn read(&self) -> ConfigRead<'_> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(ConfigError::source_failure(std::io::Error::other("SECRET")));
            }
            Ok(self.value.lock().unwrap().clone())
        })
    }
}
async fn fixture() -> (tokio::net::TcpListener, Arc<Source>, ConnectionServices) {
    let (listener, options) = support::listener().await;
    let source = Arc::new(Source {
        value: Mutex::new(ConnectionConfig::from_options(&options)),
        calls: AtomicUsize::new(0),
        fail: false.into(),
    });
    (listener, source, ConnectionServices::new(options.roots))
}

fn rejected_login(number: u32) -> Vec<u8> {
    let mut body = number.to_le_bytes().to_vec();
    body.extend([1, 14, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut token = vec![0xaa];
    token.extend((body.len() as u16).to_le_bytes());
    token.extend(body);
    token
}

#[tokio::test]
async fn authentication_refusal_rereads_once_and_only_reopens_for_changed_settings() {
    for rejection in [18456, 18452] {
        let (listener, source, services) = fixture().await;
        let update = source.clone();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut peer, _) = Peer::await_login(socket, false).await;
            update.value.lock().unwrap().password = "rotated-test-password".into();
            peer.reply(&rejected_login(rejection)).await;
            peer.expect_eof().await;
            Peer::login_next(&listener, 0x74000004, false)
                .await
                .drain_to_eof()
                .await;
        });
        let pool = Pool::from_config(source.clone(), 1, services, PoolPolicy::default()).unwrap();
        let lease = pool.acquire().await.unwrap();
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
        drop(lease);
        pool.close().await.unwrap();
        server.await.unwrap();
    }
}

#[tokio::test]
async fn unchanged_refused_credentials_are_not_retried() {
    for rejection in [18456, 18452] {
        let (listener, source, services) = fixture().await;
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut peer, _) = Peer::await_login(socket, false).await;
            peer.reply(&rejected_login(rejection)).await;
            peer.expect_eof().await;
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
        let pool = Pool::from_config(source.clone(), 1, services, PoolPolicy::default()).unwrap();
        assert!(pool.acquire().await.is_err());
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
        pool.close().await.unwrap();
        server.await.unwrap();
    }
}

#[tokio::test]
async fn failed_read_is_redacted_and_a_later_read_can_succeed_on_the_same_pool() {
    let (listener, source, services) = fixture().await;
    source.fail.store(true, Ordering::SeqCst);
    let pool = Pool::from_config(source.clone(), 1, services, PoolPolicy::default()).unwrap();
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    let error = pool.acquire().await.err().unwrap();
    assert_eq!(error.step, Step::Configuration);
    assert!(!format!("{error:?} {error}").contains("SECRET"));
    let ErrorKind::Configuration(cause) = error.kind else {
        panic!("configuration cause")
    };
    assert!(cause.source_error().is_some());
    assert_eq!(pool.in_use(), 0);
    source.fail.store(false, Ordering::SeqCst);
    let server = tokio::spawn(async move { Peer::login(listener).await.drain_to_eof().await });
    let first = pool.acquire().await.unwrap();
    assert_eq!(first.release().await.unwrap(), ReleaseOutcome::Returned);
    let reused = pool.acquire().await.unwrap();
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    drop(reused);
    pool.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn late_login_is_superseded_and_invalid_reads_do_not_replace_accepted_settings() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (listener, source, services) = fixture().await;
        let (seen, waiting) = tokio::sync::oneshot::channel();
        let (finish, proceed) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut old, _) = Peer::await_login(socket, false).await;
            seen.send(()).unwrap();
            let newer = Peer::login_next(&listener, 0x74000004, false).await;
            proceed.await.unwrap();
            old.accept_login(0x74000004, false, &[]).await;
            old.drain_to_eof().await;
            newer.drain_to_eof().await;
        });
        let pool = Arc::new(Pool::from_config(source.clone(), 2, services, PoolPolicy::default()).unwrap());
        let opener = { let pool = pool.clone(); tokio::spawn(async move {pool.acquire().await}) };
        waiting.await.unwrap();
        source.value.lock().unwrap().password = "artificial-B".into();
        let newer = pool.acquire().await.unwrap();
        finish.send(()).unwrap();
        let error = opener.await.unwrap().err().unwrap();
        assert!(matches!(error.kind, ErrorKind::Configuration(ref e) if e.phase == ConfigPhase::Superseded));
        assert_eq!(pool.in_use(), 1);
        source.value.lock().unwrap().password = "artificial-C".into();
        // Reading a valid new value accepts it before a network/login failure.
        source.value.lock().unwrap().port = 0;
        assert!(pool.acquire().await.is_err()); // invalid values do not supersede B
        assert_eq!(newer.release().await.unwrap(), ReleaseOutcome::Returned);
        pool.close().await.unwrap();
        server.await.unwrap();
    }).await.unwrap();
}

struct Waiting {
    entered: tokio::sync::Notify,
}
impl ConfigService for Waiting {
    fn read(&self) -> ConfigRead<'_> {
        Box::pin(async move {
            self.entered.notify_one();
            std::future::pending().await
        })
    }
}
#[tokio::test]
async fn closing_or_canceling_a_source_wait_frees_capacity_and_timeout_covers_the_gate() {
    for close in [false, true] {
        let (_, _, services) = fixture().await;
        let source = Arc::new(Waiting {
            entered: tokio::sync::Notify::new(),
        });
        let pool = Arc::new(
            Pool::from_config(source.clone(), 1, services, PoolPolicy::default()).unwrap(),
        );
        let opening = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.acquire().await })
        };
        source.entered.notified().await;
        if close {
            pool.close().await.unwrap();
            assert!(opening.await.unwrap().is_err());
        } else {
            opening.abort();
            assert!(opening.await.err().unwrap().is_cancelled());
        }
        assert_eq!(pool.in_use(), 0);
        pool.close().await.unwrap();
    }
    let (_, _, services) = fixture().await;
    let source = Arc::new(Waiting {
        entered: tokio::sync::Notify::new(),
    });
    let policy = PoolPolicy {
        timeout: Duration::from_millis(40),
        ..PoolPolicy::default()
    };
    let pool = Pool::from_config(source.clone(), 2, services, policy).unwrap();
    let (a, b) = tokio::join!(pool.acquire(), pool.acquire());
    for result in [a, b] {
        let error = result.err().unwrap();
        assert_eq!(error.step, Step::Configuration);
        assert!(matches!(error.kind, ErrorKind::Timeout));
    }
    assert_eq!(pool.in_use(), 0);
}

#[test]
fn values_compare_credentials_but_debug_never_prints_them() {
    let a = ConnectionConfig::new("host", 1433, "user", "SECRET");
    let mut b = a.clone();
    b.password = "different".into();
    assert_ne!(a, b);
    assert!(b.compatible_with(&a));
    b.database = "elsewhere".into();
    assert!(!b.compatible_with(&a));
    assert!(!format!("{a:?}").contains("SECRET"));
}

struct WaitOnRecovery {
    value: ConnectionConfig,
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
}
impl ConfigService for WaitOnRecovery {
    fn read(&self) -> ConfigRead<'_> {
        Box::pin(async move {
            if self.calls.fetch_add(1, Ordering::SeqCst) != 0 {
                self.entered.notify_one();
                return std::future::pending().await;
            }
            Ok(self.value.clone())
        })
    }
}
#[tokio::test]
async fn root_close_interrupts_borrowed_recovery_during_its_configuration_read() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (listener, source, services) = fixture().await;
        let source = Arc::new(WaitOnRecovery {
            value: source.value.lock().unwrap().clone(),
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
        });
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut peer, _) = Peer::await_login(socket, false).await;
            peer.accept_login(0x74000004, false, &[0xae, 1, 0, 0, 0, 0, 255])
                .await;
            (peer, listener)
        });
        let pool = Pool::from_config(source.clone(), 1, services, PoolPolicy::default()).unwrap();
        let lease = pool.acquire().await.unwrap();
        let close = lease.close_handle();
        let (peer, listener) = server.await.unwrap();
        drop(peer);
        while !lease.is_closed() {
            tokio::task::yield_now().await;
        }
        pool.close().await.unwrap();
        let recovery = tokio::spawn(async move { lease.recover().await });
        source.entered.notified().await;
        close.close();
        assert!(recovery.await.unwrap().is_err());
        use std::{future::poll_fn, task::Poll};
        poll_fn(|cx| {
            assert!(listener.poll_accept(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(pool.in_use(), 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn lost_password_change_completion_is_uncertain_and_is_never_retried() {
    let (listener, mut options) = support::listener().await;
    options.new_password = "artificial-new-password".into();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (peer, login) = Peer::await_login(socket, false).await;
        assert_ne!(login[27] & 1, 0); // fChangePassword
        drop(peer); // LOGIN7 arrived; its server-side outcome is unknowable.
        listener
    });
    let error = tds_client::Connection::connect(options)
        .await
        .err()
        .unwrap();
    assert!(error.password_change_uncertain);
    assert!(error.to_string().contains("may already have changed"));
    assert_eq!(error.execution, tds_client::Execution::NotSent); // application SQL
    let listener = server.await.unwrap();
    use std::{future::poll_fn, task::Poll};
    poll_fn(|cx| {
        assert!(listener.poll_accept(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn recovery_candidate_cannot_install_after_another_opening_accepts_new_settings() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (listener, source, services) = fixture().await;
        let initial = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut peer, _) = Peer::await_login(socket, false).await;
            peer.accept_login(0x74000004, false, &[0xae, 1, 0, 0, 0, 0, 255]).await;
            (peer, listener)
        });
        let pool = Pool::from_config(source.clone(), 2, services, PoolPolicy::default()).unwrap();
        let lease = pool.acquire().await.unwrap();
        let (peer, listener) = initial.await.unwrap(); drop(peer);
        while !lease.is_closed() { tokio::task::yield_now().await; }
        let (seen, waiting) = tokio::sync::oneshot::channel();
        let (finish, proceed) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut recovering, _) = Peer::await_login(socket, false).await;
            seen.send(()).unwrap();
            let newer = Peer::login_next(&listener, 0x74000004, false).await;
            proceed.await.unwrap();
            recovering.accept_login(0x74000004, false, &[0xae, 1, 0, 0, 0, 0, 255]).await;
            recovering.drain_to_eof().await;
            newer.drain_to_eof().await;
        });
        let recovery = tokio::spawn(async move { let result = lease.recover().await; (lease, result) });
        waiting.await.unwrap();
        source.value.lock().unwrap().app_name = "changed".into();
        let newer = pool.acquire().await.unwrap();
        finish.send(()).unwrap();
        let (lease, result) = recovery.await.unwrap();
        let error = result.err().unwrap();
        let ErrorKind::SessionNotRecovered {cause: Some(cause), ..} = &error.cause().kind else {panic!("recovery cause: {error:?}")};
        assert!(matches!(&cause.cause().kind, ErrorKind::Configuration(e) if e.phase == ConfigPhase::Superseded));
        assert_eq!(lease.recoveries(), 0);
        drop(lease); drop(newer); pool.close().await.unwrap();
        server.await.unwrap();
    }).await.unwrap();
}
