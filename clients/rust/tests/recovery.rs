//! Controlled recovery failure boundaries, independent of Docker and credentials.
#![cfg(feature = "tokio")]
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tds_client::{Batch, Connection, ErrorKind, Execution};
use tokio::{io::AsyncReadExt, time::timeout};
mod support;

fn recovery_ack() -> Vec<u8> {
    vec![0xae, 1, 0, 0, 0, 0, 255]
}
async fn broken(connection: &Connection) {
    timeout(Duration::from_secs(3), async {
        while !connection.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
fn has_timeout(error: &tds_client::Error) -> bool {
    match &error.cause().kind {
        ErrorKind::Timeout => true,
        ErrorKind::SessionNotRecovered {
            cause: Some(error), ..
        } => has_timeout(error),
        _ => false,
    }
}

#[tokio::test]
async fn recovery_requires_a_server_acknowledgement_and_never_opens_an_application_channel_on_refusal()
 {
    let (listener, options) = support::listener().await;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, login) = support::Peer::await_login(socket, false).await;
        assert_ne!(login[27] & 0x10, 0);
        peer.accept_login(0x74000004, false, &recovery_ack()).await;
        // Return control of the break to the test, so login readiness is known.
        (peer, listener)
    });
    let connection = Connection::connect(options).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let (peer, listener) = server.await.unwrap();
    drop(peer);
    broken(&connection).await;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, login) = support::Peer::await_login(socket, false).await;
        let at = u16::from_le_bytes(login[56..58].try_into().unwrap()) as usize;
        let feature = u32::from_le_bytes(login[at..at + 4].try_into().unwrap()) as usize;
        assert!(u32::from_le_bytes(login[feature + 1..feature + 5].try_into().unwrap()) > 0);
        peer.accept_login(0x74000004, false, &[]).await; // ordinary new session, not recovery
        peer.expect_eof().await;
    });
    let error = connection.recover().await.unwrap_err();
    assert!(error.to_string().contains("without agreeing"));
    assert_eq!(connection.recoveries(), 0);
    assert!(channel.exchange(Batch::new("SELECT 1")).await.is_err());
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn recovery_timeout_closes_the_candidate_and_a_later_explicit_attempt_can_succeed() {
    let (listener, mut options) = support::listener().await;
    options.timeout = Duration::from_millis(500);
    let calls = Arc::new(AtomicUsize::new(0));
    let callbacks = calls.clone();
    options.observe = Some(tds_client::observe::Observer::new(
        tds_client::observe::Level::Outline,
        move |event| {
            if event.text.starts_with("recover ·") {
                callbacks.fetch_add(1, Ordering::SeqCst);
                return Err(std::io::Error::other("optional display failed"));
            }
            Ok(())
        },
    ));
    let (cut, cutting) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = support::Peer::await_login(socket, false).await;
        peer.accept_login(0x74000004, false, &recovery_ack()).await;
        cutting.await.unwrap();
        drop(peer);
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 16384];
        while socket.read(&mut bytes).await.unwrap() != 0 {} // silent TLS peer
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = support::Peer::await_login(socket, false).await;
        peer.accept_login(0x74000004, false, &recovery_ack()).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let _channel = connection.serial_channel().await.unwrap();
    cut.send(()).unwrap();
    broken(&connection).await;
    assert!(has_timeout(&connection.recover().await.unwrap_err()));
    assert!(connection.observation_error().is_some());
    assert_eq!(connection.recoveries(), 0);
    connection.recover().await.unwrap();
    assert_eq!(connection.recoveries(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1); // failed observer stays disabled across the failed attempt
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn a_preexisting_root_close_permission_interrupts_a_silent_recovery_login() {
    let (listener, options) = support::listener().await;
    let (cut, cutting) = tokio::sync::oneshot::channel();
    let (arrived, arrival) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = support::Peer::await_login(socket, false).await;
        peer.accept_login(0x74000004, false, &recovery_ack()).await;
        cutting.await.unwrap();
        drop(peer);
        let (mut socket, _) = listener.accept().await.unwrap();
        arrived.send(()).unwrap();
        let mut bytes = [0; 16384];
        while socket.read(&mut bytes).await.unwrap() != 0 {}
    });
    let connection = Connection::connect(options).await.unwrap();
    let close = connection.close_handle();
    cut.send(()).unwrap();
    broken(&connection).await;
    {
        let recovering = connection.recover();
        tokio::pin!(recovering);
        tokio::select! {
            result = &mut recovering => panic!("completed before peer went silent: {result:?}"),
            _ = arrival => {},
        }
        close.close();
        assert!(
            timeout(Duration::from_secs(2), &mut recovering)
                .await
                .unwrap()
                .is_err()
        );
    }
    server.await.unwrap();
    connection.close().await.unwrap();
}

#[tokio::test]
async fn failed_recovery_recording_factory_is_terminal_before_a_second_socket_opens() {
    let (listener, mut options) = support::listener().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    options.capture_factory = Some(Arc::new(move || {
        if count.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(tds_client::capture::Capture::new(std::io::sink()))
        } else {
            Err(std::io::Error::other("recording unavailable"))
        }
    }));
    let (cut, cutting) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = support::Peer::await_login(socket, false).await;
        peer.accept_login(0x74000004, false, &recovery_ack()).await;
        cutting.await.unwrap();
        drop(peer);
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    let connection = Connection::connect(options).await.unwrap();
    cut.send(()).unwrap();
    broken(&connection).await;
    let error = connection.recover().await.unwrap_err();
    assert!(error.to_string().contains("recording"));
    assert_eq!(error.execution, Execution::NotSent);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(connection.recover().await.is_err());
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn attaching_a_direct_recording_requires_a_factory_for_recovery() {
    let (listener, options) = support::listener().await;
    let (cut, cutting) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = support::Peer::await_login(socket, false).await;
        peer.accept_login(0x74000004, false, &recovery_ack()).await;
        cutting.await.unwrap();
        drop(peer);
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    let connection = Connection::connect(options).await.unwrap();
    connection
        .set_capture(Some(tds_client::capture::Capture::new(std::io::sink())))
        .await
        .unwrap();
    cut.send(()).unwrap();
    broken(&connection).await;
    assert!(
        connection
            .recover()
            .await
            .unwrap_err()
            .to_string()
            .contains("capture_factory")
    );
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn malformed_duplicate_or_unrequested_recovery_acknowledgements_fail_login() {
    for (feature, requested) in [
        (vec![0xae, 2, 0, 0, 0, 0, 255], true),
        (vec![0xae, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 255], true),
        (vec![0xae, 1, 6, 0, 0, 0, 9, 255, 1, 0, 0, 0, 255], true),
        (recovery_ack(), false),
    ] {
        let (listener, mut options) = support::listener().await;
        options.session_recovery = requested;
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut peer, _) = support::Peer::await_login(socket, false).await;
            peer.accept_login(0x74000004, false, &feature).await;
            peer.expect_eof().await;
        });
        let error = match Connection::connect(options).await {
            Err(error) => error,
            Ok(_) => panic!("accepted invalid acknowledgement"),
        };
        assert_eq!(error.step, tds_client::Step::Login);
        assert!(matches!(error.cause().kind, ErrorKind::Malformed { .. }));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn dropping_a_submitted_recovery_future_discards_its_candidate() {
    let (listener, options) = support::listener().await;
    let (cut, cutting) = tokio::sync::oneshot::channel();
    let (arrived, arrival) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = support::Peer::await_login(socket, false).await;
        peer.accept_login(0x74000004, false, &recovery_ack()).await;
        cutting.await.unwrap();
        drop(peer);
        let (mut socket, _) = listener.accept().await.unwrap();
        arrived.send(()).unwrap();
        let mut bytes = [0; 16384];
        while socket.read(&mut bytes).await.unwrap() != 0 {}
    });
    let connection = Connection::connect(options).await.unwrap();
    cut.send(()).unwrap();
    broken(&connection).await;
    let mut recovering = Box::pin(connection.recover());
    tokio::select! { result = &mut recovering => panic!("unexpected completion: {result:?}"), _ = arrival => {} }
    drop(recovering);
    assert!(connection.recover().await.is_err());
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    connection.close().await.unwrap();
}

#[tokio::test]
async fn a_new_recording_write_failure_discards_before_sending_the_recovery_hello() {
    struct BrokenOutput;
    impl std::io::Write for BrokenOutput {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("recording write failed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (listener, mut options) = support::listener().await;
    let calls = Arc::new(AtomicUsize::new(0));
    options.capture_factory = Some(Arc::new(move || {
        Ok(if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            tds_client::capture::Capture::new(std::io::sink())
        } else {
            tds_client::capture::Capture::new(BrokenOutput)
        })
    }));
    let (cut, cutting) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = support::Peer::await_login(socket, false).await;
        peer.accept_login(0x74000004, false, &recovery_ack()).await;
        cutting.await.unwrap();
        drop(peer);
        let (mut candidate, _) = listener.accept().await.unwrap();
        assert_eq!(candidate.read(&mut [0; 1]).await.unwrap(), 0);
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    let connection = Connection::connect(options).await.unwrap();
    cut.send(()).unwrap();
    broken(&connection).await;
    assert!(
        connection
            .recover()
            .await
            .unwrap_err()
            .to_string()
            .contains("recording")
    );
    assert!(connection.recover().await.is_err());
    connection.close().await.unwrap();
    server.await.unwrap();
}
