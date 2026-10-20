//! One channel lifetime is revoked before cleanup, released only after proof.
#![cfg(feature = "tokio")]
mod support;
use std::time::Duration;
use support::{Peer, done, listener};
use tds_client::{Batch, Connection, ErrorKind, packet};
use tokio::sync::oneshot;

#[tokio::test]
async fn busy_close_waits_for_ack_and_its_message_then_stale_controls_are_harmless() {
    let (listener, config) = listener().await;
    let (sent, ordinary) = oneshot::channel();
    let (allow_ack, ack) = oneshot::channel();
    let (sent_ack, ack_arrived) = oneshot::channel();
    let (end_ack, end) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        assert_eq!(peer.message().await.0, packet::ATTENTION);
        peer.reply(&done(0)).await;
        sent.send(()).unwrap();
        ack.await.unwrap();
        peer.reply_with_end(&done(0x20), 4096, false).await;
        sent_ack.send(()).unwrap();
        end.await.unwrap();
        peer.reply(&[]).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(&done(0)).await;
        peer.expect_eof().await; // Stay connected until the client closes.
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut old = connection.serial_channel().await.unwrap();
    let close = old.close_handle();
    let mut response = old.exchange(Batch::new("old")).await.unwrap();
    {
        let closing = close.close();
        tokio::pin!(closing);
        tokio::select! { result = &mut closing => panic!("released before ACK: {result:?}"), _ = ordinary => {} }
        assert!(connection.serial_channel().await.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut closing)
                .await
                .is_err()
        );
        allow_ack.send(()).unwrap();
        ack_arrived.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut closing)
                .await
                .is_err()
        );
        end_ack.send(()).unwrap();
        closing.await.unwrap();
    }
    let mut replacement = connection.serial_channel().await.unwrap();
    let error = response.next().await.unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Closed));
    assert_eq!(error.execution, tds_client::Execution::PossiblyExecuted);
    assert!(
        error
            .response
            .unwrap()
            .completions()
            .last()
            .unwrap()
            .acknowledges_cancel()
    );
    drop(response);
    close.close().await.unwrap();
    close.close().await.unwrap();
    assert!(old.exchange(Batch::new("stale")).await.is_err());
    replacement
        .exchange(Batch::new("replacement"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    drop(old); // Old authority destruction must not discard the replacement.
    replacement.close().await.unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn delegated_close_wakes_a_waiting_owner_and_all_close_waiters() {
    let (listener, config) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        assert_eq!(peer.message().await.0, packet::ATTENTION);
        peer.reply(&done(0x20)).await;
        peer.expect_eof().await; // successful cleanup is checked while the peer remains connected
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let close = channel.close_handle();
    let duplicate = close.clone();
    let mut response = channel.exchange(Batch::new("waiting owner")).await.unwrap();
    let (owner, first, second) = tokio::join!(response.next(), close.close(), duplicate.close());
    first.unwrap();
    second.unwrap();
    let error = owner.unwrap_err();
    assert!(matches!(
        error.kind,
        ErrorKind::Closed | ErrorKind::Canceled
    ));
    assert!(error.response.unwrap().ended);
    drop(response);
    assert!(!connection.is_closed());
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn failed_channel_cleanup_is_shared_and_discards_without_an_owner_read() {
    let (listener, mut config) = listener().await;
    config.cleanup_timeout = Duration::from_millis(50);
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        assert_eq!(peer.message().await.0, packet::ATTENTION);
        peer.reply(&done(0)).await;
        peer.expect_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let close = channel.close_handle();
    let duplicate = close.clone();
    let response = channel.exchange(Batch::new("missing ACK")).await.unwrap();
    let (first, second) = tokio::join!(close.close(), duplicate.close());
    for error in [first.unwrap_err(), second.unwrap_err()] {
        let ErrorKind::Cleanup { original, cleanup } = error.kind else {
            panic!("both causes required");
        };
        assert!(matches!(original.kind, ErrorKind::Closed));
        let ErrorKind::Shared(cause) = cleanup.kind else {
            panic!("shared cleanup cause required");
        };
        assert!(matches!(cause.cause().kind, ErrorKind::Timeout));
    }
    assert!(connection.is_closed());
    drop(response);
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn dropping_a_pending_channel_close_discards() {
    let (listener, config) = listener().await;
    let (sent, attention) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        assert_eq!(peer.message().await.0, packet::ATTENTION);
        sent.send(()).unwrap();
        peer.expect_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let close = channel.close_handle();
    let response = channel
        .exchange(Batch::new("abandoned close"))
        .await
        .unwrap();
    {
        let closing = close.close();
        tokio::pin!(closing);
        tokio::select! { result = &mut closing => panic!("early close: {result:?}"), _ = attention => {} }
    }
    assert!(connection.is_closed());
    drop(response);
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn malformed_or_fatal_drain_keeps_the_shared_cause_and_partial_record() {
    for fatal in [false, true] {
        let (listener, config) = listener().await;
        let server = tokio::spawn(async move {
            let mut peer = Peer::login(listener).await;
            assert_eq!(peer.message().await.0, packet::BATCH);
            assert_eq!(peer.message().await.0, packet::ATTENTION);
            if fatal {
                let mut body = include_bytes!("fixtures/responses/messages.bin")[..51].to_vec();
                body[0] = 0xaa;
                body[8] = 20; // explicitly synthetic fatal ERROR, preserving the capture itself
                body.extend(done(0x20));
                peer.reply(&body).await;
            } else {
                peer.reply(&[0xab, 1, 0, 0]).await;
            }
            peer.expect_eof().await;
        });
        let connection = Connection::connect(config).await.unwrap();
        let mut channel = connection.serial_channel().await.unwrap();
        let close = channel.close_handle();
        let response = channel.exchange(Batch::new("failed drain")).await.unwrap();
        let error = close.close().await.unwrap_err();
        let record = error.response.unwrap();
        assert!(!record.ended);
        let ErrorKind::Cleanup { original, cleanup } = error.kind else {
            panic!("missing both causes");
        };
        assert!(matches!(original.kind, ErrorKind::Closed));
        let ErrorKind::Shared(cause) = cleanup.kind else {
            panic!("missing shared failure");
        };
        if fatal {
            assert!(
                matches!(cause.cause().kind, ErrorKind::Server(ref message) if message.severity == 20)
            );
            assert_eq!(record.errors().next().unwrap().severity, 20);
        } else {
            assert!(matches!(cause.cause().kind, ErrorKind::Malformed { .. }));
        }
        assert!(connection.is_closed());
        drop(response);
        connection.close().await.unwrap();
        server.await.unwrap();
    }
}
