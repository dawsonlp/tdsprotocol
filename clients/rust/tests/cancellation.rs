//! Controlled, verified-TLS peers expose cancellation races that a fast live
//! server cannot reliably produce. No Docker or local credentials required.
#![cfg(feature = "tokio")]
mod support;
use std::time::Duration;
use support::{Peer, done, listener};
use tds_client::{Batch, Connection, Error, ErrorKind, Execution, Record, Step, packet};
use tokio::sync::oneshot;

#[tokio::test]
async fn verified_peer_cannot_silently_change_the_negotiated_tds_version() {
    let (listener, config) = listener().await;
    let server = tokio::spawn(async move {
        Peer::login_with_version(listener, 0x73000003)
            .await
            .expect_eof()
            .await;
    });
    let error = match Connection::connect(config).await {
        Ok(_) => panic!("wrong TDS version accepted"),
        Err(error) => error,
    };
    assert_eq!(error.step, Step::Login);
    assert!(matches!(
        error.kind,
        ErrorKind::Unsupported("server TDS version")
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn close_waits_for_later_ack_and_repeated_or_stale_handles_emit_no_attention() {
    let (listener, config) = listener().await;
    let (ordinary_sent, ordinary) = oneshot::channel();
    let (acknowledge, ack) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        assert_eq!(peer.message().await, (packet::ATTENTION, vec![]));
        peer.reply(&done(0)).await;
        ordinary_sent.send(()).unwrap();
        ack.await.unwrap();
        peer.reply(&done(0x20)).await;
        // Neither repeated cancellation nor the old handle may put a second
        // Attention ahead of the replacement exchange.
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(&done(0)).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let response = channel.exchange(Batch::new("SELECT 1")).await.unwrap();
    let stale = response.cancel_handle();
    {
        let closing = response.close();
        tokio::pin!(closing);
        tokio::select! { result = &mut closing => panic!("cleanup ended before ACK: {result:?}"), _ = ordinary => {} }
        stale.cancel();
        stale.cancel();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), closing.as_mut())
                .await
                .is_err()
        );
        assert!(!connection.is_closed());
        acknowledge.send(()).unwrap();
        closing.await.unwrap();
    }
    let mut response = channel.exchange(Batch::new("SELECT 2")).await.unwrap();
    stale.cancel();
    assert!(matches!(
        response.next().await.unwrap(),
        Some(Record::Done(_))
    ));
    assert!(response.next().await.unwrap().is_none());
    drop(response);
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn external_cancel_wakes_an_advancing_reader_only_after_acknowledgement() {
    let (listener, config) = listener().await;
    let (sent, received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        sent.send(()).unwrap();
        assert_eq!(peer.message().await, (packet::ATTENTION, vec![]));
        peer.reply(&done(0x20)).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(&done(0)).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel.exchange(Batch::new("SELECT 1")).await.unwrap();
    let cancel = response.cancel_handle();
    let canceller = tokio::spawn(async move {
        received.await.unwrap();
        cancel.cancel();
    });
    let error = response.next().await.unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Canceled));
    assert!(response.timing().until_first_packet().is_some());
    assert!(response.timing().until_end().is_some());
    assert!(!connection.is_closed());
    assert!(response.next().await.unwrap().is_none());
    drop(response);
    let mut response = channel.exchange(Batch::new("SELECT 2")).await.unwrap();
    assert!(response.next().await.unwrap().is_some());
    drop(response);
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    canceller.await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn missing_ack_times_out_autonomously_even_without_an_application_read() {
    let (listener, mut config) = listener().await;
    config.cleanup_timeout = Duration::from_millis(150);
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        assert_eq!(peer.message().await.0, packet::ATTENTION);
        peer.reply(&done(0)).await;
        peer.expect_eof().await; // Ordinary DONE is insufficient.
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let response = channel.exchange(Batch::new("SELECT 1")).await.unwrap();
    response.cancel_handle().cancel();
    server.await.unwrap();
    assert!(connection.is_closed());
    let error = response.close().await.unwrap_err();
    assert_eq!(error.step, Step::Cleanup);
    let ErrorKind::Cleanup { original, cleanup } = error.kind else {
        panic!("missing both causes");
    };
    assert!(matches!(original.kind, ErrorKind::Canceled));
    assert!(matches!(cleanup.cause().kind, ErrorKind::Timeout));
    assert_eq!(cleanup.step, Step::Cleanup);
    connection.close().await.unwrap();
}

#[tokio::test]
async fn cleanup_failure_preserves_the_callers_original_failure() {
    let (listener, config) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        assert_eq!(peer.message().await.0, packet::ATTENTION);
        peer.reply(&[0xab, 1, 0, 0]).await;
        peer.expect_eof().await; // Bounded INFO with truncated fields.
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let response = channel.exchange(Batch::new("SELECT 1")).await.unwrap();
    let original = Error {
        password_change_uncertain: false,
        step: Step::Exchange,
        execution: Execution::PossiblyExecuted,
        kind: ErrorKind::State("original application failure"),
        response: None,
    };
    let error = response.close_after(original).await;
    let ErrorKind::Cleanup { original, cleanup } = error.kind else {
        panic!("original failure was replaced");
    };
    assert!(matches!(
        original.kind,
        ErrorKind::State("original application failure")
    ));
    assert!(matches!(cleanup.cause().kind, ErrorKind::Malformed { .. }));
    assert!(connection.is_closed());
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn successful_cleanup_returns_the_original_failure_without_replacing_it() {
    let (listener, config) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        assert_eq!(peer.message().await.0, packet::ATTENTION);
        peer.reply(&done(0x20)).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(&done(0)).await;
        peer.expect_eof().await; // Stay connected until the client closes.
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let response = channel.exchange(Batch::new("SELECT 1")).await.unwrap();
    let original = Error {
        password_change_uncertain: false,
        step: Step::Exchange,
        execution: Execution::PossiblyExecuted,
        kind: ErrorKind::State("original application failure"),
        response: None,
    };
    let error = response.close_after(original).await;
    assert!(matches!(
        error.kind,
        ErrorKind::State("original application failure")
    ));
    assert!(!connection.is_closed());
    let mut response = channel.exchange(Batch::new("SELECT 2")).await.unwrap();
    response.next().await.unwrap();
    drop(response);
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn dropping_close_or_a_cancel_waiting_read_discards_immediately() {
    for close in [true, false] {
        let (listener, config) = listener().await;
        let (attention_seen, seen) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut peer = Peer::login(listener).await;
            assert_eq!(peer.message().await.0, packet::BATCH);
            assert_eq!(peer.message().await.0, packet::ATTENTION);
            attention_seen.send(()).unwrap();
            peer.expect_eof().await;
        });
        let connection = Connection::connect(config).await.unwrap();
        let mut channel = connection.serial_channel().await.unwrap();
        let mut response = channel.exchange(Batch::new("SELECT 1")).await.unwrap();
        if close {
            let closing = response.close();
            tokio::pin!(closing);
            tokio::select! { _ = seen => {}, result = &mut closing => panic!("unexpected completion: {result:?}") }
            // Leaving this block drops the owned Response in the close future.
        } else {
            response.cancel_handle().cancel();
            {
                let reading = response.next();
                tokio::pin!(reading);
                tokio::select! { _ = seen => {}, result = &mut reading => panic!("unexpected completion: {result:?}") }
            }
            // The Response still exists; dropping only its read future must
            // nevertheless revoke the connection and its consumed notification.
            assert!(connection.is_closed());
            drop(response);
        }
        assert!(connection.is_closed());
        connection.close().await.unwrap();
        server.await.unwrap();
    }
}
