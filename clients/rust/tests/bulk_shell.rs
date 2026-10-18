#![cfg(feature = "tokio")]
mod support;
use std::time::Duration;
use support::{Peer, done, listener};
use tds_client::{Batch, Connection, IntegerSize, SqlType, TypeInfo, tokens::Column};
fn columns() -> Vec<Column> {
    vec![Column {
        user_type: 0,
        flags: 1,
        name: "a".into(),
        type_info: TypeInfo {
            sql_type: SqlType::Integer {
                size: IntegerSize::Int,
            },
            code: 0x26,
            max_length: Some(4),
            legacy: None,
            clr_assembly: None,
            json_utf8: false,
        },
    }]
}
#[tokio::test]
async fn forgotten_writer_cannot_bypass_continuation_guard_and_delegated_close_drains() {
    let (listener, options) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, 1);
        peer.reply(&done(0)).await;
        // The forbidden ordinary batch never reaches the server.
        assert_eq!(peer.message().await.0, 6);
        peer.reply(&done(0x20)).await;
        assert_eq!(peer.message().await.0, 1);
        peer.reply(&done(0)).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let mut ch = connection.serial_channel().await.unwrap();
    let close = ch.close_handle();
    let writer = ch
        .bulk("INSERT BULK artificial(a int)", columns())
        .await
        .unwrap();
    std::mem::forget(writer);
    let error = match ch.exchange(Batch::new("forbidden")).await {
        Ok(_) => panic!("ordinary request bypassed the unfinished bulk load"),
        Err(error) => error,
    };
    assert_eq!(error.execution, tds_client::Execution::NotSent);
    assert!(matches!(error.kind, tds_client::ErrorKind::State(_)));
    close.close().await.unwrap();
    connection
        .serial_channel()
        .await
        .unwrap()
        .exchange(Batch::new("again"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}
#[tokio::test]
async fn prepared_abort_waits_for_attention_ack_not_an_ordinary_completion() {
    let (listener, mut options) = listener().await;
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = events.clone();
    options.observe = Some(tds_client::observe::Observer::new(
        tds_client::observe::Level::Outline,
        move |event| {
            observed.lock().unwrap().push(event.text.clone());
            Ok(())
        },
    ));
    let (seen, received) = tokio::sync::oneshot::channel();
    let (ack, release) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, 1);
        peer.reply(&done(0)).await;
        assert_eq!(peer.message().await.0, 6);
        peer.reply(&done(0)).await;
        seen.send(()).unwrap();
        release.await.unwrap();
        peer.reply(&done(0x20)).await;
        assert_eq!(peer.message().await.0, 1);
        peer.reply(&done(0)).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let mut ch = connection.serial_channel().await.unwrap();
    let writer = ch
        .bulk("INSERT BULK artificial(a int)", columns())
        .await
        .unwrap();
    let mut abort = Box::pin(writer.abort());
    tokio::select! {_=&mut abort=>panic!("abort ended before any acknowledgement"), _=received=>{}}
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut abort)
            .await
            .is_err()
    );
    ack.send(()).unwrap();
    abort.await.unwrap();
    ch.exchange(Batch::new("again"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
    assert_eq!(
        events
            .lock()
            .unwrap()
            .iter()
            .filter(|text| *text == "→ attention")
            .count(),
        1
    );
}
#[tokio::test]
async fn prepared_abort_timeout_discards_and_retains_the_cleanup_error() {
    let (listener, mut options) = listener().await;
    options.cleanup_timeout = Duration::from_millis(50);
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        peer.message().await;
        peer.reply(&done(0)).await;
        assert_eq!(peer.message().await.0, 6);
        peer.expect_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let mut ch = connection.serial_channel().await.unwrap();
    let error = ch
        .bulk("INSERT BULK artificial(a int)", columns())
        .await
        .unwrap()
        .abort()
        .await
        .unwrap_err();
    assert!(
        matches!(error.cause().kind, tds_client::ErrorKind::Cleanup { .. }),
        "{error:?}"
    );
    assert!(ch.exchange(Batch::new("not reusable")).await.is_err());
    connection.close().await.unwrap();
    server.await.unwrap();
}
