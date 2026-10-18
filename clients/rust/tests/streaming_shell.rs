//! Controlled peers prove cleanup consequences independently of SQL Server.
#![cfg(feature = "tokio")]
mod support;
use std::{collections::VecDeque, time::Duration};
use support::{Peer, done, listener};
use tds_client::{
    Batch, Call, Chunk, Connection, ErrorKind, Param, Source, SourceRead, SqlType, StreamedCall,
};
struct Pieces(VecDeque<std::io::Result<Chunk>>);
impl Source for Pieces {
    fn next_chunk(&mut self) -> SourceRead<'_> {
        Box::pin(async { self.0.pop_front().transpose() })
    }
}
fn fails(partial: bool) -> StreamedCall {
    let mut pieces = VecDeque::new();
    if partial {
        pieces.push_back(Ok(Chunk::Binary(vec![7; 20000])));
    }
    pieces.push_back(Err(std::io::Error::other("producer failed")));
    StreamedCall::new(Call::new(
        "artificial",
        vec![Param::new("@b", SqlType::BinaryMax, None)],
    ))
    .source(0, Pieces(pieces))
}
#[tokio::test]
async fn partial_source_failure_uses_ignore_eom_drains_and_preserves_reuse() {
    let (listener, options) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, tds_client::packet::RPC);
        assert_eq!(peer.last_status, 3); // IGNORE + EOM, never Attention for partial input.
        peer.reply(&done(2)).await;
        assert_eq!(peer.message().await.0, tds_client::packet::BATCH);
        peer.reply(&done(0)).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let error = match channel.exchange(fails(true)).await {
        Ok(_) => panic!(),
        Err(e) => e,
    };
    assert!(matches!(error.kind, ErrorKind::Io(_)));
    assert!(error.response.unwrap().ended);
    channel
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
async fn source_cleanup_timeout_retains_both_causes_and_discards_transport() {
    let (listener, mut options) = listener().await;
    options.cleanup_timeout = Duration::from_millis(50);
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        peer.message().await;
        assert_eq!(peer.last_status, 3);
        peer.expect_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let error = match tokio::time::timeout(Duration::from_secs(2), channel.exchange(fails(true)))
        .await
        .unwrap()
    {
        Ok(_) => panic!(),
        Err(e) => e,
    };
    let ErrorKind::Cleanup { original, cleanup } = &error.cause().kind else {
        panic!("{error:?}")
    };
    assert!(matches!(original.cause().kind, ErrorKind::Io(_)));
    assert!(matches!(cleanup.cause().kind, ErrorKind::Timeout));
    assert!(channel.exchange(Batch::new("no reuse")).await.is_err());
    connection.close().await.unwrap();
    server.await.unwrap();
}
#[tokio::test]
async fn abandoned_chunk_read_revokes_transport_without_advancing_hidden_state() {
    let (listener, options) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        peer.message().await;
        let mut body = vec![0x81, 1, 0];
        body.extend([0; 6]);
        body.extend([0xa5, 0xff, 0xff, 0, 0xd1]);
        body.extend((u64::MAX - 1).to_le_bytes());
        body.extend(3_u32.to_le_bytes());
        body.extend(b"abc");
        peer.reply_with_end(&body, 4096, false).await;
        peer.expect_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    {
        let mut response = channel.exchange(Batch::new("large")).await.unwrap();
        {
            let mut set = response.next_result_set().await.unwrap().unwrap();
            let mut row = set.streamed_row().await.unwrap().unwrap();
            let Some(tds_client::Cell::Stream(mut value)) = row.next_value().await.unwrap() else {
                panic!()
            };
            assert_eq!(
                value.next_chunk().await.unwrap(),
                Some(Chunk::Binary(b"abc".to_vec()))
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(20), value.next_chunk())
                    .await
                    .is_err()
            );
        }
        assert_eq!(response.snapshot().result_sets()[0].rows_read, 0);
    }
    assert!(channel.exchange(Batch::new("no reuse")).await.is_err());
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn source_bindings_validate_before_poll_or_send_and_leave_channel_reusable() {
    let (listener, options) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        // No rejected request ever reaches this peer.
        assert_eq!(peer.message().await.0, tds_client::packet::BATCH);
        peer.reply(&done(0)).await;
        peer.drain_to_eof().await;
    });
    struct Uncalled;
    impl Source for Uncalled {
        fn next_chunk(&mut self) -> SourceRead<'_> {
            panic!("invalid binding polled")
        }
    }
    let connection = Connection::connect(options).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    for index in [0, 1] {
        let call = Call::new("invalid", vec![Param::new("@b", SqlType::Bit, None)]);
        let request = StreamedCall::new(call).source(index, Uncalled);
        let error = match channel.exchange(request).await {
            Ok(_) => panic!(),
            Err(e) => e,
        };
        assert!(matches!(error.kind, ErrorKind::Parameter(_)));
        assert_eq!(error.execution, tds_client::Execution::NotSent);
    }
    // The entire batch validates before even the first valid producer runs.
    let valid = StreamedCall::new(Call::new(
        "first",
        vec![Param::new("@b", SqlType::BinaryMax, None)],
    ))
    .source(0, Uncalled);
    let invalid = StreamedCall::new(Call::new(
        "second",
        vec![Param::new("@b", SqlType::Bit, None)],
    ))
    .source(0, Uncalled);
    let error = match channel
        .exchange(tds_client::StreamedCalls(vec![valid, invalid]))
        .await
    {
        Ok(_) => panic!("invalid later call accepted"),
        Err(error) => error,
    };
    assert_eq!(error.execution, tds_client::Execution::NotSent);
    channel
        .exchange(Batch::new("valid"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn channel_close_interrupts_a_partly_sent_waiting_source_then_releases_lifetime() {
    let (listener, options) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        peer.message().await;
        assert_eq!(peer.last_status, 3);
        peer.reply(&done(2)).await;
        peer.message().await;
        peer.reply(&done(0)).await;
        peer.drain_to_eof().await;
    });
    struct WaitAfter {
        reached: Option<tokio::sync::oneshot::Sender<()>>,
        first: bool,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    impl Source for WaitAfter {
        fn next_chunk(&mut self) -> SourceRead<'_> {
            Box::pin(async move {
                if !self.first {
                    self.first = true;
                    return Ok(Some(Chunk::Binary(vec![1; 20000])));
                }
                self.reached.take().unwrap().send(()).unwrap();
                std::future::pending().await
            })
        }
    }
    impl Drop for WaitAfter {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
    let connection = Connection::connect(options).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let close = channel.close_handle();
    let (reached, waiting) = tokio::sync::oneshot::channel();
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let request = StreamedCall::new(Call::new(
        "artificial",
        vec![Param::new("@b", SqlType::BinaryMax, None)],
    ))
    .source(
        0,
        WaitAfter {
            reached: Some(reached),
            first: false,
            dropped: dropped.clone(),
        },
    );
    tokio::join!(
        async {
            assert!(channel.exchange(request).await.is_err());
        },
        async {
            waiting.await.unwrap();
            close.close().await.unwrap();
        }
    );
    assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
    assert!(channel.exchange(Batch::new("stale")).await.is_err());
    connection
        .serial_channel()
        .await
        .unwrap()
        .exchange(Batch::new("new lifetime"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}
