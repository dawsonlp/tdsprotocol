//! Diagnostic policy through real TLS, with controlled failures and no SQL Server.
#![cfg(feature = "tokio")]
mod support;
use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use support::{Peer, done, listener};
use tds_client::Value::Integer as Int;
use tds_client::{
    Batch, Connection, ErrorKind, Record,
    capture::Capture,
    observe::{Event, Inspection, Level, Observer},
};

#[derive(Clone, Default)]
struct Output {
    bytes: Arc<Mutex<Vec<u8>>>,
    fail: Arc<AtomicBool>,
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail.load(Ordering::Acquire) {
            return Err(io::Error::other("recording failed"));
        }
        self.bytes.lock().unwrap().extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[tokio::test]
async fn failed_channel_observer_is_disabled_without_losing_capture_or_reuse() {
    let (listener, mut options) = listener().await;
    let output = Output::default();
    let captured = output.clone();
    options.capture_factory = Some(Arc::new(move || Ok(Capture::new(captured.clone()))));
    options.observe = Some(Observer::new(Level::Full, |event| {
        if event.kind == "channel" {
            Err(io::Error::other("display failed"))
        } else {
            Ok(())
        }
    }));
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        for _ in 0..2 {
            peer.message().await;
            peer.reply(&done(0)).await;
        }
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    assert_eq!(
        connection.observation_error().unwrap().to_string(),
        "display failed"
    );
    for _ in 0..2 {
        channel
            .exchange(Batch::new("SELECT 1"))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    }
    assert!(!connection.is_closed());
    connection.set_observe(None).await.unwrap();
    assert!(connection.observation_error().is_none());
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
    let bytes = output.bytes.lock().unwrap().clone();
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("SQL batch"))
            .count(),
        2
    );
}

#[tokio::test]
async fn saved_recording_failure_on_channel_open_reports_cause_and_closes_socket() {
    let (listener, options) = listener().await;
    let server = tokio::spawn(async move {
        Peer::login(listener).await.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let output = Output::default();
    output.fail.store(true, Ordering::Release);
    connection
        .set_capture(Some(Capture::new(output)))
        .await
        .unwrap();
    let error = connection.serial_channel().await.err().unwrap();
    assert!(matches!(error.cause().kind, ErrorKind::Capture(_)));
    assert!(connection.is_closed());
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn saved_recording_failure_on_response_preserves_prefix_and_discards_connection() {
    let (listener, options) = listener().await;
    let (sent, received) = tokio::sync::oneshot::channel();
    let (continue_send, continue_receive) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        peer.message().await;
        let mut prefix = vec![0x81, 1, 0, 0, 0, 0, 0, 0, 0, 0x38, 1, b'a', 0, 0xd1];
        prefix.extend(11_i32.to_le_bytes());
        peer.reply_with_end(&prefix, 4096, false).await;
        let _ = sent.send(());
        continue_receive.await.unwrap();
        peer.reply(&done(0)).await;
        peer.drain_to_eof().await;
    });
    let output = Output::default();
    let connection = Connection::connect(options).await.unwrap();
    connection
        .set_capture(Some(Capture::new(output.clone())))
        .await
        .unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel.exchange(Batch::new("SELECT 1")).await.unwrap();
    received.await.unwrap();
    assert!(matches!(
        response.next().await.unwrap(),
        Some(Record::Columns(_))
    ));
    assert_eq!(
        response.next().await.unwrap(),
        Some(Record::Row(vec![Some(Int(11))]))
    );
    output.fail.store(true, Ordering::Release);
    continue_send.send(()).unwrap();
    let error = response.next().await.unwrap_err();
    assert!(matches!(error.cause().kind, ErrorKind::Capture(_)));
    assert!(error.response.is_some() && connection.is_closed());
    assert_eq!(
        error.response.as_ref().unwrap().result_sets()[0].rows_read,
        1
    );
    drop(response);
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn levels_preserve_records_and_lines_and_full_credentials_stay_redacted() {
    let mut previous = None;
    for level in [Level::Off, Level::Outline, Level::Full] {
        let (listener, mut options) = listener().await;
        let events = Arc::new(Mutex::new(Vec::<Event>::new()));
        let collected = events.clone();
        options.observe = Some(Observer::new(level, move |e| {
            collected.lock().unwrap().push(e.clone());
            Ok(())
        }));
        let server = tokio::spawn(async move {
            let mut peer = Peer::login(listener).await;
            peer.message().await;
            peer.reply(include_bytes!("fixtures/responses/counts.bin"))
                .await;
            peer.drain_to_eof().await;
        });
        let connection = Connection::connect(options).await.unwrap();
        let mut channel = connection.serial_channel().await.unwrap();
        let mut response = channel.exchange(Batch::new("SELECT 1")).await.unwrap();
        let (mut rows, mut counts) = (Vec::new(), Vec::new());
        while let Some(record) = response.next().await.unwrap() {
            match record {
                Record::Row(row) => rows.push(row),
                Record::Done(done) => counts.push(done.row_count),
                _ => {}
            }
        }
        assert_eq!(
            rows,
            [vec![Some(Int(1))], vec![Some(Int(3))], vec![Some(Int(4))]]
        );
        assert_eq!(counts, [Some(3), Some(2), Some(3), Some(3)]);
        response.finish().await.unwrap();
        drop(response);
        channel.close().await.unwrap();
        connection.close().await.unwrap();
        server.await.unwrap();
        let events = events.lock().unwrap();
        if level == Level::Off {
            assert!(events.is_empty());
            continue;
        }
        let lines: Vec<_> = events.iter().map(|e| e.text.clone()).collect();
        if let Some(previous) = &previous {
            assert_eq!(&lines, previous);
        }
        previous = Some(lines);
        if level == Level::Outline {
            assert!(events.iter().all(|e| e.inspection.is_none()));
        } else {
            let body = events
                .iter()
                .find_map(|e| match &e.inspection {
                    Some(Inspection::Packet { header, body })
                        if header[0] == tds_client::packet::LOGIN =>
                    {
                        Some(body)
                    }
                    _ => None,
                })
                .unwrap();
            let start = usize::from(u16::from_le_bytes(body[44..46].try_into().unwrap()));
            let count = usize::from(u16::from_le_bytes(body[46..48].try_into().unwrap())) * 2;
            assert!(body[start..start + count].iter().all(|byte| *byte == 0));
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e.inspection, Some(Inspection::Record(Record::Row(_)))))
            );
        }
    }
}

#[tokio::test]
async fn recording_failure_before_request_write_never_sends_unrecorded_sql() {
    let (listener, options) = listener().await;
    let server = tokio::spawn(async move {
        Peer::login(listener).await.expect_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let output = Output::default();
    connection
        .set_capture(Some(Capture::new(output.clone())))
        .await
        .unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    output.fail.store(true, Ordering::Release);
    let error = channel
        .exchange(Batch::new("must not reach server"))
        .await
        .err()
        .unwrap();
    assert!(matches!(error.cause().kind, ErrorKind::Capture(_)));
    assert!(connection.is_closed());
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn changing_observation_or_capture_during_an_exchange_is_refused() {
    let (listener, options) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        peer.message().await;
        peer.reply(&done(0)).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel.exchange(Batch::new("SELECT 1")).await.unwrap();
    assert!(matches!(
        connection.set_observe(None).await.unwrap_err().kind,
        ErrorKind::State(_)
    ));
    assert!(matches!(
        connection.set_capture(None).await.unwrap_err().kind,
        ErrorKind::State(_)
    ));
    response.finish().await.unwrap();
    drop(response);
    connection
        .set_capture(Some(Capture::new(Output::default())))
        .await
        .unwrap();
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn pool_factory_is_per_physical_connection_and_persists_through_reuse() {
    let (listener, mut options) = listener().await;
    let outputs = Arc::new(Mutex::new(Vec::<Output>::new()));
    let recordings = outputs.clone();
    options.capture_factory = Some(Arc::new(move || {
        let out = Output::default();
        recordings.lock().unwrap().push(out.clone());
        Ok(Capture::new(out))
    }));
    let server = tokio::spawn(async move {
        let a = Peer::login_next(&listener, 0x74000004, false).await;
        let b = Peer::login_next(&listener, 0x74000004, false).await;
        let serve = |mut peer: Peer, requests| async move {
            for _ in 0..requests {
                peer.message().await;
                peer.reply(&done(0)).await;
            }
            peer.drain_to_eof().await;
        };
        tokio::join!(serve(a, 2), serve(b, 1));
    });
    let pool = tds_client::Pool::new(options, 2).unwrap();
    let a = pool.acquire().await.unwrap();
    let b = pool.acquire().await.unwrap();
    let mut ca = a.serial_channel().await.unwrap();
    let mut cb = b.serial_channel().await.unwrap();
    ca.exchange(Batch::new("a"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    cb.exchange(Batch::new("b"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    a.release().await.unwrap();
    let reused = pool.acquire().await.unwrap();
    let mut ch = reused.serial_channel().await.unwrap();
    ch.exchange(Batch::new("a again"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    reused.release().await.unwrap();
    b.release().await.unwrap();
    pool.close().await.unwrap();
    server.await.unwrap();
    let outputs = outputs.lock().unwrap();
    assert_eq!(outputs.len(), 2);
    let counts: Vec<_> = outputs
        .iter()
        .map(|output| {
            String::from_utf8(output.bytes.lock().unwrap().clone())
                .unwrap()
                .lines()
                .filter(|line| line.contains("SQL batch"))
                .count()
        })
        .collect();
    assert_eq!(counts, [2, 1]);
}

#[tokio::test]
async fn recording_failure_while_reporting_fatal_sql_preserves_both_causes_and_record() {
    struct FailOnErrorEvent(Vec<u8>);
    impl Write for FailOnErrorEvent {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            for byte in bytes {
                if *byte == b'\n' {
                    self.0.clear();
                } else {
                    self.0.push(*byte);
                }
            }
            if self.0.windows(7).any(|b| b == b"\"event\"")
                && self.0.windows(5).any(|b| b == b"ERROR")
            {
                return Err(io::Error::other("recording failed at fatal error event"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (listener, options) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        peer.message().await;
        let mut body = include_bytes!("fixtures/responses/messages.bin").to_vec();
        body[0] = 0xaa;
        body[8] = 20; // synthetic fatal ERROR; shared capture unchanged
        peer.reply(&body).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    connection
        .set_capture(Some(Capture::new(FailOnErrorEvent(Vec::new()))))
        .await
        .unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel
        .exchange(Batch::new("synthetic fatal test"))
        .await
        .unwrap();
    let error = response.next().await.unwrap_err();
    assert!(
        matches!(error.cause().kind, ErrorKind::Cleanup { ref original, ref cleanup } if matches!(original.kind, ErrorKind::Server(ref message) if message.severity == 20) && matches!(cleanup.kind, ErrorKind::Capture(_)))
    );
    assert_eq!(
        error
            .response
            .as_ref()
            .unwrap()
            .errors()
            .next()
            .unwrap()
            .severity,
        20
    );
    assert!(connection.is_closed());
    drop(response);
    connection.close().await.unwrap();
    server.await.unwrap();
}
