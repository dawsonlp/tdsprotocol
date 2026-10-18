//! Deterministic faults at the real driver's TCP write boundary. This entire
//! module and its endpoint field are absent from ordinary library builds.
//! Successful writes still use TCP/TLS; only readiness and failure are scripted.
use super::*;
use std::{collections::VecDeque, future::Future, io};

#[path = "../../../tests/support/mod.rs"]
mod support;
use crate::{Batch, Call, Chunk, Param, Source, SourceRead, SqlType, StreamedCall, mars, packet};
use support::{Peer, done, listener};

enum Write {
    Limit(usize),
    WouldBlock,
    Pause(oneshot::Sender<()>),
    Zero,
    Fail(io::ErrorKind),
}
#[derive(Default)]
struct Script {
    steps: VecDeque<Write>,
    paused: bool,
    written: usize,
    would_block: usize,
}
#[derive(Default)]
pub(super) struct Writes {
    script: Mutex<Script>,
    changed: Notify,
}
impl Writes {
    fn arm(&self, steps: impl IntoIterator<Item = Write>) {
        let mut script = self.script.lock().unwrap();
        assert!(script.steps.is_empty() && !script.paused);
        *script = Script {
            steps: steps.into_iter().collect(),
            ..Default::default()
        };
    }
    fn resume(&self) {
        self.script.lock().unwrap().paused = false;
        self.changed.notify_one();
    }
    pub(super) async fn ready(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut script = self.script.lock().unwrap();
                if let Some(Write::Pause(_)) = script.steps.front() {
                    let Write::Pause(reached) = script.steps.pop_front().unwrap() else {
                        unreachable!()
                    };
                    script.paused = true;
                    let _ = reached.send(());
                }
                if !script.paused {
                    return;
                }
            }
            notified.await;
        }
    }
    pub(super) fn try_write(&self, socket: &TcpStream, bytes: &[u8]) -> io::Result<usize> {
        let mut script = self.script.lock().unwrap();
        let step = script.steps.pop_front();
        let result = match step {
            Some(Write::Limit(n)) => socket.try_write(&bytes[..n.min(bytes.len())]),
            Some(Write::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
            Some(Write::Zero) => Ok(0),
            Some(Write::Fail(kind)) => Err(kind.into()),
            Some(Write::Pause(_)) => panic!("write without readiness"),
            None => socket.try_write(bytes),
        };
        match &result {
            Ok(n) => {
                script.written += n;
                if let Some(Write::Limit(limit)) = step
                    && *n != 0
                    && *n < limit
                {
                    script.steps.push_front(Write::Limit(limit - n));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                script.would_block += 1;
                if let Some(Write::Limit(n)) = step {
                    script.steps.push_front(Write::Limit(n));
                }
            }
            _ => {}
        }
        result
    }
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("interruption test deadline")
}
const MODES: [(ProtocolVersion, bool); 4] = [
    (ProtocolVersion::V7_4, false),
    (ProtocolVersion::V8_0, false),
    (ProtocolVersion::V7_4, true),
    (ProtocolVersion::V8_0, true),
];
async fn login(listener: &tokio::net::TcpListener, version: ProtocolVersion, mars: bool) -> Peer {
    let (socket, _) = listener.accept().await.unwrap();
    let (mut peer, _) = Peer::await_login_protocol(
        socket,
        mars,
        include_bytes!("../../../tests/fixtures/test-server.pem"),
        version,
    )
    .await;
    peer.accept_login(0x74000004, mars, &[]).await;
    peer
}
async fn opened(peer: &mut Peer, mars: bool) {
    if mars {
        let frame = peer.frame().await;
        assert_eq!((frame.channel, frame.flags), (0, mars::SYN));
    }
}
async fn message(peer: &mut Peer, mars: bool) -> (u8, Vec<u8>, u8) {
    message_on(peer, mars, 0).await
}
async fn message_on(peer: &mut Peer, mars: bool, channel: u16) -> (u8, Vec<u8>, u8) {
    if !mars {
        let (kind, body) = peer.message().await;
        return (kind, body, peer.last_status);
    }
    let mut packets = packet::Unpacker::default();
    let mut body = Vec::new();
    loop {
        let frame = peer.frame().await;
        assert_eq!(frame.channel, channel);
        if frame.flags == mars::ACK {
            continue;
        }
        assert_eq!(frame.flags, mars::DATA);
        packets.feed(&frame.body).unwrap();
        while let Some(packet) = packets.next_packet().unwrap() {
            body.extend(packet.body);
            if packet.last {
                return (packet.kind, body, packet.status);
            }
        }
    }
}
async fn reply(peer: &mut Peer, mars: bool, sequence: u32, status: u16) {
    reply_on(peer, mars, 0, sequence, status).await;
}
async fn reply_on(peer: &mut Peer, mars: bool, channel: u16, sequence: u32, status: u16) {
    if !mars {
        peer.reply(&done(status)).await;
        return;
    }
    peer.send_frame(mars::Frame {
        channel,
        flags: mars::DATA,
        sequence,
        window: 64,
        body: packet::split(packet::REPLY, &done(status), 4096).unwrap(),
    })
    .await;
}
async fn raw_tail(mut peer: Peer) -> usize {
    let mut bytes = Vec::new();
    peer.socket.read_to_end(&mut bytes).await.unwrap();
    bytes.len()
}
fn pause_after(writes: &Writes, offset: usize) -> oneshot::Receiver<()> {
    let (reached, waiting) = oneshot::channel();
    let mut script = Vec::new();
    if offset != 0 {
        script.push(Write::Limit(offset));
    }
    script.push(Write::Pause(reached));
    writes.arm(script);
    waiting
}
async fn exchange_error(channel: &mut SerialChannel, request: impl Request + 'static) -> Error {
    match channel.exchange(request).await {
        Ok(_) => panic!("interrupted request succeeded"),
        Err(error) => error,
    }
}

#[derive(Clone, Default)]
struct Recording(Arc<Mutex<Vec<u8>>>);
impl io::Write for Recording {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn short_writes_and_would_block_resume_at_the_exact_offset_without_replaying_sql() {
    for (version, mars) in MODES {
        bounded(async {
            let (listener, mut options) = listener().await;
            options.version = version;
            options.mars = mars;
            let recording = Recording::default();
            let captured = recording.clone();
            options.capture_factory = Some(Arc::new(move || Ok(Capture::new(captured.clone()))));
            let (syn, seen) = oneshot::channel();
            let server = tokio::spawn(async move {
                let mut peer = login(&listener, version, mars).await;
                opened(&mut peer, mars).await;
                syn.send(()).unwrap();
                for (sequence, sql) in [(1, "first exact request"), (2, "next exact request")] {
                    let (kind, body, status) = message(&mut peer, mars).await;
                    assert_eq!((kind, status & 3), (packet::BATCH, 1));
                    let sql: Vec<u8> = sql.encode_utf16().flat_map(u16::to_le_bytes).collect();
                    assert_eq!(&body[22..], sql); // Exact bytes and count: no duplicate/lost prefix.
                    reply(&mut peer, mars, sequence, 0).await;
                }
                peer.drain_to_eof().await;
            });
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            seen.await.unwrap();
            let (reached, waiting) = oneshot::channel();
            connection.endpoint.writes.arm([
                Write::Limit(1),
                Write::WouldBlock,
                Write::Limit(2),
                Write::Limit(7),
                Write::Pause(reached),
                Write::Limit(3),
            ]);
            let work = async {
                channel
                    .exchange(Batch::new("first exact request"))
                    .await
                    .unwrap()
                    .finish()
                    .await
                    .unwrap();
                channel
                    .exchange(Batch::new("next exact request"))
                    .await
                    .unwrap()
                    .finish()
                    .await
                    .unwrap();
            };
            let release = async {
                waiting.await.unwrap();
                let script = connection.endpoint.writes.script.lock().unwrap();
                assert_eq!((script.written, script.would_block), (10, 1));
                drop(script);
                assert!(!connection.is_closed());
                connection.endpoint.writes.resume();
            };
            tokio::join!(work, release);
            connection.close().await.unwrap();
            server.await.unwrap();
            let mut requests = Vec::new();
            let summary = crate::replay::replay(recording.0.lock().unwrap().as_slice(), |item| {
                if let crate::replay::Content::Message(crate::replay::Message::Request(
                    crate::requests::decode::Request::Batch { sql, .. },
                )) = item.content
                {
                    requests.push(sql.to_string().unwrap());
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(summary.issues, 0);
            assert_eq!(requests, ["first exact request", "next exact request"]);
        })
        .await;
    }
}

#[tokio::test]
async fn zero_and_failed_partial_writes_discard_and_report_uncertain_execution() {
    for (version, mars) in MODES {
        for offset in [0, 1, 5, 17] {
            for zero in [true, false] {
                bounded(async {
                    let (listener, mut options) = listener().await;
                    options.version = version;
                    options.mars = mars;
                    let (syn, seen) = oneshot::channel();
                    let server = tokio::spawn(async move {
                        let mut peer = login(&listener, version, mars).await;
                        opened(&mut peer, mars).await;
                        syn.send(()).unwrap();
                        let count = raw_tail(peer).await;
                        assert!(
                            listener.into_std().unwrap().accept().is_err(),
                            "request failure reconnected"
                        );
                        count
                    });
                    let connection = Connection::connect(options).await.unwrap();
                    let mut channel = connection.serial_channel().await.unwrap();
                    seen.await.unwrap();
                    let mut steps = Vec::new();
                    if offset != 0 {
                        steps.push(Write::Limit(offset));
                    }
                    steps.push(if zero {
                        Write::Zero
                    } else {
                        Write::Fail(io::ErrorKind::BrokenPipe)
                    });
                    connection.endpoint.writes.arm(steps);
                    let error = exchange_error(&mut channel, Batch::new("must never replay")).await;
                    assert_eq!(
                        (error.step, error.execution),
                        (Step::Exchange, Execution::PossiblyExecuted)
                    );
                    let ErrorKind::Io(cause) = &error.cause().kind else {
                        panic!("{error:?}")
                    };
                    assert_eq!(
                        cause.kind(),
                        if zero {
                            io::ErrorKind::WriteZero
                        } else {
                            io::ErrorKind::BrokenPipe
                        }
                    );
                    assert!(connection.is_closed());
                    assert!(
                        channel
                            .exchange(Batch::new("forbidden reuse"))
                            .await
                            .is_err()
                    );
                    connection.close().await.unwrap();
                    assert_eq!(server.await.unwrap(), offset);
                })
                .await;
            }
        }
    }
}

#[tokio::test]
async fn aborting_the_owner_during_a_blocked_write_discards_every_selected_prefix() {
    for (version, mars) in MODES {
        for offset in [0, 1, 5, 17] {
            bounded(async {
                let (listener, mut options) = listener().await;
                options.version = version;
                options.mars = mars;
                let (syn, seen) = oneshot::channel();
                let server = tokio::spawn(async move {
                    let mut peer = login(&listener, version, mars).await;
                    opened(&mut peer, mars).await;
                    syn.send(()).unwrap();
                    let count = raw_tail(peer).await;
                    assert!(listener.into_std().unwrap().accept().is_err());
                    count
                });
                let connection = Connection::connect(options).await.unwrap();
                let mut channel = connection.serial_channel().await.unwrap();
                seen.await.unwrap();
                let waiting = pause_after(&connection.endpoint.writes, offset);
                let owner = tokio::spawn(async move {
                    let _response = channel.exchange(Batch::new("aborted owner")).await;
                    panic!("owner completed before the gate opened");
                });
                waiting.await.unwrap();
                owner.abort();
                assert!(owner.await.unwrap_err().is_cancelled());
                assert!(connection.is_closed());
                connection.close().await.unwrap();
                assert_eq!(server.await.unwrap(), offset);
            })
            .await;
        }
    }
}

#[tokio::test]
async fn a_cleanup_deadline_interrupts_a_partly_written_attention_without_reuse() {
    for (version, mars) in MODES {
        bounded(async {
            let (listener, mut options) = listener().await;
            options.version = version;
            options.mars = mars;
            options.cleanup_timeout = Duration::from_millis(100);
            let (sent, seen) = oneshot::channel();
            let server = tokio::spawn(async move {
                let mut peer = login(&listener, version, mars).await;
                opened(&mut peer, mars).await;
                assert_eq!(message(&mut peer, mars).await.0, packet::BATCH);
                sent.send(()).unwrap();
                raw_tail(peer).await
            });
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            let response = channel
                .exchange(Batch::new("awaiting response"))
                .await
                .unwrap();
            seen.await.unwrap();
            let waiting = pause_after(&connection.endpoint.writes, 3);
            let cancel = response.cancel_handle();
            cancel.cancel();
            let first = cancel.control.request().unwrap().deadline;
            waiting.await.unwrap();
            cancel.cancel();
            assert_eq!(cancel.control.request().unwrap().deadline, first);
            let error = response.close().await.unwrap_err();
            assert_eq!(
                (error.step, error.execution),
                (Step::Cleanup, Execution::PossiblyExecuted)
            );
            let ErrorKind::Cleanup { original, cleanup } = &error.cause().kind else {
                panic!("{error:?}")
            };
            assert!(matches!(original.cause().kind, ErrorKind::Canceled));
            assert!(matches!(cleanup.cause().kind, ErrorKind::Timeout));
            assert!(connection.is_closed());
            connection.close().await.unwrap();
            assert_eq!(server.await.unwrap(), 3);
        })
        .await;
    }
}

struct FailingSource {
    first: bool,
    fail_cleanup: Option<Arc<Endpoint>>,
}
impl Source for FailingSource {
    fn next_chunk(&mut self) -> SourceRead<'_> {
        Box::pin(async {
            if !self.first {
                self.first = true;
                return Ok(Some(Chunk::Binary(vec![0xa7; 12000])));
            }
            if let Some(endpoint) = self.fail_cleanup.take() {
                endpoint
                    .writes
                    .arm([Write::Limit(3), Write::Fail(io::ErrorKind::BrokenPipe)]);
            }
            Err(io::Error::other("selected producer failure"))
        })
    }
}
fn streamed(fail_cleanup: Option<Arc<Endpoint>>) -> StreamedCall {
    StreamedCall::new(Call::new(
        "artificial",
        vec![Param::new("@b", SqlType::BinaryMax, None)],
    ))
    .source(
        0,
        FailingSource {
            first: false,
            fail_cleanup,
        },
    )
}

#[tokio::test]
async fn partial_stream_writes_preserve_ignore_eom_cleanup_and_reuse() {
    for (version, mars) in MODES {
        bounded(async {
            let (listener, mut options) = listener().await;
            options.version = version; options.mars = mars;
            let (syn, seen) = oneshot::channel();
            let server = tokio::spawn(async move {
                let mut peer = login(&listener, version, mars).await;
                opened(&mut peer, mars).await;
                syn.send(()).unwrap();
                let (kind, body, status) = message(&mut peer, mars).await;
                assert_eq!((kind, status), (packet::RPC, 3)); // IGNORE + EOM, no Attention.
                assert!(body.iter().filter(|&&b| b == 0xa7).count() > 4000);
                reply(&mut peer, mars, 1, 2).await;
                assert_eq!(message(&mut peer, mars).await.0, packet::BATCH);
                reply(&mut peer, mars, 2, 0).await;
                peer.drain_to_eof().await;
            });
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            seen.await.unwrap();
            let waiting = pause_after(&connection.endpoint.writes, 5);
            let work = async {
                let error = exchange_error(&mut channel, streamed(None)).await;
                assert!(matches!(&error.cause().kind, ErrorKind::Io(e) if e.to_string() == "selected producer failure"));
                assert!(error.response.unwrap().ended);
                assert!(!connection.is_closed());
                channel.exchange(Batch::new("after successful cleanup")).await.unwrap().finish().await.unwrap();
            };
            let release = async { waiting.await.unwrap(); connection.endpoint.writes.resume(); };
            tokio::join!(work, release);
            connection.close().await.unwrap(); server.await.unwrap();
        }).await;
    }
}

#[tokio::test]
async fn a_partial_ignore_eom_write_failure_preserves_both_causes_and_discards() {
    for (version, mars) in MODES {
        bounded(async {
            let (listener, mut options) = listener().await;
            options.version = version; options.mars = mars;
            let (syn, seen) = oneshot::channel();
            let server = tokio::spawn(async move {
                let mut peer = login(&listener, version, mars).await;
                opened(&mut peer, mars).await;
                syn.send(()).unwrap();
                // Discard the partial TLS message without inventing a reply.
                raw_tail(peer).await
            });
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            seen.await.unwrap();
            let error = exchange_error(&mut channel, streamed(Some(connection.endpoint.clone()))).await;
            let ErrorKind::Cleanup { original, cleanup } = &error.cause().kind else { panic!("{error:?}") };
            assert!(matches!(&original.cause().kind, ErrorKind::Io(e) if e.to_string() == "selected producer failure"));
            assert!(matches!(&cleanup.cause().kind, ErrorKind::Io(e) if e.kind() == io::ErrorKind::BrokenPipe));
            assert_eq!(error.execution, Execution::PossiblyExecuted);
            assert!(connection.is_closed());
            let written = connection.endpoint.writes.script.lock().unwrap().written;
            assert_eq!(written, 3); // Only the cleanup script's bytes, not earlier input.
            connection.close().await.unwrap();
            assert!(server.await.unwrap() > written);
        }).await;
    }
}

fn bulk_columns() -> Vec<crate::tokens::Column> {
    vec![crate::tokens::Column {
        user_type: 0,
        flags: 1,
        name: "a".into(),
        type_info: crate::TypeInfo {
            sql_type: SqlType::Integer {
                size: crate::IntegerSize::Int,
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
async fn aborting_bulk_data_send_discards_the_prepared_continuation() {
    for (version, mars) in MODES {
        for offset in [0, 5] {
            bounded(async {
                let (listener, mut options) = listener().await;
                options.version = version;
                options.mars = mars;
                let server = tokio::spawn(async move {
                    let mut peer = login(&listener, version, mars).await;
                    opened(&mut peer, mars).await;
                    assert_eq!(message(&mut peer, mars).await.0, packet::BATCH);
                    reply(&mut peer, mars, 1, 0).await;
                    raw_tail(peer).await
                });
                let connection = Connection::connect(options).await.unwrap();
                let mut channel = connection.serial_channel().await.unwrap();
                let endpoint = connection.endpoint.clone();
                let (reached, waiting) = oneshot::channel();
                let owner = tokio::spawn(async move {
                    let writer = channel
                        .bulk("INSERT BULK artificial(a int)", bulk_columns())
                        .await
                        .unwrap();
                    let mut script = Vec::new();
                    if offset != 0 {
                        script.push(Write::Limit(offset));
                    }
                    script.push(Write::Pause(reached));
                    endpoint.writes.arm(script);
                    let _ = writer
                        .finish(vec![vec![Some(crate::Value::Integer(42))]])
                        .await;
                    panic!("bulk writer escaped the gate");
                });
                waiting.await.unwrap();
                owner.abort();
                assert!(owner.await.unwrap_err().is_cancelled());
                assert!(connection.is_closed());
                assert!(connection.recover().await.is_err()); // Never adopt an unresolved bulk operation.
                connection.close().await.unwrap();
                assert_eq!(server.await.unwrap(), offset);
            })
            .await;
        }
    }
}

#[tokio::test]
async fn a_pool_replaces_an_aborted_partial_send_without_losing_capacity_or_authority() {
    for (version, mars) in MODES {
        bounded(async {
            let (listener, mut options) = listener().await;
            options.version = version;
            options.mars = mars;
            let (opened_first, first_open) = oneshot::channel();
            let server = tokio::spawn(async move {
                let mut peer = login(&listener, version, mars).await;
                opened(&mut peer, mars).await;
                opened_first.send(()).unwrap();
                assert_eq!(raw_tail(peer).await, 5);
                // A fresh verified login, not a reset/reuse of the dirty socket.
                let mut peer = login(&listener, version, mars).await;
                opened(&mut peer, mars).await;
                let (kind, body, _) = message(&mut peer, mars).await;
                assert_eq!(kind, packet::BATCH);
                let sql: Vec<u8> = "replacement only"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect();
                assert_eq!(&body[22..], sql);
                reply(&mut peer, mars, 1, 0).await;
                peer.drain_to_eof().await;
            });
            let pool = crate::Pool::new(options, 1).unwrap();
            let lease = pool.acquire().await.unwrap();
            let mut channel = lease.serial_channel().await.unwrap();
            first_open.await.unwrap();
            let old_root = lease.close_handle();
            let old_channel = channel.close_handle();
            let waiting = pause_after(&lease.endpoint.writes, 5);
            let owner = tokio::spawn(async move {
                let _ = channel.exchange(Batch::new("must not replay")).await;
            });
            waiting.await.unwrap();
            owner.abort();
            assert!(owner.await.unwrap_err().is_cancelled());
            assert_eq!(
                lease.release().await.unwrap(),
                crate::ReleaseOutcome::Discarded
            );
            assert_eq!((pool.in_use(), pool.idle()), (0, 0));
            let next = pool.acquire().await.unwrap();
            old_root.close();
            let _ = old_channel.close().await;
            assert!(!next.is_closed());
            assert_eq!((pool.in_use(), pool.idle()), (1, 0));
            next.serial_channel()
                .await
                .unwrap()
                .exchange(Batch::new("replacement only"))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            // Drop intentionally discards; FIN return is covered separately.
            drop(next);
            assert_eq!((pool.in_use(), pool.idle()), (0, 0));
            pool.close().await.unwrap();
            server.await.unwrap();
        })
        .await;
    }
}

#[tokio::test]
async fn mars_reads_a_peer_failure_while_writes_are_blocked_and_fails_both_channels() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        bounded(async {
            let (listener, mut options) = listener().await;
            options.version = version;
            options.mars = true;
            let (inject, injecting) = oneshot::channel();
            let server = tokio::spawn(async move {
                let mut peer = login(&listener, version, true).await;
                opened(&mut peer, true).await;
                let second = peer.frame().await;
                assert_eq!((second.channel, second.flags), (1, mars::SYN));
                assert_eq!(message(&mut peer, true).await.0, packet::BATCH);
                injecting.await.unwrap();
                peer.send_raw_plain(&[0; 16]).await; // Invalid SMP signature on a verified transport.
                raw_tail(peer).await
            });
            let connection = Connection::connect(options).await.unwrap();
            let mut first = connection.serial_channel().await.unwrap();
            let mut second = connection.serial_channel().await.unwrap();
            let mut response = first
                .exchange(Batch::new("sibling awaiting response"))
                .await
                .unwrap();
            let waiting = pause_after(&connection.endpoint.writes, 5);
            let sending = tokio::spawn(async move {
                exchange_error(&mut second, Batch::new("blocked sender")).await
            });
            waiting.await.unwrap();
            inject.send(()).unwrap();
            let read_error = response.next().await.unwrap_err();
            let send_error = sending.await.unwrap();
            for error in [&read_error, &send_error] {
                assert!(matches!(error.cause().kind, ErrorKind::Malformed { .. }));
                assert_eq!(error.execution, Execution::PossiblyExecuted);
                assert!(!error.response.as_ref().unwrap().ended);
            }
            assert_eq!(
                read_error.cause().to_string(),
                send_error.cause().to_string()
            );
            assert!(connection.is_closed());
            connection.close().await.unwrap();
            assert_eq!(server.await.unwrap(), 5); // Failure arrived without opening the write gate.
        })
        .await;
    }
}

#[tokio::test]
async fn explicit_recovery_after_a_partial_write_never_replays_the_interrupted_request() {
    for (version, mars) in MODES {
        bounded(async {
            let (listener, mut options) = listener().await;
            options.version = version;
            options.mars = mars;
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let (mut peer, _) = Peer::await_login_protocol(
                    socket,
                    mars,
                    include_bytes!("../../../tests/fixtures/test-server.pem"),
                    version,
                )
                .await;
                peer.accept_login(0x74000004, mars, &[0xae, 1, 0, 0, 0, 0, 255])
                    .await;
                opened(&mut peer, mars).await;
                (peer, listener)
            });
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            let (peer, listener) = server.await.unwrap();
            let server = tokio::spawn(async move {
                assert_eq!(raw_tail(peer).await, 5);
                let (socket, _) = listener.accept().await.unwrap();
                let (mut peer, _) = Peer::await_login_protocol(
                    socket,
                    mars,
                    include_bytes!("../../../tests/fixtures/test-server.pem"),
                    version,
                )
                .await;
                peer.accept_login(0x74000004, mars, &[0xae, 1, 0, 0, 0, 0, 255])
                    .await;
                opened(&mut peer, mars).await;
                let (kind, body, _) = message(&mut peer, mars).await;
                assert_eq!(kind, packet::BATCH);
                let sql: Vec<u8> = "explicit new request"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect();
                assert_eq!(&body[22..], sql);
                reply(&mut peer, mars, 1, 0).await;
                peer.drain_to_eof().await;
            });
            let stale_guard =
                Abandon::for_epoch(connection.endpoint.clone(), connection.endpoint.epoch());
            connection
                .endpoint
                .writes
                .arm([Write::Limit(5), Write::Fail(io::ErrorKind::BrokenPipe)]);
            let error = exchange_error(&mut channel, Batch::new("never repeat this SQL")).await;
            assert_eq!(error.execution, Execution::PossiblyExecuted);
            assert_eq!(connection.recoveries(), 0);
            assert!(!connection.endpoint.is_revoked());
            connection.recover().await.unwrap();
            assert_eq!(connection.recoveries(), 1);
            drop(stale_guard);
            assert!(!connection.is_closed());
            channel
                .exchange(Batch::new("explicit new request"))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            connection.close().await.unwrap();
            server.await.unwrap();
        })
        .await;
    }
}

async fn pending_once<F: Future>(mut future: std::pin::Pin<&mut F>) {
    std::future::poll_fn(|cx| {
        assert!(
            future.as_mut().poll(cx).is_pending(),
            "future unexpectedly completed"
        );
        std::task::Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn exchange_abandonment_distinguishes_unpolled_reserved_and_submitted_work() {
    for stage in 0..3 {
        let (commands, mut receive) = mpsc::channel(1);
        let endpoint = Arc::new(Endpoint {
            writes: Default::default(),
            observation_error: Arc::new(Mutex::new(None)),
            commands,
            revoked: AtomicBool::new(false),
            returning: AtomicBool::new(false),
            changed: Notify::new(),
            position: Mutex::new((Step::Ready, Execution::NotSent)),
            failure: Mutex::new(None),
            cleanup_timeout: Duration::from_secs(5),
            epoch: Mutex::new(0),
            disconnected: AtomicBool::new(false),
            recoveries: AtomicU64::new(0),
        });
        let life = Arc::new(ChannelLife {
            pending_bulk: AtomicBool::new(false),
            id: 0,
            endpoint: Arc::downgrade(&endpoint),
            close_request: Mutex::new(None),
            close_result: Mutex::new(None),
            released: Notify::new(),
        });
        let mut channel = SerialChannel {
            endpoint: endpoint.clone(),
            life,
            next_exchange: 0,
            closed: false,
        };
        if stage == 1 {
            let (reply, _) = oneshot::channel();
            endpoint
                .commands
                .try_send(Command::Session(reply))
                .unwrap_or_else(|_| panic!("fill mailbox"));
        }
        let mut work = Box::pin(channel.exchange(Batch::new("selected submission boundary")));
        if stage != 0 {
            pending_once(work.as_mut()).await;
        }
        drop(work);
        assert_eq!(endpoint.is_revoked(), stage == 2);
        match stage {
            0 => {
                assert_eq!(channel.next_exchange, 0);
                assert!(receive.try_recv().is_err());
            }
            1 => {
                assert!(matches!(receive.try_recv().unwrap(), Command::Session(_)));
                assert!(receive.try_recv().is_err());
            }
            2 => {
                assert!(matches!(receive.try_recv().unwrap(), Command::Begin { .. }));
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn runtime_shutdown_revokes_the_current_rotated_pool_endpoint_and_closes_its_socket() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        let (send_options, options) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(bounded(async {
                    let (listener, mut options) = listener().await;
                    options.version = version;
                    send_options.send(options).unwrap();
                    let peer = login(&listener, version, false).await;
                    assert_eq!(raw_tail(peer).await, 0); // Runtime destruction closes the idle socket.
                    let mut peer = login(&listener, version, false).await;
                    assert_eq!(message(&mut peer, false).await.0, packet::BATCH);
                    peer.reply(&done(0)).await;
                    peer.drain_to_eof().await;
                }));
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let options = options.recv_timeout(Duration::from_secs(5)).unwrap();
        let (pool, lease, mut channel, stale_root) = runtime.block_on(bounded(async {
            let pool = crate::Pool::new(options, 1).unwrap();
            let first = pool.acquire().await.unwrap();
            let stale_root = first.close_handle();
            let old_endpoint = first.endpoint.clone();
            assert_eq!(
                first.release().await.unwrap(),
                crate::ReleaseOutcome::Returned
            );
            let next = pool.acquire().await.unwrap();
            assert!(!Arc::ptr_eq(&old_endpoint, &next.endpoint));
            let channel = next.serial_channel().await.unwrap();
            (pool, next, channel, stale_root)
        }));
        assert!(!lease.is_closed());
        drop(runtime);
        assert!(lease.is_closed()); // No owner/response was dropped to cause this revocation.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(bounded(async {
            assert!(
                channel
                    .exchange(Batch::new("old runtime authority"))
                    .await
                    .is_err()
            );
            drop(lease);
            assert_eq!((pool.in_use(), pool.idle()), (0, 0));
            let next = pool.acquire().await.unwrap();
            stale_root.close();
            assert!(!next.is_closed());
            next.serial_channel()
                .await
                .unwrap()
                .exchange(Batch::new("new runtime"))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            next.release().await.unwrap();
            pool.close().await.unwrap();
        }));
        server.join().unwrap();
    }
}

#[tokio::test]
async fn aborting_the_driver_during_a_partial_write_keeps_execution_uncertainty() {
    for (version, mars) in MODES {
        bounded(async {
            let (listener, mut options) = listener().await;
            options.version = version;
            options.mars = mars;
            let (syn, seen) = oneshot::channel();
            let server = tokio::spawn(async move {
                let mut peer = login(&listener, version, mars).await;
                opened(&mut peer, mars).await;
                syn.send(()).unwrap();
                raw_tail(peer).await
            });
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            seen.await.unwrap();
            let waiting = pause_after(&connection.endpoint.writes, 5);
            let mut work = Box::pin(exchange_error(
                &mut channel,
                Batch::new("driver interrupted"),
            ));
            tokio::select! {
                _ = &mut work => panic!("request escaped the gate"),
                reached = waiting => reached.unwrap(),
            }
            connection.task.as_ref().unwrap().abort();
            let error = work.await;
            assert_eq!(
                (error.step, error.execution),
                (Step::Exchange, Execution::PossiblyExecuted)
            );
            assert!(connection.is_closed());
            assert_eq!(server.await.unwrap(), 5);
            assert!(connection.close().await.is_err()); // Explicitly aborted driver join.
        })
        .await;
    }
}

#[tokio::test]
async fn delegated_close_finishes_the_partial_packet_then_ignores_and_drains_before_reuse() {
    for (version, mars) in MODES {
        bounded(async {
            let (listener, mut options) = listener().await;
            options.version = version;
            options.mars = mars;
            let (syn, seen) = oneshot::channel();
            let server = tokio::spawn(async move {
                let mut peer = login(&listener, version, mars).await;
                opened(&mut peer, mars).await;
                syn.send(()).unwrap();
                let (kind, _, status) = message(&mut peer, mars).await;
                assert_eq!((kind, status), (packet::RPC, 3));
                reply(&mut peer, mars, 1, 2).await;
                if mars {
                    let fin = peer.frame().await;
                    assert_eq!((fin.channel, fin.flags), (0, mars::FIN));
                    let syn = peer.frame().await;
                    assert_eq!((syn.channel, syn.flags), (1, mars::SYN));
                }
                assert_eq!(message_on(&mut peer, mars, 1).await.0, packet::BATCH);
                reply_on(&mut peer, mars, 1, 1, 0).await;
                peer.drain_to_eof().await;
            });
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            seen.await.unwrap();
            let close = channel.close_handle();
            let waiting = pause_after(&connection.endpoint.writes, 5);
            let owner = tokio::spawn(async move {
                let error = exchange_error(&mut channel, streamed(None)).await;
                assert!(matches!(error.cause().kind, ErrorKind::Canceled));
                assert!(error.response.unwrap().ended);
                channel
            });
            waiting.await.unwrap();
            let mut closing = Box::pin(close.close());
            pending_once(closing.as_mut()).await; // Establish close before releasing the partial write.
            connection.endpoint.writes.resume();
            closing.await.unwrap();
            let mut old = owner.await.unwrap();
            assert!(old.exchange(Batch::new("closed lifetime")).await.is_err());
            assert!(!connection.is_closed());
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
        })
        .await;
    }
}

#[tokio::test]
async fn abandoning_cleanup_during_a_partial_attention_discards_without_finishing_its_write() {
    for (version, mars) in MODES {
        for close in [false, true] {
            bounded(async {
                let (listener, mut options) = listener().await;
                options.version = version;
                options.mars = mars;
                let (sent, seen) = oneshot::channel();
                let server = tokio::spawn(async move {
                    let mut peer = login(&listener, version, mars).await;
                    opened(&mut peer, mars).await;
                    assert_eq!(message(&mut peer, mars).await.0, packet::BATCH);
                    sent.send(()).unwrap();
                    raw_tail(peer).await
                });
                let connection = Connection::connect(options).await.unwrap();
                let mut channel = connection.serial_channel().await.unwrap();
                let mut response = channel
                    .exchange(Batch::new("awaiting cleanup"))
                    .await
                    .unwrap();
                seen.await.unwrap();
                let waiting = pause_after(&connection.endpoint.writes, 3);
                if close {
                    let mut closing = Box::pin(response.close());
                    tokio::select! {
                        _ = &mut closing => panic!("cleanup escaped the gate"),
                        reached = waiting => reached.unwrap(),
                    }
                    drop(closing);
                } else {
                    response.cancel_handle().cancel();
                    let mut reading = Box::pin(response.next());
                    tokio::select! {
                        _ = &mut reading => panic!("read escaped the gate"),
                        reached = waiting => reached.unwrap(),
                    }
                    drop(reading);
                    assert!(connection.is_closed()); // Read abandonment alone, before Response Drop.
                    drop(response);
                }
                assert!(connection.is_closed());
                connection.close().await.unwrap();
                assert_eq!(server.await.unwrap(), 3);
            })
            .await;
        }
    }
}
