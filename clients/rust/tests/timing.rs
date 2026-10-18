//! Real TLS plus deterministic core tests cover separate timing boundaries.
#![cfg(feature = "tokio")]
mod support;
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
    time::Duration,
};
use support::{Peer, done, listener};
use tds_client::{
    Batch, Connection, ProtocolVersion,
    capture::Capture,
    mars,
    observe::{Event, Level, Observer},
    packet,
    replay::{self, Content},
};

#[derive(Clone, Default)]
struct Output(Arc<Mutex<Vec<u8>>>);
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn response_snapshots_observers_and_replay_preserve_timing_in_all_modes() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            for level in [Level::Off, Level::Outline, Level::Full] {
                tokio::time::timeout(Duration::from_secs(10), async {
                    let (listener, mut options) = listener().await;
                    options.version = version;
                    options.mars = mars;
                    let output = Output::default();
                    let saved = output.clone();
                    options.capture_factory =
                        Some(Arc::new(move || Ok(Capture::new(saved.clone()))));
                    let events = Arc::new(Mutex::new(Vec::<Event>::new()));
                    let observed = events.clone();
                    options.observe = Some(Observer::new(level, move |event| {
                        observed.lock().unwrap().push(event.clone());
                        Ok(())
                    }));
                    let server = tokio::spawn(async move {
                        let (socket, _) = listener.accept().await.unwrap();
                        let (mut peer, _) = Peer::await_login_protocol(
                            socket,
                            mars,
                            include_bytes!("fixtures/test-server.pem"),
                            version,
                        )
                        .await;
                        peer.accept_login(0x74000004, mars, &[]).await;
                        for sequence in 1..=2 {
                            if mars {
                                loop {
                                    let request = peer.frame().await;
                                    if request.flags == mars::DATA {
                                        break;
                                    }
                                }
                                peer.send_frame(mars::Frame {
                                    channel: 0,
                                    flags: mars::DATA,
                                    sequence,
                                    window: 64,
                                    body: packet::split(packet::REPLY, &done(0), 9).unwrap(),
                                })
                                .await;
                            } else {
                                peer.message().await;
                                peer.reply_in_packets(&done(0), 9).await;
                            }
                        }
                        peer.drain_to_eof().await;
                    });
                    let connection = Connection::connect(options).await.unwrap();
                    let mut channel = connection.serial_channel().await.unwrap();
                    let mut timings = vec![];
                    for _ in 0..2 {
                        let mut response = channel.exchange(Batch::new("SELECT 1")).await.unwrap();
                        assert!(response.timing().sent.is_some());
                        assert_eq!(response.timing().first_packet, None);
                        let fetched = response.fetch().await.unwrap();
                        assert!(fetched.ended);
                        assert_eq!(response.timing(), fetched.timing);
                        assert_eq!(response.snapshot().timing, fetched.timing);
                        assert!(fetched.timing.until_first_packet().is_some());
                        assert!(fetched.timing.until_end() >= fetched.timing.until_first_packet());
                        timings.push(fetched.timing);
                    }
                    channel.close().await.unwrap();
                    connection.close().await.unwrap();
                    server.await.unwrap();
                    let observed: Vec<_> = events
                        .lock()
                        .unwrap()
                        .iter()
                        .filter_map(|e| e.timing)
                        .collect();
                    assert_eq!(
                        observed,
                        if level == Level::Off {
                            vec![]
                        } else {
                            timings.clone()
                        }
                    );
                    let mut took = vec![];
                    let summary = replay::replay(output.0.lock().unwrap().as_slice(), |item| {
                        if let Content::Event { took: Some(t), .. } = item.content {
                            took.push(t);
                        }
                        Ok(())
                    })
                    .unwrap();
                    assert_eq!(summary.issues, 0);
                    assert_eq!(
                        took,
                        timings
                            .iter()
                            .map(|t| serde_json::Value::String(t.summary()))
                            .collect::<Vec<_>>()
                    );
                })
                .await
                .expect("timing peer deadline");
            }
        }
    }
}
