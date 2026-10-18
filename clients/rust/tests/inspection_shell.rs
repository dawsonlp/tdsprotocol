//! Live/replay field equality through real TCP/TLS and a controlled fragmenting peer.
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
    inspection::Node,
    mars,
    observe::{Level, Observer},
    packet,
    replay::{self, Content},
};
#[derive(Clone, Default)]
struct Output(Arc<Mutex<Vec<u8>>>);
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
async fn bounded<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), f)
        .await
        .expect("inspection peer deadline")
}
fn response() -> Vec<u8> {
    // INFO "test", one nullable int column a, one row 42, counted DONE.
    let info = [
        vec![0xab, 26, 0],
        50001_u32.to_le_bytes().to_vec(),
        vec![
            1, 0, 4, 0, b't', 0, b'e', 0, b's', 0, b't', 0, 1, b's', 0, 1, b'p', 0,
        ],
        42_u32.to_le_bytes().to_vec(),
    ]
    .concat();
    let mut bytes = info;
    bytes.extend([
        0x81, 1, 0, 0, 0, 0, 0, 1, 0, 0x26, 4, 1, b'a', 0, 0xd1, 4, 42, 0, 0, 0,
    ]);
    let mut end = done(0x10);
    end[5..].copy_from_slice(&1_u64.to_le_bytes());
    bytes.extend(end);
    bytes
}
fn selected(nodes: &[Node], name: &str) -> Vec<Node> {
    nodes
        .iter()
        .filter(|node| node.name == name)
        .cloned()
        .collect()
}
#[tokio::test]
async fn fragmented_live_and_replayed_fields_match_in_every_protocol_and_mars_mode() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            bounded(async {
                let (listener, mut options) = listener().await;
                options.version = version;
                options.mars = mars;
                let output = Output::default();
                let captured = output.clone();
                options.capture_factory =
                    Some(Arc::new(move || Ok(Capture::new(captured.clone()))));
                let fields = Arc::new(Mutex::new(Vec::<Node>::new()));
                let observed = fields.clone();
                options.observe = Some(Observer::new(Level::Full, move |event| {
                    observed.lock().unwrap().extend(event.fields.clone());
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
                    if mars {
                        assert_eq!(peer.frame().await.flags, mars::SYN);
                    }
                    for (index, kind) in [packet::BATCH, packet::RPC, packet::TRANSACTION]
                        .into_iter()
                        .enumerate()
                    {
                        if mars {
                            let request = peer.frame().await;
                            assert_eq!(request.flags, mars::DATA);
                            assert_eq!(request.body[0], kind);
                            peer.send_frame(mars::Frame {
                                channel: 0,
                                flags: mars::DATA,
                                sequence: index as u32 + 1,
                                window: 64,
                                body: packet::split(packet::REPLY, &response(), 9).unwrap(),
                            })
                            .await;
                        } else {
                            assert_eq!(peer.message().await.0, kind);
                            peer.reply_in_packets(&response(), 9).await;
                        }
                    }
                    peer.drain_to_eof().await;
                });
                let connection = Connection::connect(options).await.unwrap();
                let mut channel = connection.serial_channel().await.unwrap();
                channel
                    .exchange(Batch::new("SELECT 42 AS a"))
                    .await
                    .unwrap()
                    .finish()
                    .await
                    .unwrap();
                let table = tds_client::TableType::new(
                    "dbo",
                    "lines",
                    vec![
                        tds_client::SqlType::Integer {
                            size: tds_client::IntegerSize::Int,
                        }
                        .into(),
                    ],
                );
                let parameter = tds_client::Param::table(
                    "@t",
                    table,
                    Some(vec![vec![Some(tds_client::Value::Integer(7))]]),
                );
                channel
                    .exchange(tds_client::Call::new("#p", vec![parameter]))
                    .await
                    .unwrap()
                    .finish()
                    .await
                    .unwrap();
                channel
                    .exchange(tds_client::Transaction::CoordinatorAddress)
                    .await
                    .unwrap()
                    .finish()
                    .await
                    .unwrap();
                connection.close().await.unwrap();
                server.await.unwrap();
                let mut replayed = Vec::new();
                let summary = replay::replay_with_inspection(
                    output.0.lock().unwrap().as_slice(),
                    true,
                    |item| {
                        if let Content::Inspection(node) = item.content {
                            replayed.push(node);
                        }
                        Ok(())
                    },
                )
                .unwrap();
                assert_eq!(summary.issues, 0);
                let live = fields.lock().unwrap();
                for name in [
                    "TDS packet header",
                    "PRELOGIN",
                    "LOGIN7",
                    "LOGINACK",
                    "SQL batch",
                    "RPC",
                    "transaction manager",
                    "INFO",
                    "COLMETADATA",
                    "ROW",
                    "DONE",
                ] {
                    let nodes = selected(&live, name);
                    assert!(!nodes.is_empty(), "missing live {name} {version:?}/{mars}");
                    assert_eq!(
                        nodes,
                        selected(&replayed, name),
                        "{name} {version:?}/{mars}"
                    );
                }
            })
            .await;
        }
    }
}

#[tokio::test]
#[ignore = "requires Docker SQL Server and existing test CA"]
async fn sql_server_login_and_scalar_query_have_equal_live_and_saved_field_trees() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let output = Output::default();
            let captured = output.clone();
            options.capture_factory = Some(Arc::new(move || Ok(Capture::new(captured.clone()))));
            let fields = Arc::new(Mutex::new(Vec::<Node>::new()));
            let observed = fields.clone();
            options.observe = Some(Observer::new(Level::Full, move |event| {
                observed.lock().unwrap().extend(event.fields.clone());
                Ok(())
            }));
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            let mut response = channel.exchange(Batch::new("PRINT N'inspection'; SELECT CAST(42 AS int) AS answer, CAST(NULL AS int) AS missing, CAST(N'é🦀' AS nvarchar(10)) AS label"))
                .await.unwrap();
            response.finish().await.unwrap();
            assert!(response.timing().until_first_packet().is_some());
            assert!(response.timing().until_end() >= response.timing().until_first_packet());
            connection.close().await.unwrap();
            let mut replayed = Vec::new();
            let summary =
                replay::replay_with_inspection(output.0.lock().unwrap().as_slice(), true, |item| {
                    if let Content::Inspection(node) = item.content {
                        replayed.push(node);
                    }
                    Ok(())
                })
                .unwrap();
            assert_eq!(summary.issues, 0);
            for name in [
                "PRELOGIN",
                "LOGIN7",
                "LOGINACK",
                "SQL batch",
                "INFO",
                "COLMETADATA",
                "DONE",
            ] {
                let live = selected(&fields.lock().unwrap(), name);
                assert!(!live.is_empty(), "{name}");
                assert_eq!(live, selected(&replayed, name), "{name} {version:?}/{mars}");
            }
            let live_rows = fields
                .lock()
                .unwrap()
                .iter()
                .filter(|n| matches!(n.name.as_str(), "ROW" | "NBCROW"))
                .cloned()
                .collect::<Vec<_>>();
            let saved_rows = replayed
                .iter()
                .filter(|n| matches!(n.name.as_str(), "ROW" | "NBCROW"))
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(live_rows.len(), 1);
            assert_eq!(live_rows, saved_rows);
        }
    }
}
