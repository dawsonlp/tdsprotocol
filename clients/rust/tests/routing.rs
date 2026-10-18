//! One routing hop, one deadline and a fresh TLS identity at the destination.
#![cfg(feature = "tokio")]
mod support;
use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use support::{Peer, done, listener, routing as route};
use tds_client::{Batch, Connection, ErrorKind, Step};
use tds_client::{
    capture::Capture,
    observe::{Inspection, Level, Observer},
};
use tokio::net::TcpListener;

#[derive(Clone, Default)]
struct Output {
    bytes: Arc<Mutex<Vec<u8>>>,
    failed: Arc<AtomicBool>,
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failed.load(Ordering::Acquire) {
            return Err(io::Error::other("recording failed"));
        }
        self.bytes.lock().unwrap().extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn router(listener: TcpListener, target: String, port: u16, protocol: u8, old: u16) {
    let (socket, _) = listener.accept().await.unwrap();
    let (mut peer, _) = Peer::await_login(socket, false).await;
    peer.accept_login(0x74000004, false, &route(&target, port, protocol, old))
        .await;
    peer.drain_to_eof().await;
}

#[tokio::test]
async fn one_hop_verifies_destination_and_changes_login_server_name() {
    let (source, mut options) = listener().await;
    let original_port = options.port;
    let outputs = Arc::new(Mutex::new(Vec::<Output>::new()));
    let recordings = outputs.clone();
    options.capture_factory = Some(Arc::new(move || {
        let output = Output::default();
        recordings.lock().unwrap().push(output.clone());
        Ok(Capture::new(output))
    }));
    // A certificate override for the router must not be inherited by the target.
    options.server_name = Some("router.test".into());
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let first = tokio::spawn(async move {
        let (socket, _) = source.accept().await.unwrap();
        let (mut peer, _) =
            Peer::await_login_using(socket, false, include_bytes!("fixtures/test-router.pem"))
                .await;
        assert_eq!(peer.tls_server_name(), Some("router.test"));
        peer.accept_login(0x74000004, false, &route("localhost", target_port, 0, 0))
            .await;
        peer.drain_to_eof().await;
    });
    let second = tokio::spawn(async move {
        let (socket, _) = target.accept().await.unwrap();
        let (mut peer, login) = Peer::await_login(socket, false).await;
        assert_eq!(peer.tls_server_name(), Some("localhost"));
        let at = usize::from(u16::from_le_bytes([login[52], login[53]]));
        let len = usize::from(u16::from_le_bytes([login[54], login[55]])) * 2;
        let name = String::from_utf16(
            &login[at..at + len]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(name, format!("localhost,{target_port}"));
        peer.accept_login(0x74000004, false, &[]).await;
        peer.message().await;
        peer.reply(&done(0)).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    assert_eq!(connection.routed_from.as_ref().unwrap().port, original_port);
    let mut channel = connection.serial_channel().await.unwrap();
    channel
        .exchange(Batch::new("SELECT 1"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    first.await.unwrap();
    second.await.unwrap();
    let outputs = outputs.lock().unwrap();
    assert_eq!(outputs.len(), 2);
    let records: Vec<Vec<serde_json::Value>> = outputs
        .iter()
        .map(|output| {
            String::from_utf8(output.bytes.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        })
        .collect();
    assert!(records.iter().all(|lines| {
        lines
            .iter()
            .filter(|line| line["text"] == "← login reply")
            .count()
            == 1
    }));
    assert!(records[0].iter().all(|line| line["text"] != "→ SQL batch"));
    assert!(records[1].iter().any(|line| line["text"] == "→ SQL batch"));
}

#[tokio::test]
async fn route_can_be_reported_without_following_and_invalid_targets_are_refused() {
    for (host, port, protocol, old, valid) in [
        ("unused.example", 1433, 0, 0, true),
        ("unused.example", 1433, 1, 0, false),
        ("unused.example", 0, 0, 0, false),
        ("", 1433, 0, 0, false),
        ("bad\0name", 1433, 0, 0, false),
        ("unused.example", 1433, 0, 1, false),
    ] {
        let (source, mut options) = listener().await;
        options.follow_routing = false;
        let peer = tokio::spawn(router(source, host.into(), port, protocol, old));
        let error = Connection::connect(options).await.err().unwrap();
        assert_eq!(error.step, Step::Login);
        if valid {
            assert!(
                matches!(error.kind, ErrorKind::Routed(ref route) if route.server == host && route.port == port)
            );
        } else {
            assert!(matches!(
                error.kind,
                ErrorKind::Malformed { .. } | ErrorKind::Unsupported(_)
            ));
        }
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn second_route_is_refused_and_reports_the_chain() {
    let (outer, options) = listener().await;
    let first_port = options.port;
    let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let next_port = inner.local_addr().unwrap().port();
    let a = tokio::spawn(router(outer, "127.0.0.1".into(), next_port, 0, 0));
    let b = tokio::spawn(router(inner, "never-contact.example".into(), 1433, 0, 0));
    let error = Connection::connect(options).await.err().unwrap();
    assert!(
        matches!(error.kind, ErrorKind::RepeatedRoute { ref from, ref via, ref target } if from.port == first_port && via.port == next_port && target.server == "never-contact.example")
    );
    a.await.unwrap();
    b.await.unwrap();
}

#[tokio::test]
async fn recording_failure_while_reporting_a_route_prevents_following_it() {
    let (source, mut options) = listener().await;
    let output = Output::default();
    let captured = output.clone();
    let fail = output.failed.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    options.capture_factory = Some(Arc::new(move || {
        count.fetch_add(1, Ordering::Relaxed);
        Ok(Capture::new(captured.clone()))
    }));
    options.observe = Some(Observer::new(Level::Full, move |event| {
        if matches!(
            event.inspection,
            Some(Inspection::Record(tds_client::Record::Environment(
                tds_client::tokens::EnvironmentChange::Routing(_)
            )))
        ) {
            fail.store(true, Ordering::Release);
        }
        Ok(())
    }));
    let peer = tokio::spawn(router(source, "never-contact.example".into(), 1433, 0, 0));
    let error = Connection::connect(options).await.err().unwrap();
    assert!(
        matches!(error.kind, ErrorKind::Cleanup { ref original, ref cleanup } if matches!(original.kind, ErrorKind::Routed(_)) && matches!(cleanup.kind, ErrorKind::Capture(_)))
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    peer.await.unwrap();
}

#[tokio::test]
async fn redirect_does_not_restart_the_connection_timer() {
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    let (source, mut options) = listener().await;
    options.timeout = Duration::from_secs(4);
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let first = tokio::spawn(async move {
        let (socket, _) = source.accept().await.unwrap();
        let (mut peer, _) = Peer::await_login(socket, false).await;
        // Deliberate protocol delay, not an assumption about SQL Server flushing.
        tokio::time::sleep(Duration::from_secs(2)).await;
        peer.accept_login(0x74000004, false, &route("127.0.0.1", port, 0, 0))
            .await;
        peer.drain_to_eof().await;
    });
    let second = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut bytes = [0; 4096];
        // Accept the ClientHello and remain silent: the second handshake cannot
        // complete. A restarted four-second timer would exceed the outer bound.
        while socket.read(&mut bytes).await.unwrap() != 0 {}
    });
    let error = tokio::time::timeout(Duration::from_secs(5), Connection::connect(options))
        .await
        .expect("one original connection budget, including the route")
        .err()
        .unwrap();
    assert_eq!(error.step, Step::Secure);
    assert!(matches!(error.kind, ErrorKind::Timeout));
    first.await.unwrap();
    second.await.unwrap();
}
