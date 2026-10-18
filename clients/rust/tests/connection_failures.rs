//! Controlled peers isolate framing, deadline and cancellation behavior from SQL
//! Server. These tests use ephemeral loopback ports and no real credentials.
#![cfg(feature = "tokio")]
use std::time::Duration;
use tds_client::{ConnectOptions, Connection, ErrorKind, ProtocolVersion, Step, packet, prelogin};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn options(port: u16) -> ConnectOptions {
    let mut options = ConnectOptions::new(
        "127.0.0.1",
        port,
        "fake-user",
        "fake-password",
        rustls::RootCertStore::empty(),
    );
    options.timeout = Duration::from_secs(5);
    options
}
async fn hello(socket: &mut TcpStream) {
    let mut header = [0; 8];
    socket.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], packet::HELLO);
    let n = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let mut payload = vec![0; n - 8];
    socket.read_exact(&mut payload).await.unwrap();
    assert_eq!(payload, prelogin::encode()); // No login or credentials sent before verification.
}
async fn eof(mut socket: TcpStream) {
    let mut b = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), socket.read(&mut b))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn one_deadline_closes_a_silent_peer_at_the_failing_step() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        hello(&mut socket).await;
        eof(socket).await;
    });
    let mut config = options(port);
    config.timeout = Duration::from_secs(1);
    let error = match Connection::connect(config).await {
        Ok(_) => panic!("silent peer logged in"),
        Err(e) => e,
    };
    assert_eq!(error.step, Step::Hello);
    assert!(matches!(error.kind, ErrorKind::Timeout));
    peer.await.unwrap();
}

#[tokio::test]
async fn malformed_refused_and_wrong_instance_hellos_fail_before_login() {
    for kind in 0..4 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            hello(&mut socket).await;
            let mut reply = prelogin::encode();
            match kind {
                0 => reply[32] = 0, // ENCRYPT_OFF cannot satisfy full encryption.
                1 => reply[33] = 1, // INSTOPT mismatch.
                2 => {
                    socket.write_all(&[4, 1, 0, 7, 0, 0, 1, 0]).await.unwrap();
                    eof(socket).await;
                    return;
                }
                _ => {
                    socket.write_all(&[4, 1, 0]).await.unwrap();
                    return;
                } // Truncated header then EOF.
            }
            socket
                .write_all(&packet::split(packet::REPLY, &reply, 4096).unwrap())
                .await
                .unwrap();
            eof(socket).await;
        });
        let error = match Connection::connect(options(port)).await {
            Ok(_) => panic!("invalid peer accepted"),
            Err(e) => e,
        };
        assert_eq!(error.step, Step::Hello);
        match kind {
            0 | 1 => assert!(matches!(error.kind, ErrorKind::Unsupported(_))),
            2 => assert!(matches!(error.kind, ErrorKind::Malformed { .. })),
            _ => assert!(matches!(error.kind, ErrorKind::Closed)),
        }
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn aborting_connect_closes_its_owned_driver() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = options(listener.local_addr().unwrap().port());
    config.timeout = Duration::from_secs(5);
    let connecting = tokio::spawn(Connection::connect(config));
    let (mut socket, _) = listener.accept().await.unwrap();
    hello(&mut socket).await;
    connecting.abort();
    assert!(connecting.await.is_err());
    eof(socket).await;
}

#[tokio::test]
async fn unavailable_port_fails_at_tcp_start_without_protocol_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = options(listener.local_addr().unwrap().port());
    drop(listener);
    let error = match Connection::connect(config).await {
        Ok(_) => panic!("closed port accepted"),
        Err(e) => e,
    };
    assert_eq!(error.step, Step::Start);
    assert!(matches!(error.kind, ErrorKind::Io(_)));
}

#[tokio::test]
async fn tds8_starts_with_tls_and_never_falls_back_after_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = options(listener.local_addr().unwrap().port());
    config.version = ProtocolVersion::V8_0;
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 4096];
        let n = socket.read(&mut bytes).await.unwrap();
        assert!(n > 0);
        assert_eq!(bytes[0], 0x16);
        socket.write_all(&[4, 1, 0, 8, 0, 0, 1, 0]).await.unwrap();
        // The client may send a TLS alert. It must never send a PRELOGIN fallback.
        loop {
            let n = socket.read(&mut bytes).await.unwrap();
            if n == 0 {
                break;
            }
            assert_ne!(bytes[0], packet::HELLO);
        }
    });
    let error = match Connection::connect(config).await {
        Ok(_) => panic!("invalid TLS accepted"),
        Err(e) => e,
    };
    assert_eq!(error.step, Step::Secure);
    assert!(matches!(error.kind, ErrorKind::Tls(_)));
    peer.await.unwrap();
}
