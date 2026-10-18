//! A minimal, controlled TDS 8.0 peer using artificial committed TLS fixtures.
//! It speaks only enough login to test client cleanup without SQL Server or any
//! machine-specific credentials. It is a test peer, not a reference TDS server.
#![allow(dead_code)]
use rustls::{RootCertStore, ServerConfig, ServerConnection};
use std::{
    collections::VecDeque,
    io::{Cursor, Read, Write},
    sync::Arc,
};
use tds_client::{
    ConnectOptions, ProtocolVersion,
    mars::{self, Frame},
    packet::{self, Unpacker},
    prelogin,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub async fn listener() -> (TcpListener, ConnectOptions) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut include_bytes!("../fixtures/test-ca.pem").as_slice()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut options = ConnectOptions::new(
        "127.0.0.1",
        listener.local_addr().unwrap().port(),
        "fake-user",
        "fake-password",
        roots,
    );
    options.version = ProtocolVersion::V8_0;
    (listener, options)
}

pub fn done(status: u16) -> Vec<u8> {
    let mut bytes = vec![0xfd];
    bytes.extend(status.to_le_bytes());
    bytes.extend([0; 10]);
    bytes
}
pub fn routing(server: &str, port: u16, protocol: u8, old: u16) -> Vec<u8> {
    let mut value = vec![protocol];
    value.extend(port.to_le_bytes());
    let name: Vec<u16> = server.encode_utf16().collect();
    value.extend((name.len() as u16).to_le_bytes());
    value.extend(name.into_iter().flat_map(u16::to_le_bytes));
    let mut body = vec![20];
    body.extend((value.len() as u16).to_le_bytes());
    body.extend(value);
    body.extend(old.to_le_bytes());
    let mut token = vec![0xe3];
    token.extend((body.len() as u16).to_le_bytes());
    token.extend(body);
    token
}

pub struct Peer {
    pub socket: TcpStream,
    pub message_status: u8,
    pub last_status: u8,
    tls: ServerConnection,
    packets: Unpacker,
    mars: Option<mars::Decoder>,
    frames: VecDeque<Frame>,
}
impl Peer {
    pub async fn login(listener: TcpListener) -> Self {
        Self::login_with_version(listener, 0x74000004).await
    }
    pub async fn login_with_version(listener: TcpListener, version: u32) -> Self {
        Self::login_options(listener, version, false).await
    }
    pub async fn login_mars(listener: TcpListener) -> Self {
        Self::login_options(listener, 0x74000004, true).await
    }
    async fn login_options(listener: TcpListener, version: u32, mars: bool) -> Self {
        Self::login_next(&listener, version, mars).await
    }
    pub async fn login_next(listener: &TcpListener, version: u32, mars: bool) -> Self {
        let (socket, _) = listener.accept().await.unwrap();
        Self::login_socket(socket, version, mars).await
    }
    pub async fn login_socket(socket: TcpStream, version: u32, mars: bool) -> Self {
        let (mut peer, _) = Self::await_login(socket, mars).await;
        peer.accept_login(version, mars, &[]).await;
        peer
    }
    pub async fn await_login(socket: TcpStream, mars: bool) -> (Self, Vec<u8>) {
        Self::await_login_using(socket, mars, include_bytes!("../fixtures/test-server.pem")).await
    }
    pub async fn await_login_using(socket: TcpStream, mars: bool, pem: &[u8]) -> (Self, Vec<u8>) {
        Self::await_login_protocol(socket, mars, pem, ProtocolVersion::V8_0).await
    }
    pub async fn await_login_protocol(
        mut socket: TcpStream,
        mars: bool,
        pem: &[u8],
        protocol: ProtocolVersion,
    ) -> (Self, Vec<u8>) {
        if protocol == ProtocolVersion::V7_4 {
            assert_eq!(raw_message(&mut socket).await.0, packet::HELLO);
            socket
                .write_all(
                    &packet::split(packet::REPLY, &prelogin::encode_with_mars(mars), 4096).unwrap(),
                )
                .await
                .unwrap();
        }
        let mut pem = pem;
        let certificates = rustls_pemfile::certs(&mut pem)
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        let key = rustls_pemfile::private_key(
            &mut include_bytes!("../fixtures/test-server-key.pem").as_slice(),
        )
        .unwrap()
        .unwrap();
        let mut config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
        config.alpn_protocols = vec![b"tds/8.0".to_vec()];
        socket.set_nodelay(true).unwrap();
        let mut peer = Self {
            socket,
            message_status: 0,
            last_status: 0,
            tls: ServerConnection::new(Arc::new(config)).unwrap(),
            packets: Unpacker::default(),
            mars: None,
            frames: VecDeque::new(),
        };
        while peer.tls.is_handshaking() {
            if protocol == ProtocolVersion::V7_4 {
                let (kind, records) = raw_message(&mut peer.socket).await;
                assert_eq!(kind, packet::HELLO);
                let mut records = Cursor::new(records);
                while records.position() < records.get_ref().len() as u64 {
                    assert!(peer.tls.read_tls(&mut records).unwrap() > 0);
                    peer.tls.process_new_packets().unwrap();
                }
                let mut flight = Vec::new();
                while peer.tls.wants_write() {
                    peer.tls.write_tls(&mut flight).unwrap();
                }
                if !flight.is_empty() {
                    peer.socket
                        .write_all(&packet::split(packet::HELLO, &flight, 4096).unwrap())
                        .await
                        .unwrap();
                }
            } else {
                peer.receive().await;
                peer.flush().await;
            }
        }
        if protocol == ProtocolVersion::V8_0 {
            assert_eq!(peer.message().await.0, packet::HELLO);
            peer.reply(&prelogin::encode_with_mars(mars)).await;
        }
        let (kind, login) = peer.message().await;
        assert_eq!(kind, packet::LOGIN);
        (peer, login)
    }
    pub fn tls_server_name(&self) -> Option<&str> {
        self.tls.server_name()
    }
    pub async fn accept_login(&mut self, version: u32, mars: bool, extra: &[u8]) {
        let mut ack = vec![0xad, 10, 0, 1];
        ack.extend(version.to_be_bytes());
        ack.extend([0, 17, 0, 0x13, 0x97]);
        ack.extend(extra);
        ack.extend(done(0));
        self.reply(&ack).await;
        if mars {
            self.mars = Some(mars::Decoder::default());
        }
    }
    async fn receive(&mut self) {
        let mut bytes = [0; 16384];
        let n = self.socket.read(&mut bytes).await.unwrap();
        assert!(n > 0, "peer closed unexpectedly");
        let mut cursor = Cursor::new(&bytes[..n]);
        let mut plain = [0; 16384];
        while (cursor.position() as usize) < n {
            assert!(self.tls.read_tls(&mut cursor).unwrap() > 0);
            self.tls.process_new_packets().unwrap();
            loop {
                match self.tls.reader().read(&mut plain) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Some(decoder) = &mut self.mars {
                            decoder.feed(&plain[..n]).unwrap();
                            while let Some(frame) = decoder.next_frame().unwrap() {
                                self.frames.push_back(frame);
                            }
                        } else {
                            self.packets.feed(&plain[..n]).unwrap();
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("controlled TLS peer read failed: {e}"),
                }
            }
        }
    }
    async fn flush(&mut self) {
        let mut bytes = Vec::new();
        while self.tls.wants_write() {
            self.tls.write_tls(&mut bytes).unwrap();
        }
        self.socket.write_all(&bytes).await.unwrap();
    }
    pub async fn message(&mut self) -> (u8, Vec<u8>) {
        let mut body = Vec::new();
        let mut first = true;
        loop {
            if let Some(packet) = self.packets.next_packet().unwrap() {
                if first {
                    self.message_status = packet.status;
                    first = false;
                }
                body.extend(packet.body);
                if packet.last {
                    self.last_status = packet.status;
                    return (packet.kind, body);
                }
            } else {
                self.receive().await;
                self.flush().await;
            }
        }
    }
    pub async fn reply(&mut self, body: &[u8]) {
        self.reply_in_packets(body, 4096).await;
    }
    pub async fn reply_in_packets(&mut self, body: &[u8], size: usize) {
        self.reply_with_end(body, size, true).await;
    }
    pub async fn reply_with_end(&mut self, body: &[u8], size: usize, last: bool) {
        let mut packets = packet::split(packet::REPLY, body, size).unwrap();
        if !last {
            let tail = if body.is_empty() {
                0
            } else {
                ((body.len() - 1) / (size - packet::HEADER)) * size
            };
            packets[tail + 1] &= !1;
        }
        for packet in packets.chunks(size) {
            self.tls.writer().write_all(packet).unwrap();
            self.flush().await;
        }
    }
    pub async fn frame(&mut self) -> Frame {
        loop {
            if let Some(frame) = self.frames.pop_front() {
                return frame;
            }
            self.receive().await;
            self.flush().await;
        }
    }
    pub async fn send_frame(&mut self, frame: Frame) {
        self.tls
            .writer()
            .write_all(&frame.encode().unwrap())
            .unwrap();
        self.flush().await;
    }
    pub async fn send_raw_plain(&mut self, bytes: &[u8]) {
        self.tls.writer().write_all(bytes).unwrap();
        self.flush().await;
    }
    pub async fn drain_to_eof(mut self) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut bytes = [0; 16384];
        while tokio::time::timeout_at(deadline, self.socket.read(&mut bytes))
            .await
            .unwrap()
            .unwrap()
            != 0
        {}
    }
    pub async fn expect_eof(mut self) {
        let mut bytes = [0; 16384];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.socket.read(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(n, 0);
    }
}

async fn raw_message(socket: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut body = Vec::new();
    loop {
        let mut header = [0; 8];
        socket.read_exact(&mut header).await.unwrap();
        let size = usize::from(u16::from_be_bytes([header[2], header[3]]));
        assert!((8..=packet::MAX_SIZE).contains(&size));
        let mut chunk = vec![0; size - 8];
        socket.read_exact(&mut chunk).await.unwrap();
        body.extend(chunk);
        if header[1] & 1 != 0 {
            return (header[0], body);
        }
    }
}

pub fn docker_options() -> ConnectOptions {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let password = std::env::var("MSSQL_SA_PASSWORD")
        .ok()
        .or_else(|| {
            std::fs::read_to_string(root.join("docker/macos/.env"))
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find_map(|line| line.strip_prefix("MSSQL_SA_PASSWORD=").map(str::to_owned))
                })
        })
        .expect("set MSSQL_SA_PASSWORD or create docker/macos/.env");
    let pem = std::fs::read(root.join("docker/macos/tls/test-ca.pem"))
        .expect("generate the Docker test CA");
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots
            .add(cert.expect("read CA certificate"))
            .expect("valid CA");
    }
    assert!(!roots.is_empty());
    let mut options = ConnectOptions::new("127.0.0.1", 14325, "sa", password, roots);
    options.database = "tds_test".into();
    options.host_name = Some("rust-live-test".into());
    options.language = "us_english".into(); // fixture scenarios deliberately select their error-message language
    options
}
