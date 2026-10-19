//! Protocol/provider acceptance against a controlled verified-TLS peer.
//! Microsoft interoperability is a separate live GCP gate.
use tds_client::{
    Record,
    auth::{MAX_TOKEN, Token},
    login7::Login,
    tokens::Decoder,
};
#[cfg(feature = "integrated-auth")]
mod support;

#[test]
fn integrated_login_has_distinct_flags_offsets_and_masked_token() {
    let login = Login {
        integrated_security: true,
        sspi: Token::new(b"public-test-token".to_vec()).unwrap(),
        ..Default::default()
    };
    let encoded = login.encode().unwrap();
    assert_ne!(encoded[25] & 0x80, 0);
    assert_eq!(&encoded[40..48], &[94, 0, 0, 0, 94, 0, 0, 0]);
    let at = u16::from_le_bytes(encoded[78..80].try_into().unwrap()) as usize;
    let length = u16::from_le_bytes(encoded[80..82].try_into().unwrap()) as usize;
    assert_eq!(&encoded[at..at + length], b"public-test-token");
    let conflicting = Login {
        user: "sql-user".into(),
        ..login
    };
    assert!(conflicting.encode().is_err());
    assert!(!format!("{:?}", Token::new(b"canary".to_vec()).unwrap()).contains("canary"));
    assert!(Token::new(vec![0; MAX_TOKEN + 1]).is_err());
}

#[test]
fn sspi_token_fragmentation_length_and_inspection_privacy() {
    let token = b"server-token-canary";
    let mut bytes = vec![0xed];
    bytes.extend((token.len() as u16).to_le_bytes());
    bytes.extend(token);
    for split in 0..bytes.len() {
        let mut decoder = Decoder::default();
        decoder.set_inspection(true);
        decoder.feed(&bytes[..split]).unwrap();
        assert!(decoder.next_record().unwrap().is_none());
        decoder.feed(&bytes[split..]).unwrap();
        let Record::Sspi(value) = decoder.next_record().unwrap().unwrap() else {
            panic!()
        };
        assert_eq!(value.as_bytes(), token);
        let node = decoder.take_inspection().unwrap();
        assert!(node.sensitive);
        assert!(node.raw.iter().all(|v| *v == 0));
        assert!(!format!("{node:?}").contains("server-token-canary"));
    }
    let mut decoder = Decoder::default();
    decoder.feed(&[0xed, 0xff, 0xff]).unwrap();
    assert!(decoder.next_record().is_err());
}

#[cfg(feature = "integrated-auth")]
mod live_peer {
    use super::support;
    use sspi::{Sspi, SspiImpl};
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tds_client::{
        Batch, Connection,
        auth::{Method, WindowsAuth},
        observe::{Level, Observer},
        packet,
    };

    struct Server {
        provider: sspi::Ntlm,
        credentials: Option<sspi::AuthIdentityBuffers>,
    }
    impl Server {
        fn new() -> Self {
            let mut provider = sspi::Ntlm::new();
            let identity = sspi::AuthIdentity {
                username: sspi::Username::parse("TDS\\fixture").unwrap(),
                password: "test-only-password".to_string().into(),
            };
            let credentials = provider
                .acquire_credentials_handle()
                .with_credential_use(sspi::CredentialUse::Inbound)
                .with_auth_data(&identity)
                .execute(&mut provider)
                .unwrap()
                .credentials_handle;
            Self {
                provider,
                credentials,
            }
        }
        fn step(&mut self, token: Vec<u8>) -> Vec<u8> {
            let mut input = vec![sspi::SecurityBuffer::new(token, sspi::BufferType::Token)];
            let mut output = vec![sspi::SecurityBuffer::new(
                Vec::new(),
                sspi::BufferType::Token,
            )];
            let builder = self
                .provider
                .accept_security_context()
                .with_credentials_handle(&mut self.credentials)
                .with_context_requirements(sspi::ServerRequestFlags::empty())
                .with_target_data_representation(sspi::DataRepresentation::Native)
                .with_input(&mut input)
                .with_output(&mut output);
            let result = self
                .provider
                .accept_security_context_impl(builder)
                .unwrap()
                .resolve_to_result()
                .unwrap();
            if matches!(
                result.status,
                sspi::SecurityStatus::CompleteNeeded | sspi::SecurityStatus::CompleteAndContinue
            ) {
                self.provider.complete_auth_token(&mut output).unwrap();
            }
            std::mem::take(&mut output[0].buffer)
        }
    }
    fn windows(options: &mut tds_client::ConnectOptions) {
        options.authentication = tds_client::Authentication::Windows(WindowsAuth::explicit(
            Method::Ntlm,
            "TDS\\fixture",
            "test-only-password",
        ));
    }
    #[tokio::test]
    async fn ntlm_login_continues_across_tiny_packets_then_sql_is_usable_and_events_mask_tokens() {
        let (listener, mut options) = support::listener().await;
        windows(&mut options);
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = events.clone();
        options.observe = Some(Observer::new(Level::Full, move |event| {
            seen.lock().unwrap().push(format!("{event:?}"));
            Ok(())
        }));
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut peer, login) = support::Peer::await_login(socket, false).await;
            assert_ne!(login[25] & 0x80, 0);
            let at = u16::from_le_bytes(login[78..80].try_into().unwrap()) as usize;
            let len = u16::from_le_bytes(login[80..82].try_into().unwrap()) as usize;
            assert!(login[at..at + len].starts_with(b"NTLMSSP\0"));
            let mut auth = Server::new();
            let challenge = auth.step(login[at..at + len].to_vec());
            let mut reply = vec![0xed];
            reply.extend((challenge.len() as u16).to_le_bytes());
            reply.extend(&challenge);
            peer.reply_in_packets(&reply, 9).await;
            let (kind, response) = peer.message().await;
            assert_eq!(kind, packet::SSPI);
            assert!(auth.step(response).is_empty());
            peer.accept_login(0x74000004, false, &[]).await;
            assert_eq!(peer.message().await.0, packet::BATCH);
            peer.reply(&support::done(0)).await;
            peer.drain_to_eof().await;
        });
        let connection = Connection::connect(options).await.unwrap();
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
        server.await.unwrap();
        assert!(
            events
                .lock()
                .unwrap()
                .iter()
                .all(|e| !e.contains("test-only-password"))
        );
    }
    #[tokio::test]
    async fn early_login_ack_without_provider_completion_fails_closed() {
        let (listener, mut options) = support::listener().await;
        windows(&mut options);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut peer, _) = support::Peer::await_login(socket, false).await;
            peer.accept_login(0x74000004, false, &[]).await;
            peer.expect_eof().await;
        });
        assert!(Connection::connect(options).await.is_err());
        server.await.unwrap();
    }
    #[tokio::test]
    async fn stalled_kdc_is_cancelled_by_the_same_opening_deadline() {
        use tokio::{io::AsyncReadExt, net::TcpListener};
        let kdc = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (listener, mut options) = support::listener().await;

        options.timeout = Duration::from_millis(600);
        let mut auth =
            WindowsAuth::explicit(Method::Kerberos, "fixture@tds.test", "test-only-password");
        auth.kdc_url = Some(format!(
            "tcp://127.0.0.1:{}",
            kdc.local_addr().unwrap().port()
        ));
        options.authentication = tds_client::Authentication::Windows(auth);
        let kdc_peer = tokio::spawn(async move {
            let (mut socket, _) = kdc.accept().await.unwrap();
            let length = socket.read_u32().await.unwrap();
            assert!(length > 0);
            let mut body = vec![0; length as usize];
            socket.read_exact(&mut body).await.unwrap();
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
        });
        // Kerberos must contact the KDC only after TLS/PRELOGIN. The SQL peer
        // therefore sees no LOGIN7 and closes when the original deadline ends.
        let sql_peer = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let peer = support::Peer::secure_protocol(
                socket,
                false,
                include_bytes!("fixtures/test-server.pem"),
                tds_client::ProtocolVersion::V8_0,
            )
            .await;
            peer.expect_eof().await;
        });
        assert!(Connection::connect(options).await.is_err());
        tokio::time::timeout(Duration::from_secs(2), kdc_peer)
            .await
            .unwrap()
            .unwrap();
        sql_peer.await.unwrap();
    }
    #[tokio::test]
    async fn stalled_login_uses_opening_deadline_and_closes_socket() {
        let (listener, mut options) = support::listener().await;
        windows(&mut options);
        options.timeout = Duration::from_millis(200);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (peer, _) = support::Peer::await_login(socket, false).await;
            peer.expect_eof().await;
        });
        assert!(Connection::connect(options).await.is_err());
        server.await.unwrap();
    }
}
