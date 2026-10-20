//! Controlled Entra openings: these peers do not authenticate against Azure.
#![cfg(feature = "tokio")]
mod support;
use std::{
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};
use tds_client::{
    Authentication, Batch, Connection, ErrorKind, ProtocolVersion, Step,
    capture::Capture,
    entra::{
        AccessToken, EntraLogin, ProviderError, TokenFuture, TokenProvider, TokenProviders,
        TokenRequest,
    },
    fedauth::Workflow,
    observe::{Level, Observer},
    packet,
};

const SECRET: &str = "artificial-entra-secret-λ-🔑";
type Requests = Arc<Mutex<Vec<(String, Option<String>, u16)>>>;
struct Provider {
    requests: Requests,
}
impl TokenProvider for Provider {
    fn acquire<'a>(&'a self, request: TokenRequest<'a>) -> TokenFuture<'a> {
        Box::pin(async move {
            self.requests.lock().unwrap().push((
                request.resource.into(),
                request.sts_url.map(str::to_owned),
                request.port,
            ));
            Ok(AccessToken::new(SECRET.into(), None))
        })
    }
}
fn bind(options: &mut tds_client::ConnectOptions, deferred: bool) -> Requests {
    let requests = Requests::default();
    options.authentication = Authentication::Entra(if deferred {
        EntraLogin::deferred("test", "tenant/principal-v1", Workflow::Interactive)
    } else {
        EntraLogin::upfront("test", "tenant/principal-v1")
    });
    options.token_providers = TokenProviders::new().with(
        "test",
        Arc::new(Provider {
            requests: requests.clone(),
        }),
    );
    requests
}
fn info() -> Vec<u8> {
    let values: Vec<Vec<u8>> = [
        "https://login.example/tenant",
        "https://database.windows.net/",
    ]
    .iter()
    .map(|v| v.encode_utf16().flat_map(u16::to_le_bytes).collect())
    .collect();
    let mut body = 2_u32.to_le_bytes().to_vec();
    let mut offset = 22_u32;
    for (index, bytes) in values.iter().enumerate() {
        body.push(index as u8 + 1);
        body.extend((bytes.len() as u32).to_le_bytes());
        body.extend(offset.to_le_bytes());
        offset += bytes.len() as u32;
    }
    for bytes in values {
        body.extend(bytes);
    }
    let mut token = vec![0xee];
    token.extend((body.len() as u32).to_le_bytes());
    token.extend(body);
    token
}
fn hello(mars: bool) -> Vec<u8> {
    // Independent PRELOGIN directory with federation echo and a fixed nonce.
    let mars = [u8::from(mars)];
    let fields: [(u8, &[u8]); 7] = [
        (0, &[0, 1, 0, 0, 0, 0]),
        (1, &[1]),
        (2, &[0]),
        (3, &[0; 4]),
        (4, &mars),
        (6, &[1]),
        (7, &[0x5a; 32]),
    ];
    let mut result = Vec::new();
    let mut offset = 36_u16;
    for (tag, value) in fields {
        result.push(tag);
        result.extend(offset.to_be_bytes());
        result.extend((value.len() as u16).to_be_bytes());
        offset += value.len() as u16;
    }
    result.push(0xff);
    for (_, value) in fields {
        result.extend(value);
    }
    result
}
fn feature(login: &[u8]) -> Vec<u8> {
    assert_eq!(login[25] & 0x80, 0);
    assert_eq!(u16::from_le_bytes(login[42..44].try_into().unwrap()), 0);
    let pointer = u16::from_le_bytes(login[56..58].try_into().unwrap()) as usize;
    let mut at = u32::from_le_bytes(login[pointer..pointer + 4].try_into().unwrap()) as usize;
    while login[at] != 0xff {
        let length = u32::from_le_bytes(login[at + 1..at + 5].try_into().unwrap()) as usize;
        if login[at] == 2 {
            return login[at + 5..at + 5 + length].to_vec();
        }
        at += 5 + length;
    }
    panic!("missing federated feature")
}
#[derive(Clone, Default)]
struct Output(Arc<Mutex<Vec<u8>>>);
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn both_entra_paths_echo_nonce_and_use_sql_across_versions_and_mars() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            for deferred in [false, true] {
                let (listener, mut options) = support::listener().await;
                options.version = version;
                options.mars = mars;
                let requests = bind(&mut options, deferred);
                let saved = Output::default();
                let output = saved.clone();
                options.capture_factory = Some(Arc::new(move || {
                    Ok(Capture::new(output.clone()).keep_password(true))
                }));
                let events = Arc::new(Mutex::new(Vec::new()));
                let seen = events.clone();
                options.observe = Some(Observer::new(Level::Full, move |event| {
                    seen.lock().unwrap().push(event.clone());
                    Ok(())
                }));
                let server = tokio::spawn(async move {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut peer = support::Peer::secure_protocol_using_hello(
                        socket,
                        include_bytes!("fixtures/test-server.pem"),
                        version,
                        &hello(mars),
                    )
                    .await;
                    let (kind, login) = peer.message().await;
                    assert_eq!(kind, packet::LOGIN);
                    if deferred {
                        assert_eq!(feature(&login), [5, 3]);
                        peer.reply_in_packets(&info(), 9).await;
                        let (kind, body) = peer.message().await;
                        assert_eq!(kind, 0x08);
                        assert_eq!(
                            &body[8..body.len() - 32],
                            &SECRET
                                .encode_utf16()
                                .flat_map(u16::to_le_bytes)
                                .collect::<Vec<_>>()
                        );
                        assert_eq!(&body[body.len() - 32..], &[0x5a; 32]);
                    } else {
                        let data = feature(&login);
                        assert_eq!(data[0], 3);
                        assert_eq!(
                            &data[5..data.len() - 32],
                            &SECRET
                                .encode_utf16()
                                .flat_map(u16::to_le_bytes)
                                .collect::<Vec<_>>()
                        );
                        assert_eq!(&data[data.len() - 32..], &[0x5a; 32]);
                    }
                    peer.accept_login(0x74000004, mars, &[0xae, 2, 0, 0, 0, 0, 0xff])
                        .await;
                    if mars {
                        use tds_client::mars::{self, Frame};
                        let syn = peer.frame().await;
                        assert_eq!(syn.flags, mars::SYN);
                        peer.send_frame(Frame {
                            channel: syn.channel,
                            flags: mars::ACK,
                            sequence: 0,
                            window: 4,
                            body: vec![],
                        })
                        .await;
                        loop {
                            let data = peer.frame().await;
                            if data.flags == mars::DATA {
                                assert_eq!(data.body[0], packet::BATCH);
                                break;
                            }
                        }
                        peer.send_frame(Frame {
                            channel: syn.channel,
                            flags: mars::DATA,
                            sequence: 1,
                            window: 4,
                            body: packet::split(packet::REPLY, &support::done(0), 4096).unwrap(),
                        })
                        .await;
                        loop {
                            let fin = peer.frame().await;
                            if fin.flags == mars::FIN {
                                peer.send_frame(Frame {
                                    channel: syn.channel,
                                    flags: mars::FIN,
                                    sequence: 1,
                                    window: 4,
                                    body: vec![],
                                })
                                .await;
                                break;
                            }
                        }
                    } else {
                        assert_eq!(peer.message().await.0, packet::BATCH);
                        peer.reply(&support::done(0)).await;
                    }
                    use tokio::io::AsyncReadExt;
                    let mut raw = [0; 4096];
                    tokio::time::timeout(Duration::from_secs(3), async {
                        loop {
                            match peer.socket.read(&mut raw).await {
                                Ok(0) => break,
                                Err(error)
                                    if error.kind() == std::io::ErrorKind::ConnectionReset =>
                                {
                                    break;
                                }
                                Ok(_) => {}
                                Err(error) => panic!("closing peer: {error}"),
                            }
                        }
                    })
                    .await
                    .unwrap();
                });
                let connection =
                    tokio::time::timeout(Duration::from_secs(3), Connection::connect(options))
                        .await
                        .unwrap()
                        .unwrap();
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
                tokio::time::timeout(Duration::from_secs(3), server)
                    .await
                    .unwrap()
                    .unwrap();
                let calls = requests.lock().unwrap();
                assert_eq!(calls.len(), 1);
                assert_eq!(calls[0].0, "https://database.windows.net/");
                assert_eq!(
                    calls[0].1.as_deref(),
                    deferred.then_some("https://login.example/tenant")
                );
                assert!(!format!("{:?}", events.lock().unwrap()).contains(SECRET));
                use base64::Engine;
                let bytes = saved.0.lock().unwrap();
                let mut recorded = Vec::new();
                for line in bytes.split(|b| *b == b'\n').filter(|b| !b.is_empty()) {
                    let value: serde_json::Value = serde_json::from_slice(line).unwrap();
                    if let Some(encoded) = value["bytes"].as_str() {
                        recorded.extend(
                            base64::engine::general_purpose::STANDARD
                                .decode(encoded)
                                .unwrap(),
                        );
                    }
                }
                let secret: Vec<u8> = SECRET.encode_utf16().flat_map(u16::to_le_bytes).collect();
                assert!(!recorded.windows(secret.len()).any(|part| part == secret));
                fn check_tree(node: &tds_client::inspection::Node, secret: &[u8]) {
                    assert!(!node.raw.windows(secret.len()).any(|part| part == secret));
                    for child in &node.children {
                        check_tree(child, secret);
                    }
                }
                for event in events.lock().unwrap().iter() {
                    if let Some(tds_client::observe::Inspection::Packet { body, .. }) =
                        &event.inspection
                    {
                        assert!(!body.windows(secret.len()).any(|part| part == secret));
                    }
                    for field in &event.fields {
                        check_tree(field, &secret);
                    }
                }
                let mut missing = false;
                tds_client::replay::replay(std::io::Cursor::new(&*bytes), |item| {
                    if let tds_client::replay::Content::Diagnostic { description, .. } =
                        item.content
                        && description.contains("cannot be reconstructed")
                    {
                        missing = true;
                    }
                    Ok(())
                })
                .unwrap();
                assert!(missing, "masked authentication remains missing evidence");
            }
        }
    }
}

struct Slow {
    entered: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}
struct Retirement(Arc<AtomicUsize>);
impl Drop for Retirement {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
impl TokenProvider for Slow {
    fn acquire<'a>(&'a self, _: TokenRequest<'a>) -> TokenFuture<'a> {
        Box::pin(async move {
            let _guard = Retirement(self.dropped.clone());
            self.entered.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        })
    }
}
#[tokio::test]
async fn provider_deadline_and_caller_cancellation_retire_the_candidate_and_future() {
    for canceled in [false, true] {
        let (listener, mut options) = support::listener().await;
        bind(&mut options, false);
        let entered = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        options.token_providers = TokenProviders::new().with(
            "test",
            Arc::new(Slow {
                entered: entered.clone(),
                dropped: dropped.clone(),
            }),
        );
        options.timeout = if canceled {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(150)
        };
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let peer = support::Peer::secure_protocol(
                socket,
                false,
                include_bytes!("fixtures/test-server.pem"),
                ProtocolVersion::V8_0,
            )
            .await;
            peer.expect_eof().await;
        });
        let task = tokio::spawn(Connection::connect(options));
        if canceled {
            tokio::time::timeout(Duration::from_secs(2), async {
                while entered.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            task.abort();
            assert!(task.await.err().unwrap().is_cancelled());
        } else {
            let error = task.await.unwrap().err().unwrap();
            assert!(matches!(error.kind, ErrorKind::Timeout));
            assert_eq!(error.step, Step::Login);
        }
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
}

struct Refusing;
impl TokenProvider for Refusing {
    fn acquire<'a>(&'a self, _: TokenRequest<'a>) -> TokenFuture<'a> {
        Box::pin(async {
            Err(ProviderError::with_cause(std::io::Error::other(
                "provider-secret-canary",
            )))
        })
    }
}
#[tokio::test]
async fn provider_errors_hide_sensitive_causes_and_unbound_sources_fail_before_tcp() {
    let (listener, mut options) = support::listener().await;
    bind(&mut options, false);
    options.token_providers = TokenProviders::new();
    assert!(matches!(
        Connection::connect(options.clone())
            .await
            .err()
            .unwrap()
            .kind,
        ErrorKind::Parameter(_)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    options.token_providers = TokenProviders::new().with("test", Arc::new(Refusing));
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        support::Peer::secure_protocol(
            socket,
            false,
            include_bytes!("fixtures/test-server.pem"),
            ProtocolVersion::V8_0,
        )
        .await
        .expect_eof()
        .await;
    });
    let error = Connection::connect(options).await.err().unwrap();
    assert!(!format!("{error:?} {error}").contains("provider-secret-canary"));
    let ErrorKind::TokenProvider(cause) = error.kind else {
        panic!("provider category")
    };
    assert_eq!(
        cause.protected_cause().unwrap().to_string(),
        "provider-secret-canary"
    );
    server.await.unwrap();
}

#[test]
fn identity_changes_are_configuration_changes_and_runtime_tokens_are_not_compared() {
    let mut before = tds_client::ConnectionConfig::new("fixture", 1433, "user", "secret");
    before.authentication =
        Authentication::Entra(EntraLogin::upfront("source", "tenant/principal-v1"));
    let mut after = before.clone();
    assert!(after.compatible_with(&before));
    let Authentication::Entra(ref mut login) = after.authentication else {
        panic!()
    };
    login.identity = "tenant/principal-v2".into();
    assert!(!after.compatible_with(&before));
    assert!(
        !format!(
            "{:?}",
            AccessToken::new("token-canary".into(), Some(SystemTime::now()))
        )
        .contains("token-canary")
    );
}

async fn await_entra(socket: tokio::net::TcpStream, deferred: bool) -> support::Peer {
    let (mut peer, login) = support::Peer::await_login(socket, false).await;
    assert!(!feature(&login).is_empty());
    if deferred {
        peer.reply(&info()).await;
        assert_eq!(peer.message().await.0, 0x08);
    }
    peer
}

#[tokio::test]
async fn routing_requests_the_source_for_each_physical_attempt_and_refuses_a_second_route() {
    for deferred in [false, true] {
        for repeated in [false, true] {
            let (gateway, mut options) = support::listener().await;
            let (destination, _) = support::listener().await;
            let target = destination.local_addr().unwrap().port();
            let initial = options.port;
            let requests = bind(&mut options, deferred);
            let first = tokio::spawn(async move {
                let (socket, _) = gateway.accept().await.unwrap();
                let mut peer = await_entra(socket, deferred).await;
                let mut extra = vec![0xae, 2, 0, 0, 0, 0, 0xff];
                extra.extend(support::routing("127.0.0.1", target, 0, 0));
                peer.accept_login(0x74000004, false, &extra).await;
                peer.drain_to_eof().await;
            });
            let second = tokio::spawn(async move {
                let (socket, _) = destination.accept().await.unwrap();
                let mut peer = await_entra(socket, deferred).await;
                let mut extra = vec![0xae, 2, 0, 0, 0, 0, 0xff];
                if repeated {
                    extra.extend(support::routing("127.0.0.1", initial, 0, 0));
                }
                peer.accept_login(0x74000004, false, &extra).await;
                peer.drain_to_eof().await;
            });
            let result = Connection::connect(options).await;
            if repeated {
                assert!(matches!(
                    result.err().unwrap().kind,
                    ErrorKind::RepeatedRoute { .. }
                ));
            } else {
                result.unwrap().close().await.unwrap();
            }
            first.await.unwrap();
            second.await.unwrap();
            let calls = requests.lock().unwrap();
            assert_eq!(
                calls.iter().map(|c| c.2).collect::<Vec<_>>(),
                [initial, target]
            );
        }
    }
}

#[tokio::test]
async fn recovery_gets_a_new_token_without_replaying_application_sql() {
    for deferred in [false, true] {
        let (listener, mut options) = support::listener().await;
        let requests = bind(&mut options, deferred);
        let (cut, cutting) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut peer = await_entra(socket, deferred).await;
            peer.accept_login(
                0x74000004,
                false,
                &[0xae, 1, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0xff],
            )
            .await;
            cutting.await.unwrap();
            drop(peer);
            let (socket, _) = listener.accept().await.unwrap();
            let mut peer = await_entra(socket, deferred).await;
            peer.accept_login(
                0x74000004,
                false,
                &[0xae, 1, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0xff],
            )
            .await;
            assert_eq!(peer.message().await.0, packet::BATCH);
            peer.reply(&support::done(0)).await;
            peer.drain_to_eof().await;
        });
        let connection = Connection::connect(options).await.unwrap();
        let mut channel = connection.serial_channel().await.unwrap();
        cut.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !connection.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        connection.recover().await.unwrap();
        channel
            .exchange(Batch::new("SELECT 1"))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        channel.close().await.unwrap();
        assert_eq!(connection.recoveries(), 1);
        connection.close().await.unwrap();
        server.await.unwrap();
        assert_eq!(requests.lock().unwrap().len(), 2);
    }
}

struct BoundedToken {
    oversized: bool,
}
impl TokenProvider for BoundedToken {
    fn acquire<'a>(&'a self, _: TokenRequest<'a>) -> TokenFuture<'a> {
        Box::pin(async move {
            Ok(if self.oversized {
                AccessToken::new("x".repeat(tds_client::auth::MAX_TOKEN), None)
            } else {
                AccessToken::new(
                    "expired-artificial-token".into(),
                    Some(std::time::UNIX_EPOCH),
                )
            })
        })
    }
}
#[tokio::test]
async fn driver_token_bound_and_explicit_expiry_fail_without_sending_login() {
    for oversized in [false, true] {
        let (listener, mut options) = support::listener().await;
        bind(&mut options, false);
        options.token_providers =
            TokenProviders::new().with("test", Arc::new(BoundedToken { oversized }));
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            support::Peer::secure_protocol(
                socket,
                false,
                include_bytes!("fixtures/test-server.pem"),
                ProtocolVersion::V8_0,
            )
            .await
            .expect_eof()
            .await;
        });
        let error = Connection::connect(options).await.err().unwrap();
        assert_eq!(error.execution, tds_client::Execution::NotSent);
        assert!(if oversized {
            matches!(error.kind, ErrorKind::Limit(_))
        } else {
            matches!(error.kind, ErrorKind::Authentication(_))
        });
        server.await.unwrap();
    }
}

#[tokio::test]
async fn deferred_login_without_a_server_token_request_matches_python_baseline() {
    // Independently reproduced through Python test_logins.FakeServer: Python
    // accepts LOGINACK here without invoking the callback. No SQL fallback or
    // real-service validity is inferred from that controlled outcome.
    let (listener, mut options) = support::listener().await;
    let requests = bind(&mut options, true);
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, login) = support::Peer::await_login(socket, false).await;
        assert_eq!(feature(&login), [4, 3]);
        peer.accept_login(0x74000004, false, &[]).await;
        peer.drain_to_eof().await;
    });
    Connection::connect(options)
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
    server.await.unwrap();
    assert!(requests.lock().unwrap().is_empty());
}
