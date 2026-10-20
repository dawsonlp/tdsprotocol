//! Controlled Entra edge cases (Part B: B-1 to B-3). Each pins Rust's agreed
//! behavior; where Python differs, the difference is recorded in
//! `docs/design/experiments/rust-azure-code-complete.md`, not inferred here.
#![cfg(feature = "tokio")]
mod support;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use support::Peer;
use tds_client::{
    Authentication, Connection, ErrorKind, Execution, Pool, ProtocolVersion,
    entra::{AccessToken, EntraLogin, TokenFuture, TokenProvider, TokenProviders, TokenRequest},
    fedauth::Workflow,
};
use tokio::sync::oneshot;

/// Returns `token` and counts requests.
struct Provider {
    token: &'static str,
    calls: AtomicUsize,
}
impl Provider {
    fn new(token: &'static str) -> Arc<Self> {
        Arc::new(Self {
            token,
            calls: AtomicUsize::new(0),
        })
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}
impl TokenProvider for Provider {
    fn acquire<'a>(&'a self, _: TokenRequest<'a>) -> TokenFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(AccessToken::new(self.token.into(), None))
        })
    }
}
fn bind(
    options: &mut tds_client::ConnectOptions,
    deferred: bool,
    provider: Arc<dyn TokenProvider>,
) {
    options.authentication = Authentication::Entra(if deferred {
        EntraLogin::deferred("test", "tenant/principal", Workflow::Interactive)
    } else {
        EntraLogin::upfront("test", "tenant/principal")
    });
    options.token_providers = TokenProviders::new().with("test", provider);
}
/// FEDAUTHINFO with an STS URL and SPN, as in `azure_login.rs`.
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
fn rejected_login(number: u32) -> Vec<u8> {
    let mut body = number.to_le_bytes().to_vec();
    body.extend([1, 14, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut token = vec![0xaa];
    token.extend((body.len() as u16).to_le_bytes());
    token.extend(body);
    token.extend(support::done(2));
    token
}
fn malformed(error: &tds_client::Error) -> Option<&'static str> {
    match error.cause().kind {
        ErrorKind::Malformed { field, .. } => Some(field),
        _ => None,
    }
}
/// The upfront LOGIN7 FeatureExt data for FEDAUTH (id 2).
fn federated_feature(login: &[u8]) -> Vec<u8> {
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

// ---------------------------------------------------------------- B-1: FEDAUTHINFO order and limits

#[tokio::test]
async fn fedauthinfo_is_refused_for_upfront_and_sql_logins() {
    for upfront in [true, false] {
        let (listener, mut options) = support::listener().await;
        let provider = Provider::new("token");
        if upfront {
            bind(&mut options, false, provider.clone());
        }
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut peer, _) = Peer::await_login(socket, false).await;
            peer.reply(&info()).await;
            peer.expect_eof().await;
        });
        let error = Connection::connect(options).await.err().expect("refused");
        assert_eq!(malformed(&error), Some("unexpected FEDAUTHINFO"), "{error}");
        assert_eq!(
            provider.calls(),
            usize::from(upfront),
            "only the upfront token"
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn fedauthinfo_after_loginack_is_refused_without_a_token_request() {
    let (listener, mut options) = support::listener().await;
    let provider = Provider::new("token");
    bind(&mut options, true, provider.clone());
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = Peer::await_login(socket, false).await;
        peer.accept_login(0x74000004, false, &info()).await; // LOGINACK, then FEDAUTHINFO
        peer.expect_eof().await;
    });
    let error = Connection::connect(options).await.err().expect("refused");
    assert_eq!(
        malformed(&error),
        Some("late or excessive FEDAUTHINFO"),
        "{error}"
    );
    assert_eq!(provider.calls(), 0);
    server.await.unwrap();
}

#[tokio::test]
async fn a_ninth_federated_round_is_refused_after_eight_tokens() {
    let (listener, mut options) = support::listener().await;
    let provider = Provider::new("token");
    bind(&mut options, true, provider.clone());
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = Peer::await_login(socket, false).await;
        for _ in 0..tds_client::auth::MAX_ROUNDS {
            peer.reply(&info()).await;
            assert_eq!(peer.message().await.0, 0x08);
        }
        peer.reply(&info()).await;
        peer.expect_eof().await;
    });
    let error = Connection::connect(options).await.err().expect("refused");
    assert_eq!(
        malformed(&error),
        Some("late or excessive FEDAUTHINFO"),
        "{error}"
    );
    assert_eq!(provider.calls(), usize::from(tds_client::auth::MAX_ROUNDS));
    server.await.unwrap();
}

#[tokio::test]
async fn an_oversized_fedauthinfo_is_refused_before_it_is_buffered() {
    let (listener, mut options) = support::listener().await;
    let provider = Provider::new("token");
    bind(&mut options, true, provider.clone());
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = Peer::await_login(socket, false).await;
        let mut token = vec![0xee];
        token.extend((64 * 1024 + 1_u32).to_le_bytes()); // announced, never sent
        token.extend([0; 16]);
        peer.reply(&token).await;
        peer.expect_eof().await;
    });
    let error = Connection::connect(options).await.err().expect("refused");
    assert!(
        matches!(error.cause().kind, ErrorKind::Limit("FEDAUTHINFO message")),
        "{error}"
    );
    assert_eq!(provider.calls(), 0);
    server.await.unwrap();
}

// ---------------------------------------------------------------- B-2: provider results

/// Like Python, the driver sends an empty token unchanged; the server decides.
#[tokio::test]
async fn an_empty_token_is_sent_unchanged_and_the_servers_refusal_is_returned() {
    for deferred in [false, true] {
        let (listener, mut options) = support::listener().await;
        let provider = Provider::new("");
        bind(&mut options, deferred, provider.clone());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut peer, login) = Peer::await_login(socket, false).await;
            if deferred {
                peer.reply(&info()).await;
                let (kind, body) = peer.message().await;
                assert_eq!(kind, 0x08);
                // Remaining length 4 (no nonce), then a zero token length.
                assert_eq!(&body[..8], &[4, 0, 0, 0, 0, 0, 0, 0]);
            } else {
                let feature = federated_feature(&login);
                assert_eq!(&feature[1..5], &[0, 0, 0, 0], "zero token byte length");
            }
            peer.reply(&rejected_login(18456)).await;
            peer.expect_eof().await;
        });
        let error = Connection::connect(options).await.err().expect("refused");
        assert!(
            matches!(&error.cause().kind, ErrorKind::Server(m) if m.number == 18456),
            "{error}"
        );
        assert_eq!(provider.calls(), 1);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn a_token_without_expiry_metadata_is_accepted() {
    for deferred in [false, true] {
        let (listener, mut options) = support::listener().await;
        let provider = Provider::new("token-without-expiry"); // AccessToken::new(_, None)
        bind(&mut options, deferred, provider.clone());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut peer, _) = Peer::await_login(socket, false).await;
            if deferred {
                peer.reply(&info()).await;
                assert_eq!(peer.message().await.0, 0x08);
            }
            peer.accept_login(0x74000004, false, &[0xae, 2, 0, 0, 0, 0, 0xff])
                .await;
            peer.drain_to_eof().await;
        });
        Connection::connect(options)
            .await
            .unwrap()
            .close()
            .await
            .unwrap();
        assert_eq!(provider.calls(), 1);
        server.await.unwrap();
    }
}

/// Hands its result channel to the test, then waits for the token.
struct Late {
    entered: Mutex<Option<oneshot::Sender<oneshot::Sender<AccessToken>>>>,
}
impl TokenProvider for Late {
    fn acquire<'a>(&'a self, _: TokenRequest<'a>) -> TokenFuture<'a> {
        Box::pin(async move {
            let (result, waiting) = oneshot::channel();
            if let Some(entered) = self.entered.lock().unwrap().take() {
                let _ = entered.send(result);
            }
            Ok(waiting.await.expect("the test supplies a token"))
        })
    }
}
#[tokio::test]
async fn a_token_arriving_after_cancellation_has_nowhere_to_go() {
    for deferred in [false, true] {
        let (listener, mut options) = support::listener().await;
        let (entered, entering) = oneshot::channel();
        bind(
            &mut options,
            deferred,
            Arc::new(Late {
                entered: Mutex::new(Some(entered)),
            }),
        );
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            if deferred {
                let (mut peer, _) = Peer::await_login(socket, false).await;
                peer.reply(&info()).await;
                peer.expect_eof().await; // no FEDAUTH message follows
            } else {
                Peer::secure_protocol(
                    socket,
                    false,
                    include_bytes!("fixtures/test-server.pem"),
                    ProtocolVersion::V8_0,
                )
                .await
                .expect_eof() // no LOGIN7 follows
                .await;
            }
        });
        let opening = tokio::spawn(Connection::connect(options));
        let result = tokio::time::timeout(Duration::from_secs(2), entering)
            .await
            .unwrap()
            .unwrap();
        opening.abort();
        assert!(opening.await.err().unwrap().is_cancelled());
        // The provider future was dropped with the opening: the late token is refused.
        assert!(
            result
                .send(AccessToken::new("late-token".into(), None))
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }
}

// ---------------------------------------------------------------- B-3: redirect TLS and pool closure

#[tokio::test]
async fn a_wrong_certificate_at_the_redirect_target_is_refused_before_its_token() {
    for deferred in [false, true] {
        let (gateway, mut options) = support::listener().await;
        let (destination, _) = support::listener().await;
        let target = destination.local_addr().unwrap().port();
        let provider = Provider::new("token");
        bind(&mut options, deferred, provider.clone());
        let first = tokio::spawn(async move {
            let (socket, _) = gateway.accept().await.unwrap();
            let (mut peer, _) = Peer::await_login(socket, false).await;
            if deferred {
                peer.reply(&info()).await;
                assert_eq!(peer.message().await.0, 0x08);
            }
            let mut extra = vec![0xae, 2, 0, 0, 0, 0, 0xff];
            extra.extend(support::routing("localhost", target, 0, 0));
            peer.accept_login(0x74000004, false, &extra).await;
            peer.drain_to_eof().await;
        });
        // The destination presents a certificate for router.test, not localhost.
        let second = tokio::spawn(async move {
            let (socket, _) = destination.accept().await.unwrap();
            Peer::await_login_using(socket, false, include_bytes!("fixtures/test-router.pem"))
                .await;
        });
        let error = Connection::connect(options).await.err().expect("refused");
        assert!(matches!(error.cause().kind, ErrorKind::Tls(_)), "{error}");
        assert_eq!(error.execution, Execution::NotSent);
        assert_eq!(provider.calls(), 1, "the gateway's token only");
        first.await.unwrap();
        // The destination's handshake fails on its side too; only its outcome matters.
        let _ = tokio::time::timeout(Duration::from_secs(2), second).await;
    }
}

struct Pending {
    entered: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}
struct Retirement(Arc<AtomicUsize>);
impl Drop for Retirement {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
impl TokenProvider for Pending {
    fn acquire<'a>(&'a self, _: TokenRequest<'a>) -> TokenFuture<'a> {
        Box::pin(async move {
            let _guard = Retirement(self.dropped.clone());
            self.entered.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        })
    }
}
/// Rust's pool cancels an opening when it closes. Python lets the opening
/// finish, then closes the late connection (recorded difference).
#[tokio::test]
async fn closing_a_pool_cancels_an_entra_opening_waiting_for_its_token() {
    let (listener, mut options) = support::listener().await;
    let (entered, dropped) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    bind(
        &mut options,
        false,
        Arc::new(Pending {
            entered: entered.clone(),
            dropped: dropped.clone(),
        }),
    );
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        Peer::secure_protocol(
            socket,
            false,
            include_bytes!("fixtures/test-server.pem"),
            ProtocolVersion::V8_0,
        )
        .await
        .expect_eof()
        .await;
    });
    let pool = Arc::new(Pool::new(options, 1).unwrap());
    let opening = {
        let pool = pool.clone();
        tokio::spawn(async move { pool.acquire().await })
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        while entered.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    pool.close().await.unwrap();
    let error = opening.await.unwrap().err().expect("closed");
    assert!(matches!(error.kind, ErrorKind::Closed), "{error}");
    assert_eq!(dropped.load(Ordering::SeqCst), 1, "provider future dropped");
    assert_eq!(pool.in_use(), 0);
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}
