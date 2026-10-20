//! Controlled cross-feature openings: Entra with pools, configuration changes,
//! recovery, Key Vault keys and explicit no-attestation enclaves. These peers do
//! not authenticate against Azure; the vault is the official SDK over a fake transport.
#![cfg(feature = "tokio")]
#[cfg(feature = "azure-keyvault")]
#[path = "support/enclave.rs"]
mod enclave;
mod support;
#[cfg(feature = "azure-keyvault")]
#[path = "support/vault.rs"]
mod vault;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use support::Peer;
use tds_client::{
    Authentication, Batch, ConfigRead, ConfigService, Connection, ConnectionConfig,
    ConnectionServices, ErrorKind, Pool, PoolPolicy, ProtocolVersion, ReleaseOutcome,
    entra::{
        AccessToken, EntraLogin, ProviderError, TokenFuture, TokenProvider, TokenProviders,
        TokenRequest,
    },
    fedauth::Workflow,
    packet,
};
use tokio::net::{TcpListener, TcpStream};

/// Counts acquisitions and returns one artificial token; refuses the first `refuse`.
struct Provider {
    token: &'static str,
    refuse: usize,
    calls: AtomicUsize,
}
impl Provider {
    fn new(token: &'static str) -> Arc<Self> {
        Self::refusing(token, 0)
    }
    fn refusing(token: &'static str, refuse: usize) -> Arc<Self> {
        Arc::new(Self {
            token,
            refuse,
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
            if self.calls.fetch_add(1, Ordering::SeqCst) < self.refuse {
                return Err(ProviderError::refused());
            }
            Ok(AccessToken::new(self.token.into(), None))
        })
    }
}
struct Source(Mutex<ConnectionConfig>);
impl ConfigService for Source {
    fn read(&self) -> ConfigRead<'_> {
        Box::pin(async move { Ok(self.0.lock().unwrap().clone()) })
    }
}
fn login(source: &str, identity: &str, deferred: bool) -> Authentication {
    Authentication::Entra(if deferred {
        EntraLogin::deferred(source, identity, Workflow::Interactive)
    } else {
        EntraLogin::upfront(source, identity)
    })
}
/// Whether `bytes` contain `token` in its UTF-16LE wire form.
fn carries(bytes: &[u8], token: &str) -> bool {
    let wire: Vec<u8> = token.encode_utf16().flat_map(u16::to_le_bytes).collect();
    bytes.windows(wire.len()).any(|w| w == wire)
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
    token
}
const FEDAUTH_ACK: &[u8] = &[0xae, 2, 0, 0, 0, 0, 0xff];

/// Server side of one Entra LOGIN7: returns the peer, the LOGIN7 body and the
/// bytes that carry the token (LOGIN7 itself, or the deferred 0x08 message).
async fn entra(socket: TcpStream, deferred: bool) -> (Peer, Vec<u8>, Vec<u8>) {
    let (mut peer, login) = Peer::await_login(socket, false).await;
    if !deferred {
        return (peer, login.clone(), login);
    }
    peer.reply(&info()).await;
    let (kind, token) = peer.message().await;
    assert_eq!(kind, 0x08);
    (peer, login, token)
}
async fn entra_next(listener: &TcpListener, deferred: bool, token: &str, ack: &[u8]) -> Peer {
    let (socket, _) = listener.accept().await.unwrap();
    let (mut peer, _, carrier) = entra(socket, deferred).await;
    assert!(carries(&carrier, token), "expected {token}");
    peer.accept_login(0x74000004, false, ack).await;
    peer
}
/// Answer one batch and return its first packet's status (bit 8: reset).
async fn serve_batch(peer: &mut Peer) -> u8 {
    assert_eq!(peer.message().await.0, packet::BATCH);
    let status = peer.message_status;
    peer.reply(&support::done(0)).await;
    status
}
async fn query(connection: &Connection, sql: &str) {
    let mut channel = connection.serial_channel().await.unwrap();
    channel
        .exchange(Batch::new(sql))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    channel.close().await.unwrap();
}

#[tokio::test]
async fn entra_pool_requests_a_token_per_physical_login_not_per_lease() {
    for deferred in [false, true] {
        let (listener, mut options) = support::listener().await;
        let provider = Provider::new("token-a");
        options.authentication = login("a", "tenant/principal-v1", deferred);
        options.token_providers = TokenProviders::new().with("a", provider.clone());
        let server = tokio::spawn(async move {
            let mut first = entra_next(&listener, deferred, "token-a", FEDAUTH_ACK).await;
            assert_eq!(serve_batch(&mut first).await & 8, 0);
            // A returned lease is reused with a deferred reset and no new login.
            assert_eq!(serve_batch(&mut first).await & 8, 8);
            first.expect_eof().await; // A dropped lease discards its connection.
            let mut second = entra_next(&listener, deferred, "token-a", FEDAUTH_ACK).await;
            assert_eq!(serve_batch(&mut second).await & 8, 0);
            second.drain_to_eof().await;
        });
        let pool = Pool::new(options, 1).unwrap();
        let lease = pool.acquire().await.unwrap();
        query(&lease, "SELECT 1").await;
        assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Returned);
        let lease = pool.acquire().await.unwrap();
        query(&lease, "SELECT 2").await;
        assert_eq!(provider.calls(), 1);
        drop(lease);
        let lease = pool.acquire().await.unwrap();
        query(&lease, "SELECT 3").await;
        assert_eq!(provider.calls(), 2);
        assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Returned);
        pool.close().await.unwrap();
        server.await.unwrap();
    }
}

#[tokio::test]
async fn entra_identity_change_retires_returned_sessions_once_a_new_login_reads_it() {
    for deferred in [false, true] {
        for change_source in [false, true] {
            let (listener, mut options) = support::listener().await;
            let (a, b) = (Provider::new("token-a"), Provider::new("token-b"));
            options.authentication = login("a", "tenant/principal-v1", deferred);
            let source = Arc::new(Source(Mutex::new(ConnectionConfig::from_options(&options))));
            let mut services = ConnectionServices::new(options.roots);
            services.token_providers = TokenProviders::new()
                .with("a", a.clone())
                .with("b", b.clone());
            let later = if change_source { "token-b" } else { "token-a" };
            let server = tokio::spawn(async move {
                let mut old = entra_next(&listener, deferred, "token-a", FEDAUTH_ACK).await;
                serve_batch(&mut old).await;
                let mut new = entra_next(&listener, deferred, later, FEDAUTH_ACK).await;
                old.expect_eof().await; // Returned after the change: discarded.
                assert_eq!(serve_batch(&mut new).await & 8, 0);
                new.drain_to_eof().await;
            });
            let pool =
                Pool::from_config(source.clone(), 2, services, PoolPolicy::default()).unwrap();
            let old = pool.acquire().await.unwrap();
            query(&old, "SELECT 1").await;
            source.0.lock().unwrap().authentication = login(
                if change_source { "b" } else { "a" },
                "tenant/principal-v2",
                deferred,
            );
            let new = pool.acquire().await.unwrap();
            assert_eq!(old.release().await.unwrap(), ReleaseOutcome::Discarded);
            query(&new, "SELECT 2").await;
            assert_eq!(new.release().await.unwrap(), ReleaseOutcome::Returned);
            assert_eq!(
                (a.calls(), b.calls()),
                if change_source { (1, 1) } else { (2, 0) }
            );
            pool.close().await.unwrap();
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn entra_refusal_rereads_settings_once_and_only_a_changed_identity_reopens() {
    for deferred in [false, true] {
        for changed in [false, true] {
            let (listener, mut options) = support::listener().await;
            let provider = Provider::new("token-a");
            options.authentication = login("a", "tenant/principal-v1", deferred);
            let source = Arc::new(Source(Mutex::new(ConnectionConfig::from_options(&options))));
            let mut services = ConnectionServices::new(options.roots);
            services.token_providers = TokenProviders::new().with("a", provider.clone());
            let update = source.clone();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let (mut peer, _, carrier) = entra(socket, deferred).await;
                assert!(carries(&carrier, "token-a"));
                if changed {
                    update.0.lock().unwrap().authentication =
                        login("a", "tenant/principal-v2", deferred);
                }
                peer.reply(&rejected_login(18456)).await;
                peer.expect_eof().await;
                if changed {
                    entra_next(&listener, deferred, "token-a", FEDAUTH_ACK)
                        .await
                        .drain_to_eof()
                        .await;
                } else {
                    assert!(
                        tokio::time::timeout(Duration::from_millis(50), listener.accept())
                            .await
                            .is_err()
                    );
                }
            });
            let pool = Pool::from_config(source, 1, services, PoolPolicy::default()).unwrap();
            let result = pool.acquire().await;
            assert_eq!(provider.calls(), if changed { 2 } else { 1 });
            if changed {
                drop(result.unwrap());
            } else {
                assert!(result.is_err());
            }
            assert_eq!(pool.in_use(), 0);
            pool.close().await.unwrap();
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn entra_provider_refusal_in_a_pool_releases_capacity_for_the_next_opening() {
    for deferred in [false, true] {
        let (listener, mut options) = support::listener().await;
        let provider = Provider::refusing("token-a", 1);
        options.authentication = login("a", "tenant/principal-v1", deferred);
        options.token_providers = TokenProviders::new().with("a", provider.clone());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            if deferred {
                let (mut peer, _) = Peer::await_login(socket, false).await;
                peer.reply(&info()).await;
                peer.expect_eof().await;
            } else {
                // The upfront token is requested after TLS, before LOGIN7.
                Peer::secure_protocol(
                    socket,
                    false,
                    include_bytes!("fixtures/test-server.pem"),
                    ProtocolVersion::V8_0,
                )
                .await
                .expect_eof()
                .await;
            }
            let mut peer = entra_next(&listener, deferred, "token-a", FEDAUTH_ACK).await;
            serve_batch(&mut peer).await;
            peer.drain_to_eof().await;
        });
        let pool = Pool::new(options, 1).unwrap();
        let error = pool.acquire().await.err().unwrap();
        assert!(matches!(error.kind, ErrorKind::TokenProvider(_)));
        assert_eq!(pool.in_use(), 0);
        let lease = pool.acquire().await.unwrap();
        query(&lease, "SELECT 1").await;
        assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Returned);
        assert_eq!(provider.calls(), 2);
        pool.close().await.unwrap();
        server.await.unwrap();
    }
}

#[cfg(feature = "azure-keyvault")]
mod encrypted {
    use super::*;
    use crate::{enclave, vault};
    use tds_client::{
        EnclaveAttestation, IntegerSize, Param, SqlType, Value,
        encryption::{self, ColumnKey, KeySession, WrappedKey},
    };

    /// Collation ENVCHANGE, then FEATUREEXTACK: optional session recovery,
    /// federated authentication and Always Encrypted version two with VBS.
    fn acknowledgement(recovery: bool) -> Vec<u8> {
        let mut ack = vec![0xe3, 8, 0, 7, 5, 9, 4, 0xd0, 0, 0x34, 0, 0xae];
        if recovery {
            ack.extend([1, 0, 0, 0, 0]);
        }
        ack.extend([
            2, 0, 0, 0, 0, 4, 8, 0, 0, 0, 2, 3, b'V', 0, b'B', 0, b'S', 0, 0xff,
        ]);
        ack
    }
    /// LOGIN7 FeatureExt entries as (id, data).
    fn features(login: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let pointer = u16::from_le_bytes(login[56..58].try_into().unwrap()) as usize;
        let mut at = u32::from_le_bytes(login[pointer..pointer + 4].try_into().unwrap()) as usize;
        let mut found = Vec::new();
        while login[at] != 0xff {
            let length = u32::from_le_bytes(login[at + 1..at + 5].try_into().unwrap()) as usize;
            found.push((login[at], login[at + 5..at + 5 + length].to_vec()));
            at += 5 + length;
        }
        found
    }
    async fn entra_enclave_login(listener: &TcpListener, deferred: bool, recovery: bool) -> Peer {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, login, carrier) = entra(socket, deferred).await;
        assert!(carries(&carrier, "token-a"));
        let features = features(&login);
        assert!(features.iter().any(|(id, _)| *id == 2), "federated feature");
        assert!(features.contains(&(4, vec![2])), "enclave-capable AE");
        peer.accept_login(0x74000004, false, &acknowledgement(recovery))
            .await;
        peer
    }
    fn vault_root() -> [u8; 32] {
        vault::b(&vault::fixture(), "root").try_into().unwrap()
    }
    /// One description (with attestation parameters for a new session), then
    /// the call whose enclave package must authorize the vault-unwrapped key.
    async fn serve_enclave_statement(peer: &mut Peer, session: &mut Option<KeySession>) {
        let f = enclave::fixture();
        let (kind, body) = peer.message().await;
        assert_eq!(kind, packet::RPC);
        let describe = enclave::read_call(&body);
        assert_eq!(describe.parameters.len(), 3, "new enclave session");
        let Some(Value::Binary(parameters)) = describe.parameters[2].value.as_ref() else {
            panic!("attestation parameters")
        };
        *session = Some(enclave::peer_key(enclave::root_from_parameters(parameters)));
        peer.reply(&enclave::bytes(&f, "description_vault")).await;
        let (kind, body) = peer.message().await;
        assert_eq!(kind, packet::RPC);
        let call = enclave::read_call(&body);
        assert_eq!(&call.enclave_package[..8], b"session1");
        let key = ColumnKey {
            database_id: 0,
            key_id: 0,
            version: 0,
            metadata_version: [0; 8],
            values: vec![WrappedKey {
                provider: "peer".into(),
                path: "".into(),
                algorithm: "RSA_OAEP".into(),
                encrypted: vec![1],
            }],
        };
        let guard = session.as_ref().unwrap().exchange().unwrap();
        let plain = guard
            .decrypt(&key, &call.enclave_package[8..])
            .await
            .unwrap();
        assert_eq!(&plain.as_bytes()[70..], vault_root());
        let Some(Value::Encrypted(cipher)) = call.parameters[2].value.as_ref() else {
            panic!("encrypted parameter")
        };
        let cek = enclave::peer_key(vault_root());
        let guard = cek.exchange().unwrap();
        assert_eq!(
            guard.decrypt(&key, &cipher.0).await.unwrap().as_bytes(),
            &7_i64.to_le_bytes()
        );
        peer.reply(&support::done(0)).await;
    }
    async fn run_statement(encrypted: &encryption::EncryptedConnection<'_>) {
        let f = enclave::fixture();
        let mut channel = encrypted.serial_channel().await.unwrap();
        channel
            .execute(
                f["statement"].as_str().unwrap(),
                "@v int",
                vec![Param::new(
                    "@v",
                    SqlType::Integer {
                        size: IntegerSize::Int,
                    },
                    Some(Value::Integer(7)),
                )],
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        channel.close().await.unwrap();
    }
    async fn wrap<'a>(
        connection: &'a Connection,
        vault: &Arc<vault::Vault>,
    ) -> encryption::EncryptedConnection<'a> {
        let policies = encryption::Policies {
            master: encryption::Policy::Time(Duration::from_secs(60)),
            column: encryption::Policy::Time(Duration::from_secs(60)),
            ..Default::default()
        };
        connection
            .encrypted_with_providers(
                vec![Arc::new(vault::store(vault.clone()))],
                policies,
                Duration::from_secs(5),
            )
            .await
            .unwrap()
    }
    fn unwraps(vault: &vault::Vault) -> usize {
        vault
            .operations()
            .iter()
            .filter(|o| *o == "unwrapkey")
            .count()
    }

    #[tokio::test]
    async fn entra_login_negotiates_enclaves_and_key_vault_keys_reach_the_package() {
        for deferred in [false, true] {
            let (listener, mut options) = support::listener().await;
            let provider = Provider::new("token-a");
            options.authentication = login("a", "tenant/principal-v1", deferred);
            options.token_providers = TokenProviders::new().with("a", provider.clone());
            options.enclave_attestation = Some(EnclaveAttestation::None);
            let server = tokio::spawn(async move {
                let mut peer = entra_enclave_login(&listener, deferred, false).await;
                serve_batch(&mut peer).await; // Wrapper bootstrap.
                serve_enclave_statement(&mut peer, &mut None).await;
                peer.expect_eof().await;
            });
            let connection = Connection::connect(options).await.unwrap();
            let vault = Arc::new(vault::Vault::default());
            let encrypted = wrap(&connection, &vault).await;
            run_statement(&encrypted).await;
            let statistics = encrypted.statistics();
            assert_eq!(statistics.unwraps, 1);
            assert_eq!(statistics.metadata_verifications, 1);
            assert_eq!(statistics.authorized_keys, 1);
            assert_eq!(statistics.enclave_packages, 1);
            // Enclave permission and the envelope are verified before any unwrap.
            assert_eq!(vault.operations(), ["verify", "verify", "unwrapkey"]);
            assert_eq!(provider.calls(), 1);
            encrypted.close().await;
            connection.close().await.unwrap();
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn entra_recovery_gets_a_new_token_and_a_new_wrapper_unwraps_vault_keys_again() {
        for deferred in [false, true] {
            let (listener, mut options) = support::listener().await;
            let provider = Provider::new("token-a");
            options.authentication = login("a", "tenant/principal-v1", deferred);
            options.token_providers = TokenProviders::new().with("a", provider.clone());
            options.enclave_attestation = Some(EnclaveAttestation::None);
            let (cut, cutting) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut peer = entra_enclave_login(&listener, deferred, true).await;
                serve_batch(&mut peer).await;
                serve_enclave_statement(&mut peer, &mut None).await;
                cutting.await.unwrap();
                drop(peer);
                let mut peer = entra_enclave_login(&listener, deferred, true).await;
                serve_batch(&mut peer).await;
                serve_enclave_statement(&mut peer, &mut None).await;
                peer.expect_eof().await;
            });
            let connection = Connection::connect(options).await.unwrap();
            let vault = Arc::new(vault::Vault::default());
            let encrypted = wrap(&connection, &vault).await;
            run_statement(&encrypted).await;
            encrypted.close().await;
            cut.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while !connection.is_closed() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            connection.recover().await.unwrap();
            let encrypted = wrap(&connection, &vault).await;
            run_statement(&encrypted).await;
            assert_eq!(connection.recoveries(), 1);
            assert_eq!(provider.calls(), 2);
            assert_eq!(unwraps(&vault), 2);
            encrypted.close().await;
            connection.close().await.unwrap();
            server.await.unwrap();
        }
    }
}
