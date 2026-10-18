#![cfg(feature = "encryption")]
mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tds_client::{
    Batch, Connection, Pool, ProtocolVersion, ReleaseOutcome, Transaction, Value,
    encryption::{ColumnKey, Error, KeySession, LocalKeyStore, Policies, Policy, WrappedKey},
};
static DIRECTORY: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    path: PathBuf,
    key: ColumnKey,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tds-key-live-{}-{}",
            std::process::id(),
            DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(
            path.join("master.pem"),
            include_bytes!("fixtures/encryption/master.pem"),
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/encryption/python.json")).unwrap();
        let key = ColumnKey {
            database_id: 6,
            key_id: 1,
            version: 1,
            metadata_version: [0x11; 8],
            values: vec![WrappedKey {
                provider: "TDS_TEST".into(),
                path: "master.pem".into(),
                algorithm: "RSA_OAEP".into(),
                encrypted: STANDARD
                    .decode(json["wrapped"][0].as_str().unwrap())
                    .unwrap(),
            }],
        };
        Self { path, key }
    }
    fn providers(&self) -> Vec<LocalKeyStore> {
        vec![LocalKeyStore::new("TDS_TEST", &self.path).unwrap()]
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[tokio::test]
async fn kp28_controlled_physical_recovery_revokes_old_key_authority() {
    let f = Fixture::new();
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let (listener, mut options) = support::listener().await;
            options.version = version;
            options.mars = mars;
            let login_version = 0x74000004;
            let (cut, cutting) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let (mut peer, _) = support::Peer::await_login_protocol(
                    socket,
                    mars,
                    include_bytes!("fixtures/test-server.pem"),
                    version,
                )
                .await;
                peer.accept_login(login_version, mars, &[0xae, 1, 0, 0, 0, 0, 255])
                    .await;
                cutting.await.unwrap();
                drop(peer);
                let (socket, _) = listener.accept().await.unwrap();
                let (mut peer, _) = support::Peer::await_login_protocol(
                    socket,
                    mars,
                    include_bytes!("fixtures/test-server.pem"),
                    version,
                )
                .await;
                peer.accept_login(login_version, mars, &[0xae, 1, 0, 0, 0, 0, 255])
                    .await;
                peer.drain_to_eof().await;
            });
            let connection = Connection::connect(options).await.unwrap();
            let p = Policies {
                master: Policy::Time(Duration::from_secs(60)),
                column: Policy::Time(Duration::from_secs(60)),
                ..Policies::default()
            };
            let old = connection.key_session(f.providers(), p).await.unwrap();
            let old_exchange = old.exchange().unwrap();
            old_exchange
                .encrypt(&f.key, b"old epoch", false)
                .await
                .unwrap();
            cut.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while !connection.is_closed() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(old.statistics().closed);
            assert_eq!(old.statistics().live_columns, 0);
            connection.recover().await.unwrap();
            assert_eq!(connection.recoveries(), 1);
            assert_eq!(
                old_exchange
                    .encrypt(&f.key, b"retired", false)
                    .await
                    .unwrap_err(),
                Error::Closed
            );
            let new = connection.key_session(f.providers(), p).await.unwrap();
            new.exchange()
                .unwrap()
                .encrypt(&f.key, b"new epoch", false)
                .await
                .unwrap();
            assert_eq!(
                (new.statistics().master_loads, new.statistics().unwraps),
                (1, 1)
            );
            println!(
                "KP_CONTROLLED {version:?} mars={mars} old_closed={} new_loads={} recoveries={}",
                old.statistics().closed,
                new.statistics().master_loads,
                connection.recoveries()
            );
            connection.close().await.unwrap();
            assert!(new.statistics().closed);
            server.await.unwrap();
        }
    }
}
async fn sql(channel: &mut tds_client::SerialChannel, statement: &str) {
    channel
        .exchange(Batch::new(statement))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
}
async fn tx(channel: &mut tds_client::SerialChannel, transaction: Transaction) {
    channel
        .exchange(transaction)
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
}
async fn echo(channel: &mut tds_client::SerialChannel, keys: &KeySession, key: &ColumnKey) {
    let exchange = keys.exchange().unwrap();
    let plaintext = b"manually encrypted synthetic value";
    let ciphertext = exchange.encrypt(key, plaintext, false).await.unwrap();
    let hex: String = ciphertext.iter().map(|b| format!("{b:02x}")).collect();
    let response = channel
        .exchange(Batch::new(format!("SELECT 0x{hex} AS encrypted_payload")))
        .await
        .unwrap()
        .fetch()
        .await
        .unwrap();
    let Some(Value::Binary(returned)) = &response.result_sets()[0].rows().unwrap()[0][0] else {
        panic!("expected binary SQL echo");
    };
    assert_eq!(returned, &ciphertext);
    assert!(exchange.decrypt(key, returned).await.unwrap().as_bytes() == plaintext);
}

#[tokio::test]
#[ignore = "requires local Docker SQL Server and test CA"]
async fn kp26_live_transaction_boundaries_and_manual_encrypted_echo() {
    let f = Fixture::new();
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            let keys = connection
                .key_session(f.providers(), Policies::default())
                .await
                .unwrap();
            assert_eq!(
                connection
                    .key_session(f.providers(), Policies::default())
                    .await
                    .unwrap_err(),
                Error::Busy
            );
            tx(&mut channel, Transaction::Begin(Default::default())).await;
            echo(&mut channel, &keys, &f.key).await;
            echo(&mut channel, &keys, &f.key).await;
            sql(&mut channel,"SAVE TRANSACTION kp_save; ROLLBACK TRANSACTION kp_save; BEGIN TRANSACTION; COMMIT TRANSACTION").await;
            echo(&mut channel, &keys, &f.key).await;
            assert_eq!(
                (keys.statistics().master_loads, keys.statistics().unwraps),
                (1, 1)
            );
            tx(&mut channel, Transaction::Commit(Default::default())).await;
            assert_eq!(
                (
                    keys.statistics().live_masters,
                    keys.statistics().live_columns
                ),
                (0, 0)
            );
            tx(&mut channel, Transaction::Begin(Default::default())).await;
            echo(&mut channel, &keys, &f.key).await;
            tx(&mut channel, Transaction::Rollback(Default::default())).await;
            assert_eq!(
                (keys.statistics().unwraps, keys.statistics().live_columns),
                (2, 0)
            );
            println!(
                "KP_LIVE {version:?} mars={mars} transaction {:?}",
                keys.statistics()
            );
            drop(keys);
            // Attaching inside an already active transaction uses the server's
            // current descriptor, atomically with lifecycle registration.
            tx(&mut channel, Transaction::Begin(Default::default())).await;
            let keys = connection
                .key_session(f.providers(), Policies::default())
                .await
                .unwrap();
            echo(&mut channel, &keys, &f.key).await;
            echo(&mut channel, &keys, &f.key).await;
            assert_eq!(keys.statistics().unwraps, 1);
            tx(&mut channel, Transaction::Commit(Default::default())).await;
            assert_eq!(keys.statistics().live_columns, 0);
            drop(keys);
            let p = Policies {
                master: Policy::Time(Duration::from_secs(60)),
                column: Policy::Time(Duration::from_secs(60)),
                ..Policies::default()
            };
            let keys = connection.key_session(f.providers(), p).await.unwrap();
            tx(&mut channel, Transaction::Begin(Default::default())).await;
            echo(&mut channel, &keys, &f.key).await;
            tx(&mut channel, Transaction::Commit(Default::default())).await;
            echo(&mut channel, &keys, &f.key).await;
            tx(&mut channel, Transaction::Begin(Default::default())).await;
            echo(&mut channel, &keys, &f.key).await;
            tx(&mut channel, Transaction::Rollback(Default::default())).await;
            assert_eq!(
                (keys.statistics().master_loads, keys.statistics().unwraps),
                (1, 1)
            );
            println!(
                "KP_LIVE {version:?} mars={mars} timed {:?}",
                keys.statistics()
            );
            let old = keys.exchange().unwrap();
            sql(&mut channel, "USE master").await;
            assert_eq!(
                (
                    keys.statistics().live_masters,
                    keys.statistics().live_columns
                ),
                (0, 0)
            );
            assert_eq!(
                old.encrypt(&f.key, b"old context", false)
                    .await
                    .unwrap_err(),
                Error::Expired
            );
            drop(old);
            echo(&mut channel, &keys, &f.key).await;
            connection.close().await.unwrap();
            assert!(keys.statistics().closed);
            assert_eq!(keys.statistics().live_columns, 0);
        }
    }
}

#[tokio::test]
#[ignore = "requires local Docker SQL Server and test CA"]
async fn kp26_live_pool_return_and_next_borrower_reset() {
    let f = Fixture::new();
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let pool = Pool::new(options, 1).unwrap();
            let lease = pool.acquire().await.unwrap();
            let spid = lease.session().await.unwrap().session_id;
            let p = Policies {
                master: Policy::Time(Duration::from_secs(60)),
                column: Policy::Time(Duration::from_secs(60)),
                ..Policies::default()
            };
            let old = lease.key_session(f.providers(), p).await.unwrap();
            let mut channel = lease.serial_channel().await.unwrap();
            echo(&mut channel, &old, &f.key).await;
            // The next borrower must also tolerate restoration of a different
            // database context by its deferred RESET acknowledgement.
            sql(&mut channel, "USE master").await;
            channel.close().await.unwrap();
            assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Returned);
            assert!(old.statistics().closed);
            assert_eq!(
                (old.statistics().live_masters, old.statistics().live_columns),
                (0, 0)
            );
            let lease = pool.acquire().await.unwrap();
            assert_eq!(lease.session().await.unwrap().session_id, spid);
            let new = lease.key_session(f.providers(), p).await.unwrap();
            let mut channel = lease.serial_channel().await.unwrap();
            echo(&mut channel, &new, &f.key).await;
            // The first request carries deferred RESETCONNECTION. Its ACK clears
            // pre-ACK entries; decrypt reloads without killing the new lease.
            assert_eq!(new.statistics().master_loads, 2);
            println!(
                "KP_LIVE {version:?} mars={mars} pooled {:?}",
                new.statistics()
            );
            channel.close().await.unwrap();
            lease.release().await.unwrap();
            assert!(new.statistics().closed);
            pool.close().await.unwrap();
        }
    }
}
