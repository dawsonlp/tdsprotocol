use super::*;
use crate::encryption::WrappedKey;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    path::PathBuf,
    sync::{
        Condvar,
        atomic::{AtomicBool, AtomicU64},
    },
};

static DIRECTORY: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    path: PathBuf,
    json: serde_json::Value,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tds-key-policy-{}-{}",
            std::process::id(),
            DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(
            path.join("master.pem"),
            include_bytes!("../../tests/fixtures/encryption/master.pem"),
        )
        .unwrap();
        Self {
            path,
            json: serde_json::from_str(include_str!("../../tests/fixtures/encryption/python.json"))
                .unwrap(),
        }
    }
    fn key(&self, index: usize) -> ColumnKey {
        ColumnKey {
            database_id: 6,
            key_id: 1,
            version: 1,
            metadata_version: [0x11; 8],
            values: vec![WrappedKey {
                provider: "TDS_TEST".into(),
                path: "master.pem".into(),
                algorithm: "RSA_OAEP".into(),
                encrypted: bytes(&self.json["wrapped"][index]),
            }],
        }
    }
    fn session(&self, policies: Policies) -> KeySession {
        KeySession::new(
            vec![LocalKeyStore::new("TDS_TEST", &self.path).unwrap()],
            policies,
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
fn bytes(value: &serde_json::Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn policies(master: Policy, column: Policy) -> Policies {
    Policies {
        master,
        column,
        ..Policies::default()
    }
}
fn report(id: &str, s: Statistics) {
    println!("KP_EVIDENCE {id} {s:?}");
}
async fn roundtrip(exchange: &KeyExchange, key: &ColumnKey) {
    let ciphertext = exchange
        .encrypt(key, b"synthetic sensitive input", false)
        .await
        .unwrap();
    let plaintext = exchange.decrypt(key, &ciphertext).await.unwrap();
    assert!(plaintext.as_bytes() == b"synthetic sensitive input");
}
async fn twenty(policies: Policies, transaction: bool) -> Statistics {
    let fixture = Fixture::new();
    let session = fixture.session(policies);
    let key = fixture.key(0);
    if transaction {
        session.transaction_begin(77).unwrap();
    }
    for _ in 0..20 {
        let exchange = session.exchange().unwrap();
        roundtrip(&exchange, &key).await;
    }
    session.statistics()
}

#[tokio::test]
async fn kp01_default_reuses_once_for_twenty_transaction_exchanges() {
    let s = twenty(Policies::default(), true).await;
    report("KP01", s);
    assert_eq!(
        (s.master_loads, s.unwraps, s.live_masters, s.live_columns),
        (1, 1, 1, 1)
    );
}
#[tokio::test]
async fn kp02_exchange_scope_loads_and_erases_twenty_times() {
    let s = twenty(policies(Policy::Exchange, Policy::Exchange), true).await;
    report("KP02", s);
    assert_eq!(
        (s.master_loads, s.unwraps, s.live_masters, s.live_columns),
        (20, 20, 0, 0)
    );
}
#[tokio::test]
async fn kp03_transaction_master_exchange_columns() {
    let s = twenty(policies(Policy::Transaction, Policy::Exchange), true).await;
    report("KP03", s);
    assert_eq!(
        (s.master_loads, s.unwraps, s.live_masters, s.live_columns),
        (1, 20, 1, 0)
    );
}
#[tokio::test]
async fn kp04_exchange_master_transaction_columns() {
    let s = twenty(policies(Policy::Exchange, Policy::Transaction), true).await;
    report("KP04", s);
    assert_eq!(
        (s.master_loads, s.unwraps, s.live_masters, s.live_columns),
        (1, 1, 0, 1)
    );
}
#[tokio::test]
async fn kp05_autocommit_falls_back_to_exchange() {
    let s = twenty(Policies::default(), false).await;
    report("KP05", s);
    assert_eq!(
        (s.master_loads, s.unwraps, s.live_masters, s.live_columns),
        (20, 20, 0, 0)
    );
}
#[tokio::test]
async fn kp06_unchanged_outer_transaction_retains_keys_until_end() {
    let f = Fixture::new();
    let s = f.session(Policies::default());
    let key = f.key(0);
    s.transaction_begin(1).unwrap();
    roundtrip(&s.exchange().unwrap(), &key).await;
    // Savepoint rollback and inner commit announce no outer end. The adapter
    // must leave this state alone; this test does not claim SQL adapter evidence.
    roundtrip(&s.exchange().unwrap(), &key).await;
    assert_eq!(s.statistics().unwraps, 1);
    s.transaction_end();
    assert_eq!(
        (s.statistics().live_masters, s.statistics().live_columns),
        (0, 0)
    );
}
#[tokio::test]
async fn kp07_reused_descriptor_and_old_stream_cannot_join_new_transaction() {
    let f = Fixture::new();
    let s = f.session(Policies::default());
    let key = f.key(0);
    s.transaction_begin(17).unwrap();
    let old = s.exchange().unwrap();
    roundtrip(&old, &key).await;
    s.transaction_end();
    s.transaction_begin(17).unwrap();
    roundtrip(&s.exchange().unwrap(), &key).await;
    roundtrip(&old, &key).await; // old reader loads exchange-local material
    assert_eq!(
        (
            s.statistics().master_loads,
            s.statistics().unwraps,
            s.statistics().live_columns
        ),
        (3, 3, 2)
    );
    drop(old);
    assert_eq!(s.statistics().live_columns, 1);
    // Chained begin always rotates generation, even without an explicit end call.
    s.transaction_begin(17).unwrap();
    roundtrip(&s.exchange().unwrap(), &key).await;
    assert_eq!(s.statistics().unwraps, 4);
}
#[tokio::test]
async fn kp08_time_reuses_across_transactions_and_autocommit() {
    let s = twenty(
        policies(
            Policy::Time(Duration::from_secs(60)),
            Policy::Time(Duration::from_secs(60)),
        ),
        false,
    )
    .await;
    assert_eq!((s.master_loads, s.unwraps), (1, 1));
    let f = Fixture::new();
    let s = f.session(policies(
        Policy::Time(Duration::from_secs(60)),
        Policy::Time(Duration::from_secs(60)),
    ));
    let key = f.key(0);
    for descriptor in [1, 2, 3] {
        s.transaction_begin(descriptor).unwrap();
        roundtrip(&s.exchange().unwrap(), &key).await;
        s.transaction_end();
    }
    roundtrip(&s.exchange().unwrap(), &key).await;
    assert_eq!(
        (s.statistics().master_loads, s.statistics().unwraps),
        (1, 1)
    );
}
#[tokio::test(start_paused = true)]
async fn kp09_exact_deadline_is_not_refreshed_by_hit() {
    let f = Fixture::new();
    let s = f.session(policies(
        Policy::Time(Duration::from_secs(60)),
        Policy::Time(Duration::from_secs(60)),
    ));
    let key = f.key(0);
    roundtrip(&s.exchange().unwrap(), &key).await;
    tokio::time::advance(Duration::from_secs(59)).await;
    roundtrip(&s.exchange().unwrap(), &key).await;
    assert_eq!(s.statistics().unwraps, 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    roundtrip(&s.exchange().unwrap(), &key).await;
    assert_eq!(
        (s.statistics().master_loads, s.statistics().unwraps),
        (2, 2)
    );
    report("KP09", s.statistics());
}
#[tokio::test(start_paused = true)]
async fn kp10_idle_timer_erases_without_lookup_or_statistics_side_effect() {
    let f = Fixture::new();
    let s = f.session(policies(
        Policy::Time(Duration::from_secs(10)),
        Policy::Time(Duration::from_secs(10)),
    ));
    let key = f.key(0);
    roundtrip(&s.exchange().unwrap(), &key).await;
    assert_eq!(s.statistics().live_columns, 1);
    tokio::task::yield_now().await; // timer has observed insertion notification
    tokio::time::advance(Duration::from_secs(10)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        (
            s.statistics().live_masters,
            s.statistics().live_columns,
            s.statistics().expirations
        ),
        (0, 0, 2)
    );
    report("KP10", s.statistics());
}
#[tokio::test(start_paused = true)]
async fn kp11_long_transaction_and_live_stream_reload_after_expiry() {
    let f = Fixture::new();
    let s = f.session(policies(
        Policy::Time(Duration::from_secs(10)),
        Policy::Time(Duration::from_secs(10)),
    ));
    let key = f.key(0);
    s.transaction_begin(1).unwrap();
    let exchange = s.exchange().unwrap();
    let ciphertext = exchange
        .encrypt(&key, b"long stream value", false)
        .await
        .unwrap();
    tokio::time::advance(Duration::from_secs(11)).await;
    let value = exchange.decrypt(&key, &ciphertext).await.unwrap();
    assert!(value.as_bytes() == b"long stream value");
    assert!(s.inner.bank().transaction.is_some());
    assert_eq!(s.statistics().unwraps, 2);
}
#[tokio::test(start_paused = true)]
async fn kp12_master_and_column_clocks_are_independent() {
    let f = Fixture::new();
    let s = f.session(policies(
        Policy::Time(Duration::from_secs(5)),
        Policy::Time(Duration::from_secs(10)),
    ));
    let key = f.key(0);
    roundtrip(&s.exchange().unwrap(), &key).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        (s.statistics().live_masters, s.statistics().live_columns),
        (0, 1)
    );
    roundtrip(&s.exchange().unwrap(), &key).await;
    assert_eq!(s.statistics().master_loads, 1);
    // Another CEK forces a fresh master at t=6; this must not restart the
    // original column key's deadline at t=10.
    roundtrip(&s.exchange().unwrap(), &f.key(1)).await;
    assert_eq!(s.statistics().master_loads, 2);
    tokio::time::advance(Duration::from_secs(4)).await;
    roundtrip(&s.exchange().unwrap(), &key).await;
    assert_eq!(
        (s.statistics().master_loads, s.statistics().unwraps),
        (2, 3)
    );
    // Reverse lifetimes: columns expire first; unwrap reuses the master.
    let s = f.session(policies(
        Policy::Time(Duration::from_secs(10)),
        Policy::Time(Duration::from_secs(5)),
    ));
    roundtrip(&s.exchange().unwrap(), &key).await;
    tokio::time::advance(Duration::from_secs(6)).await;
    roundtrip(&s.exchange().unwrap(), &key).await;
    assert_eq!(
        (s.statistics().master_loads, s.statistics().unwraps),
        (1, 2)
    );
}
#[tokio::test]
async fn kp13_revocation_causes_and_new_borrower_isolation() {
    let f = Fixture::new();
    let key = f.key(0);
    let p = policies(
        Policy::Time(Duration::from_secs(60)),
        Policy::Time(Duration::from_secs(60)),
    );
    for reason in [
        Revocation::Reset,
        Revocation::Recovery,
        Revocation::PoolReturn,
        Revocation::Close,
    ] {
        let s = f.session(p);
        let exchange = s.exchange().unwrap();
        roundtrip(&exchange, &key).await;
        s.revoke(reason);
        assert_eq!(
            (s.statistics().live_masters, s.statistics().live_columns),
            (0, 0)
        );
        assert_eq!(
            exchange.encrypt(&key, b"x", false).await.unwrap_err(),
            Error::Closed
        );
        assert!(s.exchange().is_err());
        let next = f.session(p);
        roundtrip(&next.exchange().unwrap(), &key).await;
        assert_eq!(next.statistics().master_loads, 1);
    }
    let s = f.session(p);
    let old = s.exchange().unwrap();
    roundtrip(&old, &key).await;
    s.invalidate();
    assert_eq!(
        old.encrypt(&key, b"x", false).await.unwrap_err(),
        Error::Expired
    );
    roundtrip(&s.exchange().unwrap(), &key).await;
    assert_eq!(s.statistics().unwraps, 2);
}
#[tokio::test]
async fn kp14_complete_wrapped_identity_and_provider_binding_prevent_collision() {
    let f = Fixture::new();
    let p = Policies::default();
    let s = KeySession::new(
        vec![
            LocalKeyStore::new("TDS_TEST", &f.path).unwrap(),
            LocalKeyStore::new("OTHER", &f.path).unwrap(),
            LocalKeyStore::new("κλειδί", &f.path).unwrap(),
        ],
        p,
    )
    .unwrap();
    s.transaction_begin(1).unwrap();
    let e = s.exchange().unwrap();
    let a = f.key(0);
    let b = f.key(1); // intentionally identical numeric IDs
    let ca = e.encrypt(&a, b"same value", false).await.unwrap();
    let cb = e.encrypt(&b, b"same value", false).await.unwrap();
    assert_ne!(ca, cb);
    assert!(e.decrypt(&b, &cb).await.unwrap().as_bytes() == b"same value");
    let mut c = a.clone();
    c.values[0].provider = "OTHER".into();
    assert_eq!(e.encrypt(&c, b"same value", false).await.unwrap(), ca);
    c.values[0].provider = "κλειδί".into();
    assert_eq!(e.encrypt(&c, b"same value", false).await.unwrap(), ca);
    assert_eq!(
        (
            s.statistics().master_loads,
            s.statistics().unwraps,
            s.statistics().live_columns
        ),
        (3, 4, 4)
    );
}
#[tokio::test]
async fn kp15_eviction_reloads_without_losing_correctness() {
    let f = Fixture::new();
    let s = f.session(Policies {
        column_capacity: 1,
        ..Policies::default()
    });
    s.transaction_begin(1).unwrap();
    let e = s.exchange().unwrap();
    let a = e.encrypt(&f.key(0), b"same value", false).await.unwrap();
    roundtrip(&e, &f.key(1)).await;
    assert_eq!(e.encrypt(&f.key(0), b"same value", false).await.unwrap(), a);
    assert_eq!(
        (
            s.statistics().master_loads,
            s.statistics().unwraps,
            s.statistics().evictions,
            s.statistics().live_columns
        ),
        (1, 3, 2, 1)
    );
}

pub(super) struct LoadGate {
    entered: AtomicBool,
    started: Notify,
    released: Mutex<bool>,
    changed: Condvar,
}
impl LoadGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicBool::new(false),
            started: Notify::new(),
            released: Mutex::new(false),
            changed: Condvar::new(),
        })
    }
    pub(super) fn block(&self) {
        self.entered.store(true, Ordering::Release);
        self.started.notify_one();
        let released = self.released.lock().unwrap();
        // A failing test cannot hang Tokio runtime shutdown indefinitely.
        drop(
            self.changed
                .wait_timeout_while(released, Duration::from_secs(5), |r| !*r)
                .unwrap(),
        );
    }
    async fn entered(&self) {
        if !self.entered.load(Ordering::Acquire) {
            self.started.notified().await;
        }
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}
fn gate(s: &KeySession) -> Arc<LoadGate> {
    let gate = LoadGate::new();
    *s.inner.load_gate.lock().unwrap() = Some(gate.clone());
    gate
}
async fn drained(inner: &Inner) {
    loop {
        let changed = inner.completed.notified();
        if inner.pending.load(Ordering::Acquire) == 0 {
            break;
        }
        changed.await;
    }
}

#[tokio::test]
async fn kp16_concurrent_first_loads_are_coalesced() {
    let f = Fixture::new();
    let s = f.session(Policies::default());
    s.transaction_begin(1).unwrap();
    let load = gate(&s);
    let key = f.key(0);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let e = s.exchange().unwrap();
        let key = key.clone();
        tasks.push(tokio::spawn(async move {
            e.encrypt(&key, b"concurrent", false).await.unwrap()
        }));
    }
    load.entered().await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    load.release();
    let mut outputs = Vec::new();
    for task in tasks {
        outputs.push(task.await.unwrap());
    }
    assert!(outputs.iter().all(|o| *o == outputs[0]));
    assert_eq!(
        (
            s.statistics().master_load_attempts,
            s.statistics().master_loads,
            s.statistics().unwraps
        ),
        (1, 1, 1)
    );
    assert!(s.statistics().coalesced > 0);
    report("KP16", s.statistics());
}
#[tokio::test]
async fn kp17_canceled_request_cannot_insert_a_late_result() {
    let f = Fixture::new();
    let s = f.session(Policies::default());
    s.transaction_begin(1).unwrap();
    let load = gate(&s);
    let e = s.exchange().unwrap();
    let key = f.key(0);
    let task = tokio::spawn(async move { e.encrypt(&key, b"canceled", false).await });
    load.entered().await;
    task.abort();
    let _ = task.await;
    load.release();
    drained(&s.inner).await;
    assert_eq!(
        (
            s.statistics().live_masters,
            s.statistics().live_columns,
            s.statistics().discarded_loads
        ),
        (0, 0, 1)
    );
    report("KP17", s.statistics());
}
#[tokio::test]
async fn kp18_revoked_transaction_or_session_rejects_late_provider_result() {
    for revoke_session in [false, true] {
        let f = Fixture::new();
        let s = f.session(Policies::default());
        s.transaction_begin(1).unwrap();
        let load = gate(&s);
        let e = s.exchange().unwrap();
        let key = f.key(0);
        let task = tokio::spawn(async move { e.encrypt(&key, b"stale", false).await });
        load.entered().await;
        if revoke_session {
            s.revoke(Revocation::Recovery);
        } else {
            s.transaction_end();
            s.transaction_begin(1).unwrap();
        }
        load.release();
        assert!(task.await.unwrap().is_err());
        drained(&s.inner).await;
        assert_eq!(
            (
                s.statistics().live_masters,
                s.statistics().live_columns,
                s.statistics().discarded_loads
            ),
            (0, 0, 1)
        );
        if !revoke_session {
            roundtrip(&s.exchange().unwrap(), &f.key(0)).await;
            assert_eq!(s.statistics().unwraps, 1);
        }
    }
}
#[tokio::test]
async fn kp19_provider_errors_and_replacement_never_reuse_wrong_keys() {
    let f = Fixture::new();
    let s = f.session(Policies::default());
    s.transaction_begin(1).unwrap();
    let key = f.key(0);
    let mut missing = key.clone();
    missing.values[0].path = "missing.pem".into();
    assert_eq!(
        s.exchange()
            .unwrap()
            .encrypt(&missing, b"x", false)
            .await
            .unwrap_err(),
        Error::KeyUnavailable
    );
    let mut bad = key.clone();
    bad.values[0].encrypted[8] ^= 1;
    assert_eq!(
        s.exchange()
            .unwrap()
            .encrypt(&bad, b"x", false)
            .await
            .unwrap_err(),
        Error::Authentication
    );
    assert_eq!(
        (s.statistics().live_masters, s.statistics().live_columns),
        (0, 0)
    );
    std::fs::write(f.path.join("master.pem"), b"not a private key").unwrap();
    assert_eq!(
        s.exchange()
            .unwrap()
            .encrypt(&key, b"x", false)
            .await
            .unwrap_err(),
        Error::InvalidMasterKey
    );
    std::fs::write(
        f.path.join("master.pem"),
        include_bytes!("../../tests/fixtures/encryption/master.pem"),
    )
    .unwrap();
    roundtrip(&s.exchange().unwrap(), &key).await;
    std::fs::remove_file(f.path.join("master.pem")).unwrap();
    roundtrip(&s.exchange().unwrap(), &key).await; // retained handles remain valid
    s.invalidate();
    assert_eq!(
        s.exchange()
            .unwrap()
            .encrypt(&key, b"x", false)
            .await
            .unwrap_err(),
        Error::KeyUnavailable
    );
}
#[tokio::test(start_paused = true)]
async fn kp20_invalid_duration_and_expiry_during_acquisition() {
    let f = Fixture::new();
    for duration in [Duration::ZERO, Duration::MAX] {
        assert!(
            KeySession::new(
                vec![LocalKeyStore::new("TDS_TEST", &f.path).unwrap()],
                policies(Policy::Time(duration), Policy::Transaction)
            )
            .is_err()
        );
    }
    let s = f.session(policies(
        Policy::Time(Duration::from_secs(5)),
        Policy::Time(Duration::from_secs(5)),
    ));
    let load = gate(&s);
    let e = s.exchange().unwrap();
    let key = f.key(0);
    let task = tokio::spawn(async move { e.encrypt(&key, b"too late", false).await });
    load.entered().await;
    tokio::time::advance(Duration::from_secs(6)).await;
    load.release();
    assert_eq!(task.await.unwrap().unwrap_err(), Error::AcquisitionExpired);
    assert_eq!(
        (
            s.statistics().live_masters,
            s.statistics().live_columns,
            s.statistics().master_load_attempts
        ),
        (0, 0, 1)
    );
}
#[tokio::test]
async fn kp21_python_cipher_fixtures_and_failures() {
    let f = Fixture::new();
    let s = f.session(Policies::default());
    s.transaction_begin(1).unwrap();
    let e = s.exchange().unwrap();
    let key = f.key(0);
    for case in f.json["cases"].as_array().unwrap() {
        let plain = bytes(&case["plaintext"]);
        let expected = bytes(&case["deterministic"]);
        let random = bytes(&case["randomized"]);
        assert_eq!(e.encrypt(&key, &plain, false).await.unwrap(), expected);
        assert!(e.decrypt(&key, &expected).await.unwrap().as_bytes() == plain);
        assert!(e.decrypt(&key, &random).await.unwrap().as_bytes() == plain);
        let own = e.encrypt(&key, &plain, true).await.unwrap();
        assert!(e.decrypt(&key, &own).await.unwrap().as_bytes() == plain);
        let mut tampered = expected.clone();
        tampered[1] ^= 1;
        assert_eq!(
            e.decrypt(&key, &tampered).await.unwrap_err(),
            Error::Authentication
        );
        let mut version = expected.clone();
        version[0] = 2;
        assert_eq!(
            e.decrypt(&key, &version).await.unwrap_err(),
            Error::InvalidCiphertext
        );
        assert_eq!(
            e.decrypt(&key, &expected[..expected.len() - 1])
                .await
                .unwrap_err(),
            Error::InvalidCiphertext
        );
    }
    assert_eq!(
        e.decrypt(&key, &bytes(&f.json["invalid_padding"]))
            .await
            .unwrap_err(),
        Error::InvalidCiphertext
    );
    assert_eq!(
        e.encrypt(&key, &vec![0; MAX_VALUE + 1], false)
            .await
            .unwrap_err(),
        Error::ValueTooLarge
    );
    let mut malformed = key.clone();
    malformed.values[0].encrypted.clear();
    assert_eq!(
        e.encrypt(&malformed, b"x", false).await.unwrap_err(),
        Error::InvalidMetadata
    );
}
#[tokio::test]
async fn kp22_owned_secret_buffers_zero_before_free_and_debug_redacts() {
    let f = Fixture::new();
    let s = f.session(Policies::default());
    let key = f.key(0);
    let e = s.exchange().unwrap();
    let ciphertext = e
        .encrypt(&key, b"NEVER PRINT THIS PLAINTEXT", false)
        .await
        .unwrap();
    let plaintext = e.decrypt(&key, &ciphertext).await.unwrap();
    let text = format!("{s:?} {e:?} {key:?} {plaintext:?}");
    assert!(!text.contains("NEVER PRINT") && !text.contains("BEGIN PRIVATE KEY"));
    let audit = s.inner.audit.as_ref().unwrap().clone();
    drop(e);
    s.close().await;
    let events = audit.lock().unwrap();
    for kind in ["pem", "base64", "der", "root", "derived"] {
        assert!(
            events.iter().any(|e| e.0 == kind),
            "missing audit stage {kind}"
        );
    }
    assert!(events.iter().all(|e| e.1 > 0 && e.2));
    println!(
        "KP_EVIDENCE KP22 owned_buffers_cleared={} all_zero_before_free=true",
        events.len()
    );
    // Native key schedules/RSA components are covered by source review, not by
    // this test's owned-buffer instrumentation. Never read freed memory.
}
#[tokio::test]
async fn kp23_exchange_override_isolated_and_tightening_clears_broader_entries() {
    let f = Fixture::new();
    let mut s = f.session(policies(
        Policy::Time(Duration::from_secs(60)),
        Policy::Time(Duration::from_secs(60)),
    ));
    let key = f.key(0);
    roundtrip(&s.exchange().unwrap(), &key).await;
    let strict = s
        .exchange_with(policies(Policy::Exchange, Policy::Exchange))
        .unwrap();
    roundtrip(&strict, &key).await;
    assert_eq!(
        (
            s.statistics().master_loads,
            s.statistics().unwraps,
            s.statistics().live_columns
        ),
        (2, 2, 2)
    );
    assert_eq!(
        s.set_policies(Policies::default()).unwrap_err(),
        Error::Busy
    );
    drop(strict);
    assert_eq!(s.statistics().live_columns, 1);
    s.set_policies(Policies::default()).unwrap();
    assert_eq!(s.statistics().live_columns, 0);
    roundtrip(&s.exchange().unwrap(), &key).await;
    assert_eq!(s.statistics().unwraps, 3);
}
#[tokio::test]
async fn kp24_drop_revokes_and_close_waits_for_running_work() {
    let f = Fixture::new();
    let key = f.key(0);
    let s = f.session(Policies::default());
    let e = s.exchange().unwrap();
    roundtrip(&e, &key).await;
    let inner = s.inner.clone();
    drop(s);
    assert!(inner.bank().stats.closed);
    assert!(inner.bank().cells.is_empty());
    assert_eq!(
        e.encrypt(&key, b"x", false).await.unwrap_err(),
        Error::Closed
    );
    let s = f.session(Policies::default());
    let load = gate(&s);
    let e = s.exchange().unwrap();
    let task = tokio::spawn(async move { e.encrypt(&key, b"closing", false).await });
    load.entered().await;
    let inner = s.inner.clone();
    let closing = tokio::spawn(s.close());
    tokio::task::yield_now().await;
    assert!(inner.bank().stats.closed);
    assert!(!closing.is_finished());
    load.release();
    assert!(task.await.unwrap().is_err());
    closing.await.unwrap();
    assert_eq!(inner.pending.load(Ordering::Acquire), 0);
    assert!(inner.bank().masters.is_empty() && inner.bank().cells.is_empty());
}

#[test]
fn kp25_runtime_shutdown_revokes_an_escaped_session() {
    let f = Fixture::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let session = runtime.block_on(async {
        let s = f.session(policies(
            Policy::Time(Duration::from_secs(60)),
            Policy::Time(Duration::from_secs(60)),
        ));
        roundtrip(&s.exchange().unwrap(), &f.key(0)).await;
        assert_eq!(s.statistics().live_columns, 1);
        s
    });
    drop(runtime);
    assert_eq!(
        (
            session.statistics().closed,
            session.statistics().live_masters,
            session.statistics().live_columns
        ),
        (true, 0, 0)
    );
    report("KP25", session.statistics());
}

#[tokio::test]
async fn kp27_provider_input_hardening_and_native_consistency_checks() {
    let f = Fixture::new();
    let s = f.session(Policies::default());
    s.transaction_begin(1).unwrap();
    let key = f.key(0);
    assert_eq!(
        s.exchange()
            .unwrap()
            .decrypt(&key, b"not an encrypted value")
            .await
            .unwrap_err(),
        Error::InvalidCiphertext
    );
    assert_eq!(s.statistics().master_load_attempts, 0);
    std::fs::write(
        f.path.join("master.pem"),
        include_bytes!("../../tests/fixtures/encryption/bad-crt.pem"),
    )
    .unwrap();
    assert_eq!(
        s.exchange()
            .unwrap()
            .encrypt(&key, b"x", false)
            .await
            .unwrap_err(),
        Error::InvalidMasterKey
    );
    std::fs::write(f.path.join("master.pem"), vec![b'A'; 65_537]).unwrap();
    assert_eq!(
        s.exchange()
            .unwrap()
            .encrypt(&key, b"x", false)
            .await
            .unwrap_err(),
        Error::InvalidMasterKey
    );
    std::fs::write(
        f.path.join("master.pem"),
        include_bytes!("../../tests/fixtures/encryption/master.pem"),
    )
    .unwrap();
    roundtrip(&s.exchange().unwrap(), &key).await;
    let e = s.exchange().unwrap();
    for prefix in 0..key.values[0].encrypted.len() {
        let mut short = key.clone();
        short.values[0].encrypted.truncate(prefix);
        assert!(e.encrypt(&short, b"x", false).await.is_err());
    }
    let mut root = key.clone();
    root.values[0].encrypted = bytes(&f.json["bad_root"]);
    assert_eq!(
        e.encrypt(&root, b"x", false).await.unwrap_err(),
        Error::InvalidMetadata
    );
    let mut alternatives = key.clone();
    let mut unavailable = alternatives.values[0].clone();
    unavailable.provider = "UNREGISTERED".into();
    let mut invalid = alternatives.values[0].clone();
    invalid.encrypted[8] ^= 1;
    alternatives.values.insert(0, invalid);
    alternatives.values.insert(0, unavailable);
    assert_eq!(
        e.encrypt(&alternatives, b"fallback", false).await.unwrap(),
        e.encrypt(&key, b"fallback", false).await.unwrap()
    );
    let outside = Fixture::new();
    let mut escaped = key.clone();
    escaped.values[0].path = outside
        .path
        .join("master.pem")
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        e.encrypt(&escaped, b"x", false).await.unwrap_err(),
        Error::KeyUnavailable
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.path.join("master.pem"), f.path.join("escape.pem"))
            .unwrap();
        escaped.values[0].path = "escape.pem".into();
        assert_eq!(
            e.encrypt(&escaped, b"x", false).await.unwrap_err(),
            Error::KeyUnavailable
        );
    }
    assert!(
        KeySession::new(
            vec![
                LocalKeyStore::new("TDS_TEST", &f.path).unwrap(),
                LocalKeyStore::new("tds_test", &f.path).unwrap()
            ],
            Policies::default()
        )
        .is_err()
    );
    assert!(
        KeySession::new(
            vec![LocalKeyStore::new("TDS_TEST", &f.path).unwrap()],
            Policies {
                column_capacity: 0,
                ..Policies::default()
            }
        )
        .is_err()
    );
    println!(
        "KP_EVIDENCE KP27 truncated_wrapped_prefixes={} inconsistent_crt_rejected=true oversized_pem_rejected=true path_escape_rejected=true",
        key.values[0].encrypted.len()
    );
}

#[tokio::test]
async fn kp29_decrypted_length_limit_applies_after_unpadding() {
    use crate::encryption::{cell::Cell, secret::Secret};
    use aws_lc_rs::{
        cipher::{AES_256, EncryptionContext, PaddedBlockEncryptingKey, UnboundCipherKey},
        hmac,
    };
    let root = [7; 32];
    let cell = Cell::derive(&root, &None).unwrap();
    let hmac_root = hmac::Key::new(hmac::HMAC_SHA256, &root);
    let mut working = Secret::new(64);
    for (i, kind) in ["encryption key", "MAC key"].iter().enumerate() {
        let label:Vec<_>=format!("Microsoft SQL Server cell {kind} with encryption algorithm:AEAD_AES_256_CBC_HMAC_SHA256 and key length:256").encode_utf16().flat_map(u16::to_le_bytes).collect();
        hmac::sign_to_buffer(&hmac_root, &label, &mut working.bytes[i * 32..(i + 1) * 32]).unwrap();
    }
    let encryptor = PaddedBlockEncryptingKey::cbc_pkcs7(
        UnboundCipherKey::new(&AES_256, &working.bytes[..32]).unwrap(),
    )
    .unwrap();
    let mut payload = zeroize::Zeroizing::new(Vec::with_capacity(MAX_VALUE + 16));
    payload.resize(MAX_VALUE + 15, 0);
    encryptor
        .less_safe_encrypt(&mut *payload, EncryptionContext::Iv128([0; 16].into()))
        .unwrap();
    let mac = hmac::Key::new(hmac::HMAC_SHA256, &working.bytes[32..64]);
    let mut authenticated = vec![1];
    authenticated.extend([0; 16]);
    authenticated.extend_from_slice(&payload);
    authenticated.push(1);
    let mut out = vec![0; 33];
    out[0] = 1;
    hmac::sign_to_buffer(&mac, &authenticated, &mut out[1..33]).unwrap();
    out.extend_from_slice(&authenticated[1..authenticated.len() - 1]);
    assert_eq!(out.len(), MAX_VALUE + 65);
    assert_eq!(cell.decrypt(&out).unwrap_err(), Error::ValueTooLarge);
}

#[tokio::test]
async fn kp30_native_key_allocation_stays_stable_when_cache_grows() {
    let f = Fixture::new();
    let s = f.session(Policies::default());
    s.transaction_begin(1).unwrap();
    let key = f.key(0);
    let e = s.exchange().unwrap();
    roundtrip(&e, &key).await;
    let (address, capacity) = {
        let bank = s.inner.bank();
        (
            std::ptr::from_ref(&*bank.cells[0].value) as usize,
            bank.cells.capacity(),
        )
    };
    for id in 2..18 {
        let mut distinct = key.clone();
        distinct.key_id = id;
        roundtrip(&e, &distinct).await;
    }
    let bank = s.inner.bank();
    assert!(bank.cells.capacity() > capacity);
    assert_eq!(std::ptr::from_ref(&*bank.cells[0].value) as usize, address);
    println!(
        "KP_EVIDENCE KP30 cells={} cache_capacity_before={} after={} pointee_address_stable=true",
        bank.cells.len(),
        capacity,
        bank.cells.capacity()
    );
}
