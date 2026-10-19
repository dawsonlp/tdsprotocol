#![cfg(feature = "encryption")]
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tds_client::encryption::*;

fn key(provider: &str) -> ColumnKey {
    ColumnKey {
        database_id: 1,
        key_id: 7,
        version: 1,
        metadata_version: [4; 8],
        values: vec![WrappedKey {
            provider: provider.into(),
            path: "master.pem".into(),
            algorithm: "RSA_OAEP".into(),
            encrypted: vec![1],
        }],
    }
}
#[derive(Default)]
struct Counts {
    opens: AtomicUsize,
    unwraps: AtomicUsize,
    dropped: AtomicUsize,
    active: AtomicUsize,
}
struct Fake {
    name: &'static str,
    counts: Arc<Counts>,
    delay: Duration,
    refuse: bool,
}
struct Active(Arc<Counts>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
impl KeyProvider for Fake {
    fn name(&self) -> &str {
        self.name
    }
    fn open<'a>(&'a self, _: &'a str, _: KeyOperation) -> KeyFuture<'a, Arc<dyn MasterKey>> {
        Box::pin(async move {
            self.counts.opens.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(Fake {
                name: self.name,
                counts: self.counts.clone(),
                delay: self.delay,
                refuse: self.refuse,
            }) as Arc<dyn MasterKey>)
        })
    }
}
impl MasterKey for Fake {
    fn unwrap<'a>(&'a self, _: &'a WrappedKey, _: KeyOperation) -> KeyFuture<'a, Plaintext> {
        Box::pin(async move {
            self.counts.unwraps.fetch_add(1, Ordering::SeqCst);
            self.counts.active.fetch_add(1, Ordering::SeqCst);
            let _active = Active(self.counts.clone());
            tokio::time::sleep(self.delay).await;
            if self.refuse {
                Err(Error::Authentication)
            } else {
                Plaintext::copy(&[9; 32])
            }
        })
    }
    fn wrap<'a>(&'a self, _: &'a Plaintext, _: KeyOperation) -> KeyFuture<'a, Vec<u8>> {
        Box::pin(async { Err(Error::InvalidMetadata) })
    }
    fn sign_metadata(&self, _: bool, _: KeyOperation) -> KeyFuture<'_, Vec<u8>> {
        Box::pin(async { Err(Error::InvalidMetadata) })
    }
    fn verify_metadata<'a>(&'a self, _: bool, _: &'a [u8], _: KeyOperation) -> KeyFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }
}
fn fake(name: &'static str, delay: Duration, refuse: bool) -> (Arc<dyn KeyProvider>, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    (
        Arc::new(Fake {
            name,
            counts: counts.clone(),
            delay,
            refuse,
        }),
        counts,
    )
}
async fn started(counts: &Counts) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while counts.active.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
fn fixed() -> Policies {
    Policies {
        master: Policy::Time(Duration::from_secs(60)),
        column: Policy::Time(Duration::from_secs(60)),
        ..Default::default()
    }
}

#[tokio::test]
async fn async_refusal_falls_back_to_local_and_preserves_coalescing() {
    let (remote, counts) = fake("remote", Duration::ZERO, true);
    let local = LocalKeyStore::new(
        "local",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/encryption"),
    )
    .unwrap();
    let session = KeySession::with_providers(
        vec![remote, Arc::new(local)],
        fixed(),
        Duration::from_secs(2),
    )
    .unwrap();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/encryption/python.json")).unwrap();
    let mut column = key("remote");
    column.values.push(WrappedKey {
        provider: "LOCAL".into(),
        path: "master.pem".into(),
        algorithm: "RSA_OAEP".into(),
        encrypted: STANDARD
            .decode(fixture["wrapped"][0].as_str().unwrap())
            .unwrap(),
    });
    let guard = session.exchange().unwrap();
    let (a, b) = tokio::join!(
        guard.encrypt(&column, b"first", false),
        guard.encrypt(&column, b"first", false)
    );
    assert_eq!(a.unwrap(), b.unwrap());
    assert_eq!(counts.unwraps.load(Ordering::SeqCst), 1);
    assert_eq!(session.statistics().unwrap_attempts, 2);
    assert_eq!(session.statistics().live_masters, 1);
    assert_eq!(session.statistics().live_columns, 1);
    assert_eq!(session.statistics().coalesced, 1);
    drop(guard);
    session.close().await;
}

#[tokio::test]
async fn caller_cancel_drops_async_provider_without_installing_late_key() {
    let (provider, counts) = fake("remote", Duration::from_secs(3600), false);
    let session =
        KeySession::with_providers(vec![provider], fixed(), Duration::from_secs(30)).unwrap();
    let guard = Arc::new(session.exchange().unwrap());
    let task = tokio::spawn({
        let guard = guard.clone();
        async move { guard.encrypt(&key("remote"), b"x", false).await }
    });
    started(&counts).await;
    task.abort();
    let _ = task.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while session.statistics().pending != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(counts.active.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(session.statistics().live_columns, 0);
    assert_eq!(session.statistics().live_masters, 0);
    drop(guard);
    session.close().await;
}

#[tokio::test(start_paused = true)]
async fn one_deadline_bounds_remote_provider_and_drops_it() {
    let (provider, counts) = fake("remote", Duration::from_secs(3600), false);
    let session =
        KeySession::with_providers(vec![provider], fixed(), Duration::from_millis(20)).unwrap();
    let guard = session.exchange().unwrap();
    assert_eq!(
        guard.encrypt(&key("remote"), b"x", false).await,
        Err(Error::ProviderTimeout)
    );
    assert_eq!(counts.active.load(Ordering::SeqCst), 0);
    assert_eq!(session.statistics().live_columns, 0);
    drop(guard);
    session.close().await;
}

#[tokio::test]
async fn security_invalidation_interrupts_remote_work_and_expires_old_guard() {
    let (provider, counts) = fake("remote", Duration::from_secs(3600), false);
    let session =
        KeySession::with_providers(vec![provider], fixed(), Duration::from_secs(30)).unwrap();
    let guard = Arc::new(session.exchange().unwrap());
    let task = tokio::spawn({
        let guard = guard.clone();
        async move { guard.encrypt(&key("remote"), b"x", false).await }
    });
    started(&counts).await;
    session.invalidate();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Expired)
    );
    assert_eq!(counts.active.load(Ordering::SeqCst), 0);
    assert_eq!(session.statistics().live_columns, 0);
    drop(guard);
    session.close().await;
}

#[tokio::test]
async fn local_capability_wrap_metadata_signatures_and_owned_workers() {
    let provider = LocalKeyStore::new(
        "TDS_TEST",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/encryption"),
    )
    .unwrap();
    let operation = KeyOperation::default();
    let master = provider
        .open("master.pem", operation.clone())
        .await
        .unwrap();
    let root = Plaintext::copy(&[3; 32]).unwrap();
    let wrapped = master.wrap(&root, operation.clone()).await.unwrap();
    let evidence = WrappedKey {
        provider: "TDS_TEST".into(),
        path: "master.pem".into(),
        algorithm: "rſa_oaep".into(),
        encrypted: wrapped,
    };
    assert_eq!(
        master
            .unwrap(&evidence, operation.clone())
            .await
            .unwrap()
            .as_bytes(),
        root.as_bytes()
    );
    let signature = master.sign_metadata(true, operation.clone()).await.unwrap();
    assert!(
        master
            .verify_metadata(true, &signature, operation.clone())
            .await
            .unwrap()
    );
    assert!(
        !master
            .verify_metadata(false, &signature, operation.clone())
            .await
            .unwrap()
    );
    let output = std::env::var_os("TDS_KEY_PROVIDER_OUTPUT");
    if let Some(path) = output {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(serde_json::to_string(&serde_json::json!({"root":STANDARD.encode(root.as_bytes()),"wrapped":STANDARD.encode(evidence.encrypted),"metadata_signature":STANDARD.encode(signature)})).unwrap().as_bytes()).unwrap();
    }
    operation.drain().await;
    assert_eq!(operation.pending(), 0);
}

#[tokio::test]
async fn async_provider_preserves_every_master_column_retention_combination() {
    for master in [
        Policy::Exchange,
        Policy::Transaction,
        Policy::Time(Duration::from_secs(60)),
    ] {
        for column in [
            Policy::Exchange,
            Policy::Transaction,
            Policy::Time(Duration::from_secs(60)),
        ] {
            let (provider, counts) = fake("remote", Duration::ZERO, false);
            let session = KeySession::with_providers(
                vec![provider],
                Policies {
                    master,
                    column,
                    ..Default::default()
                },
                Duration::from_secs(2),
            )
            .unwrap();
            session.transaction_begin(1).unwrap();
            for _ in 0..2 {
                let guard = session.exchange().unwrap();
                let encrypted = guard.encrypt(&key("remote"), b"data", false).await.unwrap();
                assert_eq!(
                    guard
                        .decrypt(&key("remote"), &encrypted)
                        .await
                        .unwrap()
                        .as_bytes(),
                    b"data"
                );
            }
            assert_eq!(
                counts.unwraps.load(Ordering::SeqCst),
                if column == Policy::Exchange { 2 } else { 1 },
                "{master:?}/{column:?}"
            );
            assert_eq!(
                counts.opens.load(Ordering::SeqCst),
                if master == Policy::Exchange && column == Policy::Exchange {
                    2
                } else {
                    1
                },
                "{master:?}/{column:?}"
            );
            session.close().await;
        }
    }
}

#[tokio::test]
async fn canceled_standalone_native_job_owns_late_output_until_drain() {
    struct Owned(Arc<AtomicUsize>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let operation = KeyOperation::default();
    let dropped = Arc::new(AtomicUsize::new(0));
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let task = tokio::spawn({
        let operation = operation.clone();
        let dropped = dropped.clone();
        async move {
            operation
                .blocking(move || {
                    let _ = entered.send(());
                    wait.recv().unwrap();
                    Ok(Owned(dropped))
                })
                .await
        }
    });
    started.await.unwrap();
    task.abort();
    let _ = task.await;
    assert_eq!(operation.pending(), 1);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    let drain = operation.drain();
    tokio::pin!(drain);
    tokio::select! { _=&mut drain=>panic!("cleanup returned before native job completed"),_=tokio::task::yield_now()=>{} }
    release.send(()).unwrap();
    drain.await;
    assert_eq!(operation.pending(), 0);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}
