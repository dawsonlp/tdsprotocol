//! Actual service cost, synthetic fixtures only; no SQL or network.
//! cargo run --offline --release --features encryption --example key_policy_cost
//! Reads the intentionally PUBLIC disposable test key. Never deploy that key.
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{path::Path, time::Instant};
use tds_client::encryption::{ColumnKey, KeySession, LocalKeyStore, Policies, Policy, WrappedKey};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/encryption");
    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("python.json")).unwrap()).unwrap();
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
                .decode(fixture["wrapped"][0].as_str().unwrap())
                .unwrap(),
        }],
    };
    let mut results = Vec::new();
    for (name, master, column) in [
        ("exchange_exchange", Policy::Exchange, Policy::Exchange),
        (
            "transaction_exchange",
            Policy::Transaction,
            Policy::Exchange,
        ),
        (
            "transaction_transaction",
            Policy::Transaction,
            Policy::Transaction,
        ),
    ] {
        let session = KeySession::new(
            vec![LocalKeyStore::new("TDS_TEST", &directory).unwrap()],
            Policies {
                master,
                column,
                ..Policies::default()
            },
        )
        .unwrap();
        let mut batches = Vec::new();
        let mut observed = None;
        // One unreported warmup batch, then five batches of ten transactions.
        for batch in 0..6 {
            if batch == 1 {
                observed = Some(session.statistics());
            }
            let started = Instant::now();
            for _ in 0..10 {
                session.transaction_begin(1).unwrap();
                for _ in 0..20 {
                    let exchange = session.exchange().unwrap();
                    let ciphertext = exchange.encrypt(&key, &[0x55; 64], false).await.unwrap();
                    let plaintext = exchange.decrypt(&key, &ciphertext).await.unwrap();
                    assert!(plaintext.as_bytes() == [0x55; 64]);
                }
                session.transaction_end();
            }
            if batch > 0 {
                batches.push(started.elapsed().as_secs_f64() * 1_000_000.0 / 10.0);
            }
        }
        batches.sort_by(f64::total_cmp);
        let baseline = observed.unwrap();
        let final_stats = session.statistics();
        results.push(serde_json::json!({"profile":name,"transactions":50,"exchanges_per_transaction":20,
            "bytes_per_value":64,"work":"one deterministic encryption and authenticated decryption per exchange",
            "median_transaction_wall_us":batches[2],"batch_mean_range_us":[batches[0],batches[4]],
            "master_loads":final_stats.master_loads-baseline.master_loads,"unwraps":final_stats.unwraps-baseline.unwraps,
            "live_masters_after_end":final_stats.live_masters,"live_columns_after_end":final_stats.live_columns}));
        session.close().await;
    }
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({
        "scope":"Implemented key service, release build, warm PUBLIC synthetic PKCS8 PEM fixture; current-thread Tokio; no SQL/network or CPU measurement",
        "method":"median of five batch means, ten transactions per batch after warmup; file read, worker scheduling, guarded buffers, value crypto, exchange/end cleanup included",
        "results":results})).unwrap());
}
