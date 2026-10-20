#![cfg(feature = "azure-keyvault")]
#[path = "support/vault.rs"]
mod vault;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use std::sync::{Arc, atomic::Ordering};
use tds_client::encryption::*;
use vault::{Vault, b, fixture, store};

#[tokio::test]
async fn sdk_requests_preserve_version_verify_order_and_python_envelopes() {
    let vault = Arc::new(Vault::default());
    let store = store(vault.clone());
    let f = fixture();
    let operation = KeyOperation::default();
    let master = store
        .open(f["path"].as_str().unwrap(), operation.clone())
        .await
        .unwrap();
    assert!(vault.calls.lock().unwrap().is_empty());
    let evidence = WrappedKey {
        provider: "AZURE_KEY_VAULT".into(),
        path: f["path"].as_str().unwrap().into(),
        algorithm: "rſa_oaep".into(),
        encrypted: b(&f, "wrapped"),
    };
    let root = master.unwrap(&evidence, operation.clone()).await.unwrap();
    assert_eq!(root.as_bytes(), b(&f, "root"));
    assert_eq!(
        master.wrap(&root, operation.clone()).await.unwrap(),
        b(&f, "wrapped")
    );
    let signature = master.sign_metadata(true, operation.clone()).await.unwrap();
    assert_eq!(signature, b(&f, "metadata_signature"));
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
    let mut bad = evidence.clone();
    *bad.encrypted.last_mut().unwrap() ^= 1;
    assert_eq!(
        master.unwrap(&bad, operation.clone()).await.unwrap_err(),
        Error::Authentication
    );
    let calls = vault.calls.lock().unwrap();
    assert_eq!(
        vault.requests.load(Ordering::SeqCst),
        calls.len() + 1,
        "one initial physical authentication challenge"
    );
    assert_eq!(
        calls
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        [
            "/keys/MyKey/Version1/verify",
            "/keys/MyKey/Version1/unwrapkey",
            "/keys/MyKey/Version1/wrapkey",
            "/keys/MyKey/Version1/sign",
            "/keys/MyKey/Version1/sign",
            "/keys/MyKey/Version1/verify",
            "/keys/MyKey/Version1/verify",
            "/keys/MyKey/Version1/verify"
        ]
    );
    if let Some(path) = std::env::var_os("TDS_VAULT_PROVIDER_OUTPUT") {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(serde_json::to_string(&json!({"vault":true,"root":STANDARD.encode(root.as_bytes()),"wrapped":f["wrapped"],"metadata_signature":STANDARD.encode(signature)})).unwrap().as_bytes()).unwrap();
    }
}
#[tokio::test]
async fn vault_denial_keeps_protected_diagnostic_out_of_normal_errors() {
    let vault = Arc::new(Vault::default());
    vault.denied.store(true, Ordering::SeqCst);
    let store = store(vault.clone());
    let f = fixture();
    let op = KeyOperation::default();
    let master = store
        .open(f["path"].as_str().unwrap(), op.clone())
        .await
        .unwrap();
    let error = master.sign_metadata(true, op).await.unwrap_err();
    assert!(
        !format!("{error} {error:?} {store:?}").contains("artificial-private-provider-diagnostic")
    );
    let Error::Provider(cause) = error else {
        panic!("protected cause")
    };
    assert!(
        cause
            .protected_cause()
            .to_string()
            .contains("artificial-private-provider-diagnostic")
    );
    assert_eq!(vault.calls.lock().unwrap().len(), 1);
    assert_eq!(vault.requests.load(Ordering::SeqCst), 2);
}
