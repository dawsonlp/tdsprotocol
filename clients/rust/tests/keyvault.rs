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

// ---------------------------------------------------------------- Part B (B-4): adversarial vault cases

fn evidence(f: &serde_json::Value) -> WrappedKey {
    WrappedKey {
        provider: "AZURE_KEY_VAULT".into(),
        path: f["path"].as_str().unwrap().into(),
        algorithm: "RSA_OAEP".into(),
        encrypted: b(f, "wrapped"),
    }
}

#[tokio::test]
async fn wrong_algorithm_and_malformed_envelopes_are_refused_without_a_vault_call() {
    let vault = Arc::new(Vault::default());
    let store = store(vault.clone());
    let f = fixture();
    let op = KeyOperation::default();
    let master = store
        .open(f["path"].as_str().unwrap(), op.clone())
        .await
        .unwrap();
    let mut wrong_algorithm = evidence(&f);
    wrong_algorithm.algorithm = "RSA_OAEP_256".into();
    let mut truncated = evidence(&f);
    truncated.encrypted.truncate(4);
    let mut wrong_version = evidence(&f);
    wrong_version.encrypted[0] = 2;
    for (name, key) in [
        ("algorithm", wrong_algorithm),
        ("truncated", truncated),
        ("version", wrong_version),
    ] {
        assert_eq!(
            master.unwrap(&key, op.clone()).await.unwrap_err(),
            Error::InvalidMetadata,
            "{name}"
        );
    }
    assert!(
        vault.calls.lock().unwrap().is_empty(),
        "refused before any vault operation"
    );
}

#[tokio::test]
async fn another_key_or_version_does_not_verify_and_nothing_is_unwrapped() {
    let f = fixture();
    let op = KeyOperation::default();
    for path in [
        "https://fixture.vault.azure.net/keys/OtherKey/Version1",
        "https://fixture.vault.azure.net/keys/MyKey/Version2",
    ] {
        let vault = Arc::new(Vault::default());
        let master = store(vault.clone()).open(path, op.clone()).await.unwrap();
        // The envelope names MyKey/Version1, but SQL's metadata chose this key.
        let mut key = evidence(&f);
        key.path = path.into();
        assert_eq!(
            master.unwrap(&key, op.clone()).await.unwrap_err(),
            Error::Authentication,
            "{path}"
        );
        assert!(
            !master
                .verify_metadata(true, &b(&f, "metadata_signature"), op.clone())
                .await
                .unwrap()
        );
        assert_eq!(
            vault.operations(),
            ["verify", "verify"],
            "{path}: never unwrapkey"
        );
    }
}

#[tokio::test]
async fn a_tampered_metadata_signature_is_not_valid() {
    let vault = Arc::new(Vault::default());
    let f = fixture();
    let op = KeyOperation::default();
    let master = store(vault.clone())
        .open(f["path"].as_str().unwrap(), op.clone())
        .await
        .unwrap();
    let mut signature = b(&f, "metadata_signature");
    signature[0] ^= 1;
    assert!(
        !master
            .verify_metadata(true, &signature, op.clone())
            .await
            .unwrap()
    );
    assert!(
        !master
            .verify_metadata(false, &b(&f, "metadata_signature"), op)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_missing_key_or_unreadable_response_is_a_protected_provider_failure() {
    let f = fixture();
    let op = KeyOperation::default();
    for missing in [true, false] {
        let vault = Arc::new(Vault::default());
        if missing {
            vault.missing.store(true, Ordering::SeqCst);
        } else {
            vault.malformed.store(true, Ordering::SeqCst);
        }
        let store = store(vault.clone());
        let master = store
            .open(f["path"].as_str().unwrap(), op.clone())
            .await
            .unwrap();
        let error = master.unwrap(&evidence(&f), op.clone()).await.unwrap_err();
        assert!(matches!(error, Error::Provider(_)), "{error:?}");
        assert!(!format!("{error} {error:?}").contains("artificial-missing-key"));
        assert_eq!(
            vault.operations(),
            ["verify"],
            "no unwrap after a failed verify"
        );
    }
}

#[tokio::test]
async fn a_canceled_unwrap_issues_no_later_vault_operation() {
    let vault = Arc::new(Vault::default());
    vault.hold.store(true, Ordering::SeqCst);
    let f = fixture();
    let op = KeyOperation::default();
    let master = store(vault.clone())
        .open(f["path"].as_str().unwrap(), op.clone())
        .await
        .unwrap();
    let key = evidence(&f);
    let mut unwrapping = master.unwrap(&key, op.clone()); // an owned, boxed future
    tokio::select! {
        _ = &mut unwrapping => panic!("the vault holds the request"),
        _ = vault.entered.notified() => {}
    }
    drop(unwrapping); // the caller gives up while the vault is answering verify
    vault.hold.store(false, Ordering::SeqCst);
    vault.release.notify_one();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        vault.operations(),
        ["verify"],
        "the late verify never leads to unwrapkey"
    );
}
