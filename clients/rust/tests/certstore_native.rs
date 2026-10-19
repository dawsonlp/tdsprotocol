#![cfg(feature = "certificate-store")]
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    io::Write,
    process::{Command, Stdio},
};
use tds_client::encryption::{certstore::WindowsCertificateStore, *};

#[tokio::test]
#[ignore = "requires Windows, a dedicated non-exportable CNG RSA test certificate and Python encryption dependencies"]
#[allow(clippy::assertions_on_constants)] // Intentional runtime platform guard.
async fn native_non_exportable_certificate_mutually_wraps_and_signs_with_python() {
    // Compile the entire test on other hosts, but refuse manual execution there.
    assert!(cfg!(windows), "native acceptance must run on Windows");
    // Explicit test fixture only. This test provisions no certificate and does
    // not alter a user/machine store. The path and root are public test inputs.
    let path = std::env::var("TDS_CERTSTORE_TEST_KEY_PATH").expect("dedicated certificate path");
    let python = std::env::var_os("TDS_CERTSTORE_TEST_PYTHON")
        .expect("Python with this repository's encryption dependencies");
    let operation = KeyOperation::default();
    let master = WindowsCertificateStore
        .open(&path, operation.clone())
        .await
        .unwrap();
    let root = Plaintext::copy(&[3; 32]).unwrap();
    let wrapped = master.wrap(&root, operation.clone()).await.unwrap();
    let signature = master.sign_metadata(true, operation.clone()).await.unwrap();
    let mut child = Command::new(python)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/azure/certstore.py"
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let input = serde_json::json!({"path":path,"root":STANDARD.encode(root.as_bytes()),"wrapped":STANDARD.encode(wrapped),"signature":STANDARD.encode(signature)});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&input).unwrap().as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    let output: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let wrapped = WrappedKey {
        provider: "MSSQL_CERTIFICATE_STORE".into(),
        path,
        algorithm: "RSA_OAEP".into(),
        encrypted: STANDARD
            .decode(output["wrapped"].as_str().unwrap())
            .unwrap(),
    };
    assert_eq!(
        master
            .unwrap(&wrapped, operation.clone())
            .await
            .unwrap()
            .as_bytes(),
        root.as_bytes()
    );
    let signature = STANDARD
        .decode(output["signature"].as_str().unwrap())
        .unwrap();
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
    let mut tampered = wrapped;
    *tampered.encrypted.last_mut().unwrap() ^= 1;
    assert!(matches!(
        master.unwrap(&tampered, operation.clone()).await,
        Err(Error::Authentication)
    ));
    operation.drain().await;
    drop(master);
}
