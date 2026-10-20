//! The Windows certificate store as a live Always Encrypted key store (D-62),
//! paired with Python's `test_certstore_windows.py`. `infra/azure/windows-tests.sh`
//! runs it on the Azure SQL VM against that VM's SQL Server, after the Python test:
//! Rust reads Python's `tds_certstore` table, then writes and reads its own.
//!
//! Environment: `TDS_CERT_THUMBPRINT` (LocalMachine/My, non-exportable key),
//! `TDS_SQL_PASSWORD` (tdsadmin), `TDS_SQL_HOST` and `TDS_SQL_CA` (the disposable CA).
#![cfg(feature = "certificate-store")]
use std::{sync::Arc, time::Duration};
use tds_client::{
    Batch, ConnectOptions, Connection, IntegerSize, Param, SqlType, Value,
    encryption::{
        KeyOperation, KeyProvider, Plaintext, Policies, certstore::WindowsCertificateStore,
    },
};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}: infra/azure/windows-tests.sh"))
}
fn options(database: &str) -> ConnectOptions {
    let pem = std::fs::read(env("TDS_SQL_CA")).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let mut options = ConnectOptions::new(
        env("TDS_SQL_HOST"),
        1433,
        "tdsadmin",
        env("TDS_SQL_PASSWORD"),
        roots,
    );
    options.database = database.into();
    options
}
async fn run(connection: &Connection, sql: &str) {
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
/// Every value in `dbo.t`, read through the certificate store.
async fn read(database: &str) -> Vec<Option<Value>> {
    let connection = Connection::connect(options(database)).await.unwrap();
    let providers: Vec<Arc<dyn KeyProvider>> = vec![Arc::new(WindowsCertificateStore)];
    let encrypted = connection
        .encrypted_with_providers(providers, Policies::default(), Duration::from_secs(30))
        .await
        .unwrap();
    let mut channel = encrypted.serial_channel().await.unwrap();
    let fetched = channel
        .exchange(Batch::new("SELECT v FROM dbo.t"))
        .await
        .unwrap()
        .fetch()
        .await
        .unwrap();
    channel.close().await.unwrap();
    encrypted.close().await;
    connection.close().await.unwrap();
    fetched.result_sets()[0]
        .rows()
        .unwrap()
        .iter()
        .map(|row| row[0].clone())
        .collect()
}

#[tokio::test]
#[ignore = "live Azure campaign: on the Windows SQL VM"]
async fn certificate_store_keys_read_python_values_and_round_trip_rust_values() {
    let path = format!("LocalMachine/My/{}", env("TDS_CERT_THUMBPRINT"));
    // Python's test leaves its database: its column key was wrapped by Python's provider.
    assert_eq!(read("tds_certstore").await, [Some(Value::Integer(41000))]);
    println!("CERTSTORE read Python's value: 41000");

    let operation = KeyOperation::default();
    let master = WindowsCertificateStore
        .open(&path, operation.clone())
        .await
        .unwrap();
    let mut root = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut root).unwrap();
    let wrapped = master
        .wrap(&Plaintext::copy(&root).unwrap(), operation)
        .await
        .unwrap();
    let hex: String = wrapped.iter().map(|b| format!("{b:02x}")).collect();
    let admin = Connection::connect(options("master")).await.unwrap();
    run(&admin, "IF DB_ID('tds_rust_certstore') IS NOT NULL BEGIN ALTER DATABASE tds_rust_certstore SET SINGLE_USER \
        WITH ROLLBACK IMMEDIATE; DROP DATABASE tds_rust_certstore END; CREATE DATABASE tds_rust_certstore").await;
    run(&admin, &format!("USE tds_rust_certstore; CREATE COLUMN MASTER KEY cmk WITH \
        (KEY_STORE_PROVIDER_NAME = N'MSSQL_CERTIFICATE_STORE', KEY_PATH = N'{path}'); \
        CREATE COLUMN ENCRYPTION KEY cek WITH VALUES (COLUMN_MASTER_KEY = cmk, ALGORITHM = 'RSA_OAEP', ENCRYPTED_VALUE = 0x{hex}); \
        CREATE TABLE dbo.t (v int ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = cek, ENCRYPTION_TYPE = RANDOMIZED, \
        ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'))")).await;
    admin.close().await.unwrap();

    let connection = Connection::connect(options("tds_rust_certstore"))
        .await
        .unwrap();
    let providers: Vec<Arc<dyn KeyProvider>> = vec![Arc::new(WindowsCertificateStore)];
    let encrypted = connection
        .encrypted_with_providers(providers, Policies::default(), Duration::from_secs(30))
        .await
        .unwrap();
    let mut channel = encrypted.serial_channel().await.unwrap();
    let int = SqlType::Integer {
        size: IntegerSize::Int,
    };
    channel
        .execute(
            "INSERT dbo.t VALUES (@v)",
            "@v int",
            vec![Param::new("@v", int, Some(Value::Integer(52000)))],
        )
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    channel.close().await.unwrap();
    encrypted.close().await;
    connection.close().await.unwrap();
    assert_eq!(
        read("tds_rust_certstore").await,
        [Some(Value::Integer(52000))]
    );
    println!("CERTSTORE Rust value round trip: 52000");
}

/// Part B (B-5): a missing thumbprint or store, and a key wrapped by another
/// certificate, are refused; nothing is decrypted with the wrong key.
#[tokio::test]
#[ignore = "live Azure campaign: on the Windows SQL VM"]
async fn missing_and_wrong_certificates_are_refused() {
    let thumbprint = env("TDS_CERT_THUMBPRINT");
    let other = env("TDS_CERT_OTHER_THUMBPRINT");
    let operation = KeyOperation::default();
    for path in [
        format!("LocalMachine/My/{}", "0".repeat(40)),
        format!("CurrentUser/My/{thumbprint}"),
    ] {
        let error = WindowsCertificateStore
            .open(&path, operation.clone())
            .await
            .err()
            .expect("refused");
        println!("CERTSTORE {path}: {error}");
    }
    let right = format!("LocalMachine/My/{thumbprint}");
    let wrong = format!("LocalMachine/My/{other}");
    let wrapped = WindowsCertificateStore
        .open(&right, operation.clone())
        .await
        .unwrap()
        .wrap(&Plaintext::copy(&[9; 32]).unwrap(), operation.clone())
        .await
        .unwrap();
    let key = tds_client::encryption::WrappedKey {
        provider: "MSSQL_CERTIFICATE_STORE".into(),
        path: wrong.clone(),
        algorithm: "RSA_OAEP".into(),
        encrypted: wrapped,
    };
    let master = WindowsCertificateStore
        .open(&wrong, operation.clone())
        .await
        .unwrap();
    let error = master.unwrap(&key, operation).await.unwrap_err();
    assert!(
        matches!(
            error,
            tds_client::encryption::Error::Authentication
                | tds_client::encryption::Error::InvalidMetadata
        ),
        "{error:?}"
    );
    println!("CERTSTORE key wrapped by another certificate: {error:?}");
}
