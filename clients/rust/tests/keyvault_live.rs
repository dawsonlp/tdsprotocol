//! Real SQL Server metadata with the Key Vault provider: the official SDK over the
//! fake vault transport, so no Azure service is contacted. SQL Server stores the
//! Python-generated vault envelope as the column key and never calls the vault.
#![cfg(feature = "azure-keyvault")]
mod support;
#[path = "support/vault.rs"]
mod vault;
use std::{sync::Arc, time::Duration};
use tds_client::{encryption::Policies, *};

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
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
fn unwraps(vault: &vault::Vault) -> usize {
    vault
        .operations()
        .iter()
        .filter(|o| *o == "unwrapkey")
        .count()
}

#[tokio::test]
#[ignore = "requires Docker SQL Server; Key Vault provider across pool reuse"]
async fn key_vault_column_keys_encrypt_read_and_reunwrap_after_pool_return() {
    let mut options = support::docker_options();
    let db = format!("tds_rust_akv_{}", std::process::id());
    let admin = Connection::connect(options.clone()).await.unwrap();
    run(&admin, &format!("CREATE DATABASE {db}")).await;
    options.database = db.clone();
    options.column_encryption = true;
    let f = vault::fixture();
    let setup = Connection::connect(options.clone()).await.unwrap();
    run(&setup, &format!(
        "CREATE COLUMN MASTER KEY akv WITH (KEY_STORE_PROVIDER_NAME=N'AZURE_KEY_VAULT',KEY_PATH=N'{}'); \
         CREATE COLUMN ENCRYPTION KEY cek WITH VALUES (COLUMN_MASTER_KEY=akv,ALGORITHM='RSA_OAEP',ENCRYPTED_VALUE=0x{})",
        f["path"].as_str().unwrap(),
        hex(&vault::b(&f, "wrapped"))
    )).await;
    run(&setup, "CREATE TABLE dbo.t (id int, v int ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY=cek,ENCRYPTION_TYPE=DETERMINISTIC,ALGORITHM='AEAD_AES_256_CBC_HMAC_SHA_256'))").await;
    setup.close().await.unwrap();
    let int = SqlType::Integer {
        size: IntegerSize::Int,
    };
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            options.version = version;
            options.mars = mars;
            let vault = Arc::new(vault::Vault::default());
            let providers = || -> Vec<Arc<dyn encryption::KeyProvider>> {
                vec![Arc::new(vault::store(vault.clone()))]
            };
            let pool = Pool::new(options.clone(), 1).unwrap();
            let lease = pool.acquire().await.unwrap();
            let enc = lease
                .encrypted_with_providers(providers(), Policies::default(), Duration::from_secs(5))
                .await
                .unwrap();
            let mut ch = enc.serial_channel().await.unwrap();
            ch.exchange(Batch::new("DELETE dbo.t"))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            ch.execute(
                "INSERT dbo.t VALUES (1,@v)",
                "@v int",
                vec![Param::new("@v", int.clone(), Some(Value::Integer(42)))],
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
            ch.close().await.unwrap();
            assert_eq!(enc.statistics().unwraps, 1);
            enc.close().await;
            assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Returned);
            // The reused session gets a new key owner: keys are not carried across leases.
            let lease = pool.acquire().await.unwrap();
            let enc = lease
                .encrypted_with_providers(providers(), Policies::default(), Duration::from_secs(5))
                .await
                .unwrap();
            let mut ch = enc.serial_channel().await.unwrap();
            let found = ch
                .execute(
                    "SELECT v FROM dbo.t WHERE v=@v",
                    "@v int",
                    vec![Param::new("@v", int.clone(), Some(Value::Integer(42)))],
                )
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(
                found.result_sets()[0].rows().unwrap(),
                [vec![Some(Value::Integer(42))]]
            );
            ch.close().await.unwrap();
            assert_eq!(enc.statistics().unwraps, 1);
            enc.close().await;
            assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Returned);
            pool.close().await.unwrap();
            // Each unwrap verified the vault envelope signature first.
            assert_eq!(
                vault.operations(),
                ["verify", "unwrapkey", "verify", "unwrapkey"]
            );
            assert_eq!(unwraps(&vault), 2);
            println!("AKV_POOL {version:?} mars={mars} insert/lookup/reuse passed");
        }
    }
    run(
        &admin,
        &format!("ALTER DATABASE {db} SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE {db}"),
    )
    .await;
    admin.close().await.unwrap();
}
