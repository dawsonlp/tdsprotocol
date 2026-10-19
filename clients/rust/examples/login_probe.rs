//! Read one protected JSON configuration from stdin; never accept passwords in
//! argv. Emit only session evidence. This is a live campaign tool, not a fixture.
use std::io::Read;
use tds_client::{
    Batch, ConnectOptions, Connection, Pool, ProtocolVersion, ReleaseOutcome, SerialChannel,
    Transaction,
    auth::{Method, WindowsAuth},
};

async fn scalar(channel: &mut SerialChannel, sql: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let fetched = channel.exchange(Batch::new(sql)).await?.fetch().await?;
    fetched.result_sets()[0].rows()?[0][0]
        .as_ref()
        .and_then(|v| v.as_integer())
        .ok_or_else(|| "expected integer evidence".into())
}

async fn session_lifecycle(
    connection: &Connection,
    channel: &mut SerialChannel,
) -> Result<(), Box<dyn std::error::Error>> {
    channel
        .exchange(Batch::new("CREATE TABLE #auth_transaction(n int)"))
        .await?
        .finish()
        .await?;
    channel
        .exchange(Transaction::Begin(Default::default()))
        .await?
        .finish()
        .await?;
    if connection.session().await?.transaction == 0 {
        return Err("transaction descriptor missing".into());
    }
    channel
        .exchange(Batch::new("INSERT #auth_transaction VALUES(42)"))
        .await?
        .finish()
        .await?;
    channel
        .exchange(Transaction::Rollback(Default::default()))
        .await?
        .finish()
        .await?;
    if connection.session().await?.transaction != 0
        || scalar(channel, "SELECT COUNT(*) FROM #auth_transaction").await? != 0
    {
        return Err("rollback did not restore session/data".into());
    }
    let response = channel
        .exchange(Batch::new("WAITFOR DELAY '00:00:10'; SELECT 99"))
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    response.close().await?;
    if scalar(channel, "SELECT 42").await? != 42 {
        return Err("connection not reusable after Attention".into());
    }
    Ok(())
}

async fn pool_lifecycle(
    options: ConnectOptions,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = Pool::new(options, 1)?;
    let lease = pool.acquire().await?;
    let mut old = lease.serial_channel().await?;
    old.exchange(Batch::new("CREATE TABLE #auth_pool_reset(n int)"))
        .await?
        .finish()
        .await?;
    let original = scalar(&mut old, "SELECT @@SPID").await?;
    if lease.release().await? != ReleaseOutcome::Returned {
        return Err("pool discarded an idle authenticated connection".into());
    }
    let lease = pool.acquire().await?;
    if old.exchange(Batch::new("SELECT 0")).await.is_ok() {
        return Err("old pool channel retained authority".into());
    }
    let mut channel = lease.serial_channel().await?;
    let fetched=channel.exchange(Batch::new("SELECT @@SPID, OBJECT_ID('tempdb..#auth_pool_reset'), CONVERT(nvarchar(128),SUSER_SNAME())")).await?.fetch().await?;
    let row = &fetched.result_sets()[0].rows()?[0];
    if row[0].as_ref().and_then(|v| v.as_integer()) != Some(original)
        || row[1].is_some()
        || row[2]
            .as_ref()
            .and_then(|v| v.as_unicode())
            .ok_or("principal missing after reset")?
            .to_string()?
            .to_lowercase()
            != expected.to_lowercase()
    {
        return Err("pool reset/physical identity evidence disagrees".into());
    }
    channel.close().await?;
    lease.release().await?;
    pool.close().await?;
    Ok(())
}

#[cfg(windows)]
async fn cancel_native_opening(options: ConnectOptions) -> Result<(), Box<dyn std::error::Error>> {
    let began = tokio::time::Instant::now();
    let mut opening = Box::pin(Connection::connect(options));
    loop {
        tokio::select! {
            outcome = &mut opening => {
                if let Ok(connection) = outcome {
                    connection.close().await?;
                }
                return Err("native operation completed before a cancellation window was observed".into());
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(1)) => {
                if tds_client::auth::pending_native_workers() != 0 {
                    break;
                }
            }
        }
    }
    // No connection handle or SQL channel is installed in this probe. The
    // opening future is abandoned while its real native worker is outstanding.
    drop(opening);
    let canceled_ms = began.elapsed().as_millis();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while tds_client::auth::pending_native_workers() != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?;
    println!(
        "{}",
        serde_json::json!({"observed_active_native_worker":true,"opening_canceled":true,
            "application_sql_sent":false,"native_workers_after_cleanup":0,
            "cancel_observed_ms":canceled_ms,"cleanup_observed_ms":began.elapsed().as_millis()})
    );
    Ok(())
}

#[cfg(feature = "encryption")]
async fn encryption_smoke(
    mut options: ConnectOptions,
    key_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use tds_client::{
        IntegerSize, Param, SqlType, Value,
        encryption::{LocalKeyStore, Policies},
    };
    let admin = Connection::connect(options.clone()).await?;
    let database = format!("tds_auth_ae_{}", std::process::id());
    let mut channel = admin.serial_channel().await?;
    channel
        .exchange(Batch::new(format!("CREATE DATABASE {database}")))
        .await?
        .finish()
        .await?;
    channel.close().await?;
    options.database = database.clone();
    options.column_encryption = true;
    let result=async {
        let connection=Connection::connect(options).await?;
        let fixture:serde_json::Value=serde_json::from_str(include_str!("../tests/fixtures/encryption/python.json"))?;
        let wrapped=STANDARD.decode(fixture["wrapped"][0].as_str().ok_or("missing wrapped fixture")?)?;
        let hex:String=wrapped.iter().map(|v|format!("{v:02x}")).collect();
        let mut raw=connection.serial_channel().await?;
        raw.exchange(Batch::new(format!("CREATE COLUMN MASTER KEY cmk WITH (KEY_STORE_PROVIDER_NAME=N'TDS_LOCAL_KEYS',KEY_PATH=N'master.pem'); CREATE COLUMN ENCRYPTION KEY cek WITH VALUES (COLUMN_MASTER_KEY=cmk,ALGORITHM='RSA_OAEP',ENCRYPTED_VALUE=0x{hex})"))).await?.finish().await?;
        raw.exchange(Batch::new("CREATE TABLE dbo.auth_ae(v int ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY=cek,ENCRYPTION_TYPE=DETERMINISTIC,ALGORITHM='AEAD_AES_256_CBC_HMAC_SHA_256'))")).await?.finish().await?;
        raw.close().await?;
        let key_dir=if key_dir.is_empty() { std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/encryption") } else { key_dir.into() };
        let encrypted=connection.encrypted(vec![LocalKeyStore::new("TDS_LOCAL_KEYS",key_dir)?],Policies::default()).await?;
        let mut channel=encrypted.serial_channel().await?;
        channel.exchange(Transaction::Begin(Default::default())).await?.finish().await?;
        channel.execute("INSERT dbo.auth_ae VALUES(@v)","@v int",vec![Param::new("@v",SqlType::Integer{size:IntegerSize::Int},Some(Value::Integer(42)))]).await?.finish().await?;
        let fetched=channel.exchange(Batch::new("SELECT v FROM dbo.auth_ae")).await?.fetch().await?;
        if fetched.result_sets()[0].rows()? != [vec![Some(Value::Integer(42))]] { return Err("encrypted round trip disagrees".into()); }
        if encrypted.statistics().unwraps != 1 || encrypted.statistics().live_columns != 1 { return Err("transaction key reuse disagrees".into()); }
        channel.exchange(Transaction::Commit(Default::default())).await?.finish().await?;
        if encrypted.statistics().live_columns != 0 || encrypted.statistics().live_masters != 0 { return Err("transaction keys survived commit".into()); }
        channel.close().await?;encrypted.close().await;connection.close().await?;
        Ok::<(),Box<dyn std::error::Error>>(())
    }.await;
    let mut cleanup = admin.serial_channel().await?;
    cleanup.exchange(Batch::new(format!("ALTER DATABASE {database} SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE {database}"))).await?.finish().await?;
    cleanup.close().await?;
    admin.close().await?;
    result
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin().take(65537).read_to_end(&mut input)?;
    if input.len() > 65536 {
        return Err("configuration too large".into());
    }
    let mut config: serde_json::Value = serde_json::from_slice(&input)?;
    let password = match config["password"].take() {
        serde_json::Value::String(s) => s,
        _ => String::new(),
    };
    let password = zeroize::Zeroizing::new(password);
    let text = |name: &str| config[name].as_str().unwrap_or_default().to_owned();
    let ca = std::fs::read(text("ca_file"))?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut ca.as_slice()) {
        roots.add(certificate?)?;
    }
    let mut options = ConnectOptions::new(
        text("host"),
        config["port"].as_u64().unwrap_or(1433).try_into()?,
        "",
        "",
        roots,
    );
    options.database = "master".into();
    options.server_name = Some(text("server_name"));
    let timeout = config["timeout_ms"].as_u64().unwrap_or(30000);
    if timeout == 0 || timeout > 60000 {
        return Err("timeout must be between 1 and 60000 milliseconds".into());
    }
    options.timeout = std::time::Duration::from_millis(timeout);
    options.version = if text("tds_version") == "8.0" {
        ProtocolVersion::V8_0
    } else {
        ProtocolVersion::V7_4
    };
    options.mars = config["mars"].as_bool().unwrap_or(false);
    if text("method") == "sql" {
        options.user = text("username");
        options.password = password.to_string();
    } else {
        let method = match text("method").as_str() {
            "ntlm" => Method::Ntlm,
            "kerberos" => Method::Kerberos,
            "negotiate" => Method::Negotiate,
            _ => return Err("unknown method".into()),
        };
        let mut auth = if text("provider") == "native" {
            WindowsAuth::signed_in(method)
        } else {
            WindowsAuth::explicit(method, text("username"), password.to_string())
        };
        if !text("spn").is_empty() {
            auth.service_principal = Some(text("spn"));
        }
        if !text("kdc_url").is_empty() {
            auth.kdc_url = Some(text("kdc_url"));
        }
        auth.allow_ntlm_fallback = config["allow_ntlm_fallback"].as_bool().unwrap_or(false);
        options.windows_auth = Some(auth);
    }
    if config["cancel_on_native_worker"].as_bool().unwrap_or(false) {
        #[cfg(windows)]
        {
            if text("provider") != "native" || text("method") == "sql" {
                return Err(
                    "native cancellation probe requires native Windows authentication".into(),
                );
            }
            return cancel_native_opening(options).await;
        }
        #[cfg(not(windows))]
        return Err("native cancellation probe requires Windows".into());
    }
    let lifecycle = config["lifecycle"].as_bool().unwrap_or(false);
    let pooled = lifecycle.then(|| options.clone());
    let ae = config["local_key_ae"]
        .as_bool()
        .unwrap_or(false)
        .then(|| options.clone());
    let browser = if config["browser"].as_bool().unwrap_or(false) {
        let instance = tds_client::browser::instance(
            &options.host,
            "MSSQLSERVER",
            &tds_client::browser::Options::default(),
        )
        .await?;
        if !instance.server_name.eq_ignore_ascii_case("tdssql")
            || instance.tcp_port()? != Some(options.port)
        {
            return Err("Browser endpoint does not identify the SQL fixture".into());
        }
        Some(instance.version)
    } else {
        None
    };
    let connection = Connection::connect(options).await?;
    let mut channel = connection.serial_channel().await?;
    let mut response=channel.exchange(Batch::new("SELECT CONVERT(nvarchar(128),SUSER_SNAME()), CONVERT(nvarchar(128),ORIGINAL_LOGIN()), CONVERT(nvarchar(128),DB_NAME()), CONVERT(nvarchar(128),net_transport), CONVERT(nvarchar(128),auth_scheme), CONVERT(nvarchar(128),encrypt_option), @@SPID FROM sys.dm_exec_connections WHERE session_id=@@SPID AND parent_connection_id IS NULL")).await?;
    let fetched = response.fetch().await?;
    let mut kept = None;
    for item in fetched.result_sets() {
        for row in item.rows()? {
            if row.len() != 7 {
                return Err("unexpected session evidence shape".into());
            }
            let mut evidence = serde_json::Map::new();
            for (name, value) in [
                "principal",
                "original_login",
                "database",
                "transport",
                "auth_scheme",
                "encrypted",
            ]
            .into_iter()
            .zip(row)
            {
                let text = value
                    .as_ref()
                    .and_then(|value| value.as_unicode())
                    .ok_or("missing session evidence")?
                    .to_string()?;
                evidence.insert(name.into(), text.into());
            }
            evidence.insert(
                "spid".into(),
                row[6]
                    .as_ref()
                    .and_then(|value| value.as_integer())
                    .ok_or("missing SPID")?
                    .into(),
            );
            if kept.replace(evidence).is_some() {
                return Err("more than one session evidence row".into());
            }
        }
    }
    drop(response);
    if lifecycle {
        session_lifecycle(&connection, &mut channel).await?;
    }
    channel.close().await?;
    connection.close().await?;
    let mut kept = kept.ok_or("no session evidence row")?;
    if let Some(options) = pooled {
        pool_lifecycle(
            options,
            kept["principal"].as_str().ok_or("principal missing")?,
        )
        .await?;
        kept.insert("transaction_attention_pool_reset".into(), true.into());
    }
    if let Some(version) = browser {
        kept.insert("browser_sql_version".into(), version.into());
    }
    if let Some(options) = ae {
        #[cfg(feature = "encryption")]
        encryption_smoke(options, &text("ae_key_dir")).await?;
        #[cfg(not(feature = "encryption"))]
        {
            drop(options);
            return Err("local-key smoke requires the encryption feature".into());
        }
        #[cfg(feature = "encryption")]
        kept.insert("local_key_ae_transaction".into(), true.into());
    }
    #[cfg(windows)]
    {
        for _ in 0..100 {
            if tds_client::auth::pending_native_workers() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let pending = tds_client::auth::pending_native_workers();
        if pending != 0 {
            return Err("native worker remained after closing".into());
        }
        kept.insert("native_workers_after_close".into(), pending.into());
    }
    // Keep a common result type on platforms without native worker diagnostics.
    kept.insert("closed".into(), true.into());
    println!("{}", serde_json::Value::Object(kept));
    Ok(())
}
