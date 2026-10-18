#![cfg(feature = "encryption")]
mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value as Json, json};
use tds_client::{
    encryption::{LocalKeyStore, Policies, normalize},
    requests::decode,
    *,
};
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn parameter(text: &str) -> Param {
    let decode::Request::Rpc { mut calls, .. } =
        decode::request(packet::RPC, &unhex(text)).unwrap()
    else {
        panic!("RPC")
    };
    let p = calls.remove(0).parameters.remove(0);
    Param::new("@v", p.type_info.sql_type, p.value.as_ref().cloned())
}
fn corpus() -> Vec<Json> {
    serde_json::from_str(include_str!("fixtures/encryption/sql.json")).unwrap()
}
#[test]
fn every_supported_sql_type_matches_python_normalization_and_exact_denormalization() {
    let mut checked = 0;
    for case in corpus() {
        for e in case["entries"].as_array().unwrap() {
            let p = parameter(e["rpc"].as_str().unwrap());
            let Some(value) = p.value.as_ref() else {
                continue;
            };
            let plain = normalize::normalize(&p.sql_type, value).unwrap();
            assert_eq!(
                hex(plain.as_bytes()),
                e["normal"].as_str().unwrap(),
                "{}",
                case["declared"]
            );
            let decoded = normalize::denormalize(&p.sql_type, plain.as_bytes()).unwrap();
            let expected = parameter(e["decoded_rpc"].as_str().unwrap())
                .value
                .take_scalar()
                .unwrap();
            assert_eq!(decoded, expected, "{}", case["declared"]);
            checked += 1;
        }
    }
    assert_eq!(checked, 56);
    assert!(
        normalize::normalize(
            &SqlType::Integer {
                size: IntegerSize::Tiny
            },
            &Value::Integer(-1)
        )
        .is_err()
    );
    assert!(normalize::denormalize(&SqlType::Bit, &2_i64.to_le_bytes()).is_err());
    assert!(
        normalize::denormalize(
            &SqlType::Integer {
                size: IntegerSize::Small
            },
            &i64::MAX.to_le_bytes()
        )
        .is_err()
    );
}

#[tokio::test]
#[ignore = "requires Docker SQL Server and .NET SqlClient interoperability container"]
async fn rust_and_sqlclient_mutually_read_write_lookup_and_bulk_every_encrypted_sql_type() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let db = format!("tds_rust_ae_{}", std::process::id());
    let options = support::docker_options();
    let password = options.password.clone();
    let admin = Connection::connect(options.clone()).await.unwrap();
    let mut ch = admin.serial_channel().await.unwrap();
    ch.exchange(Batch::new(format!("CREATE DATABASE {db}")))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    ch.close().await.unwrap();
    let mut options = options;
    options.database = db.clone();
    options.column_encryption = true;
    let connection = Connection::connect(options.clone()).await.unwrap();
    let fixture: Json =
        serde_json::from_str(include_str!("fixtures/encryption/python.json")).unwrap();
    let wrapped = STANDARD
        .decode(fixture["wrapped"][0].as_str().unwrap())
        .unwrap();
    let mut raw = connection.serial_channel().await.unwrap();
    raw.exchange(Batch::new(format!("CREATE COLUMN MASTER KEY cmk WITH (KEY_STORE_PROVIDER_NAME=N'TDS_LOCAL_KEYS', KEY_PATH=N'master.pem'); CREATE COLUMN ENCRYPTION KEY cek WITH VALUES (COLUMN_MASTER_KEY=cmk, ALGORITHM='RSA_OAEP', ENCRYPTED_VALUE=0x{})",hex(&wrapped)))).await.unwrap().finish().await.unwrap();
    raw.close().await.unwrap();
    let key_dir = root.join("clients/rust/tests/fixtures/encryption");
    let encrypted = connection
        .encrypted(
            vec![LocalKeyStore::new("TDS_LOCAL_KEYS", &key_dir).unwrap()],
            Policies::default(),
        )
        .await
        .unwrap();
    let mut channel = encrypted.serial_channel().await.unwrap();
    let cases = corpus();
    for (index, case) in cases.iter().enumerate() {
        let declared = case["declared"].as_str().unwrap();
        let collation = case["collation"].as_str().unwrap();
        for prefix in ["rust", "rustb", "net"] {
            let sql = format!(
                "CREATE TABLE dbo.{prefix}_t{index} (id int NOT NULL, d {declared} {collation} ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY=cek,ENCRYPTION_TYPE=DETERMINISTIC,ALGORITHM='AEAD_AES_256_CBC_HMAC_SHA_256'), r {declared} {collation} ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY=cek,ENCRYPTION_TYPE=RANDOMIZED,ALGORITHM='AEAD_AES_256_CBC_HMAC_SHA_256'))"
            );
            channel
                .exchange(Batch::new(sql))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
        }
        let mut rows = vec![];
        for (id, e) in case["entries"].as_array().unwrap().iter().enumerate() {
            let p = parameter(e["rpc"].as_str().unwrap());
            let mut d = p.clone();
            d.name = "@d".into();
            let mut r = p.clone();
            r.name = "@r".into();
            channel
                .execute(
                    &format!("INSERT dbo.rust_t{index} VALUES (@id,@d,@r)"),
                    &format!("@id int,@d {declared},@r {declared}"),
                    vec![
                        Param::new(
                            "@id",
                            SqlType::Integer {
                                size: IntegerSize::Int,
                            },
                            Some(Value::Integer(id as i64)),
                        ),
                        d,
                        r,
                    ],
                )
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            rows.push(vec![
                Some(Value::Integer(id as i64)),
                p.value.as_ref().cloned(),
                p.value.as_ref().cloned(),
            ]);
        }
        let fetched = channel
            .exchange(Batch::new(format!(
                "SELECT TOP 0 id,d,r FROM dbo.rustb_t{index}"
            )))
            .await
            .unwrap()
            .fetch()
            .await
            .unwrap();
        let columns = fetched.result_sets()[0].columns.clone();
        // Fixture strings use the same Latin-1 encoding but a different sort
        // collation. Label bulk bytes explicitly with the destination metadata.
        for row in &mut rows {
            for (column, value) in columns.iter().zip(row) {
                if let (Some(how), Some(Value::Text(text))) = (&column.type_info.encryption, value)
                    && let SqlType::Character { collation, .. }
                    | SqlType::CharacterMax { collation, .. } = &how.base.sql_type
                {
                    text.collation = *collation;
                }
            }
        }
        let cipher = match columns[1].type_info.sql_type {
            SqlType::Binary { length, .. } => format!("varbinary({length})"),
            SqlType::BinaryMax => "varbinary(max)".to_owned(),
            _ => panic!("cipher type"),
        };
        channel
            .bulk(
                format!("INSERT BULK dbo.rustb_t{index} (id int NOT NULL,d {cipher},r {cipher})"),
                columns.clone(),
                rows,
            )
            .await
            .unwrap_or_else(|e| panic!("bulk {declared}: {e}; metadata {columns:?}"));
    }
    channel.close().await.unwrap();
    // Run an independent implementation in Microsoft's SDK image, never through
    // Python's crypto implementation. The fixture generator only supplied values.
    let spec = json!({"database":db,"read":["rust","rustb"],"cases":cases.iter().map(|c|c["spec"].clone()).collect::<Vec<_>>()});
    let mut child = Command::new(root.join("clients/python/tests/dotnet/run.sh"))
        .arg(&key_dir)
        .env("TDS_PASSWORD", password)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(spec.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Json = serde_json::from_str(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    let mut channel = encrypted.serial_channel().await.unwrap();
    for (i, (case, result)) in cases
        .iter()
        .zip(result["cases"].as_array().unwrap())
        .enumerate()
    {
        for prefix in ["rust", "rustb"] {
            let expected = case["expected_net"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| json!([v, v]))
                .collect::<Vec<_>>();
            assert_eq!(
                result["read"][prefix],
                json!(expected),
                "SqlClient read {}",
                case["declared"]
            );
            let lookups = case["entries"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .take(2)
                .map(|(id, e)| {
                    if e["rpc"] == e["net_rpc"] {
                        json!([id])
                    } else {
                        json!([])
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(
                result["lookup"][prefix],
                json!(lookups),
                "SqlClient lookup {}",
                case["declared"]
            );
        }
        if case["declared"] == "time(0)" {
            assert!(
                result["error"]
                    .as_str()
                    .unwrap()
                    .contains("time(7) encrypted")
            );
            continue;
        }
        assert!(
            result.get("error").is_none(),
            "{}: {}",
            case["declared"],
            result
        );
        let fetched = channel
            .exchange(Batch::new(format!(
                "SELECT d,r FROM dbo.net_t{i} ORDER BY id"
            )))
            .await
            .unwrap()
            .fetch()
            .await
            .unwrap();
        for (row, e) in fetched.result_sets()[0]
            .rows()
            .unwrap()
            .iter()
            .zip(case["entries"].as_array().unwrap())
        {
            let mut p = parameter(e["net_rpc"].as_str().unwrap());
            let base = &fetched.result_sets()[0].columns[0]
                .type_info
                .encryption
                .as_ref()
                .unwrap()
                .base
                .sql_type;
            if let Some(Value::Text(text)) = p.value.as_ref().cloned() {
                let mut text = text;
                if let SqlType::Character { collation, .. }
                | SqlType::CharacterMax { collation, .. } = base
                {
                    text.collation = *collation;
                    p.value = ParamValue::Scalar(Some(Value::Text(text)));
                    p.sql_type = base.clone();
                }
            }
            let expected = p.value.as_ref().map(|v| {
                normalize::denormalize(
                    &p.sql_type,
                    normalize::normalize(&p.sql_type, v).unwrap().as_bytes(),
                )
                .unwrap()
            });
            assert_eq!(
                row,
                &vec![expected.clone(), expected],
                "Rust read {}",
                case["declared"]
            );
        }
        let declared = case["declared"].as_str().unwrap();
        for (id, e) in case["entries"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .take(2)
        {
            let mut p = parameter(e["net_rpc"].as_str().unwrap());
            p.name = "@d".into();
            let found = channel
                .execute(
                    &format!("SELECT id FROM dbo.net_t{i} WHERE d=@d"),
                    &format!("@d {declared}"),
                    vec![p],
                )
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(
                found.result_sets()[0].rows().unwrap(),
                &[vec![Some(Value::Integer(id as i64))]],
                "Rust lookup {}",
                case["declared"]
            );
        }
    }
    println!(
        "AE_INTEROP types={} insert_rows={} bulk_rows={} net_write_types={} statistics={:?}",
        cases.len(),
        cases
            .iter()
            .map(|c| c["entries"].as_array().unwrap().len())
            .sum::<usize>(),
        cases
            .iter()
            .map(|c| c["entries"].as_array().unwrap().len())
            .sum::<usize>(),
        cases.len() - 1,
        encrypted.statistics()
    );
    channel.close().await.unwrap();
    encrypted.close().await;
    connection.close().await.unwrap();
    let mut cleanup = admin.serial_channel().await.unwrap();
    cleanup
        .exchange(Batch::new(format!(
            "ALTER DATABASE {db} SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE {db}"
        )))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    cleanup.close().await.unwrap();
    admin.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires Docker SQL Server; encryption lifecycle matrix"]
async fn transparent_encryption_policies_outputs_cancellation_pool_reset_and_large_values() {
    use encryption::{Error as CryptoError, Policy};
    use std::time::Duration;
    let mut options = support::docker_options();
    let db = format!("tds_rust_ae_lifecycle_{}", std::process::id());
    let admin = Connection::connect(options.clone()).await.unwrap();
    let mut raw = admin.serial_channel().await.unwrap();
    raw.exchange(Batch::new(format!("CREATE DATABASE {db}")))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    raw.close().await.unwrap();
    options.database = db.clone();
    options.column_encryption = true;
    let setup = Connection::connect(options.clone()).await.unwrap();
    let f: Json = serde_json::from_str(include_str!("fixtures/encryption/python.json")).unwrap();
    let wrapped = STANDARD.decode(f["wrapped"][0].as_str().unwrap()).unwrap();
    let mut raw = setup.serial_channel().await.unwrap();
    raw.exchange(Batch::new(format!("CREATE COLUMN MASTER KEY cmk WITH (KEY_STORE_PROVIDER_NAME=N'TDS_LOCAL_KEYS',KEY_PATH=N'master.pem'); CREATE COLUMN ENCRYPTION KEY cek WITH VALUES (COLUMN_MASTER_KEY=cmk,ALGORITHM='RSA_OAEP',ENCRYPTED_VALUE=0x{})",hex(&wrapped)))).await.unwrap().finish().await.unwrap();
    raw.exchange(Batch::new("CREATE TABLE dbo.policy (id int,v int ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY=cek,ENCRYPTION_TYPE=DETERMINISTIC,ALGORITHM='AEAD_AES_256_CBC_HMAC_SHA_256')); CREATE TABLE dbo.large_ae (v varbinary(max) ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY=cek,ENCRYPTION_TYPE=RANDOMIZED,ALGORITHM='AEAD_AES_256_CBC_HMAC_SHA_256'))")).await.unwrap().finish().await.unwrap();
    raw.close().await.unwrap();
    setup.close().await.unwrap();
    let key_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/encryption");
    let int = SqlType::Integer {
        size: IntegerSize::Int,
    };
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            options.version = version;
            options.mars = mars;
            let pool = Pool::new(options.clone(), 1).unwrap();
            let lease = pool.acquire().await.unwrap();
            let enc = lease
                .encrypted(
                    vec![LocalKeyStore::new("TDS_LOCAL_KEYS", &key_dir).unwrap()],
                    Policies::default(),
                )
                .await
                .unwrap();
            let mut ch = enc.serial_channel().await.unwrap();
            ch.exchange(Batch::new("DELETE dbo.policy; DELETE dbo.large_ae"))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            ch.execute(
                "INSERT dbo.policy VALUES (1,@v)",
                "@v int",
                vec![Param::new("@v", int.clone(), Some(Value::Integer(42)))],
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
            assert_eq!(enc.statistics().live_columns, 0);
            ch.exchange(Transaction::Begin(Default::default()))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            let before = enc.statistics().unwraps;
            for _ in 0..2 {
                let f = ch
                    .exchange(Batch::new("SELECT v FROM dbo.policy"))
                    .await
                    .unwrap()
                    .fetch()
                    .await
                    .unwrap();
                assert_eq!(
                    f.result_sets()[0].rows().unwrap(),
                    &[vec![Some(Value::Integer(42))]]
                );
            }
            assert_eq!(enc.statistics().unwraps, before + 1);
            assert_eq!(enc.statistics().live_columns, 1);
            let before_exchange = enc.statistics().unwraps;
            for _ in 0..2 {
                ch.exchange_with(
                    Batch::new("SELECT v FROM dbo.policy"),
                    Some(Policies {
                        master: Policy::Exchange,
                        column: Policy::Exchange,
                        ..Policies::default()
                    }),
                )
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            }
            assert_eq!(enc.statistics().unwraps, before_exchange + 2);
            assert_eq!(enc.statistics().live_columns, 1);

            let output = ch
                .execute(
                    "SELECT @o=v FROM dbo.policy WHERE id=1",
                    "@o int OUTPUT",
                    vec![Param::new("@o", int.clone(), None).output()],
                )
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert!(
                output
                    .returns()
                    .iter()
                    .flat_map(|r| &r.outputs)
                    .any(|o| o.value == Some(Value::Integer(42))),
                "{output:?}"
            );
            let mut response = ch
                .exchange(Batch::new(
                    "SELECT TOP (100000) p.v FROM dbo.policy p CROSS JOIN sys.all_objects a CROSS JOIN sys.all_objects b; WAITFOR DELAY '00:00:30'",
                ))
                .await
                .unwrap();
            while !matches!(response.next().await.unwrap(), Some(Record::Row(_))) {}
            response.cancel_handle().cancel();
            let canceled = response.finish().await.unwrap_err();
            assert!(matches!(canceled.cause().kind, ErrorKind::Canceled));
            let canceled = canceled.response.as_ref().unwrap();
            assert!(canceled.ended && canceled.canceled, "{canceled:?}");
            drop(response);
            let f = ch
                .exchange(Batch::new("SELECT v FROM dbo.policy"))
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(
                f.result_sets()[0].rows().unwrap()[0][0],
                Some(Value::Integer(42))
            );
            ch.exchange(Transaction::Rollback(Default::default()))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            assert_eq!(enc.statistics().live_columns, 0);
            // Fixed-age retention crosses autocommit exchange boundaries, then
            // reacquires after idle expiry. A long transaction remains usable.
            ch.close().await.unwrap();
            let mut enc = enc;
            enc.set_policies(Policies {
                master: Policy::Time(Duration::from_millis(500)),
                column: Policy::Time(Duration::from_millis(500)),
                ..Policies::default()
            })
            .unwrap();
            let mut ch = enc.serial_channel().await.unwrap();
            let before = enc.statistics().unwraps;
            for _ in 0..2 {
                ch.exchange(Batch::new("SELECT v FROM dbo.policy"))
                    .await
                    .unwrap()
                    .fetch()
                    .await
                    .unwrap();
            }
            assert_eq!(enc.statistics().unwraps, before + 1);
            ch.exchange(Transaction::Begin(Default::default()))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(700)).await;
            ch.exchange(Batch::new("SELECT v FROM dbo.policy"))
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(enc.statistics().unwraps, before + 2);
            println!(
                "AE_COUNTS {version:?} mars={mars} time_reacquisitions={} statistics={:?}",
                enc.statistics().unwraps - before,
                enc.statistics()
            );
            ch.exchange(Transaction::Rollback(Default::default()))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            // Complete encrypted PLP cells cross the ordinary 1 MiB token bound.
            let bytes = vec![0x5a; 1024 * 1024 + 17];
            ch.execute(
                "INSERT dbo.large_ae VALUES (@v)",
                "@v varbinary(max)",
                vec![Param::new(
                    "@v",
                    SqlType::BinaryMax,
                    Some(Value::Binary(bytes.clone())),
                )],
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
            let f = ch
                .exchange(Batch::new("SELECT v FROM dbo.large_ae"))
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(
                f.result_sets()[0].rows().unwrap()[0][0],
                Some(Value::Binary(bytes))
            );
            ch.close().await.unwrap();
            enc.close().await;
            assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Returned);
            let lease = pool.acquire().await.unwrap();
            // A new wrapper flushes the deferred reset before acquiring a key.
            let enc = lease
                .encrypted(
                    vec![LocalKeyStore::new("TDS_LOCAL_KEYS", &key_dir).unwrap()],
                    Policies::default(),
                )
                .await
                .unwrap();
            let mut ch = enc.serial_channel().await.unwrap();
            let f = ch
                .exchange(Batch::new("SELECT v FROM dbo.policy"))
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(
                f.result_sets()[0].rows().unwrap()[0][0],
                Some(Value::Integer(42))
            );
            assert_eq!(enc.statistics().unwraps, 1);
            ch.close().await.unwrap();
            enc.close().await;
            assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Returned);
            pool.close().await.unwrap();
            println!(
                "AE_LIFECYCLE {version:?} mars={mars} transaction/output/cancel/age/large/pool-reset passed"
            );
        }
    }
    // No configured provider: an explicit failed-cell marker, then readable DONE.
    let connection = Connection::connect(options.clone()).await.unwrap();
    let enc = connection
        .encrypted(
            vec![LocalKeyStore::new("UNREGISTERED", &key_dir).unwrap()],
            Policies::default(),
        )
        .await
        .unwrap();
    let mut ch = enc.serial_channel().await.unwrap();
    let f = ch
        .exchange(Batch::new("SELECT v FROM dbo.policy"))
        .await
        .unwrap()
        .fetch()
        .await
        .unwrap();
    assert!(
        matches!(&f.result_sets()[0].rows().unwrap()[0][0],Some(Value::NotDecrypted {reason,..}) if reason==&CryptoError::KeyUnavailable.to_string())
    );
    ch.close().await.unwrap();
    enc.close().await;
    connection.close().await.unwrap();
    let mut cleanup = admin.serial_channel().await.unwrap();
    cleanup
        .exchange(Batch::new(format!(
            "ALTER DATABASE {db} SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE {db}"
        )))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    cleanup.close().await.unwrap();
    admin.close().await.unwrap();
}

#[derive(Clone, Default)]
struct CaptureBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for CaptureBuffer {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[tokio::test]
async fn authenticated_cells_tampering_nulls_discard_and_raw_capture_keep_their_boundaries() {
    use std::sync::{Arc, Mutex};
    use tds_client::{
        capture::Capture,
        observe::{Level, Observer},
    };
    let (listener, mut options) = support::listener().await;
    options.column_encryption = true;
    let capture = CaptureBuffer::default();
    let captured = capture.clone();
    options.capture_factory = Some(Arc::new(move || Ok(Capture::new(captured.clone()))));
    let observations = Arc::new(Mutex::new(String::new()));
    let observed = observations.clone();
    options.observe = Some(Observer::new(Level::Full, move |event| {
        observed.lock().unwrap().push_str(&format!("{event:?}"));
        Ok(())
    }));
    let fixture: Json =
        serde_json::from_str(include_str!("fixtures/encryption/authenticated.json")).unwrap();
    let canary = fixture["canary"].as_str().unwrap().to_owned();
    let body = unhex(fixture["body"].as_str().unwrap());
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = support::Peer::await_login(socket, false).await;
        // Feature4/version1 plus the current SQL collation.
        peer.accept_login(
            0x74000004,
            false,
            &[
                0xae, 4, 1, 0, 0, 0, 1, 255, 0xe3, 8, 0, 7, 5, 9, 4, 0xd0, 0, 0x34, 0,
            ],
        )
        .await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(&support::done(0)).await; // bootstrap
        for _ in 0..2 {
            assert_eq!(peer.message().await.0, packet::BATCH);
            peer.reply_in_packets(&body, 37).await;
        }
        assert_eq!(peer.message().await.0, packet::BATCH); // bulk preparation
        peer.reply(&support::done(0)).await;
        let (kind, bulk) = peer.message().await;
        assert_eq!(kind, packet::BULK);
        let records = decode::bulk_with_encryption(&bulk, true).unwrap();
        assert!(
            matches!(&records[1],Record::Row(row) if matches!(&row[0],Some(Value::Encrypted(_))))
        );
        peer.reply(&body).await; // also authenticate bulk's returned rows
        let (kind, describe) = peer.message().await;
        assert_eq!(kind, packet::RPC);
        let decode::Request::Rpc { calls, .. } = decode::request(kind, &describe).unwrap() else {
            panic!("describe RPC")
        };
        assert!(
            matches!(&calls[0].procedure,decode::Procedure::Name(name) if name==&"sp_describe_parameter_encryption".into())
        );
        let mut error = 33277_i32.to_le_bytes().to_vec();
        error.extend([1, 16]);
        let text: Vec<u16> = "description refused".encode_utf16().collect();
        error.extend((text.len() as u16).to_le_bytes());
        error.extend(text.iter().flat_map(|u| u.to_le_bytes()));
        error.extend([0, 0]);
        error.extend(1_u32.to_le_bytes());
        let mut reply = vec![0xaa];
        reply.extend((error.len() as u16).to_le_bytes());
        reply.extend(error);
        reply.extend(support::done(2));
        peer.reply(&reply).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(&support::done(0)).await; // reuse, no application UPDATE
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let key_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/encryption");
    let enc = connection
        .encrypted(
            vec![LocalKeyStore::new("TDS_LOCAL_KEYS", key_dir).unwrap()],
            Policies::default(),
        )
        .await
        .unwrap();
    let mut ch = enc.serial_channel().await.unwrap();
    let f = ch
        .exchange(Batch::new("SELECT encrypted_value"))
        .await
        .unwrap()
        .fetch()
        .await
        .unwrap();
    let rows = f.result_sets()[0].rows().unwrap();
    assert_eq!(rows[0][0], Some(Value::Unicode(canary.as_str().into())));
    assert!(
        matches!(&rows[1][0],Some(Value::NotDecrypted {reason,..}) if reason.contains("authenticate"))
    );
    assert_eq!(rows[2][0], None);
    assert_eq!(rows[3][0], rows[0][0]);
    let before = enc.statistics().unwraps;
    ch.exchange(Batch::new("SELECT discarded_encrypted_value"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    assert_eq!(
        enc.statistics().unwraps,
        before,
        "discarded rows should not load/unwrap/decrypt"
    );
    let invalid = ch
        .execute(
            "INSERT t VALUES (@v)",
            "@v tinyint",
            vec![Param::new(
                "@v",
                SqlType::Integer {
                    size: IntegerSize::Tiny,
                },
                Some(Value::Integer(-1)),
            )],
        )
        .await
        .err()
        .expect("invalid scalar refused");
    assert_eq!(invalid.execution, Execution::NotSent);
    let returned = ch
        .bulk(
            "INSERT BULK synthetic (v varbinary(129))",
            f.result_sets()[0].columns.clone(),
            vec![vec![Some(Value::Unicode(canary.as_str().into()))]],
        )
        .await
        .unwrap();
    let returned = returned.result_sets()[0].rows().unwrap();
    assert_eq!(returned[0][0], Some(Value::Unicode(canary.as_str().into())));
    assert!(matches!(&returned[1][0], Some(Value::NotDecrypted { .. })));
    assert_eq!(
        enc.statistics().unwraps,
        before + 1,
        "bulk inputs and returned rows share one guard"
    );
    let refused = ch
        .execute(
            "UPDATE synthetic SET v=@v",
            "@v int",
            vec![Param::new(
                "@v",
                SqlType::Integer {
                    size: IntegerSize::Int,
                },
                Some(Value::Integer(42)),
            )],
        )
        .await
        .err()
        .expect("description refused");
    assert_eq!(refused.execution, Execution::NotSent);
    assert!(matches!(refused.kind, ErrorKind::ServerErrors(_)));
    ch.exchange(Batch::new("SELECT safe_reuse_after_describe_error"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    ch.close().await.unwrap();
    enc.close().await;
    connection.close().await.unwrap();
    server.await.unwrap();
    let bytes = capture.0.lock().unwrap().clone();
    let mut replayed = vec![];
    let summary = replay::replay(bytes.as_slice(), |item| {
        replayed.push(item);
        Ok(())
    })
    .unwrap();
    assert_eq!(summary.issues, 0, "{replayed:?}");
    assert!(replayed.iter().any(|i|matches!(&i.content,replay::Content::Record(r) if matches!(r.as_ref(),Record::Row(row) if matches!(&row[0],Some(Value::Encrypted(_)))))));
    let visible = String::from_utf8(bytes).unwrap() + &observations.lock().unwrap();
    assert!(!visible.contains(&canary));
    assert!(!visible.contains("BEGIN PRIVATE KEY"));
    assert!(!format!("{replayed:?}").contains(&canary));
}
