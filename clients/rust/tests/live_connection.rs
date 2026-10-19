//! Explicit live acceptance. Run --ignored; unavailable setup is a failure.
//! All tests read the same ignored credentials/CA used by the Python suite.
use std::{path::PathBuf, time::Duration};
use tds_client::Value::Integer as Int;
use tds_client::{Batch, Connection, ErrorKind, Record};
mod support;
use support::docker_options as options;

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn one_hop_router_reaches_docker_with_two_independent_recordings() {
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };
    use tds_client::capture::Capture;
    #[derive(Clone, Default)]
    struct Output(Arc<Mutex<Vec<u8>>>);
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for version in [
        tds_client::ProtocolVersion::V7_4,
        tds_client::ProtocolVersion::V8_0,
    ] {
        for mars in [false, true] {
            let mut config = options();
            config.version = version;
            config.mars = mars;
            let destination_port = config.port;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let source_port = listener.local_addr().unwrap().port();
            config.port = source_port;
            config.server_name = Some("router.test".into());
            for certificate in
                rustls_pemfile::certs(&mut include_bytes!("fixtures/test-ca.pem").as_slice())
            {
                config.roots.add(certificate.unwrap()).unwrap();
            }
            let outputs = Arc::new(Mutex::new(Vec::<Output>::new()));
            let recordings = outputs.clone();
            config.capture_factory = Some(Arc::new(move || {
                let output = Output::default();
                recordings.lock().unwrap().push(output.clone());
                Ok(Capture::new(output))
            }));
            let router = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let (mut peer, _) = support::Peer::await_login_protocol(
                    socket,
                    mars,
                    include_bytes!("fixtures/test-router.pem"),
                    version,
                )
                .await;
                peer.accept_login(
                    0x74000004,
                    mars,
                    &support::routing("localhost", destination_port, 0, 0),
                )
                .await;
                peer.drain_to_eof().await;
            });
            let connection = Connection::connect(config).await.unwrap();
            assert_eq!(connection.routed_from.as_ref().unwrap().port, source_port);
            let mut channel = connection.serial_channel().await.unwrap();
            assert_eq!(
                rows(&mut channel, "SELECT 42 AS a").await,
                [vec![Some(Int(42))]]
            );
            channel.close().await.unwrap();
            connection.close().await.unwrap();
            router.await.unwrap();
            let outputs = outputs.lock().unwrap();
            assert_eq!(outputs.len(), 2);
            for output in outputs.iter() {
                let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
                let lines: Vec<serde_json::Value> = text
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                assert_eq!(
                    lines
                        .iter()
                        .filter(|line| line["text"] == "← login reply")
                        .count(),
                    1
                );
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn observation_failure_and_recording_work_in_each_transport_mode() {
    use std::{
        io::{self, Write},
        sync::Arc,
    };
    use tds_client::{
        capture::Capture,
        observe::{Level, Observer},
    };
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("recording unavailable"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let output = std::env::var_os("TDS_CAPTURE_PROBE_DIR").map(PathBuf::from);
    for version in [
        tds_client::ProtocolVersion::V7_4,
        tds_client::ProtocolVersion::V8_0,
    ] {
        for mars in [false, true] {
            let path = output
                .clone()
                .unwrap_or_else(std::env::temp_dir)
                .join(format!(
                    "rust-{version:?}-{mars}-{}-{}.jsonl",
                    std::process::id(),
                    time::OffsetDateTime::now_utc().unix_timestamp_nanos()
                ));
            let file = path.clone();
            let mut config = options();
            config.version = version;
            config.mars = mars;
            config.capture_factory = Some(Arc::new(move || Capture::create(&file)));
            config.observe = Some(Observer::new(Level::Full, |event| {
                if event.kind == "channel" {
                    Err(io::Error::other("display failed"))
                } else {
                    Ok(())
                }
            }));
            let connection = Connection::connect(config).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            assert!(connection.observation_error().is_some());
            assert_eq!(
                rows(&mut channel, "SELECT 42 AS a").await,
                vec![vec![Some(Int(42))]]
            );
            assert_eq!(
                rows(&mut channel, "SELECT 43 AS a").await,
                vec![vec![Some(Int(43))]]
            );
            channel.close().await.unwrap();
            connection.close().await.unwrap();
            let content = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<serde_json::Value> = content
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(lines[0]["t"], 0);
            assert!(lines[0]["start"].as_str().unwrap().ends_with('Z'));
            assert_eq!(
                lines
                    .iter()
                    .filter(|line| line["text"]
                        .as_str()
                        .is_some_and(|text| text.contains("SQL batch")))
                    .count(),
                2
            );
            if output.is_none() {
                std::fs::remove_file(path).unwrap();
            }

            let mut config = options();
            config.version = version;
            config.mars = mars;
            let connection = Connection::connect(config).await.unwrap();
            connection
                .set_capture(Some(Capture::new(Broken)))
                .await
                .unwrap();
            let error = connection.serial_channel().await.err().unwrap();
            assert!(matches!(error.cause().kind, ErrorKind::Capture(_)));
            assert!(connection.is_closed());
            connection.close().await.unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn login_options_choose_session_defaults_and_identify_the_connection() {
    for version in [
        tds_client::ProtocolVersion::V7_4,
        tds_client::ProtocolVersion::V8_0,
    ] {
        for mars in [false, true] {
            for odbc in [false, true] {
                let mut config = options();
                config.version = version;
                config.mars = mars;
                config.odbc = odbc;
                config.language = "Deutsch".into();
                config.app_name = "rust-service-λ".into();
                config.host_name = Some("rust-host-1".into());
                config.read_only_intent = true;
                let connection = Connection::connect(config).await.unwrap();
                assert_eq!(
                    connection
                        .session()
                        .await
                        .unwrap()
                        .language
                        .to_string()
                        .unwrap(),
                    "Deutsch"
                );
                let mut channel = connection.serial_channel().await.unwrap();
                assert_eq!(rows(&mut channel, "SELECT CASE WHEN APP_NAME() = N'rust-service-λ' AND HOST_NAME() = N'rust-host-1' THEN 1 ELSE 0 END, host_process_id FROM sys.dm_exec_sessions WHERE session_id = @@SPID").await,
                    [vec![Some(Int(1)), Some(Int(i64::from(std::process::id())))]]);
                let settings = rows(&mut channel, "SELECT CAST(SESSIONPROPERTY('ANSI_NULLS') AS int), CAST(SESSIONPROPERTY('ANSI_PADDING') AS int), CAST(SESSIONPROPERTY('ANSI_WARNINGS') AS int), CAST(SESSIONPROPERTY('CONCAT_NULL_YIELDS_NULL') AS int), CAST(SESSIONPROPERTY('QUOTED_IDENTIFIER') AS int), CAST(SESSIONPROPERTY('ARITHABORT') AS int), @@TEXTSIZE").await;
                let expected = if odbc {
                    vec![1, 1, 1, 1, 1, 0, -1]
                } else {
                    vec![0, 0, 0, 0, 0, 0, 4096]
                };
                assert_eq!(
                    settings,
                    [expected
                        .into_iter()
                        .map(|n| Some(Int(n)))
                        .collect::<Vec<_>>()]
                );
                // Read-only intent is a routing hint; a writable SQL Server
                // remains writable. Permissions still belong to the server.
                assert_eq!(rows(&mut channel, "CREATE TABLE #intent (n int); INSERT #intent VALUES (7); SELECT n FROM #intent").await, [vec![Some(Int(7))]]);
                channel.close().await.unwrap();
                connection.close().await.unwrap();
            }
            let mut config = options();
            config.version = version;
            config.mars = mars;
            config.language.clear();
            config.host_name = None;
            assert!(config.odbc); // the application defaults, rather than an explicit override
            let connection = Connection::connect(config).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            assert_eq!(rows(&mut channel, "SELECT CASE WHEN @@LANGUAGE = (SELECT default_language_name FROM sys.server_principals WHERE name = ORIGINAL_LOGIN()) THEN 1 ELSE 0 END").await, [vec![Some(Int(1))]]);
            channel.close().await.unwrap();
            connection.close().await.unwrap();

            let mut config = options();
            config.version = version;
            config.mars = mars;
            config.language = "tds_language_that_does_not_exist".into();
            let error = Connection::connect(config).await.err().unwrap();
            assert_eq!(error.step, tds_client::Step::Login);
            assert!(matches!(error.kind, ErrorKind::Server(_)));
        }
    }
}

async fn rows(channel: &mut tds_client::SerialChannel, sql: &str) -> Vec<tds_client::Row> {
    let mut response = channel.exchange(Batch::new(sql)).await.expect("send batch");
    let mut rows = Vec::new();
    let mut final_done = false;
    while let Some(item) = response.next().await.expect("read response") {
        match item {
            Record::Row(row) => rows.push(row),
            Record::Error(error) => panic!("SQL error {}", error.number),
            Record::Done(done) if done.is_final() => {
                assert!(!done.has_error());
                final_done = true;
            }
            _ => {}
        }
    }
    assert!(final_done);
    rows
}

async fn records(
    channel: &mut tds_client::SerialChannel,
    sql: &str,
) -> tds_client::Result<Vec<Record>> {
    let mut response = channel.exchange(Batch::new(sql)).await?;
    let mut items = Vec::new();
    while let Some(item) = response.next().await? {
        items.push(item);
    }
    Ok(items)
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn checked_finish_fetch_and_partial_fetch_preserve_python_reading_rules() {
    for version in [
        tds_client::ProtocolVersion::V7_4,
        tds_client::ProtocolVersion::V8_0,
    ] {
        let mut config = options();
        config.version = version;
        let connection = Connection::connect(config).await.unwrap();
        let mut channel = connection.serial_channel().await.unwrap();
        {
            let mut response = channel
                .exchange(Batch::new("SELECT 1 UNION ALL SELECT 2"))
                .await
                .unwrap();
            response.finish().await.unwrap();
            let record = response.snapshot();
            assert!(record.ended);
            assert_eq!(record.result_sets()[0].rows_read, 2);
            assert!(matches!(
                record.result_sets()[0].rows(),
                Err(tds_client::RowsNotAvailable::NotRetained { rows_read: 2 })
            ));
        }
        let fetched = {
            let mut response = channel.exchange(Batch::new("PRINT N'Rust response test'; SELECT n FROM (VALUES (3), (1), (2)) v(n) ORDER BY n; SELECT CAST(NULL AS int) AS nothing WHERE 1 = 0")).await.unwrap();
            response.fetch().await.unwrap()
        };
        assert_eq!(fetched.messages().count(), 1);
        assert_eq!(
            fetched.result_sets()[0].rows().unwrap(),
            &[vec![Some(Int(1))], vec![Some(Int(2))], vec![Some(Int(3))]]
        );
        assert!(fetched.result_sets()[1].rows().unwrap().is_empty());
        {
            let mut response = channel
                .exchange(Batch::new("SELECT 1 UNION ALL SELECT 2; SELECT 3"))
                .await
                .unwrap();
            while !matches!(response.next().await.unwrap(), Some(Record::Row(_))) {}
            let partial = response.fetch().await.unwrap();
            assert!(matches!(
                partial.result_sets()[0].rows(),
                Err(tds_client::RowsNotAvailable::NotRetained { rows_read: 2 })
            ));
            assert_eq!(
                partial.result_sets()[1].rows().unwrap(),
                &[vec![Some(Int(3))]]
            );
            let mut remaining = Vec::new();
            while let Some(record) = response.next().await.unwrap() {
                if let Record::Row(row) = record {
                    remaining.push(row);
                }
            }
            assert_eq!(remaining, [vec![Some(Int(2))], vec![Some(Int(3))]]);
        }
        {
            let mut response = channel.exchange(Batch::new("SET ANSI_WARNINGS ON; SELECT 11; SELECT 1 / 0; SELECT 22; SET ANSI_WARNINGS OFF")).await.unwrap();
            let error = response.fetch().await.unwrap_err();
            assert!(
                matches!(error.kind, ErrorKind::ServerErrors(ref errors) if errors.iter().any(|error| error.number == 8134))
            );
            let record = error.response.unwrap();
            assert!(record.ended);
            assert_eq!(record.result_sets().len(), 3);
            assert_eq!(
                record.result_sets()[0].rows().unwrap(),
                &[vec![Some(Int(11))]]
            );
            assert_eq!(
                record.result_sets()[2].rows().unwrap(),
                &[vec![Some(Int(22))]]
            );
            response.finish().await.unwrap(); // Already reported, never twice.
        }
        assert_eq!(rows(&mut channel, "SELECT 42").await, [vec![Some(Int(42))]]);
        channel.close().await.unwrap();
        connection.close().await.unwrap();
        assert_eq!(fetched.result_sets()[0].rows().unwrap().len(), 3);
    }
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn delegated_channel_close_drains_before_reopen_and_stale_authority_is_rejected() {
    for version in [
        tds_client::ProtocolVersion::V7_4,
        tds_client::ProtocolVersion::V8_0,
    ] {
        let mut config = options();
        config.version = version;
        let connection = Connection::connect(config).await.unwrap();
        let mut old = connection.serial_channel().await.unwrap();
        let close = old.close_handle();
        let mut response = old.exchange(Batch::new("SELECT TOP (100000) 11 FROM sys.all_objects a CROSS JOIN sys.all_objects b; WAITFOR DELAY '00:00:10'; SELECT 12")).await.unwrap();
        while !matches!(response.next().await.unwrap(), Some(Record::Row(_))) {}
        let (closed, owner) = tokio::join!(close.close(), response.finish());
        closed.unwrap();
        assert!(owner.is_err());
        let record = response.snapshot();
        assert!(record.ended && record.canceled);
        assert!(record.completions().last().unwrap().acknowledges_cancel());
        let mut replacement = connection.serial_channel().await.unwrap();
        drop(response);
        close.close().await.unwrap();
        assert!(old.exchange(Batch::new("SELECT 999")).await.is_err());
        assert_eq!(
            rows(&mut replacement, "SELECT 42").await,
            [vec![Some(Int(42))]]
        );
        drop(old);
        assert!(!connection.is_closed());
        replacement.close().await.unwrap();
        connection.close().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn restricted_database_principal_receives_denial_without_automatic_grants() {
    // Privileged setup is distinct from assertions under the restricted token.
    // This tests EXECUTE AS USER, not a separately authenticated low-privilege login.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("tds_rust_perm_{}_{nonce:x}", std::process::id());
    let admin = Connection::connect(options()).await.unwrap();
    let mut setup = admin.serial_channel().await.unwrap();
    let creation = records(&mut setup,&format!("SET XACT_ABORT ON; BEGIN TRANSACTION; CREATE USER [{name}] WITHOUT LOGIN; CREATE TABLE dbo.[{name}] (id int NOT NULL); INSERT dbo.[{name}] VALUES (1); DENY SELECT ON OBJECT::dbo.[{name}] TO [{name}]; COMMIT TRANSACTION;")).await;
    let created = creation.as_ref().is_ok_and(|items| {
        !items
            .iter()
            .any(|record| matches!(record, Record::Error(_)))
    });
    let observations = async {
        if !created {
            return Err(tds_client::Error {
                password_change_uncertain: false,
                step: tds_client::Step::Exchange,
                execution: tds_client::Execution::NotSent,
                kind: ErrorKind::State("restricted-principal setup failed"),
                response: None,
            });
        }
        let connection = Connection::connect(options()).await?;
        let mut channel = connection.serial_channel().await?;
        let observations = async {
            let allowed = records(
                &mut channel,
                &format!("EXECUTE AS USER = N'{name}'; SELECT 1, IS_ROLEMEMBER(N'db_owner')"),
            )
            .await?;
            let denied = records(&mut channel, &format!("SELECT id FROM dbo.[{name}]"))
                .await
                .unwrap_err();
            let reused = records(&mut channel, "SELECT 2").await?;
            Ok::<_, tds_client::Error>((allowed, denied, reused))
        }
        .await;
        drop(channel);
        connection.close().await?;
        observations
    }
    .await;
    // Clean up before asserting observations, so an assertion failure does not
    // strand a principal or object. Setup uses a private transaction/name.
    let cleanup = records(&mut setup,&format!("IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION; DROP TABLE IF EXISTS dbo.[{name}]; DROP USER IF EXISTS [{name}];")).await;
    setup.close().await.unwrap();
    admin.close().await.unwrap();
    assert!(
        !cleanup
            .unwrap()
            .iter()
            .any(|record| matches!(record, Record::Error(_)))
    );
    assert!(created, "principal setup failed: {creation:?}");
    let (allowed, denied, reused) = observations.unwrap();
    assert!(allowed.iter().any(
        |record| matches!(record,Record::Row(row) if row == &vec![Some(Int(1)),Some(Int(0))])
    ));
    assert!(
        matches!(denied.kind, ErrorKind::ServerErrors(ref errors) if errors.iter().any(|error| error.number == 229))
    );
    assert!(
        denied
            .response
            .unwrap()
            .completions()
            .any(|done| done.is_final() && done.has_error())
    );
    assert!(
        reused
            .iter()
            .any(|record| matches!(record,Record::Row(row) if row == &vec![Some(Int(2))]))
    );
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn verified_login_two_exchanges_and_clean_close() {
    for version in [
        tds_client::ProtocolVersion::V7_4,
        tds_client::ProtocolVersion::V8_0,
    ] {
        let mut config = options();
        config.version = version;
        let connection = Connection::connect(config)
            .await
            .expect("verified TDS login");
        let session = connection.session().await.unwrap();
        assert_eq!(session.database.to_string().unwrap(), "tds_test");
        assert_eq!(session.language.to_string().unwrap(), "us_english");
        let [major, minor, hi, lo] = session.server_version.unwrap();
        println!(
            "verified {version:?} / {:?}; SQL Server {major}.{minor}.{}; packet size {}; database tds_test",
            session.tls_version.unwrap(),
            u16::from_be_bytes([hi, lo]),
            session.packet_size
        );
        let mut channel = connection.serial_channel().await.unwrap();
        assert!(connection.serial_channel().await.is_err());
        assert_eq!(
            rows(&mut channel, "SELECT 1").await,
            vec![vec![Some(Int(1))]]
        );
        assert_eq!(rows(&mut channel,"SELECT CAST(-32768 AS smallint), CAST(255 AS tinyint), CAST(-9223372036854775808 AS bigint), CAST(NULL AS int); SELECT 2").await,
        vec![vec![Some(Int(-32768)),Some(Int(255)),Some(Int(i64::MIN)),None],vec![Some(Int(2))]]);
        channel.close().await.unwrap();
        let mut channel = connection.serial_channel().await.unwrap();
        assert_eq!(
            rows(&mut channel, "SELECT 3").await,
            vec![vec![Some(Int(3))]]
        );
        assert_eq!(
            rows(&mut channel, &format!("{}SELECT 5", " ".repeat(70000))).await,
            vec![vec![Some(Int(5))]]
        );
        assert_eq!(
            rows(&mut channel, "BEGIN TRANSACTION; SELECT @@TRANCOUNT").await,
            vec![vec![Some(Int(1))]]
        );
        assert_ne!(connection.session().await.unwrap().transaction, 0);
        assert_eq!(
            rows(
                &mut channel,
                "SELECT @@TRANCOUNT; COMMIT TRANSACTION; SELECT @@TRANCOUNT"
            )
            .await,
            vec![vec![Some(Int(1))], vec![Some(Int(0))]]
        );
        assert_eq!(connection.session().await.unwrap().transaction, 0);
        channel.close().await.unwrap();
        connection.close().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn awaited_attention_cleanup_reuses_the_channel_without_inferring_rollback() {
    for version in [
        tds_client::ProtocolVersion::V7_4,
        tds_client::ProtocolVersion::V8_0,
    ] {
        let mut config = options();
        config.version = version;
        let connection = Connection::connect(config).await.unwrap();
        let mut channel = connection.serial_channel().await.unwrap();
        assert_eq!(
            rows(
                &mut channel,
                "SET XACT_ABORT OFF; BEGIN TRANSACTION; SELECT @@TRANCOUNT"
            )
            .await,
            vec![vec![Some(Int(1))]]
        );
        let transaction = connection.session().await.unwrap().transaction;
        assert_ne!(transaction, 0);
        // One row may be buffered until WAITFOR ends. Force actual packets,
        // then cancel after reading only the first row of the larger result.
        let mut response = channel
            .exchange(Batch::new("SELECT TOP (100000) 11 FROM sys.all_objects a CROSS JOIN sys.all_objects b; WAITFOR DELAY '00:00:10'; SELECT 12"))
            .await
            .unwrap();
        loop {
            if let Some(Record::Row(row)) = response.next().await.unwrap() {
                assert_eq!(row, vec![Some(Int(11))]);
                break;
            }
        }
        response.close().await.unwrap();
        assert!(!connection.is_closed());
        assert_eq!(connection.session().await.unwrap().transaction, transaction);
        assert_eq!(
            rows(
                &mut channel,
                "SELECT @@TRANCOUNT; COMMIT TRANSACTION; SELECT @@TRANCOUNT"
            )
            .await,
            vec![vec![Some(Int(1))], vec![Some(Int(0))]]
        );
        channel.close().await.unwrap();
        connection.close().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn shared_cancel_handles_acknowledge_and_cannot_cancel_the_next_exchange() {
    for version in [
        tds_client::ProtocolVersion::V7_4,
        tds_client::ProtocolVersion::V8_0,
    ] {
        let mut config = options();
        config.version = version;
        let connection = Connection::connect(config).await.unwrap();
        let mut channel = connection.serial_channel().await.unwrap();
        let mut response = channel
            .exchange(Batch::new("WAITFOR DELAY '00:00:10'; SELECT 12"))
            .await
            .unwrap();
        let stale = response.cancel_handle();
        let cancel = stale.clone();
        let task = tokio::spawn(async move {
            cancel.cancel();
            cancel.cancel();
        });
        let error = response.next().await.unwrap_err();
        assert!(matches!(error.kind, ErrorKind::Canceled));
        assert!(response.next().await.unwrap().is_none());
        drop(response);
        task.await.unwrap();
        assert!(!connection.is_closed());
        let mut response = channel.exchange(Batch::new("SELECT 42")).await.unwrap();
        stale.cancel();
        let mut found = false;
        while let Some(record) = response.next().await.unwrap() {
            if let Record::Row(row) = record {
                assert_eq!(row, vec![Some(Int(42))]);
                found = true;
            }
        }
        assert!(found);
        response.close().await.unwrap();
        channel.close().await.unwrap();
        connection.close().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn channel_moves_to_another_task_and_sql_errors_remain_ordered() {
    let connection = Connection::connect(options()).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    channel = tokio::spawn(async move {
        assert_eq!(
            rows(&mut channel, "SELECT 41").await,
            vec![vec![Some(Int(41))]]
        );
        channel
    })
    .await
    .unwrap();
    {
        let mut response = channel
            .exchange(Batch::new(
                "SELECT * FROM tds_rust_nonexistent_object_aa8d47",
            ))
            .await
            .unwrap();
        let mut error_seen = false;
        loop {
            match response.next().await {
                Ok(Some(Record::Error(error))) => {
                    assert_eq!(error.number, 208);
                    error_seen = true;
                }
                Ok(Some(_)) => {}
                Err(error) => {
                    assert!(matches!(error.kind, ErrorKind::ServerErrors(_)));
                    assert_eq!(error.response.unwrap().errors().next().unwrap().number, 208);
                    break;
                }
                Ok(None) => panic!("SQL error was not reported at completion"),
            }
        }
        assert!(response.next().await.unwrap().is_none());
        assert!(error_seen);
    }
    assert_eq!(
        rows(&mut channel, "SELECT 42").await,
        vec![vec![Some(Int(42))]]
    );
    channel.close().await.unwrap();
    connection.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn abandoned_forgotten_and_canceled_reads_cannot_reuse_the_connection() {
    let connection = Connection::connect(options()).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    drop(channel.exchange(Batch::new("SELECT 1")).await.unwrap());
    assert!(connection.is_closed());
    assert!(channel.exchange(Batch::new("SELECT 2")).await.is_err());
    connection.close().await.unwrap();

    let connection = Connection::connect(options()).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    std::mem::forget(channel.exchange(Batch::new("SELECT 1")).await.unwrap());
    let error = match channel.exchange(Batch::new("SELECT 2")).await {
        Ok(_) => panic!("forgotten response allowed reuse"),
        Err(e) => e,
    };
    assert!(matches!(error.kind, ErrorKind::State(_)));
    connection.close().await.unwrap();

    let connection = Connection::connect(options()).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel
        .exchange(Batch::new("WAITFOR DELAY '00:00:10'; SELECT 1"))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), response.next())
            .await
            .is_err()
    );
    assert!(connection.is_closed());
    drop(response);
    connection.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn close_permission_wakes_a_waiting_reader_and_parent_drop_revokes_channels() {
    let connection = Connection::connect(options()).await.unwrap();
    let control = connection.close_handle();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel
        .exchange(Batch::new("WAITFOR DELAY '00:00:10'; SELECT 1"))
        .await
        .unwrap();
    let closer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        control.close();
    });
    assert!(
        tokio::time::timeout(Duration::from_secs(2), response.next())
            .await
            .unwrap()
            .is_err()
    );
    closer.await.unwrap();
    drop(response);
    connection.close().await.unwrap();

    let connection = Connection::connect(options()).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    drop(connection);
    assert!(channel.exchange(Batch::new("SELECT 1")).await.is_err());
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn certificate_identity_and_login_failures_are_not_bypassed() {
    for version in [
        tds_client::ProtocolVersion::V7_4,
        tds_client::ProtocolVersion::V8_0,
    ] {
        let mut config = options();
        config.version = version;
        config.roots = rustls::RootCertStore::empty();
        let error = match Connection::connect(config).await {
            Ok(_) => panic!("untrusted CA accepted"),
            Err(e) => e,
        };
        assert_eq!(error.step, tds_client::Step::Secure);
        assert!(matches!(error.kind, ErrorKind::Tls(_)));
        let mut config = options();
        config.version = version;
        config.server_name = Some("wrong-name.invalid".into());
        let error = match Connection::connect(config).await {
            Ok(_) => panic!("wrong hostname accepted"),
            Err(e) => e,
        };
        assert!(matches!(error.kind, ErrorKind::Tls(_)));
        let mut config = options();
        config.version = version;
        config
            .authentication
            .sql_credentials_mut()
            .unwrap()
            .password = "deliberately incorrect test password".to_string().into();
        let error = match Connection::connect(config).await {
            Ok(_) => panic!("wrong password accepted"),
            Err(e) => e,
        };
        assert_eq!(error.step, tds_client::Step::Login);
        assert!(matches!(error.kind, ErrorKind::Server(_)));
        let mut config = options();
        config.version = version;
        config.database = "tds_rust_nonexistent_database_aa8d47".into();
        let error = match Connection::connect(config).await {
            Ok(_) => panic!("unavailable database accepted"),
            Err(e) => e,
        };
        assert!(matches!(error.kind, ErrorKind::Server(_)));
    }
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn aborting_the_channel_owner_revokes_its_in_flight_exchange() {
    let connection = Connection::connect(options()).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let owner = tokio::spawn(async move {
        let _response = channel
            .exchange(Batch::new("WAITFOR DELAY '00:00:10'; SELECT 1"))
            .await
            .unwrap();
        started.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    ready.await.unwrap();
    owner.abort();
    assert!(owner.await.unwrap_err().is_cancelled());
    assert!(connection.is_closed());
    connection.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn broken_transport_after_transmission_reports_uncertainty_without_reconnect() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = options();
    config.port = listener.local_addr().unwrap().port();
    let (cut, mut cut_after_login) = tokio::sync::oneshot::channel();
    let proxy = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut server = TcpStream::connect("127.0.0.1:14325").await.unwrap();
        let mut from_client = [0; 16384];
        let mut from_server = [0; 16384];
        loop {
            tokio::select! {
                biased;
                _ = &mut cut_after_login => break,
                result = client.read(&mut from_client) => {
                    let n = result.unwrap(); assert!(n > 0); server.write_all(&from_client[..n]).await.unwrap();
                }
                result = server.read(&mut from_server) => {
                    let n = result.unwrap(); assert!(n > 0); client.write_all(&from_server[..n]).await.unwrap();
                }
            }
        }
        // See actual request ciphertext, then lose the transport. From the
        // client's perspective delivery/execution is unknown; no replay is safe.
        assert!(client.read(&mut from_client).await.unwrap() > 0);
        drop(client);
        drop(server);
        assert!(
            tokio::time::timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err()
        );
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    cut.send(()).unwrap();
    let mut response = channel.exchange(Batch::new("SELECT 1")).await.unwrap();
    let error = response.next().await.unwrap_err();
    assert_eq!(error.execution, tds_client::Execution::PossiblyExecuted);
    assert!(!error.response.as_ref().unwrap().ended);
    assert!(connection.is_closed());
    drop(response);
    connection.close().await.unwrap();
    proxy.await.unwrap();
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn mars_interleaves_readers_and_a_stalled_reader_does_not_block_its_sibling() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for version in [tds_client::ProtocolVersion::V7_4, tds_client::ProtocolVersion::V8_0] {
            let mut config = options(); config.version = version; config.mars = true;
            let connection = Connection::connect(config).await.unwrap();
            let mut slow = connection.serial_channel().await.unwrap();
            let mut fast = connection.serial_channel().await.unwrap();
            let mut pending = slow.exchange(Batch::new("SELECT TOP (50000) CAST(ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS int) n FROM sys.all_objects a CROSS JOIN sys.all_objects b")).await.unwrap();
            // Consume no slow rows. The large result exhausts its SMP window.
            assert_eq!(rows(&mut fast, "SELECT 42").await, [vec![Some(Int(42))]]);
            let mut seen = 0;
            while seen < 10 { if matches!(pending.next().await.unwrap(), Some(Record::Row(_))) { seen += 1; } }
            assert_eq!(rows(&mut fast, "SELECT 43").await, [vec![Some(Int(43))]]);
            pending.close().await.unwrap();
            assert_eq!(rows(&mut slow, "SELECT 44").await, [vec![Some(Int(44))]]);
            slow.close().await.unwrap(); fast.close().await.unwrap(); connection.close().await.unwrap();
        }
    }).await.expect("MARS sibling progress and cleanup deadline");
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn mars_large_request_resumes_credit_and_channels_observe_one_session() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for version in [tds_client::ProtocolVersion::V7_4, tds_client::ProtocolVersion::V8_0] {
            let mut config = options(); config.version = version; config.mars = true;
            let connection = Connection::connect(config).await.unwrap();
            let mut first = connection.serial_channel().await.unwrap();
            let mut second = connection.serial_channel().await.unwrap();
            // More than the initial four DATA frames in each direction.
            let sql = format!("/* {} */ SELECT @@SPID", "credit ".repeat(10000));
            let spid = rows(&mut first, &sql).await;
            assert_eq!(rows(&mut second, "SELECT @@SPID").await, spid);
            let mut response = first.exchange(Batch::new("SELECT TOP (10000) CAST(1 AS int) FROM sys.all_objects a CROSS JOIN sys.all_objects b")).await.unwrap();
            let record = response.fetch().await.unwrap(); assert_eq!(record.result_sets()[0].rows_read, 10000); drop(response);
            assert_eq!(connection.session().await.unwrap().session_id as i64, spid[0][0].as_ref().unwrap().as_integer().unwrap());
            first.close().await.unwrap(); second.close().await.unwrap(); connection.close().await.unwrap();
        }
    }).await.expect("MARS request/response credit deadline");
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn mars_busy_channel_close_preserves_sibling_and_stale_handles_are_inert() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for version in [
            tds_client::ProtocolVersion::V7_4,
            tds_client::ProtocolVersion::V8_0,
        ] {
            let mut config = options();
            config.version = version;
            config.mars = true;
            let connection = Connection::connect(config).await.unwrap();
            let mut first = connection.serial_channel().await.unwrap();
            let mut sibling = connection.serial_channel().await.unwrap();
            let close = first.close_handle();
            let mut response = first
                .exchange(Batch::new("WAITFOR DELAY '00:00:20'; SELECT 1"))
                .await
                .unwrap();
            let cancel = response.cancel_handle();
            close.close().await.unwrap();
            assert_eq!(rows(&mut sibling, "SELECT 51").await, [vec![Some(Int(51))]]);
            let error = response.next().await.unwrap_err();
            assert!(matches!(error.cause().kind, ErrorKind::Closed));
            drop(response);
            let mut replacement = connection.serial_channel().await.unwrap();
            close.close().await.unwrap();
            cancel.cancel();
            assert_eq!(
                rows(&mut replacement, "SELECT 52").await,
                [vec![Some(Int(52))]]
            );
            replacement.close().await.unwrap();
            sibling.close().await.unwrap();
            connection.close().await.unwrap();
        }
    })
    .await
    .expect("MARS busy close deadline");
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn mars_external_cancel_preserves_siblings_but_abandonment_discards_them() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for version in [tds_client::ProtocolVersion::V7_4, tds_client::ProtocolVersion::V8_0] {
            let mut config=options();config.version=version;config.mars=true;
            let connection=Connection::connect(config).await.unwrap();
            let mut first=connection.serial_channel().await.unwrap();let mut sibling=connection.serial_channel().await.unwrap();
            let mut response=first.exchange(Batch::new("SELECT TOP (5000) CAST(1 AS int) FROM sys.all_objects a CROSS JOIN sys.all_objects b; WAITFOR DELAY '00:00:20'; SELECT 2")).await.unwrap();
            while !matches!(response.next().await.unwrap(),Some(Record::Row(_))) {}
            response.cancel_handle().cancel();
            let error=response.fetch().await.unwrap_err();assert!(matches!(error.kind,ErrorKind::Canceled));
            let record=error.response.unwrap();assert!(record.canceled);assert!(record.completions().any(|d|d.acknowledges_cancel()));drop(response);
            assert_eq!(rows(&mut first,"SELECT 77").await,[vec![Some(Int(77))]]);assert_eq!(rows(&mut sibling,"SELECT 78").await,[vec![Some(Int(78))]]);
            let abandoned=first.exchange(Batch::new("WAITFOR DELAY '00:00:20'; SELECT 1")).await.unwrap();
            let mut pending=sibling.exchange(Batch::new("SELECT 2")).await.unwrap();
            drop(abandoned);assert!(pending.next().await.is_err());assert!(connection.is_closed());drop(pending);
            connection.close().await.unwrap();
        }
    }).await.expect("MARS cancel/abandonment deadline");
}

async fn transport_identity(channel: &mut tds_client::SerialChannel) -> Vec<tds_client::Row> {
    rows(channel,"SELECT CONVERT(bigint, SUBSTRING(CONVERT(binary(16), connection_id), 1, 8)), CONVERT(bigint, SUBSTRING(CONVERT(binary(16), connection_id), 9, 8)) FROM sys.dm_exec_connections WHERE session_id=@@SPID AND parent_connection_id IS NULL").await
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn pool_reset_restores_session_and_revokes_surviving_authority() {
    tokio::time::timeout(Duration::from_secs(30),async {
        for version in [tds_client::ProtocolVersion::V7_4,tds_client::ProtocolVersion::V8_0] {
            for mars in [false,true] {
                let mut config=options();config.version=version;config.mars=mars;
                let pool=tds_client::Pool::new(config,1).unwrap();
                let lease=pool.acquire().await.unwrap();let mut old=lease.serial_channel().await.unwrap();
                let identity=transport_identity(&mut old).await;assert_eq!(identity.len(),1);
                let baseline=rows(&mut old,"SELECT DB_ID(), @@LANGID, @@DATEFIRST").await;
                let session=lease.session().await.unwrap();let close=lease.close_handle();let channel_close=old.close_handle();
                records(&mut old,"USE tempdb; SET LANGUAGE French; SET DATEFIRST 3; CREATE TABLE #rust_pool_private(n int); INSERT #rust_pool_private VALUES (1)").await.unwrap();
                assert_eq!(lease.session().await.unwrap().database.to_string().unwrap(),"tempdb");
                if !mars {records(&mut old,"BEGIN TRANSACTION").await.unwrap();assert_ne!(lease.session().await.unwrap().transaction,0);}
                assert_eq!(lease.release().await.unwrap(),tds_client::ReleaseOutcome::Returned);
                let next=pool.acquire().await.unwrap();assert!(old.exchange(Batch::new("must never send")).await.is_err());close.close();channel_close.close().await.unwrap();
                let mut ch=next.serial_channel().await.unwrap();
                let state=rows(&mut ch,"SELECT DB_ID(), @@LANGID, @@DATEFIRST, OBJECT_ID('tempdb..#rust_pool_private'), @@TRANCOUNT").await;
                assert_eq!(&state[0][..3],&baseline[0][..]);assert_eq!(&state[0][3..],&[None,Some(Int(0))]);
                let reset=next.session().await.unwrap();assert_eq!(reset.database,session.database);assert_eq!(reset.language,session.language);assert_eq!(reset.collation,session.collation);assert_eq!(reset.transaction,0);
                assert_eq!(transport_identity(&mut ch).await,identity); // A GUID, so recycled SPIDs cannot fake reuse.
                assert_eq!(next.release().await.unwrap(),tds_client::ReleaseOutcome::Returned);pool.close().await.unwrap();
            }
        }
    }).await.expect("pool reset matrix deadline");
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn pool_reuses_proven_cancellation_but_discards_dropped_leases() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for version in [
            tds_client::ProtocolVersion::V7_4,
            tds_client::ProtocolVersion::V8_0,
        ] {
            for mars in [false, true] {
                let mut config = options();
                config.version = version;
                config.mars = mars;
                let pool = tds_client::Pool::new(config, 1).unwrap();
                let lease = pool.acquire().await.unwrap();
                let mut ch = lease.serial_channel().await.unwrap();
                let first = transport_identity(&mut ch).await;
                let mut response = ch.exchange(Batch::new("SELECT TOP (5000) CAST(1 AS int) FROM sys.all_objects a CROSS JOIN sys.all_objects b; WAITFOR DELAY '00:00:20'; SELECT 2")).await.unwrap();
                while !matches!(response.next().await.unwrap(),Some(Record::Row(_))) {}
                response.close().await.unwrap();
                assert_eq!(
                    lease.release().await.unwrap(),
                    tds_client::ReleaseOutcome::Returned
                );
                let next = pool.acquire().await.unwrap();
                let mut ch = next.serial_channel().await.unwrap();
                assert_eq!(transport_identity(&mut ch).await, first);
                let stale = next.close_handle();
                drop(next);
                let final_lease = pool.acquire().await.unwrap();
                let mut ch = final_lease.serial_channel().await.unwrap();
                let fresh = transport_identity(&mut ch).await;
                assert_ne!(fresh, first);
                stale.close();
                assert_eq!(rows(&mut ch, "SELECT 99").await, [vec![Some(Int(99))]]);
                pool.close().await.unwrap();
                assert!(!final_lease.is_closed());
                assert_eq!(
                    final_lease.release().await.unwrap(),
                    tds_client::ReleaseOutcome::Discarded
                );
            }
        }
    })
    .await
    .expect("pool cancellation/drop matrix deadline");
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn pool_capacity_waiting_and_borrowers_use_independent_sessions() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for version in [
            tds_client::ProtocolVersion::V7_4,
            tds_client::ProtocolVersion::V8_0,
        ] {
            for mars in [false, true] {
                let mut config = options();
                config.version = version;
                config.mars = mars;
                let pool = tds_client::Pool::new(config, 2).unwrap();
                let (a, b) = tokio::join!(pool.acquire(), pool.acquire());
                let a = a.unwrap();
                let b = b.unwrap();
                assert_eq!(pool.in_use(), 2);
                let mut ac = a.serial_channel().await.unwrap();
                let mut bc = b.serial_channel().await.unwrap();
                let aid = transport_identity(&mut ac).await;
                let bid = transport_identity(&mut bc).await;
                assert_ne!(aid, bid);
                records(
                    &mut ac,
                    "CREATE TABLE #rust_pool_owner(n int); INSERT #rust_pool_owner VALUES (17)",
                )
                .await
                .unwrap();
                assert_eq!(
                    rows(&mut bc, "SELECT OBJECT_ID('tempdb..#rust_pool_owner')").await,
                    [vec![None]]
                );
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), pool.acquire())
                        .await
                        .is_err()
                );
                assert_eq!(
                    a.release().await.unwrap(),
                    tds_client::ReleaseOutcome::Returned
                );
                let c = pool.acquire().await.unwrap();
                let mut cc = c.serial_channel().await.unwrap();
                assert_eq!(transport_identity(&mut cc).await, aid);
                assert_eq!(
                    rows(&mut cc, "SELECT OBJECT_ID('tempdb..#rust_pool_owner')").await,
                    [vec![None]]
                );
                b.release().await.unwrap();
                c.release().await.unwrap();
                assert_eq!((pool.in_use(), pool.idle()), (0, 2));
                pool.close().await.unwrap();
            }
        }
    })
    .await
    .expect("pool capacity/isolation matrix deadline");
}
