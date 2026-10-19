//! The Python recovery experiment, exercised through Rust's public handles.
#![cfg(feature = "tokio")]
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tds_client::Value::Integer as Int;
use tds_client::{Batch, Connection, ErrorKind, ProtocolVersion, Record, SerialChannel};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
mod support;

fn live_options() -> tds_client::ConnectOptions {
    let Some(path) = std::env::var_os("TDS_LIVE_CONFIG") else {
        return support::docker_options();
    };
    // An explicit protected configuration permits the same scenarios against
    // the Windows lab through a loopback SSH tunnel. Never print its contents.
    let bytes =
        zeroize::Zeroizing::new(std::fs::read(path).expect("read protected live configuration"));
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).expect("valid protected live configuration");
    let pem =
        std::fs::read(value["ca_file"].as_str().expect("live CA path")).expect("read live CA");
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots
            .add(certificate.expect("live CA certificate"))
            .expect("valid live CA");
    }
    let mut options = tds_client::ConnectOptions::new(
        "127.0.0.1",
        value["port"]
            .as_u64()
            .expect("live tunnel port")
            .try_into()
            .expect("valid live port"),
        value["username"].as_str().expect("live username"),
        value["password"].as_str().expect("live password"),
        roots,
    );
    options.server_name = Some(
        value["server_name"]
            .as_str()
            .expect("verified server hostname")
            .into(),
    );
    options.database = "master".into();
    options
}

#[derive(Clone, Default)]
struct Output(Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Relay {
    port: u16,
    cut: watch::Sender<u64>,
    accepted: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Relay {
    async fn new(target: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (cut, mut stopping) = watch::channel(0);
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        let task = tokio::spawn(async move {
            let mut pipes = JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let (mut client, _) = result.unwrap();
                        count.fetch_add(1, Ordering::SeqCst);
                        let mut stop = stopping.clone();
                        stop.borrow_and_update();
                        pipes.spawn(async move {
                            let mut server = TcpStream::connect(("127.0.0.1", target)).await.unwrap();
                            tokio::select! {
                                _ = stop.changed() => {},
                                _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {},
                            }
                        });
                    }
                    _ = stopping.changed() => {},
                    _ = pipes.join_next(), if !pipes.is_empty() => {},
                }
            }
        });
        Self {
            port,
            cut,
            accepted,
            task,
        }
    }
    async fn break_connection(&self, connection: &Connection) {
        self.cut.send_modify(|n| *n += 1);
        timeout(Duration::from_secs(5), async {
            while !connection.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("driver observes the transport break");
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn rows(channel: &mut SerialChannel, sql: &str) -> Vec<tds_client::Row> {
    let mut response = channel.exchange(Batch::new(sql)).await.unwrap();
    let fetched = response.fetch().await.unwrap();
    fetched
        .result_sets()
        .iter()
        .flat_map(|set| set.rows().unwrap().iter().cloned())
        .collect()
}

struct ConfigSource(std::sync::Mutex<tds_client::ConnectionConfig>);
impl tds_client::ConfigService for ConfigSource {
    fn read(&self) -> tds_client::ConfigRead<'_> {
        Box::pin(async { Ok(self.0.lock().unwrap().clone()) })
    }
}
async fn credential_sql(channel: &mut SerialChannel, sql: String) {
    // Never render a credential-bearing batch in a failing test report.
    let response = channel.exchange(Batch::new(sql)).await;
    assert!(response.is_ok(), "disposable login request failed");
    assert!(
        response.unwrap().finish().await.is_ok(),
        "disposable login SQL failed"
    );
}
async fn drop_login(channel: &mut SerialChannel, name: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut response = channel
            .exchange(Batch::new(format!("DROP LOGIN [{name}]")))
            .await
            .unwrap();
        match response.finish().await {
            Ok(()) => return,
            Err(error) => {
                assert!(
                    matches!(&error.cause().kind, ErrorKind::ServerErrors(errors) if errors.iter().any(|e| e.number == 15434))
                        && tokio::time::Instant::now() < deadline,
                    "disposable login cleanup failed"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}
fn isolated_login() -> (String, String, String) {
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    (
        format!("tds_rust_config_{id}"),
        format!("Aa1!_{id}_old"),
        format!("Bb2!_{id}_new"),
    )
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn pool_rotation_and_borrowed_recovery_read_current_credentials() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let (name, a, b) = isolated_login();
            let admin = Connection::connect(live_options()).await.unwrap();
            let mut ddl = admin.serial_channel().await.unwrap();
            credential_sql(
                &mut ddl,
                format!("CREATE LOGIN [{name}] WITH PASSWORD='{a}', CHECK_POLICY=OFF"),
            )
            .await;
            let outcome = async {
                let mut options = live_options();
                let relay = Relay::new(options.port).await;
                options.port = relay.port;
                options.user = name.clone();
                options.password = a;
                options.database.clear();
                options.version = version;
                options.mars = mars;
                let source = Arc::new(ConfigSource(std::sync::Mutex::new(
                    tds_client::ConnectionConfig::from_options(&options),
                )));
                let mut services = tds_client::ConnectionServices::new(options.roots);
                services.server_name = options.server_name;
                let pool = tds_client::Pool::from_config(
                    source.clone(),
                    2,
                    services,
                    tds_client::PoolPolicy::default(),
                )
                .unwrap();
                let first = pool.acquire().await?;
                let mut original = first.serial_channel().await?;
                rows(&mut original, "SELECT 11").await;
                credential_sql(
                    &mut ddl,
                    format!("ALTER LOGIN [{name}] WITH PASSWORD='{b}'"),
                )
                .await;
                assert!(
                    pool.acquire().await.is_err(),
                    "stale credential must fail loudly"
                );
                source.0.lock().unwrap().password = b.clone();
                let second = pool.acquire().await?;
                assert_eq!(
                    rows(&mut original, "SELECT 12").await,
                    [vec![Some(Int(12))]]
                );
                assert_eq!(
                    first.release().await?,
                    tds_client::ReleaseOutcome::Discarded
                );
                assert_eq!(
                    second.release().await?,
                    tds_client::ReleaseOutcome::Returned
                );
                let second = pool.acquire().await?;
                let mut active = second.serial_channel().await?;
                rows(&mut active, "SELECT 21").await;
                let c = format!("{b}_again");
                credential_sql(
                    &mut ddl,
                    format!("ALTER LOGIN [{name}] WITH PASSWORD='{c}'"),
                )
                .await;
                source.0.lock().unwrap().password = c;
                relay.break_connection(&second).await;
                pool.close().await?;
                // Refuse a changed identity before dialing; a corrected source
                // can still recover this same borrowed logical connection.
                source.0.lock().unwrap().database = "tempdb".into();
                assert!(second.recover().await.is_err());
                assert_eq!(second.recoveries(), 0);
                source.0.lock().unwrap().database.clear();
                second.recover().await?;
                assert_eq!(rows(&mut active, "SELECT 33").await, [vec![Some(Int(33))]]);
                assert_eq!(second.recoveries(), 1);
                assert_eq!(
                    second.release().await?,
                    tds_client::ReleaseOutcome::Discarded
                );
                tds_client::Result::Ok(())
            }
            .await;
            drop_login(&mut ddl, &name).await;
            admin.close().await.unwrap();
            outcome.unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn direct_password_change_promotes_credential_only_after_successful_login() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        let (name, a, b) = isolated_login();
        let admin = Connection::connect(live_options()).await.unwrap();
        let mut ddl = admin.serial_channel().await.unwrap();
        credential_sql(
            &mut ddl,
            format!("CREATE LOGIN [{name}] WITH PASSWORD='{a}', CHECK_POLICY=OFF"),
        )
        .await;
        let outcome = async {
            let mut options = live_options();
            let relay = Relay::new(options.port).await;
            options.port = relay.port;
            options.user = name.clone();
            options.password = a;
            options.new_password = b;
            options.database.clear();
            options.version = version;
            let connection = Connection::connect(options).await?;
            let mut original = connection.serial_channel().await?;
            rows(&mut original, "SELECT 1").await;
            relay.break_connection(&connection).await;
            connection.recover().await?;
            assert_eq!(rows(&mut original, "SELECT 2").await, [vec![Some(Int(2))]]);
            connection.close().await?;
            tds_client::Result::Ok(())
        }
        .await;
        drop_login(&mut ddl, &name).await;
        admin.close().await.unwrap();
        outcome.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn original_channels_and_close_controls_survive_repeated_recovery() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            timeout(Duration::from_secs(30), async {
                let mut config = live_options();
                let relay = Relay::new(config.port).await;
                config.port = relay.port;
                config.version = version;
                config.mars = mars;
                let outputs = Arc::new(std::sync::Mutex::new(Vec::<Output>::new()));
                let recordings = outputs.clone();
                config.capture_factory = Some(Arc::new(move || {
                    let output = Output::default();
                    recordings.lock().unwrap().push(output.clone());
                    Ok(tds_client::capture::Capture::new(output))
                }));
                let connection = Connection::connect(config).await.unwrap();
                let root_close = connection.close_handle();
                let mut retired = connection.serial_channel().await.unwrap();
                let retired_close = retired.close_handle();
                assert_eq!(rows(&mut retired, "SELECT 10").await, [vec![Some(Int(10))]]);
                retired_close.close().await.unwrap();
                let mut channel = connection.serial_channel().await.unwrap();
                let close = channel.close_handle();
                let mut sibling = if mars {
                    Some(connection.serial_channel().await.unwrap())
                } else {
                    None
                };
                rows(
                    &mut channel,
                    "USE tempdb; SET LANGUAGE Deutsch; SET DATEFIRST 3; SET TEXTSIZE 100",
                )
                .await;
                let retained = channel
                    .exchange(Batch::new("SELECT 11"))
                    .await
                    .unwrap()
                    .fetch()
                    .await
                    .unwrap();
                for cycle in 0..3 {
                    relay.break_connection(&connection).await;
                    if cycle == 1 {
                        connection.recover().await.unwrap();
                    }
                    assert_eq!(
                        rows(&mut channel, "SELECT @@DATEFIRST, @@TEXTSIZE").await,
                        [vec![Some(Int(3)), Some(Int(100))]]
                    );
                    assert_eq!(connection.recoveries(), cycle + 1);
                    let session = connection.session().await.unwrap();
                    assert_eq!(session.language, "Deutsch".into());
                    assert_eq!(session.database, "tempdb".into());
                    retired_close.close().await.unwrap();
                    if let Some(sibling) = &mut sibling {
                        let mut first = channel.exchange(Batch::new("SELECT 23")).await.unwrap();
                        let mut second = sibling.exchange(Batch::new("SELECT 24")).await.unwrap();
                        assert_eq!(
                            second.fetch().await.unwrap().result_sets()[0]
                                .rows()
                                .unwrap(),
                            [vec![Some(Int(24))]]
                        );
                        assert_eq!(
                            first.fetch().await.unwrap().result_sets()[0]
                                .rows()
                                .unwrap(),
                            [vec![Some(Int(23))]]
                        );
                    }
                    assert_eq!(
                        retained.result_sets()[0].rows().unwrap(),
                        [vec![Some(Int(11))]]
                    );
                }
                if mars {
                    let mut later = connection.serial_channel().await.unwrap();
                    assert_eq!(rows(&mut later, "SELECT 25").await, [vec![Some(Int(25))]]);
                    later.close().await.unwrap();
                }
                close.close().await.unwrap();
                assert!(channel.exchange(Batch::new("SELECT -1")).await.is_err());
                if let Some(mut sibling) = sibling {
                    assert_eq!(rows(&mut sibling, "SELECT 26").await, [vec![Some(Int(26))]]);
                    sibling.close().await.unwrap();
                }
                assert_eq!(relay.accepted.load(Ordering::SeqCst), 4);
                root_close.close();
                assert!(connection.is_closed());
                connection.close().await.unwrap();
                let outputs = outputs.lock().unwrap();
                assert_eq!(outputs.len(), 4);
                for (epoch, output) in outputs.iter().enumerate() {
                    let bytes = output.0.lock().unwrap();
                    let mut replayed =
                        std::collections::BTreeMap::<Option<u64>, Vec<tds_client::Row>>::new();
                    let replay = tds_client::replay::replay(bytes.as_slice(), |item| {
                        if let tds_client::replay::Content::Record(record) = item.content
                            && let Record::Row(row) = *record
                        {
                            replayed.entry(item.channel).or_default().push(row);
                        }
                        Ok(())
                    })
                    .unwrap();
                    assert_eq!(replay.issues, 0, "recovery recording epoch {epoch}");
                    if epoch == 0 {
                        assert!(
                            replayed
                                .values()
                                .flatten()
                                .any(|row| row == &vec![Some(Int(11))])
                        );
                    } else if mars {
                        assert!(replayed[&Some(1)].contains(&vec![Some(Int(23))]));
                        assert!(!replayed[&Some(1)].contains(&vec![Some(Int(24))]));
                        assert!(replayed[&Some(2)].contains(&vec![Some(Int(24))]));
                    }
                    let text = std::str::from_utf8(&bytes).unwrap();
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
                    if let Some(directory) = std::env::var_os("TDS_RECOVERY_CAPTURE_DIR") {
                        let path = std::path::PathBuf::from(directory);
                        std::fs::create_dir_all(&path).unwrap();
                        std::fs::write(
                            path.join(format!("{version:?}-mars-{mars}-epoch-{epoch}.jsonl")),
                            &*bytes,
                        )
                        .unwrap();
                    }
                }
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn interrupted_exchange_is_not_replayed_and_old_guards_cannot_close_replacement() {
    use std::{
        future::{Future, poll_fn},
        task::Poll,
    };
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            for abandon in [false, true] {
                timeout(Duration::from_secs(20), async {
                    let mut config = live_options();
                    let relay = Relay::new(config.port).await;
                    config.port = relay.port;
                    config.version = version;
                    config.mars = mars;
                    let connection = Connection::connect(config).await.unwrap();
                    let mut channel = connection.serial_channel().await.unwrap();
                    let mut old = channel.exchange(Batch::new("SELECT 11; RAISERROR ('ready', 0, 1) WITH NOWAIT; WAITFOR DELAY '00:00:30'; SELECT 12")).await.unwrap();
                    while !matches!(old.next().await.unwrap(), Some(Record::Row(row)) if row == [Some(Int(11))]) {}
                    assert!(!old.snapshot().ended);
                    let cancel = old.cancel_handle();
                    let mut read = Box::pin(old.next());
                    relay.cut.send_modify(|n| *n += 1);
                    loop {
                        // Consume already buffered tokens, but never poll the
                        // failed read after epoch retirement. Keep its armed
                        // guard across recovery to test late abandonment.
                        let buffered = poll_fn(|cx| {
                            if connection.is_closed() { return Poll::Ready(None); }
                            match read.as_mut().poll(cx) {
                                Poll::Ready(result) => Poll::Ready(Some(result)),
                                Poll::Pending => { cx.waker().wake_by_ref(); Poll::Pending }
                            }
                        }).await;
                        let Some(buffered) = buffered else { break; };
                        buffered.unwrap();
                        drop(read);
                        read = Box::pin(old.next());
                    }
                    if abandon {
                        connection.recover().await.unwrap();
                        drop(read); // armed old read guard; replacement must survive
                        drop(old); // unfinished old response; replacement must survive
                    } else {
                        // A reply already delivered before the cut may still
                        // return an old buffered token. The next pull must
                        // report the failed exchange, never read the new one.
                        let failure = match read.await {
                            Err(failure) => failure,
                            Ok(_) => old.next().await.unwrap_err(),
                        };
                        assert_eq!(failure.execution, tds_client::Execution::PossiblyExecuted);
                        assert!(!failure.response.as_ref().unwrap().ended);
                        drop(old);
                        assert!(channel.exchange(Batch::new("SELECT -1")).await.is_err());
                        assert_eq!(relay.accepted.load(Ordering::SeqCst), 1); // no automatic reconnect/replay
                        connection.recover().await.unwrap();
                    }
                    let mut current = channel.exchange(Batch::new("SELECT 22; RAISERROR ('ready', 0, 1) WITH NOWAIT; WAITFOR DELAY '00:00:00.2'; SELECT 23")).await.unwrap();
                    while !matches!(current.next().await.unwrap(), Some(Record::Row(row)) if row == [Some(Int(22))]) {}
                    cancel.cancel(); // control from before physical epoch rotation
                    current.finish().await.unwrap();
                    drop(current);
                    assert_eq!(rows(&mut channel, "SELECT 24").await, [vec![Some(Int(24))]]);
                    assert_eq!(relay.accepted.load(Ordering::SeqCst), 2);
                    assert_eq!(connection.recoveries(), 1);
                    channel.close().await.unwrap();
                    connection.close().await.unwrap();
                }).await.unwrap();
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn server_state_refusals_and_feature_opt_out_prevent_reconnection() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            for (sql, reason, recovery) in [
                ("BEGIN TRANSACTION", "transaction is open", true),
                ("CREATE TABLE #t (a int)", "temporary table exists", true),
                ("SELECT 1", "login did not request", false),
            ] {
                // SQL Server rolls back a transaction left open at the end of
                // a MARS batch (3997); that cannot establish an idle refusal.
                if mars && sql == "BEGIN TRANSACTION" {
                    continue;
                }
                let mut config = live_options();
                let relay = Relay::new(config.port).await;
                config.port = relay.port;
                config.version = version;
                config.mars = mars;
                config.session_recovery = recovery;
                let connection = Connection::connect(config).await.unwrap();
                let mut channel = connection.serial_channel().await.unwrap();
                rows(&mut channel, sql).await;
                relay.break_connection(&connection).await;
                let failure = connection.recover().await.unwrap_err();
                assert!(matches!(
                    failure.cause().kind,
                    ErrorKind::SessionNotRecovered { .. }
                ));
                assert!(failure.to_string().contains(reason), "{failure}");
                assert_eq!(relay.accepted.load(Ordering::SeqCst), 1);
                connection.close().await.unwrap();
            }
        }
    }
}
