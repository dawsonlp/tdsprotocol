//! The live Azure campaign (D-62): Rust against `infra/azure`, paired with
//! Python's `test_azure_live.py`, `test_kerberos_azure.py` and `infra/azure/paired.py`.
//! Every test is ignored: deploy the infrastructure, run `configure.py`, then
//!
//! ```sh
//! cargo test --all-features --test azure_live -- --ignored --test-threads=1 mac_     # this machine
//! cargo test --features azure-keyvault,system-gssapi --test azure_live -- --ignored runner_   # the runner
//! ```
//!
//! `infra/azure/azure.json` names the resources; `secrets/` holds passwords and
//! the disposable CA. Set `TDS_AZURE_INFRA` to read them elsewhere. Azure SQL's
//! public CA roots come from `TDS_AZURE_ROOTS` or the system bundle.
#![cfg(feature = "azure-keyvault")]
use serde_json::Value as Json;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tds_client::{
    Authentication, Batch, Collation, ConnectOptions, Connection, EnclaveAttestation, ErrorKind,
    IntegerSize, Param, Pool, ProtocolVersion, ReleaseOutcome, SqlType, Value,
    encryption::{KeyOperation, KeyProvider, Plaintext, Policies, keyvault::AzureKeyVaultKeyStore},
    entra::{
        AccessToken, EntraLogin, TokenFuture, TokenProvider, TokenProviders, TokenRequest,
        azure::{AzureTokenProvider, TokenCredential, azure_identity},
    },
    fedauth::Workflow,
    values::SqlText,
};

struct Lab {
    dir: PathBuf,
    places: Json,
    secrets: Option<Json>,
}
fn lab() -> Lab {
    let dir = std::env::var_os("TDS_AZURE_INFRA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../infra/azure"));
    let places = std::fs::read_to_string(dir.join("azure.json"))
        .expect("infra/azure/azure.json: terraform apply, then configure.py");
    let secrets = std::fs::read_to_string(dir.join("secrets/secrets.json")).ok();
    Lab {
        places: serde_json::from_str(&places).unwrap(),
        secrets: secrets.map(|s| serde_json::from_str(&s).unwrap()),
        dir,
    }
}
impl Lab {
    fn get(&self, key: &str) -> &str {
        self.places[key]
            .as_str()
            .unwrap_or_else(|| panic!("azure.json has no {key}"))
    }
    fn secret(&self, key: &str) -> String {
        let secrets = self
            .secrets
            .as_ref()
            .expect("infra/azure/secrets/secrets.json");
        secrets[key].as_str().unwrap().to_owned()
    }
    /// The disposable CA that signed SQL Server's certificate on the Windows VM.
    fn vm_roots(&self) -> rustls::RootCertStore {
        pem_roots(&self.dir.join(self.get("sql_vm_ca")))
    }
}
fn pem_roots(path: &std::path::Path) -> rustls::RootCertStore {
    let pem = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    assert!(!roots.is_empty(), "{}: no certificates", path.display());
    roots
}
/// Azure SQL's certificates chain to public authorities.
fn public_roots() -> rustls::RootCertStore {
    let candidates = [
        std::env::var("TDS_AZURE_ROOTS").unwrap_or_default(),
        "/etc/ssl/cert.pem".into(),
        "/etc/ssl/certs/ca-certificates.crt".into(),
    ];
    let path = candidates
        .iter()
        .find(|p| !p.is_empty() && std::path::Path::new(p).exists())
        .expect("a PEM bundle of public CA roots: set TDS_AZURE_ROOTS");
    pem_roots(std::path::Path::new(path))
}

/// Records every request the driver makes, then asks the real provider.
struct Counting {
    inner: Arc<dyn TokenProvider>,
    resources: Mutex<Vec<String>>,
}
impl Counting {
    fn new(inner: Arc<dyn TokenProvider>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            resources: Mutex::default(),
        })
    }
    fn resources(&self) -> Vec<String> {
        self.resources.lock().unwrap().clone()
    }
}
impl TokenProvider for Counting {
    fn acquire<'a>(&'a self, request: TokenRequest<'a>) -> TokenFuture<'a> {
        self.resources
            .lock()
            .unwrap()
            .push(request.resource.to_owned());
        self.inner.acquire(request)
    }
}
struct Unusable;
impl TokenProvider for Unusable {
    fn acquire<'a>(&'a self, _: TokenRequest<'a>) -> TokenFuture<'a> {
        Box::pin(async { Ok(AccessToken::new("not-a-valid-entra-token".into(), None)) })
    }
}
fn cli_credential() -> Arc<dyn TokenCredential> {
    azure_identity::AzureCliCredential::new(None).unwrap()
}
fn cli() -> Arc<Counting> {
    Counting::new(Arc::new(
        AzureTokenProvider::azure_cli(Default::default()).unwrap(),
    ))
}
fn entra(source: &str, deferred: bool) -> Authentication {
    Authentication::Entra(if deferred {
        EntraLogin::deferred(source, source, Workflow::Interactive)
    } else {
        EntraLogin::upfront(source, source)
    })
}
fn azure_sql(
    lab: &Lab,
    authentication: Authentication,
    providers: TokenProviders,
) -> ConnectOptions {
    let mut options =
        ConnectOptions::new(lab.get("azure_sql_server"), 1433, "", "", public_roots());
    options.database = lab.get("azure_sql_database").into();
    options.authentication = authentication;
    options.token_providers = providers;
    options.timeout = Duration::from_secs(60);
    options
}
fn windows_sql(lab: &Lab, authentication: Authentication) -> ConnectOptions {
    let mut options =
        ConnectOptions::new(lab.get("sql_vm_public_ip"), 1433, "", "", lab.vm_roots());
    options.authentication = authentication;
    options
}
/// A serverless database answers 40613 while it resumes from auto-pause.
async fn connect(options: ConnectOptions) -> Connection {
    for attempt in 1.. {
        match Connection::connect(options.clone()).await {
            Ok(connection) => return connection,
            Err(e)
                if attempt < 8
                    && matches!(&e.cause().kind, ErrorKind::Server(m) if m.number == 40613) =>
            {
                println!("database resuming (40613); trying again in 20 s");
                tokio::time::sleep(Duration::from_secs(20)).await;
            }
            Err(e) => panic!("connecting failed: {e}"),
        }
    }
    unreachable!()
}
fn text(value: &Option<Value>) -> String {
    match value {
        Some(Value::Unicode(t)) => t.to_string().unwrap(),
        Some(Value::Text(t)) => t.decode().unwrap().to_string().unwrap(),
        other => panic!("expected text, got {other:?}"),
    }
}
async fn rows(connection: &Connection, sql: &str) -> Vec<Vec<Option<Value>>> {
    let mut channel = connection.serial_channel().await.unwrap();
    let fetched = channel
        .exchange(Batch::new(sql))
        .await
        .unwrap()
        .fetch()
        .await
        .unwrap();
    channel.close().await.unwrap();
    fetched
        .result_sets()
        .first()
        .map(|set| set.rows().unwrap().to_vec())
        .unwrap_or_default()
}
async fn run(connection: &Connection, sql: &str) {
    rows(connection, sql).await;
}
/// (login name, database user, database)
async fn who(connection: &Connection) -> (String, String, String) {
    let row = rows(connection, "SELECT SUSER_SNAME(), USER_NAME(), DB_NAME()").await[0].clone();
    (text(&row[0]), text(&row[1]), text(&row[2]))
}
const VERSIONS: [ProtocolVersion; 2] = [ProtocolVersion::V7_4, ProtocolVersion::V8_0];

// ---------------------------------------------------------------- Entra ID on Azure SQL

#[tokio::test]
#[ignore = "live Azure campaign: Azure CLI user"]
async fn mac_entra_tokens_up_front_and_mid_login_route_and_name_the_user() {
    let lab = lab();
    for deferred in [false, true] {
        for version in VERSIONS {
            for mars in [false, true] {
                let provider = cli();
                let mut options = azure_sql(
                    &lab,
                    entra("cli", deferred),
                    TokenProviders::new().with("cli", provider.clone()),
                );
                options.version = version;
                options.mars = mars;
                let connection = connect(options).await;
                let (login, _, database) = who(&connection).await;
                assert!(login.contains('@'), "{login}");
                assert_eq!(database, lab.get("azure_sql_database"));
                let route = connection.routed_from.clone();
                assert!(
                    route.is_some(),
                    "connection policy Redirect routes every login"
                );
                // Up front: one token per physical login, the gateway's and the
                // destination's. Deferred: Azure's gateway routes without
                // FEDAUTHINFO, so only the destination asks (Python matches).
                let resources = provider.resources();
                assert_eq!(
                    resources.len(),
                    if deferred { 1 } else { 2 },
                    "{resources:?}"
                );
                if deferred {
                    assert!(
                        resources
                            .iter()
                            .all(|r| r.starts_with("https://database.windows.net"))
                    );
                }
                println!(
                    "ENTRA cli deferred={deferred} {version:?} mars={mars} routed tokens={} login={login}",
                    resources.len()
                );
                connection.close().await.unwrap();
            }
        }
    }
}

#[tokio::test]
#[ignore = "live Azure campaign: SQL login baseline"]
async fn mac_sql_login_on_azure_sql() {
    let lab = lab();
    for version in VERSIONS {
        let mut options = azure_sql(
            &lab,
            Authentication::sql("tdsadmin", lab.secret("sql_admin_password")),
            TokenProviders::new(),
        );
        options.version = version;
        let connection = connect(options).await;
        assert_eq!(who(&connection).await.0, "tdsadmin");
        println!(
            "SQL tdsadmin {version:?} routed={}",
            connection.routed_from.is_some()
        );
        connection.close().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "live Azure campaign: service principal"]
async fn mac_service_principal_logs_in_with_both_flows() {
    let lab = lab();
    let credential = azure_identity::ClientSecretCredential::new(
        lab.get("tenant_id"),
        lab.get("service_principal_client_id").to_owned(),
        lab.secret("service_principal_secret").into(),
        None,
    )
    .unwrap();
    for deferred in [false, true] {
        let provider = Counting::new(Arc::new(AzureTokenProvider::new(credential.clone())));
        let options = azure_sql(
            &lab,
            entra("principal", deferred),
            TokenProviders::new().with("principal", provider.clone()),
        );
        let connection = connect(options).await;
        let (login, user, _) = who(&connection).await;
        assert_eq!(user, lab.get("service_principal_name"));
        assert_eq!(provider.resources().len(), if deferred { 1 } else { 2 });
        println!("ENTRA service principal deferred={deferred} login={login} user={user}");
        connection.close().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "live Azure campaign: unsupported-feature policy (PY-AZ-06)"]
async fn mac_azure_only_features_fail_closed_only_on_enabled_acknowledgement() {
    let lab = lab();
    for name in [
        "azure_sql_support",
        "dns_caching",
        "enhanced_routing",
        "global_transactions",
    ] {
        let mut options = azure_sql(
            &lab,
            entra("cli", false),
            TokenProviders::new().with("cli", cli()),
        );
        let probes = &mut options.azure_feature_probes;
        match name {
            "azure_sql_support" => probes.azure_sql_support = true,
            "dns_caching" => probes.dns_caching = true,
            "enhanced_routing" => probes.enhanced_routing = true,
            _ => probes.global_transactions = true,
        }
        match Connection::connect(options).await {
            Ok(connection) => {
                println!("FEATURE {name}: absent or disabled acknowledgement; SQL allowed");
                connection.close().await.unwrap();
            }
            Err(e) => {
                assert!(
                    matches!(e.cause().kind, ErrorKind::UnsupportedFeatureEnabled(_)),
                    "{name}: {e}"
                );
                println!("FEATURE {name}: enabled acknowledgement; opening refused before SQL");
            }
        }
    }
}

#[tokio::test]
#[ignore = "live Azure campaign: pools"]
async fn mac_entra_pool_requests_tokens_per_physical_login_not_per_lease() {
    let lab = lab();
    for mars in [false, true] {
        let provider = cli();
        let mut options = azure_sql(
            &lab,
            entra("cli", false),
            TokenProviders::new().with("cli", provider.clone()),
        );
        options.mars = mars;
        drop(connect(options.clone()).await); // resume a paused database first
        let before = provider.resources().len();
        let pool = Pool::new(options, 1).unwrap();
        let lease = pool.acquire().await.unwrap();
        who(&lease).await;
        assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Returned);
        let lease = pool.acquire().await.unwrap();
        who(&lease).await;
        assert_eq!(
            provider.resources().len() - before,
            2,
            "reuse requests no token"
        );
        drop(lease); // discarded
        let lease = pool.acquire().await.unwrap();
        who(&lease).await;
        assert_eq!(provider.resources().len() - before, 4);
        assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Returned);
        pool.close().await.unwrap();
        println!("POOL mars={mars}: 2 logins, 4 token requests, 1 reuse without a token");
    }
}

#[tokio::test]
#[ignore = "live Azure campaign: token refusal"]
async fn mac_unusable_token_is_refused_before_any_sql() {
    let lab = lab();
    for deferred in [false, true] {
        let options = azure_sql(
            &lab,
            entra("bad", deferred),
            TokenProviders::new().with("bad", Arc::new(Unusable)),
        );
        let error = Connection::connect(options).await.err().expect("refused");
        assert!(
            matches!(
                error.cause().kind,
                ErrorKind::Server(_) | ErrorKind::Authentication(_)
            ),
            "{error}"
        );
        assert!(!format!("{error:?} {error}").contains("not-a-valid-entra-token"));
        println!("REFUSED unusable token deferred={deferred}: {error}");
    }
}

// ---------------------------------------------------------------- SQL Server on Windows: NTLM and the Browser

#[tokio::test]
#[ignore = "live Azure campaign: Windows SQL Server"]
async fn mac_ntlm_with_local_and_domain_accounts_and_a_wrong_password() {
    use tds_client::auth::{Method, WindowsAuth};
    let lab = lab();
    let accounts = [
        (
            "tdssql\\tdsadmin",
            lab.secret("windows_admin_password"),
            "TDSSQL\\TDSADMIN",
        ),
        (
            "TDS\\tdsuser",
            lab.secret("test_user_password"),
            "TDS\\TDSUSER",
        ),
    ];
    for version in VERSIONS {
        for (user, password, expected) in &accounts {
            let auth = WindowsAuth::explicit(Method::Ntlm, *user, password.clone());
            let mut options = windows_sql(&lab, Authentication::Windows(auth));
            options.version = version;
            let connection = connect(options).await;
            assert_eq!(who(&connection).await.0.to_uppercase(), *expected);
            println!("NTLM {user} {version:?}");
            connection.close().await.unwrap();
        }
        let auth = WindowsAuth::explicit(Method::Ntlm, "tdssql\\tdsadmin", "not the password");
        let mut options = windows_sql(&lab, Authentication::Windows(auth));
        options.version = version;
        let error = Connection::connect(options).await.err().expect("refused");
        assert!(
            matches!(&error.cause().kind, ErrorKind::Server(m) if m.number == 18452),
            "{error}"
        );
        println!("NTLM wrong password {version:?}: 18452");
    }
}

#[tokio::test]
#[ignore = "live Azure campaign: SQL Server Browser"]
async fn mac_the_browser_finds_the_default_instance() {
    use tds_client::browser::{Options, instance, machine};
    let lab = lab();
    let options = Options {
        timeout_ms: 3000,
        ..Default::default()
    };
    let host = lab.get("sql_vm_public_ip");
    let default = instance(host, "MSSQLSERVER", &options).await.unwrap();
    assert_eq!(default.tcp_port().unwrap(), Some(1433));
    assert_eq!(default.server_name.to_uppercase(), "TDSSQL");
    let every = machine(host, &options).await.unwrap();
    assert_eq!(
        every
            .iter()
            .map(|i| i.instance_name.as_str())
            .collect::<Vec<_>>(),
        ["MSSQLSERVER"]
    );
    println!("BROWSER MSSQLSERVER on 1433");
}

// ---------------------------------------------------------------- Key Vault and the VBS enclave, paired with Python

const VAULT_VALUE: &str = "kept in a vault";
const STAFF: [(&str, i32); 3] = [("Ada", 41000), ("Alan", 52000), ("Grace", 61000)];

fn nvarchar(collation: Collation) -> SqlType {
    SqlType::Character {
        length: 50,
        varying: true,
        unicode: true,
        collation,
    }
}
fn nvarchar_value(value: &str) -> Value {
    Value::Unicode(SqlText::from(value))
}
fn int() -> SqlType {
    SqlType::Integer {
        size: IntegerSize::Int,
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn names(rows: &[Vec<Option<Value>>]) -> Vec<String> {
    rows.iter().map(|row| text(&row[0])).collect()
}

/// Rust's tables use a vault master key that allows enclave computations, so one
/// key serves the deterministic and the enclave-enabled randomized columns.
async fn create_rust_schema(admin: &Connection, store: &AzureKeyVaultKeyStore, key_url: &str) {
    run(admin, "DROP TABLE IF EXISTS dbo.rust_akv; DROP TABLE IF EXISTS dbo.rust_enclave; \
        IF EXISTS (SELECT 1 FROM sys.column_encryption_keys WHERE name = 'rust_cek') DROP COLUMN ENCRYPTION KEY rust_cek; \
        IF EXISTS (SELECT 1 FROM sys.column_master_keys WHERE name = 'rust_cmk') DROP COLUMN MASTER KEY rust_cmk").await;
    let operation = KeyOperation::default();
    let master = store.open(key_url, operation.clone()).await.unwrap();
    let mut root = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut root).unwrap();
    let wrapped = master
        .wrap(&Plaintext::copy(&root).unwrap(), operation.clone())
        .await
        .unwrap();
    let signature = master.sign_metadata(true, operation).await.unwrap();
    run(admin, &format!(
        "CREATE COLUMN MASTER KEY rust_cmk WITH (KEY_STORE_PROVIDER_NAME = N'AZURE_KEY_VAULT', KEY_PATH = N'{key_url}', \
         ENCLAVE_COMPUTATIONS (SIGNATURE = 0x{})); \
         CREATE COLUMN ENCRYPTION KEY rust_cek WITH VALUES (COLUMN_MASTER_KEY = rust_cmk, ALGORITHM = 'RSA_OAEP', ENCRYPTED_VALUE = 0x{})",
        hex(&signature), hex(&wrapped))).await;
    run(admin, "CREATE TABLE dbo.rust_akv (v nvarchar(50) COLLATE Latin1_General_BIN2 ENCRYPTED WITH \
        (COLUMN_ENCRYPTION_KEY = rust_cek, ENCRYPTION_TYPE = DETERMINISTIC, ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256')); \
        CREATE TABLE dbo.rust_enclave (id int, name nvarchar(50) COLLATE Latin1_General_BIN2 ENCRYPTED WITH \
        (COLUMN_ENCRYPTION_KEY = rust_cek, ENCRYPTION_TYPE = RANDOMIZED, ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'), \
        salary int ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = rust_cek, ENCRYPTION_TYPE = RANDOMIZED, \
        ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'))").await;
}

/// Write Rust's values, read them back, then read Python's tables when
/// `TDS_AZURE_PAIRED=1` (after `paired.py write`).
#[tokio::test]
#[ignore = "live Azure campaign: Key Vault and enclave, paired with Python"]
async fn mac_key_vault_and_enclave_values_round_trip_and_read_python_values() {
    let lab = lab();
    let key_url = lab.get("key_vault_key_id");
    let store = AzureKeyVaultKeyStore::new(cli_credential());
    let admin = connect(azure_sql(
        &lab,
        entra("cli", false),
        TokenProviders::new().with("cli", cli()),
    ))
    .await;
    create_rust_schema(&admin, &store, key_url).await;
    admin.close().await.unwrap();

    let mut options = azure_sql(
        &lab,
        entra("cli", false),
        TokenProviders::new().with("cli", cli()),
    );
    options.enclave_attestation = Some(EnclaveAttestation::None);
    let connection = connect(options).await;
    let collation = Collation(
        connection
            .session()
            .await
            .unwrap()
            .collation
            .try_into()
            .unwrap(),
    );
    let providers: Vec<Arc<dyn KeyProvider>> =
        vec![Arc::new(AzureKeyVaultKeyStore::new(cli_credential()))];
    let encrypted = connection
        .encrypted_with_providers(providers, Policies::default(), Duration::from_secs(60))
        .await
        .unwrap();
    let mut channel = encrypted.serial_channel().await.unwrap();
    let mut fetch = async |sql: &str, declarations: &str, params: Vec<Param>| {
        channel
            .execute(sql, declarations, params)
            .await
            .unwrap()
            .fetch()
            .await
            .unwrap()
            .result_sets()
            .first()
            .map(|set| set.rows().unwrap().to_vec())
            .unwrap_or_default()
    };
    fetch(
        "INSERT dbo.rust_akv VALUES (@v)",
        "@v nvarchar(50)",
        vec![Param::new(
            "@v",
            nvarchar(collation),
            Some(nvarchar_value(VAULT_VALUE)),
        )],
    )
    .await;
    assert_eq!(
        names(&fetch("SELECT v FROM dbo.rust_akv", "", vec![]).await),
        [VAULT_VALUE]
    );
    for (id, (name, salary)) in STAFF.iter().enumerate() {
        fetch(
            "INSERT dbo.rust_enclave VALUES (@id, @name, @salary)",
            "@id int, @name nvarchar(50), @salary int",
            vec![
                Param::new("@id", int(), Some(Value::Integer(id as i64))),
                Param::new("@name", nvarchar(collation), Some(nvarchar_value(name))),
                Param::new("@salary", int(), Some(Value::Integer(*salary as i64))),
            ],
        )
        .await;
    }
    let mut paired = vec!["rust"];
    if std::env::var("TDS_AZURE_PAIRED").as_deref() == Ok("1") {
        assert_eq!(
            names(&fetch("SELECT v FROM dbo.python_akv", "", vec![]).await),
            [VAULT_VALUE]
        );
        paired.push("python");
    }
    for prefix in &paired {
        let like = fetch(
            &format!("SELECT name FROM dbo.{prefix}_enclave WHERE name LIKE @p ORDER BY id"),
            "@p nvarchar(50)",
            vec![Param::new(
                "@p",
                nvarchar(collation),
                Some(nvarchar_value("A%")),
            )],
        )
        .await;
        let more = fetch(
            &format!("SELECT name FROM dbo.{prefix}_enclave WHERE salary > @s ORDER BY id"),
            "@s int",
            vec![Param::new("@s", int(), Some(Value::Integer(50000)))],
        )
        .await;
        assert_eq!(names(&like), ["Ada", "Alan"], "{prefix} LIKE");
        assert_eq!(names(&more), ["Alan", "Grace"], "{prefix} range");
        println!("ENCLAVE {prefix} table: LIKE 'A%' = Ada, Alan; salary > 50000 = Alan, Grace");
    }
    channel.close().await.unwrap();
    let statistics = encrypted.statistics();
    assert!(statistics.enclave_packages > 0);
    println!(
        "VAULT unwraps={} enclave packages={} read tables={paired:?}",
        statistics.unwraps, statistics.enclave_packages
    );
    encrypted.close().await;
    connection.close().await.unwrap();
}

// ---------------------------------------------------------------- On the runner: managed identity and Kerberos

#[tokio::test]
#[ignore = "live Azure campaign: on the runner VM"]
async fn runner_managed_identity_logs_in_and_uses_the_vault() {
    let lab = lab();
    let credential: Arc<dyn TokenCredential> =
        azure_identity::ManagedIdentityCredential::new(None).unwrap();
    for deferred in [false, true] {
        let provider = Counting::new(Arc::new(AzureTokenProvider::new(credential.clone())));
        let options = azure_sql(
            &lab,
            entra("identity", deferred),
            TokenProviders::new().with("identity", provider.clone()),
        );
        let connection = connect(options).await;
        let (login, user, _) = who(&connection).await;
        assert_eq!(user, lab.get("runner_identity_name"));
        assert_eq!(provider.resources().len(), if deferred { 1 } else { 2 });
        println!("ENTRA managed identity deferred={deferred} login={login} user={user}");
        connection.close().await.unwrap();
    }
    let operation = KeyOperation::default();
    let master = AzureKeyVaultKeyStore::new(credential)
        .open(lab.get("key_vault_key_id"), operation.clone())
        .await
        .unwrap();
    let signature = master.sign_metadata(true, operation.clone()).await.unwrap();
    assert!(
        master
            .verify_metadata(true, &signature, operation)
            .await
            .unwrap()
    );
    println!("VAULT managed identity: sign and verify");
}

#[cfg(feature = "system-gssapi")]
async fn kerberos(
    lab: &Lab,
    method: tds_client::auth::Method,
    version: ProtocolVersion,
) -> tds_client::Result<Connection> {
    use tds_client::auth::WindowsAuth;
    let host = format!("tdssql.{}", lab.get("domain"));
    let mut options = ConnectOptions::new(host, 1433, "", "", lab.vm_roots());
    options.authentication = Authentication::Windows(WindowsAuth::system_cache(method));
    options.version = version;
    Connection::connect(options).await
}

#[cfg(feature = "system-gssapi")]
#[tokio::test]
#[ignore = "live Azure campaign: on the runner VM, with a kinit ticket"]
async fn runner_kerberos_and_negotiate_use_the_tickets_user() {
    use tds_client::auth::Method;
    let lab = lab();
    for version in VERSIONS {
        for method in [Method::Kerberos, Method::Negotiate] {
            let connection = kerberos(&lab, method, version).await.unwrap();
            assert_eq!(who(&connection).await.0.to_uppercase(), "TDS\\TDSUSER");
            let scheme = rows(
                &connection,
                "SELECT auth_scheme FROM sys.dm_exec_connections WHERE session_id = @@SPID",
            )
            .await;
            assert_eq!(text(&scheme[0][0]), "KERBEROS", "{method:?}");
            println!("KERBEROS {method:?} {version:?}: TDS\\tdsuser, scheme KERBEROS");
            connection.close().await.unwrap();
        }
    }
}

/// Run by `kerberos.sh` without a ticket (after `kdestroy`) and with an expired
/// one: Rust refuses before any login, never falling back to NTLM, and keeps
/// GSSAPI's status numbers so the two cases can be told apart (B-7).
#[cfg(feature = "system-gssapi")]
#[tokio::test]
#[ignore = "live Azure campaign: on the runner VM, without a usable ticket"]
async fn runner_without_a_usable_ticket_kerberos_and_negotiate_are_refused() {
    use tds_client::auth::{GssapiStatusKind, Method};
    let expired = match std::env::var("TDS_EXPECT_TICKET").as_deref() {
        Ok("absent") => false,
        Ok("expired") => true,
        _ => {
            println!("skipped: set TDS_EXPECT_TICKET=absent (after kdestroy) or expired");
            return;
        }
    };
    let lab = lab();
    for method in [Method::Kerberos, Method::Negotiate] {
        // Observed with MIT Kerberos: no ticket is GSS_S_NO_CRED for both. An
        // expired ticket is GSS_S_FAILURE; Kerberos keeps the ticket-expired
        // minor, but SPNEGO substitutes its own, so Negotiate reports Failure.
        let expected = match (expired, method) {
            (false, _) => GssapiStatusKind::NoCredentials,
            (true, Method::Kerberos) => GssapiStatusKind::CredentialsExpired,
            (true, _) => GssapiStatusKind::Failure,
        };
        let error = kerberos(&lab, method, ProtocolVersion::V8_0)
            .await
            .err()
            .expect("refused");
        let ErrorKind::GssapiRefused(status) = error.cause().kind else {
            panic!("{method:?}: expected a GSSAPI refusal before login: {error}");
        };
        println!(
            "TICKET expired={expired} {method:?}: kind={:?} major=0x{:08x} minor=0x{:08x}: {error}",
            status.kind(),
            status.major,
            status.minor
        );
        assert_eq!(status.kind(), expected, "{error}");
    }
}

// ---------------------------------------------------------------- Part B, live

struct Empty;
impl TokenProvider for Empty {
    fn acquire<'a>(&'a self, _: TokenRequest<'a>) -> TokenFuture<'a> {
        Box::pin(async { Ok(AccessToken::new(String::new(), None)) })
    }
}

/// B-2: an empty token is sent unchanged (as Python does); Azure decides. It
/// closes the connection during login, without an error token; Python's client
/// observes the same ("the server closed the connection") for both flows.
#[tokio::test]
#[ignore = "live Azure campaign: Part B"]
async fn mac_b2_azure_closes_the_connection_on_an_empty_token() {
    let lab = lab();
    for deferred in [false, true] {
        let options = azure_sql(
            &lab,
            entra("empty", deferred),
            TokenProviders::new().with("empty", Arc::new(Empty)),
        );
        let error = Connection::connect(options).await.err().expect("refused");
        assert!(matches!(error.cause().kind, ErrorKind::Closed), "{error}");
        assert_eq!(error.step, tds_client::Step::Login);
        assert_eq!(error.execution, tds_client::Execution::NotSent);
        println!("B-2 empty token deferred={deferred}: {error}");
    }
}

fn az(args: &[&str]) -> String {
    let done = std::process::Command::new("az")
        .args(args)
        .output()
        .unwrap();
    assert!(
        done.status.success(),
        "az {}: {}",
        args[..3].join(" "),
        String::from_utf8_lossy(&done.stderr)
    );
    String::from_utf8(done.stdout).unwrap().trim().to_owned()
}

/// B-4: vault refusals against the real Key Vault.
#[tokio::test]
#[ignore = "live Azure campaign: Part B"]
async fn mac_b4_key_vault_missing_key_tampered_envelope_and_rotation() {
    let lab = lab();
    let key_url = lab.get("key_vault_key_id");
    let vault_url = key_url.split("/keys/").next().unwrap().to_owned();
    let vault_name = vault_url
        .trim_start_matches("https://")
        .split('.')
        .next()
        .unwrap()
        .to_owned();
    let store = AzureKeyVaultKeyStore::new(cli_credential());
    let op = KeyOperation::default();
    let wrapped_by = async |path: &str| {
        let master = store.open(path, op.clone()).await.unwrap();
        let wrapped = master
            .wrap(&Plaintext::copy(&[7; 32]).unwrap(), op.clone())
            .await
            .unwrap();
        tds_client::encryption::WrappedKey {
            provider: "AZURE_KEY_VAULT".into(),
            path: path.into(),
            algorithm: "RSA_OAEP".into(),
            encrypted: wrapped,
        }
    };
    let unwrap = async |path: &str, key: &tds_client::encryption::WrappedKey| {
        let master = store.open(path, op.clone()).await.unwrap();
        master.unwrap(key, op.clone()).await
    };

    let good = wrapped_by(key_url).await;
    assert_eq!(unwrap(key_url, &good).await.unwrap().as_bytes(), [7; 32]);
    let missing = format!("{vault_url}/keys/tds-missing-key");
    let error = unwrap(&missing, &good).await.unwrap_err();
    assert!(
        matches!(error, tds_client::encryption::Error::Provider(_)),
        "{error:?}"
    );
    println!("B-4 missing key: {error}");
    let mut tampered = good.clone();
    *tampered.encrypted.last_mut().unwrap() ^= 1;
    assert_eq!(
        unwrap(key_url, &tampered).await.unwrap_err(),
        tds_client::encryption::Error::Authentication
    );
    println!("B-4 tampered envelope signature: Authentication");

    // A dedicated key, so rotation leaves the campaign's tables intact.
    // A new name per run: a deleted key keeps its name while soft-deleted.
    let name = &format!("tds-rotation-{}", std::process::id());
    az(&[
        "keyvault",
        "key",
        "create",
        "--vault-name",
        &vault_name,
        "--name",
        name,
        "--kty",
        "RSA",
        "--size",
        "2048",
        "--ops",
        "wrapKey",
        "unwrapKey",
        "sign",
        "verify",
        "-o",
        "none",
    ]);
    let versionless = format!("{vault_url}/keys/{name}");
    let pinned = az(&[
        "keyvault",
        "key",
        "show",
        "--vault-name",
        &vault_name,
        "--name",
        name,
        "--query",
        "key.kid",
        "-o",
        "tsv",
    ]);
    let by_versionless = wrapped_by(&versionless).await;
    let by_pinned = wrapped_by(&pinned).await;
    az(&[
        "keyvault",
        "key",
        "create",
        "--vault-name",
        &vault_name,
        "--name",
        name,
        "--kty",
        "RSA",
        "--size",
        "2048",
        "--ops",
        "wrapKey",
        "unwrapKey",
        "sign",
        "verify",
        "-o",
        "none",
    ]); // a new current version
    assert_eq!(
        unwrap(&pinned, &by_pinned).await.unwrap().as_bytes(),
        [7; 32]
    );
    let after = unwrap(&versionless, &by_versionless).await;
    println!(
        "B-4 after rotation: pinned path unwraps; versionless path: {:?}",
        after.as_ref().map(|_| "unwrapped")
    );
    assert_eq!(
        after.unwrap_err(),
        tds_client::encryption::Error::Authentication,
        "the new version cannot verify the old envelope"
    );
    az(&[
        "keyvault",
        "key",
        "delete",
        "--vault-name",
        &vault_name,
        "--name",
        name,
        "-o",
        "none",
    ]);
    // Purging can lag the deletion; the resource group's deletion is the backstop.
    let purged = std::process::Command::new("az")
        .args([
            "keyvault",
            "key",
            "purge",
            "--vault-name",
            &vault_name,
            "--name",
            name,
        ])
        .output()
        .is_ok_and(|o| o.status.success());
    println!("B-4 rotation key {name} deleted; purged={purged}");
}

/// B-6: after pool return the session resets; a new wrapper re-authorizes
/// keys and establishes a new enclave session (Rust's agreed scope). Reads
/// `python_enclave` (vault key), written by `paired.py write` before Rust's run.
#[tokio::test]
#[ignore = "live Azure campaign: Part B (after paired.py write)"]
async fn mac_b6_enclave_queries_work_again_after_pool_return() {
    let lab = lab();
    let mut options = azure_sql(
        &lab,
        entra("cli", false),
        TokenProviders::new().with("cli", cli()),
    );
    options.enclave_attestation = Some(EnclaveAttestation::None);
    drop(connect(options.clone()).await);
    let pool = Pool::new(options, 1).unwrap();
    for round in 1..=2 {
        let lease = pool.acquire().await.unwrap();
        let providers: Vec<Arc<dyn KeyProvider>> =
            vec![Arc::new(AzureKeyVaultKeyStore::new(cli_credential()))];
        let encrypted = lease
            .encrypted_with_providers(providers, Policies::default(), Duration::from_secs(60))
            .await
            .unwrap();
        let mut channel = encrypted.serial_channel().await.unwrap();
        let like = channel
            .execute(
                "SELECT name FROM dbo.python_enclave WHERE name LIKE @p ORDER BY id",
                "@p nvarchar(50)",
                vec![Param::new(
                    "@p",
                    nvarchar(Collation(
                        lease.session().await.unwrap().collation.try_into().unwrap(),
                    )),
                    Some(nvarchar_value("A%")),
                )],
            )
            .await
            .unwrap()
            .fetch()
            .await
            .unwrap();
        assert_eq!(
            names(like.result_sets()[0].rows().unwrap()),
            ["Ada", "Alan"]
        );
        channel.close().await.unwrap();
        let statistics = encrypted.statistics();
        assert!(statistics.authorized_keys >= 1 && statistics.enclave_packages >= 1);
        println!(
            "B-6 lease {round}: authorized keys={} packages={}",
            statistics.authorized_keys, statistics.enclave_packages
        );
        encrypted.close().await;
        assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Returned);
    }
    pool.close().await.unwrap();
}

/// B-9: the `tds` CLI's Entra modes with the signed-in Azure CLI user.
#[tokio::test]
#[ignore = "live Azure campaign: Part B"]
async fn mac_b9_cli_entra_modes_log_in() {
    let lab = lab();
    let roots = ["/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .unwrap();
    for mode in ["entra-upfront", "entra-deferred"] {
        let done = std::process::Command::new(env!("CARGO_BIN_EXE_tds"))
            .args([
                "--host",
                lab.get("azure_sql_server"),
                "--port",
                "1433",
                "--database",
                lab.get("azure_sql_database"),
                "--auth",
                mode,
                "--ca-file",
                roots,
                "--timeout",
                "60",
                "--query",
                "SELECT SUSER_SNAME() AS who",
            ])
            .output()
            .unwrap();
        let out = String::from_utf8_lossy(&done.stdout);
        assert!(
            done.status.success(),
            "{mode}: {out} {}",
            String::from_utf8_lossy(&done.stderr)
        );
        assert!(out.contains('@'), "{mode}: {out}");
        println!(
            "B-9 tds --auth {mode}: {}",
            out.lines()
                .filter(|l| l.contains('@'))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
}

// ---------------------------------------------------------------- Follow-ups, live

/// Follow-up B: the server ends the session (`KILL` from an admin connection);
/// explicit recovery asks the credential source again and restores session
/// state, without replaying SQL. Run under the connection policy in force
/// (`TDS_AZURE_POLICY` labels the output).
#[tokio::test]
#[ignore = "live Azure campaign: follow-ups"]
async fn mac_recovery_after_the_server_ends_the_session() {
    let lab = lab();
    let policy = std::env::var("TDS_AZURE_POLICY").unwrap_or_else(|_| "unlabeled".into());
    let admin = connect(azure_sql(
        &lab,
        entra("cli", false),
        TokenProviders::new().with("cli", cli()),
    ))
    .await;
    for deferred in [false, true] {
        let provider = cli();
        let connection = connect(azure_sql(
            &lab,
            entra("cli", deferred),
            TokenProviders::new().with("cli", provider.clone()),
        ))
        .await;
        run(&connection, "SET DATEFIRST 3; SET TEXTSIZE 100").await;
        let Some(Value::Integer(spid)) =
            rows(&connection, "SELECT CAST(@@SPID AS int)").await[0][0]
        else {
            panic!("spid")
        };
        let before = provider.resources().len();
        run(&admin, &format!("KILL {spid}")).await;
        // Azure resets the transport at once; a channel or request then reports
        // the break, and nothing is retried.
        let failed = match connection.serial_channel().await {
            Err(e) => Some(e),
            Ok(mut channel) => match channel.exchange(Batch::new("SELECT 1")).await {
                Ok(mut response) => response.finish().await.err(),
                Err(e) => Some(e),
            },
        };
        println!(
            "RECOVERY {policy} deferred={deferred}: after KILL: {:?}",
            failed.as_ref().map(|e| e.to_string())
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            while !connection.is_closed() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the driver observes the server's close");
        match connection.recover().await {
            Ok(()) => {
                let state = rows(
                    &connection,
                    "SELECT CAST(@@DATEFIRST AS int), CAST(@@TEXTSIZE AS int), CAST(@@SPID AS int)",
                )
                .await;
                println!(
                    "RECOVERY {policy} deferred={deferred}: recovered; recoveries={} new tokens={} state={:?} old spid={spid}",
                    connection.recoveries(),
                    provider.resources().len() - before,
                    state[0]
                );
                assert_eq!(state[0][0], Some(Value::Integer(3)), "DATEFIRST restored");
                assert_eq!(state[0][1], Some(Value::Integer(100)), "TEXTSIZE restored");
                assert!(
                    provider.resources().len() > before,
                    "the credential source was asked again"
                );
            }
            Err(e) => {
                println!("RECOVERY {policy} deferred={deferred}: server refused recovery: {e}");
                assert!(
                    matches!(
                        e.cause().kind,
                        ErrorKind::SessionNotRecovered { .. } | ErrorKind::Server(_)
                    ),
                    "{e}"
                );
            }
        }
        connection.close().await.unwrap();
    }
    admin.close().await.unwrap();
}

/// Runs `infra/azure/scripts/rotation.ps1` on a VM. The password goes to `az`
/// as a parameter, as `configure.py` passes secrets; it is a throwaway account.
fn rotation_account(lab: &Lab, vm: &str, action: &str, scope: &str, name: &str, password: &str) {
    let script = format!("@{}", lab.dir.join("scripts/rotation.ps1").display());
    let mut args = vec![
        "vm",
        "run-command",
        "invoke",
        "-g",
        lab.get("resource_group"),
        "-n",
        vm,
        "--command-id",
        "RunPowerShellScript",
        "--scripts",
        &script,
        "-o",
        "json",
        "--parameters",
    ];
    let (a, s, n, p) = (
        format!("Action={action}"),
        format!("Scope={scope}"),
        format!("Name={name}"),
        format!("Password={password}"),
    );
    args.extend([a.as_str(), s.as_str(), n.as_str(), p.as_str()]);
    let out: Json = serde_json::from_str(&az(&args)).unwrap();
    let message = |code: &str| {
        out["value"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["code"].as_str().unwrap_or("").contains(code))
            .map(|m| m["message"].as_str().unwrap_or("").trim().to_owned())
            .collect::<String>()
    };
    assert!(
        message("StdErr").is_empty(),
        "{vm} {action}: {}",
        message("StdErr")
    );
    assert!(
        message("StdOut").contains(&format!("{action} done")),
        "{}",
        message("StdOut")
    );
}
fn throwaway_password() -> String {
    let mut bytes = [0_u8; 9];
    aws_lc_rs::rand::fill(&mut bytes).unwrap();
    format!(
        "Tds-{}-Rr7!",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
struct WindowsSource(std::sync::Mutex<tds_client::ConnectionConfig>);
impl tds_client::ConfigService for WindowsSource {
    fn read(&self) -> tds_client::ConfigRead<'_> {
        Box::pin(async move { Ok(self.0.lock().unwrap().clone()) })
    }
}

/// Follow-up C: rotate a Windows account's password during a pool's life. A
/// refused new login re-reads settings once and reopens with the new password;
/// sessions opened with the old password are discarded on return. Whether the
/// old password is still accepted right after the change is recorded: AD keeps
/// a domain account's previous password usable for NTLM for a while by default.
#[tokio::test]
#[ignore = "live Azure campaign: follow-ups (Windows VMs)"]
async fn mac_windows_password_rotation_during_a_pool() {
    use tds_client::{
        ConnectionConfig, ConnectionServices, Pool, PoolPolicy,
        auth::{Method, WindowsAuth},
    };
    let lab = lab();
    let mut sql = ConnectOptions::new(
        lab.get("sql_vm_public_ip"),
        1433,
        "tdsadmin",
        lab.secret("sql_admin_password"),
        lab.vm_roots(),
    );
    sql.timeout = Duration::from_secs(30);
    for (scope, vm, prefix) in [
        ("local", "vm-tds-sql", "TDSSQL"),
        ("domain", "vm-tds-dc", "TDS"),
    ] {
        let (first, second) = (throwaway_password(), throwaway_password());
        // A new name each run: a reused name can map to a deleted account's cached SID.
        let name = format!("tdsrot-{}", &throwaway_password()[4..12]);
        rotation_account(&lab, vm, "create", scope, &name, &first);
        let login = format!("{prefix}\\{name}");
        let admin = connect(sql.clone()).await;
        run(
            &admin,
            &format!("IF SUSER_ID(N'{login}') IS NULL CREATE LOGIN [{login}] FROM WINDOWS"),
        )
        .await;
        let mut options = windows_sql(
            &lab,
            Authentication::Windows(WindowsAuth::explicit(Method::Ntlm, &login, &first)),
        );
        options.timeout = Duration::from_secs(30);
        let source = Arc::new(WindowsSource(std::sync::Mutex::new(
            ConnectionConfig::from_options(&options),
        )));
        let pool = Pool::from_config(
            source.clone(),
            3,
            ConnectionServices::new(lab.vm_roots()),
            PoolPolicy::default(),
        )
        .unwrap();
        let old = pool.acquire().await.unwrap();
        assert_eq!(who(&old).await.0.to_uppercase(), login.to_uppercase());

        rotation_account(&lab, vm, "set", scope, &name, &second);
        let with_old = pool.acquire().await;
        let old_accepted = with_old.is_ok();
        match &with_old {
            Ok(_) => println!(
                "ROTATION {scope}: the old password still logged in right after the change"
            ),
            Err(e) => {
                assert!(
                    matches!(&e.cause().kind, ErrorKind::Server(m) if m.number == 18452),
                    "{e}"
                );
                println!(
                    "ROTATION {scope}: the old password is refused (18452); unchanged settings are not retried"
                );
            }
        }
        source.0.lock().unwrap().authentication =
            Authentication::Windows(WindowsAuth::explicit(Method::Ntlm, &login, &second));
        let new = pool.acquire().await.unwrap();
        assert_eq!(who(&new).await.0.to_uppercase(), login.to_uppercase());
        println!("ROTATION {scope}: a new login with the new password after re-reading settings");
        // The session opened with the old password is retired when it comes back.
        assert_eq!(old.release().await.unwrap(), ReleaseOutcome::Discarded);
        assert_eq!(new.release().await.unwrap(), ReleaseOutcome::Returned);
        if let Ok(lease) = with_old {
            drop(lease);
        }
        pool.close().await.unwrap();
        // A closing pool's sessions can outlive close() briefly on the server:
        // end them (each may already be gone) and retry the drop.
        run(&admin, &format!("DECLARE @i int = 0, @k nvarchar(max); WHILE SUSER_ID(N'{login}') IS NOT NULL AND @i < 10 BEGIN SET @k = N''; SELECT @k += N'BEGIN TRY KILL ' + CAST(session_id AS nvarchar) + N' END TRY BEGIN CATCH END CATCH;' FROM sys.dm_exec_sessions WHERE login_name = N'{login}'; EXEC (@k); BEGIN TRY DROP LOGIN [{login}] END TRY BEGIN CATCH WAITFOR DELAY '00:00:01' END CATCH; SET @i += 1; END")).await;
        assert!(
            rows(&admin, &format!("SELECT SUSER_ID(N'{login}')")).await[0][0].is_none(),
            "login dropped"
        );
        admin.close().await.unwrap();
        rotation_account(&lab, vm, "remove", scope, &name, "");
        println!("ROTATION {scope}: done (old password accepted after the change: {old_accepted})");
    }
}

/// The application-signed assertion that `infra/azure/paired.py assertion`
/// wrote (valid for ten minutes): signing belongs to the application.
#[derive(Debug)]
struct SignedAssertion(String);
#[async_trait::async_trait]
impl azure_identity::ClientAssertion for SignedAssertion {
    async fn secret(
        &self,
        _: Option<azure_core::http::ClientMethodOptions<'_>>,
    ) -> azure_core::Result<String> {
        Ok(self.0.clone())
    }
}

/// Follow-up F1: a certificate-based service principal without OpenSSL, through
/// `ClientAssertionCredential` (owner decision F3, exception E-CRED-1).
#[tokio::test]
#[ignore = "live Azure campaign: follow-ups (after paired.py assertion)"]
async fn mac_client_assertion_logs_in_with_both_flows() {
    let lab = lab();
    let jwt = std::fs::read_to_string(lab.dir.join("secrets/assertion.jwt"))
        .expect("run infra/azure/paired.py assertion first");
    let credential: Arc<dyn TokenCredential> = azure_identity::ClientAssertionCredential::new(
        lab.get("tenant_id").to_owned(),
        lab.get("service_principal_client_id").to_owned(),
        SignedAssertion(jwt),
        None,
    )
    .unwrap();
    for deferred in [false, true] {
        let provider = Counting::new(Arc::new(AzureTokenProvider::new(credential.clone())));
        let options = azure_sql(
            &lab,
            entra("assertion", deferred),
            TokenProviders::new().with("assertion", provider.clone()),
        );
        let connection = connect(options).await;
        let (login, user, _) = who(&connection).await;
        assert_eq!(user, lab.get("service_principal_name"));
        println!("ENTRA client assertion deferred={deferred} login={login} user={user}");
        connection.close().await.unwrap();
    }
}

/// Follow-up F2: the Azure Developer CLI credential, with `azd` signed in as the
/// campaign's service principal (`azd auth login --client-certificate ...`).
#[tokio::test]
#[ignore = "live Azure campaign: follow-ups (after azd auth login)"]
async fn mac_azure_developer_cli_logs_in_with_both_flows() {
    let lab = lab();
    let credential: Arc<dyn TokenCredential> =
        azure_identity::AzureDeveloperCliCredential::new(None).unwrap();
    for deferred in [false, true] {
        let provider = Counting::new(Arc::new(AzureTokenProvider::new(credential.clone())));
        let options = azure_sql(
            &lab,
            entra("azd", deferred),
            TokenProviders::new().with("azd", provider.clone()),
        );
        let connection = connect(options).await;
        let (login, user, _) = who(&connection).await;
        assert_eq!(user, lab.get("service_principal_name"));
        println!("ENTRA Azure Developer CLI deferred={deferred} login={login} user={user}");
        connection.close().await.unwrap();
    }
}
