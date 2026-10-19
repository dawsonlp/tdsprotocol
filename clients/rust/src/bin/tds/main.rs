//! A small, literal client of the public API: connect, open a channel, exchange,
//! read, close. No driver logic belongs here. Use --observe to see the wire work.
mod params;
mod replay;
use std::{path::PathBuf, sync::Arc};
use tds_client::{
    Batch, Call, Cell, Chunk, ConnectOptions, Connection, ProtocolVersion, Source, SourceRead,
    StreamedCall, Value,
    auth::{Method, WindowsAuth},
    capture::Capture,
    observe::{Level, Observer},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const HELP: &str = "tds — explore the Rust TDS client

Usage: tds [connection options] [--query SQL | --proc NAME [parameters]]
       tds --replay PATH [--observe off|outline|full]

Connection:
  --host HOST           default 127.0.0.1
  --port PORT           default 14325 (repository Docker server)
  --user USER           default sa
  --database NAME       default tds_test
  --password-env NAME   default MSSQL_SA_PASSWORD; never a password argument
  --auth sql|ntlm|kerberos|negotiate   default sql; others need integrated-auth
  --native-windows      use signed-in Windows identity instead of a password
  --spn NAME            explicit SQL service principal
  --kdc-url tcp://HOST:88   portable Kerberos/Negotiate KDC
  --allow-ntlm-fallback  explicitly permit Negotiate to choose NTLM
  --ca-file PATH        certificate authority PEM; verification is always enabled
  --server-name NAME    explicit certificate name, if different from host
  --tds-version 7.4|8.0 default 7.4
  --mars               use MARS framing
  --timeout SECONDS     total opening budget, default 15

Requests:
  --demo-transactions   run explicit begin/save/rollback/commit and show server state
  --demo-bulk           stream rows into a temporary table; demonstrate finish/abort
  --query SQL           literal batch, default SELECT 1 AS answer
  --proc NAME           a named stored procedure, sent as RPC
  --param NAME:TYPE=VALUE       input parameter; empty name means positional
  --output NAME:TYPE=VALUE      input/output parameter
  --null NAME:TYPE             explicit SQL NULL
  --out-null NAME:TYPE         NULL input/output parameter
  --default NAME:TYPE          use the procedure's default
  --param-file NAME:varbinary(max)=PATH  stream binary file bytes as input

Parameter types: integer widths, bit, real/float, decimal(p,s)/numeric(p,s),
money/smallmoney, nvarchar(n|max)/nchar(n), varchar(n|max)/char(n),
varbinary(n|max)/binary(n), xml/json, vector(n[,float32|float16]), date,
time(s), datetime2(s), datetimeoffset(s), datetime (days,ticks),
smalldatetime (days,minutes), uniqueidentifier, clr(schema.name) (hex bytes). Values are parsed as the
declared type; strings are never inserted into SQL. Binary values are hex.

Reading/diagnostics:
  --replay PATH        inspect a Python/Rust recording offline; no connection
  --fetch              retain the entire response, then print it
  --stream             borrow rows/cells; print chunk sizes and short previews
  --observe off|outline|full   default outline, written to stderr
  --capture PATH       create a saved conversation exclusively (query/data included)
  --help               show this text without connecting

Default credentials/CA are read from the repository's existing Docker setup.
Other servers should supply --ca-file and the password environment variable.
Without --fetch, rows are read forward and printed one at a time.
";

struct Args {
    authentication: Option<Method>,
    native_windows: bool,
    spn: Option<String>,
    kdc_url: Option<String>,
    allow_ntlm_fallback: bool,
    replay: Option<PathBuf>,
    host: String,
    port: u16,
    user: String,
    database: String,
    password_env: String,
    ca: PathBuf,
    server_name: Option<String>,
    version: ProtocolVersion,
    mars: bool,
    timeout: std::time::Duration,
    query: Option<String>,
    demo_transactions: bool,
    demo_bulk: bool,
    procedure: Option<String>,
    parameters: Vec<(String, String)>,
    observe: Level,
    capture: Option<PathBuf>,
    fetch: bool,
    stream: bool,
}
impl Args {
    fn read() -> Result<Option<Self>> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut args = Self {
            authentication: None,
            native_windows: false,
            spn: None,
            kdc_url: None,
            allow_ntlm_fallback: false,
            replay: None,
            host: "127.0.0.1".into(),
            port: 14325,
            user: "sa".into(),
            database: "tds_test".into(),
            password_env: "MSSQL_SA_PASSWORD".into(),
            ca: root.join("docker/macos/tls/test-ca.pem"),
            server_name: None,
            version: ProtocolVersion::V7_4,
            mars: false,
            timeout: std::time::Duration::from_secs(15),
            query: None,
            demo_transactions: false,
            demo_bulk: false,
            procedure: None,
            parameters: Vec::new(),
            observe: Level::Outline,
            capture: None,
            fetch: false,
            stream: false,
        };
        let mut words = std::env::args().skip(1);
        let mut live_options = false;
        while let Some(option) = words.next() {
            live_options |= !matches!(option.as_str(), "--replay" | "--observe" | "--help" | "-h");
            match option.as_str() {
                "--help" | "-h" => {
                    println!("{HELP}");
                    return Ok(None);
                }
                "--mars" => {
                    args.mars = true;
                    continue;
                }
                "--native-windows" => {
                    args.native_windows = true;
                    continue;
                }
                "--allow-ntlm-fallback" => {
                    args.allow_ntlm_fallback = true;
                    continue;
                }
                "--demo-transactions" => {
                    args.demo_transactions = true;
                    continue;
                }
                "--demo-bulk" => {
                    args.demo_bulk = true;
                    continue;
                }
                "--stream" => {
                    args.stream = true;
                    continue;
                }
                "--fetch" => {
                    args.fetch = true;
                    continue;
                }
                _ => {}
            }
            let value = words.next().ok_or("option requires a value; use --help")?;
            match option.as_str() {
                "--replay" => args.replay = Some(value.into()),
                "--host" => args.host = value,
                "--port" => args.port = value.parse()?,
                "--user" => args.user = value,
                "--database" => args.database = value,
                "--password-env" => args.password_env = value,
                "--auth" => {
                    args.authentication = match value.as_str() {
                        "sql" => None,
                        "ntlm" => Some(Method::Ntlm),
                        "kerberos" => Some(Method::Kerberos),
                        "negotiate" => Some(Method::Negotiate),
                        _ => return Err("unknown authentication method".into()),
                    }
                }
                "--spn" => args.spn = Some(value),
                "--kdc-url" => args.kdc_url = Some(value),
                "--ca-file" => args.ca = value.into(),
                "--server-name" => args.server_name = Some(value),
                "--tds-version" => {
                    args.version = match value.as_str() {
                        "7.4" => ProtocolVersion::V7_4,
                        "8.0" => ProtocolVersion::V8_0,
                        _ => return Err("TDS version must be 7.4 or 8.0".into()),
                    }
                }
                "--timeout" => {
                    args.timeout = std::time::Duration::try_from_secs_f64(value.parse()?)?
                }
                "--query" => args.query = Some(value),
                "--proc" => args.procedure = Some(value),
                "--param" | "--output" | "--null" | "--out-null" | "--default" | "--param-file" => {
                    args.parameters.push((option, value))
                }
                "--observe" => {
                    args.observe = match value.as_str() {
                        "off" => Level::Off,
                        "outline" => Level::Outline,
                        "full" => Level::Full,
                        _ => return Err("observe must be off, outline or full".into()),
                    }
                }
                "--capture" => args.capture = Some(value.into()),
                _ => return Err("unknown option; use --help".into()),
            }
        }
        if args.replay.is_some() && live_options {
            return Err(
                "--replay accepts only --observe; omit live connection/request options".into(),
            );
        }
        if args.demo_bulk && args.demo_transactions {
            return Err("choose one demonstration".into());
        }
        if (args.demo_transactions || args.demo_bulk)
            && (args.query.is_some() || args.procedure.is_some() || !args.parameters.is_empty())
        {
            return Err(
                "demonstrations are self-contained; omit query/procedure parameters".into(),
            );
        }
        if args.stream && args.fetch {
            return Err("choose --stream or --fetch".into());
        }
        if args.query.is_some() && args.procedure.is_some() {
            return Err("choose --query or --proc".into());
        }
        if args.authentication.is_none()
            && (args.native_windows
                || args.spn.is_some()
                || args.kdc_url.is_some()
                || args.allow_ntlm_fallback)
        {
            return Err(
                "Windows authentication options require --auth ntlm, kerberos or negotiate".into(),
            );
        }
        if !args.parameters.is_empty() && args.procedure.is_none() {
            return Err("parameters require --proc".into());
        }
        Ok(Some(args))
    }
    fn password(&self) -> Result<String> {
        if let Ok(password) = std::env::var(&self.password_env) {
            return Ok(password);
        }
        if self.password_env == "MSSQL_SA_PASSWORD" {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
            if let Ok(contents) = std::fs::read_to_string(root.join("docker/macos/.env"))
                && let Some(password) = contents
                    .lines()
                    .find_map(|line| line.strip_prefix("MSSQL_SA_PASSWORD="))
            {
                return Ok(password.to_owned());
            }
        }
        Err("password environment variable is unavailable".into())
    }
}
fn cell(value: Option<&Value>) -> String {
    match value {
        None => "NULL".into(),
        Some(Value::Integer(v)) => v.to_string(),
        Some(Value::Bit(v)) => v.to_string(),
        Some(Value::Real(v)) => v.to_float().to_string(),
        Some(Value::Float(v)) => v.to_float().to_string(),
        Some(Value::Decimal(v)) => v.to_string(),
        Some(Value::Unicode(v)) => v
            .to_string()
            .map(|s| format!("{s:?}"))
            .unwrap_or_else(|_| format!("UTF16 {:?}", v.0)),
        Some(Value::Text(raw)) => match raw.decode() {
            Ok(text) => cell(Some(&Value::Unicode(text))),
            Err(_) => format!("{raw:?}"),
        },
        Some(Value::Binary(v)) => format!(
            "0x{}",
            v.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
        Some(value) => format!("{value:?}"),
    }
}
fn row(values: &tds_client::Row) {
    println!(
        "{}",
        values
            .iter()
            .map(|v| cell(v.as_ref()))
            .collect::<Vec<_>>()
            .join("\t")
    );
}
fn columns(columns: &[tds_client::tokens::Column]) {
    println!(
        "{}",
        columns
            .iter()
            .map(|c| c.name.to_string().unwrap_or_else(|_| "<UTF16 name>".into()))
            .collect::<Vec<_>>()
            .join("\t")
    );
}
struct FileSource(tokio::fs::File);
impl Source for FileSource {
    fn next_chunk(&mut self) -> SourceRead<'_> {
        Box::pin(async move {
            use tokio::io::AsyncReadExt;
            let mut bytes = vec![0; 65536];
            let count = self.0.read(&mut bytes).await?;
            bytes.truncate(count);
            Ok((count != 0).then_some(Chunk::Binary(bytes)))
        })
    }
}
fn preview(chunk: &Chunk) -> String {
    match chunk {
        Chunk::Unicode(text) => format!(
            "{:?}",
            String::from_utf16_lossy(&text.0[..text.0.len().min(24)])
        ),
        Chunk::Binary(bytes) => format!("{:02x?}", &bytes[..bytes.len().min(16)]),
        Chunk::Text(text) => format!(
            "{:02x?} under {:?}",
            &text.bytes[..text.bytes.len().min(16)],
            text.collation
        ),
    }
}
async fn transaction_demo(
    connection: &Connection,
    channel: &mut tds_client::SerialChannel,
) -> Result<()> {
    use tds_client::{
        Isolation, Transaction as T,
        transactions::{Begin, End},
    };
    let operations = [
        (
            "begin",
            T::Begin(Begin {
                isolation: Isolation::Serializable,
                name: "demo".into(),
            }),
        ),
        ("savepoint", T::Save("before".into())),
        (
            "rollback to savepoint",
            T::Rollback(End {
                name: "before".into(),
                begin: None,
            }),
        ),
        ("commit", T::Commit(End::default())),
    ];
    for (label, operation) in operations {
        channel.exchange(operation).await?.finish().await?;
        println!(
            "{label}: transaction descriptor {}",
            connection.session().await?.transaction
        );
        let mut response = channel
            .exchange(Batch::new(
                "SELECT @@TRANCOUNT AS nesting, XACT_STATE() AS state",
            ))
            .await?;
        let fetched = response.fetch().await?;
        for set in fetched.result_sets() {
            columns(&set.columns);
            for values in set.rows()? {
                row(values);
            }
        }
    }
    Ok(())
}
async fn bulk_demo(channel: &mut tds_client::SerialChannel) -> Result<()> {
    channel
        .exchange(Batch::new(
            "CREATE TABLE #tds_cli_bulk(n int,note nvarchar(max))",
        ))
        .await?
        .finish()
        .await?;
    let metadata = channel
        .exchange(Batch::new("SELECT TOP 0 n,note FROM #tds_cli_bulk"))
        .await?
        .fetch()
        .await?
        .result_sets()[0]
        .columns
        .clone();
    let rows = vec![
        vec![Some(Value::Integer(1)), Some(Value::Unicode("é🦀".into()))],
        vec![
            Some(Value::Integer(2)),
            Some(Value::Unicode(tds_client::SqlText(
                "large ".repeat(100000).encode_utf16().collect(),
            ))),
        ],
    ];
    let loaded = channel
        .bulk(
            "INSERT BULK #tds_cli_bulk(n int,note nvarchar(max))",
            metadata.clone(),
        )
        .await?
        .finish_source(rows.into_iter())
        .await?;
    println!(
        "bulk finish: {} rows",
        loaded
            .completions()
            .filter_map(|d| d.row_count)
            .sum::<u64>()
    );
    channel
        .bulk(
            "INSERT BULK #tds_cli_bulk(n int,note nvarchar(max))",
            metadata,
        )
        .await?
        .abort()
        .await?;
    println!("bulk abort: acknowledged; earlier rows preserved");
    let fetched = channel
        .exchange(Batch::new(
            "SELECT n,DATALENGTH(note) AS bytes FROM #tds_cli_bulk ORDER BY n",
        ))
        .await?
        .fetch()
        .await?;
    for set in fetched.result_sets() {
        columns(&set.columns);
        for values in set.rows()? {
            row(values);
        }
    }
    channel
        .exchange(Batch::new("DROP TABLE #tds_cli_bulk"))
        .await?
        .finish()
        .await?;
    Ok(())
}
async fn run(args: Args) -> Result<()> {
    if let Some(path) = &args.replay {
        return replay::run(path, args.observe);
    }
    let password = if args.native_windows {
        String::new()
    } else {
        args.password()?
    };
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&args.ca)?;
    for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots.add(cert?)?;
    }
    if roots.is_empty() {
        return Err("CA file contains no certificates".into());
    }
    let mut options = if let Some(method) = args.authentication {
        let mut auth = if args.native_windows {
            WindowsAuth::signed_in(method)
        } else {
            WindowsAuth::explicit(method, args.user, password)
        };
        auth.service_principal = args.spn;
        auth.kdc_url = args.kdc_url;
        auth.allow_ntlm_fallback = args.allow_ntlm_fallback;
        ConnectOptions::integrated(args.host, args.port, auth, roots)
    } else {
        ConnectOptions::new(args.host, args.port, args.user, password, roots)
    };
    options.database = args.database;
    options.server_name = args.server_name;
    options.version = args.version;
    options.mars = args.mars;
    options.timeout = args.timeout;
    if args.observe != Level::Off {
        options.observe = Some(Observer::new(args.observe, |event| {
            eprintln!("{:>8.3}s {}", event.elapsed.as_secs_f64(), event.text);
            if let Some(timing) = event.timing {
                let summary = timing.summary();
                if !summary.is_empty() {
                    eprintln!("           {summary}");
                }
            }
            if let Some(inspection) = &event.inspection {
                eprintln!("{}", inspection.render());
            }
            for node in &event.fields {
                eprintln!("{}", node.render());
            }
            Ok(())
        }));
    }
    if let Some(path) = args.capture {
        let next = std::sync::atomic::AtomicUsize::new(0);
        options.capture_factory = Some(Arc::new(move || {
            let index = next
                .try_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |n| n.checked_add(1),
                )
                .map_err(|_| std::io::Error::other("recording sequence exhausted"))?;
            let mut target = path.clone().into_os_string();
            if index != 0 {
                target.push(format!(".{index}"));
            }
            let target = PathBuf::from(target);
            let capture = Capture::create(&target)?;
            eprintln!("recording {}", target.display());
            Ok(capture)
        }));
    }
    let connection = Connection::connect(options).await?;
    let result = async {
        let mut channel = connection.serial_channel().await?;
        if args.demo_transactions { return transaction_demo(&connection, &mut channel).await; }
        if args.demo_bulk { return bulk_demo(&mut channel).await; }
        let mut response = if let Some(procedure) = args.procedure {
            let collation = connection.session().await?.collation;
            let collation = tds_client::Collation(
                collation
                    .try_into()
                    .map_err(|_| "server has not announced a collation")?,
            );
            let mut parameters = Vec::new();
            let mut files = Vec::new();
            for (kind, spec) in &args.parameters {
                if kind == "--param-file" {
                    let (head, path) = spec.split_once('=').ok_or("file parameter requires NAME:TYPE=PATH")?;
                    let param = params::parse("--null", head, collation)?;
                    if param.sql_type != tds_client::SqlType::BinaryMax {
                        return Err("--param-file requires varbinary(max); file bytes have no implicit text codec".into());
                    }
                    files.push((parameters.len(), FileSource(tokio::fs::File::open(path).await?)));
                    parameters.push(param);
                } else { parameters.push(params::parse(kind, spec, collation)?); }
            }
            let mut call = StreamedCall::new(Call::new(procedure, parameters));
            for (index, source) in files { call = call.source(index, source); }
            channel.exchange(call).await?
        } else {
            channel
                .exchange(Batch::new(
                    args.query.unwrap_or_else(|| "SELECT 1 AS answer".into()),
                ))
                .await?
        };
        if args.fetch {
            let kept = response.fetch().await?;
            for set in kept.result_sets() {
                columns(&set.columns);
                for values in set.rows()? {
                    row(values);
                }
            }
        } else if args.stream {
            while let Some(mut set) = response.next_result_set().await? {
                columns(&set.columns);
                while let Some(mut values) = set.streamed_row().await? {
                    println!("row");
                    let mut index = 0;
                    while let Some(value) = values.next_value().await? {
                        index += 1;
                        match value {
                            Cell::Null => println!("  cell {index}: NULL"),
                            Cell::Scalar(value) => println!("  cell {index}: {}", cell(Some(&value))),
                            Cell::Stream(mut value) => {
                                println!("  cell {index}: {:?}, wire total bytes {:?}", value.sql_type, value.total_length);
                                let mut count = 0_u64;
                                while let Some(chunk) = value.next_chunk().await? {
                                    count += chunk.byte_len() as u64;
                                    println!("    {} typed bytes · {}", chunk.byte_len(), preview(&chunk));
                                }
                                println!("    end · {count} bytes in typed chunks");
                            }
                        }
                    }
                }
            }
        } else {
            while let Some(mut set) = response.next_result_set().await? {
                columns(&set.columns);
                while let Some(values) = set.next_row().await? {
                    row(&values);
                }
            }
        }
        let kept = response.snapshot();
        for message in kept.messages() {
            eprintln!("message {}: {}", message.number, message.text.to_string()?);
        }
        for (index, returned) in kept.returns().iter().enumerate() {
            println!(
                "call {}: return {}, failed {}",
                index + 1,
                returned
                    .status
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "not supplied".into()),
                returned.failed
            );
            for output in &returned.outputs {
                println!(
                    "output {} [{}] = {}",
                    output.name.to_string()?,
                    output.ordinal,
                    cell(output.value.as_ref())
                );
            }
        }
        Result::Ok(())
    }
    .await;
    let closed = connection.close().await;
    result?;
    closed?;
    Ok(())
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let result = match Args::read() {
        Ok(Some(args)) => run(args).await,
        Ok(None) => Ok(()),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        if let Some(tds) = error.downcast_ref::<tds_client::Error>()
            && let Some(record) = &tds.response
        {
            for message in record.errors() {
                eprintln!(
                    "SQL {}: {}",
                    message.number,
                    message
                        .text
                        .to_string()
                        .unwrap_or_else(|_| "<UTF16 message>".into())
                );
            }
        }
        std::process::exit(1);
    }
}
