//! Exercise the actual executable, not a parallel command-line implementation.
#![cfg(feature = "tokio")]
use std::process::Command;
fn tds() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tds"))
}
#[test]
fn help_requires_no_credentials_and_invalid_arguments_fail_before_network_setup() {
    let output = tds()
        .arg("--help")
        .env_remove("MSSQL_SA_PASSWORD")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("--proc"));
    let output = tds()
        .args(["--query", "SELECT 1", "--proc", "anything"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("choose --query or --proc")
    );
    let output = tds().args(["--param", "@x:int=1"]).output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn offline_replay_uses_no_live_configuration_and_reports_truncated_evidence() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let path = std::env::temp_dir().join(format!("tds-cli-replay-{}.jsonl", std::process::id()));
    let body = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let packet = tds_client::packet::split(4, &body, 4096).unwrap();
    let line =
        serde_json::json!({"t":0,"packet":"receive","channel":7,"bytes":STANDARD.encode(packet)});
    std::fs::write(&path, line.to_string()).unwrap();
    let output = tds()
        .args(["--replay", path.to_str().unwrap(), "--observe", "full"])
        .env_remove("MSSQL_SA_PASSWORD")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let full = String::from_utf8_lossy(&output.stdout);
    assert!(full.contains("0 issues"));
    assert!(full.contains("TDS packet header [Packet 0..8]"));
    assert!(full.contains("status [Token 1..3]"));
    assert!(full.contains("docs/design/3-reference/response.md"));
    let output = tds()
        .args([
            "--replay",
            path.to_str().unwrap(),
            "--ca-file",
            "missing-ca-file",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("omit live"));
    std::fs::write(&path, "{invalid-recording").unwrap();
    let output = tds()
        .args(["--replay", path.to_str().unwrap(), "--observe", "off"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Malformed"));
    std::fs::remove_file(path).unwrap();
}
#[test]
#[ignore = "requires the Docker SQL Server and test CA"]
fn executable_reads_rows_calls_output_parameters_and_reports_sql_errors() {
    for protocol in ["7.4", "8.0"] {
        for mars in [false, true] {
            let mut command = tds();
            command.args(["--observe", "off", "--tds-version", protocol]);
            if mars {
                command.arg("--mars");
            }
            let output = command
                .args([
                    "--proc",
                    "sp_executesql",
                    "--param",
                    "@stmt:nvarchar(4000)=SELECT @x AS answer; SET @x=42",
                    "--param",
                    "@params:nvarchar(4000)=@x int OUTPUT",
                    "--output",
                    "@x:int=7",
                ])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("answer\n7\n"));
            assert!(text.contains("output @x [2] = 42"));
        }
    }
    let output = tds()
        .args([
            "--observe",
            "off",
            "--fetch",
            "--query",
            "SELECT CAST(NULL AS int) AS missing, N'typed 🦀' AS label",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("NULL\t\"typed 🦀\"")
    );
    let output = tds()
        .args([
            "--observe",
            "off",
            "--query",
            "SELECT * FROM table_that_does_not_exist",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("SQL 208:")
    );
}

#[test]
#[ignore = "requires the Docker SQL Server and test CA"]
fn executable_streams_result_chunks_and_binary_file_parameters() {
    let path = std::env::temp_dir().join(format!("tds-cli-source-{}.bin", std::process::id()));
    std::fs::write(&path, vec![0x5a; 2 * 1024 * 1024]).unwrap();
    for version in ["7.4", "8.0"] {
        for mars in [false, true] {
            let mut command = tds();
            command.args(["--observe", "off", "--tds-version", version, "--stream"]);
            if mars {
                command.arg("--mars");
            }
            let output = command.args([
                "--proc", "sp_executesql",
                "--param", "@stmt:nvarchar(max)=SELECT DATALENGTH(@b) AS count, REPLICATE(CAST(N'x' AS nvarchar(max)), 600000) AS text",
                "--param", "@params:nvarchar(max)=@b varbinary(max)",
                "--param-file", &format!("@b:varbinary(max)={}", path.display()),
            ]).output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("cell 1: 2097152"));
            assert!(text.contains("end · 1200000 bytes"));
            assert!(text.len() < 100000); // Output is a chunk summary, not a retained whole value.
        }
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
#[ignore = "requires the Docker SQL Server and test CA"]
fn executable_demonstrates_explicit_transaction_state() {
    for version in ["7.4", "8.0"] {
        for mars in [false, true] {
            let mut command = tds();
            command.args([
                "--observe",
                "off",
                "--tds-version",
                version,
                "--demo-transactions",
            ]);
            if mars {
                command.arg("--mars");
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("begin: transaction descriptor"));
            assert!(text.contains("rollback to savepoint: transaction descriptor"));
            assert!(
                text.contains("commit: transaction descriptor 0\nnesting\tstate\n0\t0"),
                "{text}"
            );
        }
    }
}

#[test]
#[ignore = "requires the Docker SQL Server and test CA"]
fn executable_demonstrates_streamed_bulk_finish_and_explicit_abort() {
    for version in ["7.4", "8.0"] {
        for mars in [false, true] {
            let mut command = tds();
            command.args(["--observe", "off", "--tds-version", version, "--demo-bulk"]);
            if mars {
                command.arg("--mars");
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("bulk finish: 2 rows"), "{text}");
            assert!(
                text.contains("bulk abort: acknowledged; earlier rows preserved"),
                "{text}"
            );
            assert!(text.contains("1\t6\n2\t1200000"), "{text}");
        }
    }
}
