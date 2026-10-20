//! The `tds` CLI's Entra modes (Part B: B-9), run as the real executable. A fake
//! `az` first on PATH stands in for the Azure CLI that the official credential
//! invokes (`/bin/sh -c "cd /bin && az account get-access-token ..."`).
#![cfg(all(unix, feature = "azure-identity"))]
mod support;
use std::{os::unix::fs::PermissionsExt, path::PathBuf};
use support::Peer;

const TOKEN: &str = "fake-cli-token-for-tds";

/// A directory holding the fake `az`, which logs its arguments and prints a token.
fn fake_az(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("tds-fake-az-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("calls.log");
    let script = dir.join("az");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\nnow=$(date +%s)\n\
             printf '{{\"accessToken\":\"{TOKEN}\",\"expires_on\":%s,\"tokenType\":\"Bearer\"}}' $((now + 3600))\n",
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    (dir, log)
}
fn carries(bytes: &[u8]) -> bool {
    let wire: Vec<u8> = TOKEN.encode_utf16().flat_map(u16::to_le_bytes).collect();
    bytes.windows(wire.len()).any(|w| w == wire)
}
/// FEDAUTHINFO naming Azure SQL's SPN, as in `azure_login.rs`.
fn info() -> Vec<u8> {
    let values: Vec<Vec<u8>> = [
        "https://login.example/tenant",
        "https://database.windows.net/",
    ]
    .iter()
    .map(|v| v.encode_utf16().flat_map(u16::to_le_bytes).collect())
    .collect();
    let mut body = 2_u32.to_le_bytes().to_vec();
    let mut offset = 22_u32;
    for (index, bytes) in values.iter().enumerate() {
        body.push(index as u8 + 1);
        body.extend((bytes.len() as u32).to_le_bytes());
        body.extend(offset.to_le_bytes());
        offset += bytes.len() as u32;
    }
    for bytes in values {
        body.extend(bytes);
    }
    let mut token = vec![0xee];
    token.extend((body.len() as u32).to_le_bytes());
    token.extend(body);
    token
}

#[tokio::test]
async fn cli_entra_modes_send_the_azure_cli_token_and_never_print_it() {
    for (mode, deferred) in [("entra-upfront", false), ("entra-deferred", true)] {
        let (listener, _) = support::listener().await;
        let port = listener.local_addr().unwrap().port();
        let (dir, log) = fake_az(mode);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut peer, login) = Peer::await_login(socket, false).await;
            let carrier = if deferred {
                peer.reply(&info()).await;
                let (kind, body) = peer.message().await;
                assert_eq!(kind, 0x08);
                body
            } else {
                login
            };
            assert!(
                carries(&carrier),
                "the Azure CLI's token reaches the server"
            );
            peer.accept_login(0x74000004, false, &[0xae, 2, 0, 0, 0, 0, 0xff])
                .await;
            assert_eq!(peer.message().await.0, tds_client::packet::BATCH);
            peer.reply(&support::done(0)).await;
            peer.drain_to_eof().await;
        });
        let path = format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_tds"))
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--database",
                "tds_test",
                "--auth",
                mode,
                "--ca-file",
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/test-ca.pem"),
                "--tds-version",
                "8.0",
                "--query",
                "SELECT 1",
            ])
            .env("PATH", path)
            .env_remove("MSSQL_SA_PASSWORD")
            .output()
            .await
            .unwrap();
        let printed = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "{mode}: {printed}");
        assert!(!printed.contains(TOKEN), "{mode}: token printed");
        server.await.unwrap();
        let calls = std::fs::read_to_string(&log).unwrap();
        assert!(
            calls.contains("--scope https://database.windows.net/.default"),
            "{mode}: {calls}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn cli_entra_refuses_windows_options_before_any_network_activity() {
    for extra in [["--native-windows", ""], ["--spn", "MSSQLSvc/host:1433"]] {
        let mut args = vec!["--host", "192.0.2.1", "--auth", "entra-upfront", extra[0]];
        if !extra[1].is_empty() {
            args.push(extra[1]);
        }
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_tds"))
            .args(&args)
            .env_remove("MSSQL_SA_PASSWORD")
            .output()
            .unwrap();
        assert!(!output.status.success(), "{args:?}");
        println!(
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
}
