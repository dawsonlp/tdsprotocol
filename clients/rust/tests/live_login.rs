//! Separately authenticated principals, not EXECUTE AS on an administrator.
//! Setup/cleanup use the existing ignored Docker credentials and disposable names.
#![cfg(feature = "tokio")]
use std::time::{SystemTime, UNIX_EPOCH};
use tds_client::Value::Integer as Int;
use tds_client::{Batch, Connection, ErrorKind, ProtocolVersion, SerialChannel};
mod support;

async fn rows(
    channel: &mut SerialChannel,
    sql: impl Into<String>,
) -> tds_client::Result<Vec<tds_client::Row>> {
    let mut response = channel.exchange(Batch::new(sql)).await?;
    let fetched = response.fetch().await?;
    Ok(fetched
        .result_sets()
        .iter()
        .flat_map(|set| set.rows().expect("complete fetched rows").iter().cloned())
        .collect())
}
#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn restricted_sql_login_has_only_its_actual_permissions_in_each_transport_mode() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let login = format!("tds_rust_login_{}_{}", std::process::id(), stamp);
    let table = format!("tds_rust_denied_{}_{}", std::process::id(), stamp);
    let password = format!("LocalTest_Aa1!_{stamp}"); // ephemeral local test credential; never printed
    let options = support::docker_options();
    let admin = Connection::connect(options.clone()).await.unwrap();
    let mut setup = admin.serial_channel().await.unwrap();
    let setup_result = rows(&mut setup, format!("CREATE LOGIN [{login}] WITH PASSWORD='{password}', CHECK_POLICY=OFF; CREATE USER [{login}] FOR LOGIN [{login}]; CREATE TABLE dbo.[{table}] (a int); INSERT dbo.[{table}] VALUES (42); DENY SELECT ON dbo.[{table}] TO [{login}]")).await;
    let observations = if setup_result.is_ok() {
        let login_name = login.clone();
        let denied_table = table.clone();
        async {
            let mut observed = Vec::new();
            for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
                for mars in [false, true] {
                    let mut config = options.clone();
                    config.user = login_name.clone();
                    config.password = password.clone();
                    config.version = version;
                    config.mars = mars;
                    let connection = Connection::connect(config).await?;
                    let mut channel = connection.serial_channel().await?;
                    let roles = rows(
                        &mut channel,
                        "SELECT IS_SRVROLEMEMBER('sysadmin'), IS_MEMBER('db_owner')",
                    )
                    .await?;
                    let denied =
                        rows(&mut channel, format!("SELECT a FROM dbo.[{denied_table}]")).await;
                    let reused = rows(&mut channel, "SELECT 7").await?;
                    let session = connection.session().await?;
                    observed.push((roles, denied, reused, session.database));
                    channel.close().await?;
                    connection.close().await?;
                }
            }
            Ok::<_, tds_client::Error>(observed)
        }
        .await
    } else {
        Err(setup_result.unwrap_err())
    };
    // The setup transport may itself have failed. Cleanup gets fresh privileged
    // authority rather than trying to reuse an uncertain protocol conversation.
    admin.close().await.unwrap();
    drop(setup);
    let cleanup_admin = Connection::connect(options).await.unwrap();
    let mut setup = cleanup_admin.serial_channel().await.unwrap();
    // Even a failed client check cleans its own isolated objects. KILL only this
    // generated login's sessions if a failed opening/operation left one ending.
    let cleanup = rows(&mut setup, format!("DECLARE @kill nvarchar(max)=N''; SELECT @kill += N'KILL '+CONVERT(nvarchar(12),session_id)+N';' FROM sys.dm_exec_sessions WHERE login_name=N'{login}'; IF LEN(@kill)>0 EXEC sp_executesql @kill; DROP USER IF EXISTS [{login}]; DROP TABLE IF EXISTS dbo.[{table}]; IF EXISTS(SELECT 1 FROM sys.server_principals WHERE name=N'{login}') DROP LOGIN [{login}]")).await;
    setup.close().await.unwrap();
    cleanup_admin.close().await.unwrap();
    cleanup.unwrap();
    for (roles, denied, reused, database) in observations.unwrap() {
        assert_eq!(roles, [vec![Some(Int(0)), Some(Int(0))]]);
        let denied = match denied {
            Err(error) => error,
            Ok(_) => panic!("restricted login read the denied table"),
        };
        assert!(
            matches!(&denied.kind, ErrorKind::ServerErrors(errors) if errors.iter().any(|e| e.number == 229))
        );
        assert!(denied.response.as_ref().unwrap().ended);
        assert_eq!(reused, [vec![Some(Int(7))]]);
        assert_eq!(database, "tds_test".into());
    }
}
