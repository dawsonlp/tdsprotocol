#![cfg(feature = "tokio")]
mod support;
use tds_client::{
    Batch, Connection, ErrorKind, ProtocolVersion, RowRead, RowSource, Transaction, Value,
};
async fn fetch(ch: &mut tds_client::SerialChannel, sql: &str) -> tds_client::FetchedResponse {
    ch.exchange(Batch::new(sql))
        .await
        .unwrap()
        .fetch()
        .await
        .unwrap()
}
struct Failing {
    at: usize,
    stop: usize,
}

#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn bulk_uses_result_fixed_codes_and_incremental_large_cells_without_rounding() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let connection = Connection::connect(options).await.unwrap();
            let mut ch = connection.serial_channel().await.unwrap();
            fetch(&mut ch,"CREATE TABLE #wide(id int NOT NULL,b bit NOT NULL,d decimal(38,7),m money,u nvarchar(max),x varbinary(max),dt datetime2(7),v sql_variant,vec vector(3)); INSERT #wide VALUES(7,1,-1234567890123456789012345678901.1234567,-1.2345,REPLICATE(CAST(N'é🦀' AS nvarchar(max)),100000),CONVERT(varbinary(max),REPLICATE(CAST('xyz' AS varchar(max)),100000)),'0001-01-01T00:00:00.0000001',CAST(42 AS bigint),CAST('[1,2.5,3]' AS vector(3))); INSERT #wide(id,b) VALUES(8,0)").await;
            let original = fetch(&mut ch, "SELECT * FROM #wide ORDER BY id").await;
            let rows = original.result_sets()[0].rows().unwrap().to_vec();
            let columns = original.result_sets()[0].columns.clone();
            fetch(&mut ch, "DELETE #wide").await;
            ch.bulk("INSERT BULK #wide(id int NOT NULL,b bit NOT NULL,d decimal(38,7),m money,u nvarchar(max),x varbinary(max),dt datetime2(7),v sql_variant,vec vector(3))",columns).await.unwrap().finish_source(rows.clone().into_iter()).await.unwrap();
            assert_eq!(
                fetch(&mut ch, "SELECT * FROM #wide ORDER BY id")
                    .await
                    .result_sets()[0]
                    .rows()
                    .unwrap(),
                rows
            );
            connection.close().await.unwrap();
        }
    }
}
impl RowSource for Failing {
    fn next_row(&mut self) -> RowRead<'_> {
        Box::pin(async {
            if self.at == self.stop {
                return Err(std::io::Error::other("synthetic row failure"));
            }
            self.at += 1;
            Ok(Some(vec![Some(Value::Integer(self.at as i64))]))
        })
    }
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn borrowed_bulk_finish_abort_encoding_failures_and_row_sources_preserve_the_session() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let connection = Connection::connect(options).await.unwrap();
            let mut ch = connection.serial_channel().await.unwrap();
            fetch(&mut ch, "CREATE TABLE #b(a int)").await;
            let columns = fetch(&mut ch, "SELECT TOP 0 a FROM #b").await.result_sets()[0]
                .columns
                .clone();
            let result = ch
                .bulk("INSERT BULK #b(a int)", columns.clone())
                .await
                .unwrap()
                .finish(vec![
                    vec![Some(Value::Integer(1))],
                    vec![Some(Value::Integer(2))],
                ])
                .await
                .unwrap();
            assert_eq!(result.completions().last().unwrap().row_count, Some(2));
            fetch(&mut ch, "DELETE #b").await;
            for stop in [0, 10000] {
                let error = ch
                    .bulk("INSERT BULK #b(a int)", columns.clone())
                    .await
                    .unwrap()
                    .finish_source(Failing { at: 0, stop })
                    .await
                    .unwrap_err();
                assert!(matches!(error.kind, ErrorKind::Io(_)), "{error:?}");
                assert_eq!(
                    fetch(&mut ch, "SELECT COUNT(*) FROM #b")
                        .await
                        .result_sets()[0]
                        .rows()
                        .unwrap()[0][0],
                    Some(Value::Integer(0))
                );
            }
            let error = ch
                .bulk("INSERT BULK #b(a int)", columns.clone())
                .await
                .unwrap()
                .finish(vec![vec![]])
                .await
                .unwrap_err();
            assert!(matches!(error.kind, ErrorKind::Parameter(_)), "{error:?}");
            assert!(
                ch.bulk("INSERT BULK #missing(a int)", columns.clone())
                    .await
                    .is_err()
            );
            fetch(&mut ch, "SET XACT_ABORT OFF").await;
            ch.exchange(Transaction::Begin(Default::default()))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            fetch(&mut ch, "INSERT #b VALUES(7)").await;
            ch.bulk("INSERT BULK #b(a int)", columns.clone())
                .await
                .unwrap()
                .abort()
                .await
                .unwrap();
            assert_eq!(
                fetch(&mut ch, "SELECT COUNT(*),@@TRANCOUNT,XACT_STATE() FROM #b")
                    .await
                    .result_sets()[0]
                    .rows()
                    .unwrap(),
                [vec![Some(Value::Integer(1)); 3]]
            );
            let closer = ch.close_handle();
            let writer = ch.bulk("INSERT BULK #b(a int)", columns).await.unwrap();
            closer.close().await.unwrap();
            drop(writer); // Proven delegated cleanup must not revoke the connection.
            let mut next = connection.serial_channel().await.unwrap();
            next.exchange(Transaction::Rollback(Default::default()))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            assert_eq!(
                fetch(&mut next, "SELECT COUNT(*) FROM #b")
                    .await
                    .result_sets()[0]
                    .rows()
                    .unwrap()[0][0],
                Some(Value::Integer(0))
            );
            connection.close().await.unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn bulk_drop_and_unresolved_pool_return_discard_instead_of_handing_off_the_continuation() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let pool = tds_client::Pool::new(options, 1).unwrap();
            let lease = pool.acquire().await.unwrap();
            let mut ch = lease.serial_channel().await.unwrap();
            fetch(&mut ch, "CREATE TABLE #b(a int)").await;
            let columns = fetch(&mut ch, "SELECT TOP 0 a FROM #b").await.result_sets()[0]
                .columns
                .clone();
            let writer = ch
                .bulk("INSERT BULK #b(a int)", columns.clone())
                .await
                .unwrap();
            let released = lease.release().await.unwrap();
            assert!(matches!(released, tds_client::ReleaseOutcome::Discarded));
            let lease = pool.acquire().await.unwrap();
            drop(writer); // Old authority cannot revoke the new borrower.
            let mut next = lease.serial_channel().await.unwrap();
            assert_eq!(
                fetch(&mut next, "SELECT 9").await.result_sets()[0]
                    .rows()
                    .unwrap()[0][0],
                Some(Value::Integer(9))
            );
            fetch(&mut next, "CREATE TABLE #b(a int)").await;
            drop(next.bulk("INSERT BULK #b(a int)", columns).await.unwrap());
            assert!(next.exchange(Batch::new("SELECT 10")).await.is_err());
            drop(next);
            drop(lease);
            pool.close().await.unwrap();
        }
    }
}
