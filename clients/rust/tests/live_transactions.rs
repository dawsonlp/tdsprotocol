#![cfg(feature = "tokio")]
mod support;
use tds_client::{
    Batch, Connection, ErrorKind, Isolation, Pool, ProtocolVersion, Transaction as T, Value,
    transactions::{Begin, End},
};
async fn sql(channel: &mut tds_client::SerialChannel, text: &str) -> tds_client::FetchedResponse {
    channel
        .exchange(Batch::new(text))
        .await
        .unwrap()
        .fetch()
        .await
        .unwrap()
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn transaction_operations_follow_announcements_savepoints_errors_and_shared_state() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            sql(&mut channel, "CREATE TABLE #tm(n int)").await;
            channel
                .exchange(T::Begin(Begin {
                    isolation: Isolation::Serializable,
                    name: "outer".into(),
                }))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            let descriptor = connection.session().await.unwrap().transaction;
            assert_ne!(descriptor, 0);
            sql(&mut channel, "INSERT #tm VALUES(1)").await;
            channel
                .exchange(T::Save("before".into()))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            sql(&mut channel, "INSERT #tm VALUES(2)").await;
            channel
                .exchange(T::Rollback(End {
                    name: "before".into(),
                    begin: None,
                }))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            assert_eq!(connection.session().await.unwrap().transaction, descriptor);
            channel
                .exchange(T::Begin(Begin::default()))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            channel
                .exchange(T::Commit(End::default()))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            assert_eq!(connection.session().await.unwrap().transaction, descriptor);
            if mars {
                let mut sibling = connection.serial_channel().await.unwrap();
                let fetched = sql(&mut sibling, "SELECT @@TRANCOUNT").await;
                assert_eq!(
                    fetched.result_sets()[0].rows().unwrap()[0][0],
                    Some(Value::Integer(1))
                );
                sibling.close().await.unwrap();
            }
            channel
                .exchange(T::Commit(End {
                    begin: Some(Begin {
                        isolation: Isolation::ReadCommitted,
                        name: "next".into(),
                    }),
                    ..End::default()
                }))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            assert_ne!(connection.session().await.unwrap().transaction, 0);
            channel
                .exchange(T::Rollback(End::default()))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            assert_eq!(connection.session().await.unwrap().transaction, 0);
            assert_eq!(
                sql(&mut channel, "SELECT SUM(n) FROM #tm")
                    .await
                    .result_sets()[0]
                    .rows()
                    .unwrap()[0][0],
                Some(Value::Integer(1))
            );
            let error = channel
                .exchange(T::Commit(End::default()))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap_err();
            assert!(matches!(error.kind, ErrorKind::ServerErrors(_)));
            channel
                .exchange(T::Begin(Begin::default()))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            assert!(
                channel
                    .exchange(T::Save("".into()))
                    .await
                    .unwrap()
                    .finish()
                    .await
                    .is_err()
            );
            assert_eq!(connection.session().await.unwrap().transaction, 0); // Server's refusal rolls it back.
            assert!(
                channel
                    .exchange(T::Propagate(vec![1, 2, 3]))
                    .await
                    .unwrap()
                    .finish()
                    .await
                    .is_err()
            );
            sql(&mut channel, "SELECT 42").await;
            connection.close().await.unwrap();
        }
    }
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn deferred_pool_reset_applies_to_a_transaction_manager_request() {
    let pool = Pool::new(support::docker_options(), 1).unwrap();
    let first = pool.acquire().await.unwrap();
    sql(
        &mut first.serial_channel().await.unwrap(),
        "SET DATEFIRST 3",
    )
    .await;
    first.release().await.unwrap();
    let next = pool.acquire().await.unwrap();
    let mut channel = next.serial_channel().await.unwrap();
    channel
        .exchange(T::Begin(Begin::default()))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    assert_eq!(
        sql(&mut channel, "SELECT @@DATEFIRST,@@TRANCOUNT")
            .await
            .result_sets()[0]
            .rows()
            .unwrap()[0],
        vec![Some(Value::Integer(7)), Some(Value::Integer(1))]
    );
    channel
        .exchange(T::Rollback(End::default()))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    next.release().await.unwrap();
    pool.close().await.unwrap();
}
