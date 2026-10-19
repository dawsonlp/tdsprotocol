#![cfg(feature = "tokio")]
mod support;
use tds_client::{
    Batch, Call, Collation, Connection, ErrorKind, IntegerSize, Param, ProtocolVersion, Row, Sort,
    SqlType, StreamedCall, TableColumn, TableType, Value,
};
fn int() -> SqlType {
    SqlType::Integer {
        size: IntegerSize::Int,
    }
}
async fn batch(ch: &mut tds_client::SerialChannel, sql: String) -> tds_client::Result<()> {
    ch.exchange(Batch::new(sql)).await?.finish().await
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn owned_and_produced_table_parameters_defaults_outputs_and_hints_reach_real_procedures() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let name = format!("tds_rows_{}_{stamp}", std::process::id());
            let proc = format!("{name}_p");
            let connection = Connection::connect(options.clone()).await.unwrap();
            let mut ch = connection.serial_channel().await.unwrap();
            let outcome = async {
                batch(&mut ch, format!(
                    "CREATE TYPE dbo.[{name}] AS TABLE(                     id int IDENTITY,a int NOT NULL,b nvarchar(max),c AS(a*2))"
                )).await?;
                batch(&mut ch, format!(
                    "CREATE PROCEDURE dbo.[{proc}] @t dbo.[{name}] READONLY,@n int OUTPUT AS                      BEGIN SET NOCOUNT ON; SELECT id,a,b,c FROM @t ORDER BY a;                      SET @n=(SELECT COUNT(*) FROM @t); RETURN 17; END"
                )).await?;
                let collation = Collation(connection.session().await?.collation.try_into().unwrap());
                let mut table = TableType::new("dbo", name.as_str(), vec![
                    TableColumn::default_value(int()),
                    int().into(),
                    SqlType::CharacterMax { unicode: true, collation }.into(),
                    TableColumn::default_value(int()),
                ]);
                let make = |parameter| Call::new(format!("dbo.{proc}"), vec![
                    parameter,
                    Param::new("@n", int(), Some(Value::Integer(0))).output(),
                ]);
                let supplied = vec![
                    vec![Some(Value::Integer(7)), Some(Value::Unicode("é🦀".into()))],
                    vec![Some(Value::Integer(9)), None],
                ];
                let owned = ch.exchange(make(Param::table("@t", table.clone(), Some(supplied))))
                    .await?.fetch().await?;
                let empty = ch.exchange(make(Param::default_value(
                    "@t", SqlType::Table(Box::new(table.clone())),
                ))).await?.fetch().await?;
                let refused = ch.exchange(make(Param::table("@t", table.clone(), None)))
                    .await?.fetch().await.unwrap_err();
                let refused_by_server = matches!(refused.kind, ErrorKind::ServerErrors(_));
                // Placement includes default columns, whose values are omitted.
                // Hint applicability remains the server's decision.
                table.order = vec![(2, Sort::Ascending)];
                table.unique = vec![2];
                table.send_order = vec![4, 3, 2, 1];
                let large = "é🦀".repeat(300000);
                let rows: Vec<Row> = vec![
                    vec![Some(Value::Integer(11)), Some(Value::Unicode(large.as_str().into()))],
                    vec![Some(Value::Integer(12)), None],
                ];
                let source = StreamedCall::new(make(Param::table("@t", table, None)))
                    .table_source(0, rows.into_iter());
                let produced = ch.exchange(source).await?.fetch().await?;
                Ok::<_, tds_client::Error>((owned, empty, refused_by_server, produced, large))
            }.await;
            // Always attempt object cleanup before inspecting semantic assertions.
            connection.close().await.unwrap();
            let admin = Connection::connect(options).await.unwrap();
            let mut cleanup = admin.serial_channel().await.unwrap();
            batch(
                &mut cleanup,
                format!("DROP PROCEDURE IF EXISTS dbo.[{proc}]; DROP TYPE IF EXISTS dbo.[{name}]"),
            )
            .await
            .unwrap();
            admin.close().await.unwrap();
            let (owned, empty, refused, produced, large) = outcome.unwrap();
            assert!(refused);
            assert_eq!(
                owned.result_sets()[0].rows().unwrap(),
                [
                    vec![
                        Some(Value::Integer(1)),
                        Some(Value::Integer(7)),
                        Some(Value::Unicode("é🦀".into())),
                        Some(Value::Integer(14))
                    ],
                    vec![
                        Some(Value::Integer(2)),
                        Some(Value::Integer(9)),
                        None,
                        Some(Value::Integer(18))
                    ]
                ]
            );
            assert_eq!(owned.returns()[0].status, Some(17));
            assert_eq!(
                owned.returns()[0].output_named(&"@n".into()).unwrap().value,
                Some(Value::Integer(2))
            );
            assert!(empty.result_sets()[0].rows().unwrap().is_empty());
            assert_eq!(
                produced.result_sets()[0].rows().unwrap()[0][2],
                Some(Value::Unicode(large.as_str().into()))
            );
            assert_eq!(
                produced.returns()[0]
                    .output_named(&"@n".into())
                    .unwrap()
                    .value,
                Some(Value::Integer(2))
            );
        }
    }
}
