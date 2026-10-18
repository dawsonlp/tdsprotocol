//! Stored procedures are real RPC messages, never SQL string interpolation.
#![cfg(feature = "tokio")]
mod support;
use tds_client::{
    Batch, Builtin, Call, Calls, Connection, IntegerSize, Param, Pool, ProtocolVersion,
    ReleaseOutcome, SqlType, Value, values::*,
};
fn int() -> SqlType {
    SqlType::Integer {
        size: IntegerSize::Int,
    }
}
fn unicode(value: &str) -> Option<Value> {
    Some(Value::Unicode(value.into()))
}
async fn batch(channel: &mut tds_client::SerialChannel, sql: &str) {
    channel
        .exchange(Batch::new(sql))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn defaults_outputs_grouped_returns_saved_metadata_and_errors_preserve_reuse() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            batch(&mut channel,"CREATE PROCEDURE #tds_rpc @a int=7, @b int=NULL OUTPUT, @text nvarchar(200)=N'default' AS BEGIN SET NOCOUNT ON; SELECT @a AS a,@text AS label,@b AS original; SET @b=COALESCE(@b,0)+@a; RETURN 23; END").await;
            let collation = tds_client::Collation(
                connection
                    .session()
                    .await
                    .unwrap()
                    .collation
                    .try_into()
                    .unwrap(),
            );
            let text = SqlType::Character {
                length: 200,
                varying: true,
                unicode: true,
                collation,
            };
            let call = Call::new(
                "#tds_rpc",
                vec![
                    Param::default_value("@a", int()),
                    Param::new("@b", int(), Some(Value::Integer(5))).output(),
                    Param::new("@text", text.clone(), unicode("D🦀")),
                ],
            );
            let kept = channel
                .exchange(call.clone())
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(
                kept.result_sets()[0].rows().unwrap(),
                [vec![
                    Some(Value::Integer(7)),
                    unicode("D🦀"),
                    Some(Value::Integer(5))
                ]]
            );
            assert_eq!(kept.returns().len(), 1);
            assert_eq!(kept.returns()[0].status, Some(23));
            assert_eq!(
                kept.returns()[0].output_named(&"@b".into()).unwrap().value,
                Some(Value::Integer(12))
            );
            let mut saved = call.clone();
            saved.options.no_metadata = true;
            saved.columns = vec![kept.result_sets()[0].columns.clone()];
            let reused = channel
                .exchange(saved)
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(
                reused.result_sets()[0].rows().unwrap(),
                kept.result_sets()[0].rows().unwrap()
            );
            let calls = Calls(vec![
                Call::new(
                    "#tds_rpc",
                    vec![
                        Param::new("@a", int(), Some(Value::Integer(3))),
                        Param::new("@b", int(), None).output(),
                        Param::new("@text", text, None),
                    ],
                ),
                call,
            ]);
            let returned = channel
                .exchange(calls)
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(
                returned
                    .returns()
                    .iter()
                    .map(|r| r.status)
                    .collect::<Vec<_>>(),
                [Some(23), Some(23)]
            );
            assert_eq!(
                returned.returns()[0].output_at(1).unwrap().value,
                Some(Value::Integer(3))
            );
            assert_eq!(
                returned.returns()[1].output_at(1).unwrap().value,
                Some(Value::Integer(12))
            );
            // Refusal precedes request bytes and leaves this channel reusable.
            assert!(
                channel
                    .exchange(Call::new(
                        "#tds_rpc",
                        vec![Param::new(
                            "@a",
                            SqlType::Integer {
                                size: IntegerSize::Tiny
                            },
                            Some(Value::Integer(-1))
                        )]
                    ))
                    .await
                    .is_err()
            );
            batch(&mut channel, "SELECT 1").await;
            let failed = channel
                .exchange(Call::new("procedure_that_does_not_exist", vec![]))
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap_err();
            assert!(failed.response.as_ref().unwrap().ended);
            batch(&mut channel, "SELECT 2").await;
            connection.close().await.unwrap();
            assert_eq!(kept.returns()[0].status, Some(23));
        }
    }
}

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn typed_scalar_inputs_round_trip_exactly_and_rpc_applies_pool_reset() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let pool = Pool::new(options, 1).unwrap();
            let first = pool.acquire().await.unwrap();
            batch(
                &mut first.serial_channel().await.unwrap(),
                "SET DATEFIRST 3",
            )
            .await;
            assert_eq!(first.release().await.unwrap(), ReleaseOutcome::Returned);
            let connection = pool.acquire().await.unwrap();
            let collation = tds_client::Collation(
                connection
                    .session()
                    .await
                    .unwrap()
                    .collation
                    .try_into()
                    .unwrap(),
            );
            let text = |length| SqlType::Character {
                length,
                varying: true,
                unicode: true,
                collation,
            };
            let pairs = vec![
                (int(), Some(Value::Integer(-123)), "int"),
                (
                    SqlType::Integer {
                        size: IntegerSize::Big,
                    },
                    Some(Value::Integer(i64::MIN)),
                    "bigint",
                ),
                (SqlType::Bit, Some(Value::Bit(true)), "bit"),
                (
                    SqlType::Real,
                    Some(Value::Real(SqlReal::from_float(1.5))),
                    "real",
                ),
                (
                    SqlType::Float,
                    Some(Value::Float(SqlFloat::from_float(-2.5))),
                    "float",
                ),
                (
                    SqlType::Decimal {
                        precision: 38,
                        scale: 10,
                        numeric: false,
                    },
                    Some(Value::Decimal(
                        SqlDecimal::new(true, 123456789012345678901234567890, 10).unwrap(),
                    )),
                    "decimal(38,10)",
                ),
                (
                    SqlType::Money,
                    Some(Value::Money(SqlMoney(i64::MIN))),
                    "money",
                ),
                (
                    SqlType::SmallMoney,
                    Some(Value::Money(SqlMoney(i64::from(i32::MAX)))),
                    "smallmoney",
                ),
                (
                    SqlType::Date,
                    Some(Value::Date(SqlDate::from_ymd(1, 1, 1).unwrap())),
                    "date",
                ),
                (
                    SqlType::Time { scale: 7 },
                    Some(Value::Time(SqlTime::from_ticks(1).unwrap())),
                    "time(7)",
                ),
                (
                    SqlType::DateTime2 { scale: 7 },
                    Some(Value::DateTime2(SqlDateTime2 {
                        date: SqlDate::from_ymd(9999, 12, 31).unwrap(),
                        time: SqlTime::from_ticks(TICKS_PER_DAY - 1).unwrap(),
                    })),
                    "datetime2(7)",
                ),
                (
                    SqlType::DateTimeOffset { scale: 7 },
                    Some(Value::DateTimeOffset(
                        SqlDateTimeOffset::new(
                            SqlDateTime2 {
                                date: SqlDate::from_ymd(1, 1, 1).unwrap(),
                                time: SqlTime::from_ticks(840 * 60 * TICKS_PER_SECOND).unwrap(),
                            },
                            -840,
                        )
                        .unwrap(),
                    )),
                    "datetimeoffset(7)",
                ),
                (
                    SqlType::DateTime,
                    Some(Value::DateTime(SqlDateTime::new(0, 1).unwrap())),
                    "datetime",
                ),
                (
                    SqlType::SmallDateTime,
                    Some(Value::SmallDateTime(SqlSmallDateTime::new(0, 1).unwrap())),
                    "smalldatetime",
                ),
                (
                    SqlType::Guid,
                    Some(Value::Guid(SqlGuid([1; 16]))),
                    "uniqueidentifier",
                ),
                (text(200), unicode("typed 🦀"), "nvarchar(200)"),
                (
                    SqlType::Binary {
                        length: 3,
                        varying: true,
                    },
                    Some(Value::Binary(vec![0, 1, 255])),
                    "varbinary(3)",
                ),
                (int(), None, "int"),
            ];
            let statement = format!(
                "SELECT {},@@DATEFIRST",
                (0..pairs.len())
                    .map(|i| format!("@p{i}"))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let declarations = pairs
                .iter()
                .enumerate()
                .map(|(i, (_, _, name))| format!("@p{i} {name}"))
                .collect::<Vec<_>>()
                .join(",");
            let mut params = vec![
                Param::new("@stmt", text(4000), unicode(&statement)),
                Param::new("@params", text(4000), unicode(&declarations)),
            ];
            let mut expected = Vec::new();
            for (index, (ty, value, _)) in pairs.into_iter().enumerate() {
                expected.push(value.clone());
                params.push(Param::new(
                    SqlText::from(format!("@p{index}").as_str()),
                    ty,
                    value,
                ));
            }
            expected.push(Some(Value::Integer(7))); // ODBC baseline after RESET_COMPLETE
            let mut channel = connection.serial_channel().await.unwrap();
            let kept = channel
                .exchange(Call::new(Builtin::SpExecuteSql, params))
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(kept.result_sets()[0].rows().unwrap(), [expected]);
            assert_eq!(
                connection.release().await.unwrap(),
                ReleaseOutcome::Returned
            );
            pool.close().await.unwrap();
        }
    }
}
