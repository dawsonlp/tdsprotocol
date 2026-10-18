//! Actual SQL values under both TDS versions and plain/MARS transports.
#![cfg(feature = "tokio")]
use tds_client::{Batch, Connection, ProtocolVersion, SqlType, values::*};
mod support;

#[tokio::test]
#[ignore = "requires the Docker SQL Server and test CA"]
async fn heterogeneous_scalars_keep_exact_values_nulls_and_retention() {
    // Explicit SQL types/collation keep the fixture independent of login defaults.
    let cases = [
        ("tinyint", "255", Value::Integer(255)),
        ("bit", "1", Value::Bit(true)),
        ("real", "1.5", Value::Real(SqlReal::from_float(1.5))),
        ("float", "-2.5", Value::Float(SqlFloat::from_float(-2.5))),
        (
            "decimal(38,38)",
            "-0.99999999999999999999999999999999999999",
            Value::Decimal(SqlDecimal::new(true, 10_u128.pow(38) - 1, 38).unwrap()),
        ),
        (
            "numeric(10,2)",
            "1.50",
            Value::Decimal(SqlDecimal::new(false, 150, 2).unwrap()),
        ),
        (
            "money",
            "-922337203685477.5808",
            Value::Money(SqlMoney(i64::MIN)),
        ),
        (
            "smallmoney",
            "214748.3647",
            Value::Money(SqlMoney(i64::from(i32::MAX))),
        ),
        (
            "nvarchar(2)",
            "0x00D87800",
            Value::Unicode(SqlText(vec![0xd800, 0x78])),
        ),
        (
            "varbinary(4)",
            "0x0001FF00",
            Value::Binary(vec![0, 1, 255, 0]),
        ),
        (
            "uniqueidentifier",
            "'01234567-89ab-cdef-0123-456789abcdef'",
            Value::Guid(SqlGuid([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef,
            ])),
        ),
        (
            "date",
            "'0001-01-01'",
            Value::Date(SqlDate::from_days(0).unwrap()),
        ),
        (
            "time(7)",
            "'23:59:59.9999999'",
            Value::Time(SqlTime::from_ticks(TICKS_PER_DAY - 1).unwrap()),
        ),
        (
            "datetime2(7)",
            "'9999-12-31T23:59:59.9999999'",
            Value::DateTime2(SqlDateTime2 {
                date: SqlDate::from_ymd(9999, 12, 31).unwrap(),
                time: SqlTime::from_ticks(TICKS_PER_DAY - 1).unwrap(),
            }),
        ),
        (
            "datetimeoffset(7)",
            "'2026-10-17T00:00:00.0000001+14:00'",
            Value::DateTimeOffset(
                SqlDateTimeOffset::new(
                    SqlDateTime2 {
                        date: SqlDate::from_ymd(2026, 10, 16).unwrap(),
                        time: SqlTime::from_ticks(10 * 3600 * TICKS_PER_SECOND + 1).unwrap(),
                    },
                    840,
                )
                .unwrap(),
            ),
        ),
        (
            "datetime",
            "'1900-01-01T00:00:00.003'",
            Value::DateTime(SqlDateTime::new(0, 1).unwrap()),
        ),
        (
            "smalldatetime",
            "'2079-06-06T23:59:00'",
            Value::SmallDateTime(SqlSmallDateTime::new(u16::MAX, 1439).unwrap()),
        ),
    ];
    let select = cases
        .iter()
        .enumerate()
        .map(|(i, (kind, literal, _))| format!("CONVERT({kind},{literal}) AS c{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let nulls = cases
        .iter()
        .enumerate()
        .map(|(i, (kind, _, _))| format!("CONVERT({kind},NULL) AS c{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let text = "CONVERT(varchar(4),0x8081FF00) COLLATE SQL_Latin1_General_CP1_CI_AS";
    let sql = format!(
        "SELECT {select}; SELECT {nulls}; SELECT {text} AS raw_text; SELECT CAST(N'' AS nvarchar(1)),CAST(0x AS varbinary(1));"
    );
    let expected: Vec<_> = cases.iter().map(|(_, _, v)| Some(v.clone())).collect();
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut config = support::docker_options();
            config.version = version;
            config.mars = mars;
            let connection = Connection::connect(config).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            let mut response = channel.exchange(Batch::new(sql.clone())).await.unwrap();
            let fetched = response.fetch().await.unwrap();
            // A checked finish can still inspect and read the kept response.
            response.finish().await.unwrap();
            drop(response);
            let mut reuse = channel
                .exchange(Batch::new("SELECT CAST(1 AS bit)"))
                .await
                .unwrap();
            assert_eq!(
                reuse.fetch().await.unwrap().result_sets()[0]
                    .rows()
                    .unwrap(),
                [vec![Some(Value::Bit(true))]]
            );
            drop(reuse);
            channel.close().await.unwrap();
            connection.close().await.unwrap();
            // Owned values remain usable after transport destruction.
            let sets = fetched.result_sets();
            assert_eq!(sets.len(), 4);
            assert_eq!(
                sets[0].rows().unwrap(),
                std::slice::from_ref(&expected),
                "{version:?} mars={mars}"
            );
            assert_eq!(sets[1].rows().unwrap(), [vec![None; cases.len()]]);
            assert_eq!(
                sets[3].rows().unwrap(),
                [vec![
                    Some(Value::Unicode(SqlText::default())),
                    Some(Value::Binary(Vec::new()))
                ]]
            );
            let Value::Text(raw) = sets[2].rows().unwrap()[0][0].as_ref().unwrap() else {
                panic!("expected raw collated text")
            };
            assert_eq!(raw.bytes, [0x80, 0x81, 0xff, 0]);
            let SqlType::Character { collation, .. } = sets[2].columns[0].type_info.sql_type else {
                panic!("expected character type")
            };
            assert_eq!(collation, raw.collation);
        }
    }
}
