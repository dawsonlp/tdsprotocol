//! Exact RPC framing, parameter refusal, output token boundaries and grouping.
use tds_client::{
    Builtin, Call, CallOptions, Calls, Collation, IntegerSize, Param, Record, Request, SqlText,
    SqlType, TypeInfo, Value,
    requests::Context,
    tokens::{Column, Decoder},
};
fn int() -> SqlType {
    SqlType::Integer {
        size: IntegerSize::Int,
    }
}
fn text(n: u16) -> SqlType {
    SqlType::Character {
        length: n,
        varying: true,
        unicode: true,
        collation: Collation([9, 4, 0xd0, 0, 0x34]),
    }
}
fn unicode(s: &str) -> Option<Value> {
    Some(Value::Unicode(s.into()))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn rpc_bodies_match_python_names_numbers_flags_default_null_and_batch_separator() {
    let context = Context {
        column_encryption: false,
        enclaves: false,
        transaction: 17,
        outstanding: 2,
    };
    let expected: Vec<String> =
        serde_json::from_str(include_str!("fixtures/rpc/python.json")).unwrap();
    let mut named = Call::new(
        "dbo.p",
        vec![
            Param::new("@x", int(), Some(Value::Integer(42))).output(),
            Param::new("@label", text(8), unicode("D🦀")),
            Param::default_value("@fallback", int()),
        ],
    );
    named.options = CallOptions {
        recompile: true,
        reuse_metadata: true,
        ..Default::default()
    };
    let calls = Calls(vec![
        Call::new(
            Builtin::SpExecuteSql,
            vec![
                Param::new("@stmt", text(4000), unicode("SELECT @n")),
                Param::new("@params", text(4000), unicode("@n int")),
                Param::new("@n", int(), None),
            ],
        ),
        Call::new("dbo.next", vec![]),
    ]);
    let mut saved = Call::new("dbo.saved", vec![]);
    saved.options.no_metadata = true;
    saved.columns = vec![vec![Column {
        user_type: 0,
        flags: 1,
        type_info: TypeInfo {
            sql_type: int(),
            code: 0x26,
            max_length: Some(4),
            legacy: None,
            clr_assembly: None,
            json_utf8: false,
            encryption: None,
        },
        name: "v".into(),
    }]];
    for (request, expected) in [&named as &dyn Request, &calls, &saved]
        .into_iter()
        .zip(expected)
    {
        let encoded = request.encode_request(&context).unwrap();
        assert_eq!(encoded.kind, tds_client::packet::RPC);
        assert_eq!(hex(&encoded.body), expected);
    }
}
#[test]
fn invalid_declarations_values_and_rounding_are_refused_without_exposing_values() {
    let values = [
        (
            SqlType::Integer {
                size: IntegerSize::Tiny,
            },
            Some(Value::Integer(-1)),
        ),
        (int(), Some(Value::Unicode("SECRET".into()))),
        (text(1), unicode("🦀")),
        (
            SqlType::Time { scale: 0 },
            Some(Value::Time(tds_client::SqlTime::from_ticks(1).unwrap())),
        ),
        (
            SqlType::Decimal {
                precision: 2,
                scale: 1,
                numeric: false,
            },
            Some(Value::Decimal(
                tds_client::SqlDecimal::new(false, 123, 2).unwrap(),
            )),
        ),
    ];
    for (ty, value) in values {
        let error = ty.encode_parameter(value.as_ref()).unwrap_err();
        assert!(matches!(error.kind, tds_client::ErrorKind::Parameter(_)));
        assert!(!format!("{error:?} {error}").contains("SECRET"));
    }
    assert!(
        Calls(vec![])
            .encode_request(&Context {
                column_encryption: false,
                enclaves: false,
                transaction: 0,
                outstanding: 1
            })
            .is_err()
    );
    let mut missing = Call::new("saved", vec![]);
    missing.options.no_metadata = true;
    assert!(
        missing
            .encode_request(&Context {
                column_encryption: false,
                enclaves: false,
                transaction: 0,
                outstanding: 1
            })
            .is_err()
    );
    let mut decoder = Decoder::default();
    decoder.feed(&[0x81, 0xff, 0xff]).unwrap();
    assert!(matches!(
        decoder.next_record().unwrap_err().kind,
        tds_client::ErrorKind::Malformed { .. }
    ));
}
fn output() -> Vec<u8> {
    let mut data = vec![
        0xac, 2, 0, 2, b'@', 0, b'x', 0, 1, 0, 0, 0, 0, 1, 0, 0x26, 4, 4,
    ];
    data.extend(42_i32.to_le_bytes());
    data
}
#[test]
fn output_values_decode_transactionally_across_every_boundary() {
    let bytes = output();
    for cut in 0..=bytes.len() {
        let mut decoder = Decoder::default();
        decoder.feed(&bytes[..cut]).unwrap();
        if cut < bytes.len() {
            assert!(decoder.next_record().unwrap().is_none());
        }
        decoder.feed(&bytes[cut..]).unwrap();
        let Some(Record::OutputValue(value)) = decoder.next_record().unwrap() else {
            panic!("RETURNVALUE")
        };
        assert_eq!(value.ordinal, 2);
        assert_eq!(value.name, SqlText::from("@x"));
        assert_eq!(value.value, Some(Value::Integer(42)));
        assert!(!value.function_result);
        assert!(decoder.is_empty());
    }
}
