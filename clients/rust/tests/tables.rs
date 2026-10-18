use tds_client::{
    Call, Collation, IntegerSize, Param, Request, Sort, SqlText, SqlType, TableColumn, TableType,
    Value,
};
fn int() -> SqlType {
    SqlType::Integer {
        size: IntegerSize::Int,
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn input_only_table_requests_match_pythons_null_defaults_hints_and_value_layouts() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/tables/python.json")).unwrap();
    let context = tds_client::requests::Context {
        column_encryption: false,
        transaction: 17,
        outstanding: 2,
    };
    for case in cases.as_array().unwrap() {
        let mut columns = vec![];
        if case["defaulted"].as_bool().unwrap() {
            columns.push(TableColumn::default_value(int()));
        }
        columns.extend([
            int().into(),
            SqlType::CharacterMax {
                unicode: true,
                collation: Collation([9, 4, 0xd0, 0, 0x34]),
            }
            .into(),
        ]);
        let mut table = TableType::new("dbo", "lines", columns);
        if case["hints"].as_bool().unwrap() {
            table.order = vec![(2, Sort::Ascending)];
            table.unique = vec![2];
            table.send_order = vec![3, 2, 1];
        }
        // serde_json intentionally rejects unpaired JSON surrogate escapes as
        // Rust Strings; exact UTF-16 test text is constructed explicitly below.
        let rows = if case["count"].is_null() {
            None
        } else if case["count"].as_u64().unwrap() == 0 {
            Some(vec![])
        } else {
            Some(vec![
                vec![
                    Some(Value::Integer(7)),
                    Some(Value::Unicode(SqlText(vec![0xe9, 0xd83e, 0xdd80, 0xd800]))),
                ],
                vec![Some(Value::Integer(9)), None],
            ])
        };
        let param = if case["default"].as_bool().unwrap() {
            Param::default_value("@t", SqlType::Table(Box::new(table)))
        } else {
            Param::table("@t", table, rows)
        };
        let body = Call::new("#p", vec![param])
            .encode_request(&context)
            .unwrap()
            .body;
        assert_eq!(hex(&body), case["body"].as_str().unwrap());
    }
}
