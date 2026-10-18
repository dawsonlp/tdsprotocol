use tds_client::{Record, Value, tokens::Decoder};
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn row(payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0x81, 1, 0];
    b.extend([0; 6]);
    b.extend([0x62, 0x50, 0x1f, 0, 0, 0, 0xd1]);
    b.extend(payload);
    b
}
#[test]
fn variant_base_types_and_parameter_bytes_match_python_across_fragments() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/variant/python.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let payload = unhex(case["payload"].as_str().unwrap());
        let body = row(&payload);
        for stride in [1, 3, body.len()] {
            let mut d = Decoder::default();
            let mut found = None;
            for part in body.chunks(stride) {
                d.feed(part).unwrap();
                while let Some(record) = d.next_record().unwrap() {
                    if let Record::Row(r) = record {
                        found = Some(r);
                    }
                }
            }
            let cells = found.unwrap();
            assert_eq!(
                &tds_client::SqlType::Variant
                    .encode_parameter(cells[0].as_ref())
                    .unwrap()[5..],
                payload,
                "{}",
                case["name"]
            );
            if let Some(Value::Variant(v)) = &cells[0] {
                assert!(!matches!(v.sql_type, tds_client::SqlType::Variant));
            } else {
                assert!(cells[0].is_none());
            }
        }
    }
}
#[test]
fn bounded_variant_corruption_fails_instead_of_waiting_for_more_bytes() {
    for value in [
        vec![1, 0, 0, 0, 0x38],
        vec![3, 0, 0, 0, 0x38, 1, 0],
        vec![2, 0, 0, 0, 0xa7, 0],
        vec![2, 0, 0, 0, 0x28, 0],
        vec![0x51, 0x1f, 0, 0],
    ] {
        let mut d = Decoder::default();
        d.feed(&row(&value)).unwrap();
        d.next_record().unwrap();
        assert!(d.next_record().is_err(), "{value:x?}");
    }
    let bad = Value::Variant(Box::new(tds_client::SqlVariant {
        sql_type: tds_client::SqlType::BinaryMax,
        value: Value::Binary(vec![1]),
    }));
    assert!(
        tds_client::SqlType::Variant
            .encode_parameter(Some(&bad))
            .is_err()
    );
}
