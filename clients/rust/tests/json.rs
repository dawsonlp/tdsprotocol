use tds_client::{Chunk, Record, SqlText, SqlType, Value, tokens::Decoder};
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn row(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x81, 1, 0];
    bytes.extend([0; 6]);
    bytes.extend([0xf4, 0, 0xd1]);
    bytes.extend(payload);
    bytes
}
#[test]
fn json_result_encodings_and_strict_utf8_parameters_match_python_at_every_fragment() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/json/python.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let expected = case["units"]
            .as_array()
            .map(|units| SqlText(units.iter().map(|u| u.as_u64().unwrap() as u16).collect()));
        let encoded = SqlType::Json.encode_parameter(expected.clone().map(Value::Unicode).as_ref());
        if let Some(hex) = case["parameter"].as_str() {
            assert_eq!(encoded.unwrap(), unhex(hex));
        } else {
            assert!(encoded.is_err());
        }
        let bytes = row(&unhex(case["payload"].as_str().unwrap()));
        for stride in 1..=bytes.len() {
            let mut d = Decoder::default();
            d.set_utf8_support(case["utf8"].as_bool().unwrap());
            let mut actual = None;
            let mut ended = false;
            for part in bytes.chunks(stride) {
                d.feed(part).unwrap();
                while let Some(record) = d.next_record().unwrap() {
                    match record {
                        Record::ValueStart {
                            sql_type: SqlType::Json,
                            ..
                        } => actual = Some(SqlText(vec![])),
                        Record::ValueChunk(Chunk::Unicode(part)) => {
                            actual.as_mut().unwrap().0.extend(part.0)
                        }
                        Record::ValueEnd | Record::Cell(None) => ended = true,
                        _ => {}
                    }
                }
            }
            assert!(ended && d.is_empty());
            assert_eq!(actual, expected);
        }
    }
}
#[test]
fn json_utf8_rejects_overlong_out_of_range_invalid_and_truncated_characters() {
    for raw in [
        vec![0xc0, 0x80],
        vec![0xe0, 0x80, 0x80],
        vec![0xf4, 0x90, 0x80, 0x80],
        vec![0xff],
        vec![0xe2, 0x82],
        vec![0xc2, b'x'],
    ] {
        let mut payload = (raw.len() as u64).to_le_bytes().to_vec();
        payload.extend((raw.len() as u32).to_le_bytes());
        payload.extend(raw);
        payload.extend([0; 4]);
        let mut d = Decoder::default();
        d.set_utf8_support(true);
        d.feed(&row(&payload)).unwrap();
        let mut failed = false;
        loop {
            match d.next_record() {
                Ok(Some(_)) => {}
                Err(_) => {
                    failed = true;
                    break;
                }
                Ok(None) => break,
            }
        }
        assert!(failed);
    }
}
