use tds_client::{Record, SqlHalf, SqlType, Value, VectorElement, tokens::Decoder};
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn wire(info: &[u8], value: &[u8]) -> Vec<u8> {
    let mut b = vec![0x81, 1, 0];
    b.extend([0; 6]);
    b.extend(info);
    b.extend([0, 0xd1]);
    b.extend(value);
    b
}
#[test]
fn exact_vector_round_trips_match_python_and_binary16_conversion_is_exhaustive() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/vector/python.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let encoded = unhex(case["wire"].as_str().unwrap());
        let bytes = wire(&encoded[..4], &encoded[4..]);
        for stride in [1, 3, bytes.len()] {
            let mut decoder = Decoder::default();
            let mut ty = None;
            let mut row = None;
            for part in bytes.chunks(stride) {
                decoder.feed(part).unwrap();
                while let Some(record) = decoder.next_record().unwrap() {
                    match record {
                        Record::Columns(c) => ty = Some(c[0].type_info.sql_type.clone()),
                        Record::Row(r) => row = Some(r),
                        _ => {}
                    }
                }
            }
            assert_eq!(
                ty.unwrap()
                    .encode_parameter(row.unwrap()[0].as_ref())
                    .unwrap(),
                encoded
            );
        }
    }
    for bits in 0..=u16::MAX {
        let half = SqlHalf::from_bits(bits);
        if half.is_finite() {
            assert_eq!(
                SqlHalf::from_float_exact(half.to_float()).unwrap().bits(),
                bits
            );
        } else {
            assert!(!half.to_float().is_finite());
        }
    }
    assert!(SqlHalf::from_float_exact(0.1).is_err());
    assert!(SqlHalf::from_float_exact(f32::INFINITY).is_err());
}
#[test]
fn malformed_vector_layout_count_element_and_width_are_refused() {
    let encoded = SqlType::Vector {
        dimensions: 3,
        element: VectorElement::Float32,
    }
    .encode_parameter(Some(&Value::Vector(tds_client::SqlVector::Float32(
        vec![tds_client::SqlReal::from_float(1.); 3],
    ))))
    .unwrap();
    for at in [0, 2, 4, 5] {
        let mut value = encoded[4..].to_vec();
        value[2 + at] ^= 1;
        let mut d = Decoder::default();
        d.feed(&wire(&encoded[..4], &value)).unwrap();
        d.next_record().unwrap();
        assert!(d.next_record().is_err());
    }
    let mut d = Decoder::default();
    d.feed(&wire(&encoded[..4], &[1, 0, 0])).unwrap();
    d.next_record().unwrap();
    assert!(d.next_record().is_err());
}
