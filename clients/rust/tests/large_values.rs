//! Wire fragmentation is independent of PLP chunks and UTF-16 character edges.
use tds_client::{Chunk, Record, SqlText, Value, tokens::Decoder};

fn metadata(info: &[u8]) -> Vec<u8> {
    let mut b = vec![0x81, 1, 0];
    b.extend([0; 6]);
    b.extend(info);
    b.push(0);
    b
}
fn plp(bytes: &[u8], unknown: bool) -> Vec<u8> {
    let mut b = (if unknown {
        u64::MAX - 1
    } else {
        bytes.len() as u64
    })
    .to_le_bytes()
    .to_vec();
    for part in bytes.chunks(3) {
        b.extend((part.len() as u32).to_le_bytes());
        b.extend(part);
    }
    b.extend([0; 4]);
    b
}
fn decode(bytes: &[u8], stride: usize) -> Vec<Record> {
    let mut decoder = Decoder::default();
    let mut records = Vec::new();
    for part in bytes.chunks(stride) {
        decoder.feed(part).unwrap();
        while let Some(record) = decoder.next_record().unwrap() {
            records.push(record);
        }
    }
    assert!(decoder.is_empty());
    records
}
#[test]
fn plp_every_fragment_keeps_exact_unicode_and_surrogate_boundaries() {
    let units = vec![0x61, 0xd83d, 0xde42, 0xd800, 0x62, 0xdc00, 0xd801];
    let bytes: Vec<_> = units.iter().flat_map(|n: &u16| n.to_le_bytes()).collect();
    for unknown in [false, true] {
        let mut wire = metadata(&[0xe7, 0xff, 0xff, 0, 0, 0, 0, 0]);
        wire.push(0xd1);
        wire.extend(plp(&bytes, unknown));
        for stride in 1..=wire.len() {
            let records = decode(&wire, stride);
            assert!(matches!(records[1], Record::RowStart));
            let mut restored = Vec::new();
            let mut previous_high = false;
            for record in records {
                if let Record::ValueChunk(Chunk::Unicode(text)) = record {
                    assert!(!(previous_high && (0xdc00..=0xdfff).contains(&text.0[0])));
                    previous_high = text.0.last().is_some_and(|n| (0xd800..=0xdbff).contains(n));
                    restored.extend(text.0);
                }
            }
            assert_eq!(restored, units);
        }
    }
}
#[test]
fn null_empty_nbc_and_legacy_pointer_have_distinct_boundaries() {
    let mut wire = metadata(&[0xa5, 0xff, 0xff]);
    wire.push(0xd1);
    wire.extend(u64::MAX.to_le_bytes());
    wire.push(0xd1);
    wire.extend(plp(&[], false));
    wire.extend([0xd2, 1]); // NBC NULL has no value bytes.
    let records = decode(&wire, 1);
    assert_eq!(
        records
            .iter()
            .filter(|r| matches!(r, Record::Cell(None)))
            .count(),
        2
    );
    assert_eq!(
        records
            .iter()
            .filter(|r| matches!(r, Record::ValueStart { .. }))
            .count(),
        1
    );
    let mut wire = metadata(&[0x22, 0xff, 0xff, 0xff, 0x7f, 0]);
    wire.extend([0xd1, 0]); // Legacy NULL pointer.
    wire.extend([0xd1, 1, 42]);
    wire.extend([0; 8]);
    wire.extend(3_u32.to_le_bytes());
    wire.extend(b"abc");
    let records = decode(&wire, 1);
    let bytes: Vec<_> = records
        .into_iter()
        .filter_map(|r| {
            if let Record::ValueChunk(Chunk::Binary(b)) = r {
                Some(b)
            } else {
                None
            }
        })
        .flatten()
        .collect();
    assert_eq!(bytes, b"abc");
}
#[test]
fn xml_and_large_outputs_materialize_without_pending_buffer_growth() {
    let data = "<x>hi</x>"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let mut wire = vec![0xac, 0, 0, 0, 1];
    wire.extend([0; 6]);
    wire.extend([0xf1, 0]);
    wire.extend(plp(&data, true));
    for stride in 1..=wire.len() {
        let records = decode(&wire, stride);
        let Record::OutputValue(output) = &records[0] else {
            panic!()
        };
        assert_eq!(
            output.value,
            Some(Value::Unicode(SqlText::from("<x>hi</x>")))
        );
    }
    let bytes = vec![0xab; 3 * 1024 * 1024];
    let mut wire = metadata(&[0xa5, 0xff, 0xff]);
    wire.push(0xd1);
    wire.extend(plp(&bytes, false));
    let records = decode(&wire, 65536);
    let count: usize = records
        .iter()
        .filter_map(|r| {
            if let Record::ValueChunk(c) = r {
                assert!(c.byte_len() <= 65536);
                Some(c.byte_len())
            } else {
                None
            }
        })
        .sum();
    assert_eq!(count, bytes.len());
}
#[test]
fn malformed_lengths_and_unfinished_values_are_not_complete() {
    for (total, payload) in [(2_u64, vec![1]), (0, vec![1]), (3, vec![1, 2])] {
        let mut wire = metadata(&[0xa5, 0xff, 0xff]);
        wire.push(0xd1);
        wire.extend(total.to_le_bytes());
        wire.extend((payload.len() as u32).to_le_bytes());
        wire.extend(payload);
        wire.extend([0; 4]);
        let mut decoder = Decoder::default();
        decoder.feed(&wire).unwrap();
        assert!(loop {
            match decoder.next_record() {
                Ok(Some(_)) => {}
                Ok(None) => break false,
                Err(_) => break true,
            }
        });
    }
    let mut wire = metadata(&[0xe7, 0xff, 0xff, 0, 0, 0, 0, 0]);
    wire.push(0xd1);
    wire.extend(plp(&[0x61], true));
    let mut decoder = Decoder::default();
    decoder.feed(&wire).unwrap();
    assert!(loop {
        match decoder.next_record() {
            Ok(Some(_)) => {}
            Ok(None) => break false,
            Err(_) => break true,
        }
    });
    let mut decoder = Decoder::default();
    let mut wire = metadata(&[0xa5, 0xff, 0xff]);
    wire.push(0xd1);
    wire.extend(2_u64.to_le_bytes());
    decoder.feed(&wire).unwrap();
    while decoder.next_record().unwrap().is_some() {}
    assert!(!decoder.is_empty());
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn owned_large_parameter_and_result_bytes_match_python_codec() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/large/python.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let info = unhex(case["info"].as_str().unwrap());
        let mut wire = metadata(&info);
        wire.push(0xd1);
        wire.extend(unhex(case["payload"].as_str().unwrap()));
        let records = decode(&wire, 1);
        let Record::Columns(columns) = &records[0] else {
            panic!()
        };
        let sql_type = &columns[0].type_info.sql_type;
        let mut value = None;
        for record in &records {
            match record {
                Record::ValueStart { sql_type, .. } => {
                    value = Some(
                        if matches!(
                            sql_type,
                            tds_client::SqlType::BinaryMax
                                | tds_client::SqlType::LegacyImage
                                | tds_client::SqlType::Clr(_)
                        ) {
                            Value::Binary(Vec::new())
                        } else if matches!(
                            sql_type,
                            tds_client::SqlType::CharacterMax { unicode: false, .. }
                                | tds_client::SqlType::LegacyText { unicode: false, .. }
                        ) {
                            let collation = match sql_type {
                                tds_client::SqlType::CharacterMax { collation, .. }
                                | tds_client::SqlType::LegacyText { collation, .. } => *collation,
                                _ => unreachable!(),
                            };
                            Value::Text(tds_client::SqlTextBytes {
                                bytes: Vec::new(),
                                collation,
                            })
                        } else {
                            Value::Unicode(SqlText(Vec::new()))
                        },
                    )
                }
                Record::ValueChunk(chunk) => match (value.as_mut().unwrap(), chunk) {
                    (Value::Binary(b), Chunk::Binary(p)) => b.extend(p),
                    (Value::Unicode(t), Chunk::Unicode(p)) => t.0.extend(&p.0),
                    (Value::Text(t), Chunk::Text(p)) => t.bytes.extend(&p.bytes),
                    _ => panic!(),
                },
                _ => {}
            }
        }
        let raw = value.as_ref().map(|v| match v {
            Value::Binary(b) => b.clone(),
            Value::Text(t) => t.bytes.clone(),
            Value::Unicode(t) => t.0.iter().flat_map(|n| n.to_le_bytes()).collect(),
            _ => panic!(),
        });
        assert_eq!(raw, case["raw"].as_str().map(unhex), "{}", case["name"]);
        assert_eq!(
            sql_type.encode_parameter(value.as_ref()).unwrap(),
            unhex(case["parameter"].as_str().unwrap()),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn xml_schema_and_legacy_table_provenance_are_retained_separately_from_payload() {
    let records = decode(
        &metadata(&[0xf1, 1, 1, b'd', 0, 1, b's', 0, 1, 0, b'x', 0]),
        1,
    );
    let Record::Columns(columns) = &records[0] else {
        panic!()
    };
    let tds_client::SqlType::Xml {
        schema: Some(schema),
    } = &columns[0].type_info.sql_type
    else {
        panic!()
    };
    assert_eq!(schema.database, SqlText::from("d"));
    assert_eq!(schema.owner, SqlText::from("s"));
    assert_eq!(schema.collection, SqlText::from("x"));
    assert_eq!(
        columns[0]
            .type_info
            .sql_type
            .encode_parameter(None)
            .unwrap(),
        [vec![0xf1, 0], u64::MAX.to_le_bytes().to_vec()].concat()
    );
    let records = decode(
        &metadata(&[0x22, 0xff, 0xff, 0xff, 0x7f, 1, 1, 0, b't', 0]),
        1,
    );
    let Record::Columns(columns) = &records[0] else {
        panic!()
    };
    let legacy = columns[0].type_info.legacy.as_ref().unwrap();
    assert_eq!(legacy.max_length, i32::MAX as u32);
    assert_eq!(legacy.table, vec![SqlText::from("t")]);
    assert_eq!(
        columns[0].type_info.sql_type,
        tds_client::SqlType::LegacyImage
    );
}
