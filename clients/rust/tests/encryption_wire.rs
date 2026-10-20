//! AE wire reading remains available without the optional crypto adapter.
use serde_json::Value as Json;
use tds_client::*;
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn encrypted_wire_metadata_and_output_survive_every_split_and_mark_ciphertext() {
    let fixtures: Json =
        serde_json::from_str(include_str!("fixtures/encryption/wire.json")).unwrap();
    for field in ["columns_row", "output"] {
        let bytes = unhex(fixtures[field].as_str().unwrap());
        let mut whole = tokens::Decoder::default();
        whole.set_column_encryption(true);
        whole.feed(&bytes).unwrap();
        let mut expected = vec![];
        while let Some(record) = whole.next_record().unwrap() {
            expected.push(record);
        }
        if field == "columns_row" {
            assert!(
                matches!(&expected[1],Record::Row(row) if matches!(&row[0],Some(Value::Encrypted(c)) if c.0==[1,2,3]))
            );
        } else {
            assert!(
                matches!(&expected[0],Record::OutputValue(o) if matches!(&o.value,Some(Value::Encrypted(c)) if c.0==[7,7]))
            );
        }
        for split in 0..=bytes.len() {
            let mut d = tokens::Decoder::default();
            d.set_column_encryption(true);
            let mut records = vec![];
            for part in [&bytes[..split], &bytes[split..]] {
                d.feed(part).unwrap();
                while let Some(r) = d.next_record().unwrap() {
                    records.push(r);
                }
            }
            assert_eq!(records, expected, "{field}, split {split}");
            assert!(d.is_empty());
        }
        let mut unnegotiated = tokens::Decoder::default();
        unnegotiated.feed(&bytes).unwrap();
        assert!(unnegotiated.next_record().is_err());
    }
}

#[test]
fn encrypted_rpc_is_explicit_negotiated_and_replays_as_ciphertext() {
    use requests::{CipherInfo, Context, decode};
    let mut param = Param::new(
        "@s",
        SqlType::Binary {
            length: 3,
            varying: true,
        },
        Some(Value::Binary(vec![1, 2, 3])),
    );
    param.cipher = Some(CipherInfo {
        base: SqlType::Integer {
            size: IntegerSize::Int,
        },
        key: types::crypto::ColumnKey {
            database_id: 6,
            key_id: 1,
            version: 1,
            metadata_version: [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
            values: vec![],
        },
        encryption_type: 2,
        algorithm: 2,
        normalization: 1,
    });
    let call = Call::new("p", vec![param]);
    let mut context = Context {
        transaction: 0,
        outstanding: 1,
        column_encryption: false,
        enclaves: false,
    };
    assert!(call.encode_request(&context).is_err());
    context.column_encryption = true;
    let encoded = call.encode_request(&context).unwrap();
    // Python test_encryption.py's independently specified ParamCipherInfo tail.
    assert!(encoded.body.ends_with(&unhex("024000730008 A50300 0300010203 2604 0202 06000000 01000000 01000000 1112131415161718 01".replace(' ',"").as_str())));
    let decode::Request::Rpc { calls, .. } = decode::request(packet::RPC, &encoded.body).unwrap()
    else {
        panic!("RPC")
    };
    assert!(
        matches!(&calls[0].parameters[0].value,ParamValue::Scalar(Some(Value::Encrypted(c))) if c.0==[1,2,3])
    );
    assert_eq!(
        calls[0].parameters[0].type_info.value_type(),
        &SqlType::Integer {
            size: IntegerSize::Int
        }
    );
    let node = inspection::message(packet::RPC, &encoded.body).unwrap();
    assert!(node.issue.is_none(), "{node:?}");
}

#[test]
fn encrypted_metadata_rejects_invalid_key_counts_ordinals_and_cipher_types() {
    let fixture: Json =
        serde_json::from_str(include_str!("fixtures/encryption/wire.json")).unwrap();
    let bytes = unhex(fixture["columns_row"].as_str().unwrap());
    let ordinal = fixture["ordinal_offset"].as_u64().unwrap() as usize;
    let mut invalid_ordinal = bytes.clone();
    invalid_ordinal[ordinal] = 1;
    let mut many_keys = bytes.clone();
    many_keys[3..5].copy_from_slice(&4097_u16.to_le_bytes());
    let mut many_values = bytes.clone();
    many_values[25] = 17;
    let mut bad_cipher = bytes;
    bad_cipher.splice(ordinal - 3..ordinal, [0x26, 4]);
    for bytes in [invalid_ordinal, many_keys, many_values, bad_cipher] {
        let mut decoder = tokens::Decoder::default();
        decoder.set_column_encryption(true);
        decoder.feed(&bytes).unwrap();
        let error = decoder.next_record().unwrap_err();
        assert!(
            matches!(
                error.kind,
                ErrorKind::Malformed { .. } | ErrorKind::Limit(_)
            ),
            "{error:?}"
        );
    }
}
