//! Independent Python requests and incremental token-relative raw evidence.
use serde_json::Value as Json;
use tds_client::{
    inspection::{self, Basis, Node, RAW_LIMIT},
    packet,
    tokens::Decoder,
};
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn evidence(node: &Node, bytes: &[u8]) {
    assert!(node.range.start <= node.range.end);
    assert!(
        node.range.end <= bytes.len(),
        "{} {:?}/{}",
        node.name,
        node.range,
        bytes.len()
    );
    assert!(node.raw.len() <= RAW_LIMIT);
    assert_eq!(
        node.raw,
        bytes[node.range.start..node.range.start + node.raw.len()]
    );
    for child in &node.children {
        evidence(child, bytes);
    }
}
#[test]
fn rpc_table_and_transaction_fields_use_the_same_checked_readers_as_replay() {
    for (kind, fixture, key) in [
        (packet::RPC, include_str!("fixtures/rpc/python.json"), None),
        (
            packet::RPC,
            include_str!("fixtures/tables/python.json"),
            Some("body"),
        ),
        (
            packet::TRANSACTION,
            include_str!("fixtures/transactions/python.json"),
            Some("body"),
        ),
    ] {
        let cases: Json = serde_json::from_str(fixture).unwrap();
        for case in cases.as_array().unwrap() {
            let bytes = unhex(key.map_or(case, |key| &case[key]).as_str().unwrap());
            let node = inspection::message(kind, &bytes).unwrap();
            assert_eq!(node.basis, Basis::Message);
            assert_eq!(node.issue, None, "{}", node.render());
            assert!(
                node.find(&[if kind == packet::RPC {
                    "call 0"
                } else {
                    "operation"
                }])
                .is_some()
            );
            evidence(&node, &bytes);
            for end in 0..bytes.len() {
                let node = inspection::message(kind, &bytes[..end]).unwrap();
                evidence(&node, &bytes[..end]);
            }
        }
    }
}
#[test]
fn bulk_known_length_payloads_remain_raw_instead_of_fabricating_plp_headers() {
    let mut bytes = vec![0x81, 1, 0];
    bytes.extend([0; 6]);
    bytes.extend([0xa5, 0xff, 0xff, 0, 0xd1]); // max binary column, empty name, ROW
    bytes.extend(3_u64.to_le_bytes());
    bytes.extend(b"abc"); // Bulk known-length cells have no chunk headers.
    bytes.extend([0xfd, 0, 0, 0, 0]);
    bytes.extend([0; 8]);
    let node = inspection::message(packet::BULK, &bytes).unwrap();
    assert_eq!(node.issue, None, "{}", node.render());
    assert_eq!(node.find(&["data"]).unwrap().raw, b"abc");
    evidence(&node, &bytes);
}
#[test]
fn streamed_row_and_output_fields_keep_token_ranges_at_every_small_fragment() {
    let data = b"abcdefgh";
    let mut payload = 8_u64.to_le_bytes().to_vec();
    payload.extend(8_u32.to_le_bytes());
    payload.extend(data);
    payload.extend([0; 4]);
    let mut row = vec![0xd1];
    row.extend(&payload);
    let mut metadata = vec![0x81, 1, 0];
    metadata.extend([0; 6]);
    metadata.extend([0xa5, 0xff, 0xff, 0]);
    let row_wire = [metadata, row.clone()].concat();
    let mut output = vec![0xac, 0, 0, 0, 1];
    output.extend([0; 6]);
    output.extend([0xa5, 0xff, 0xff]);
    output.extend(&payload);
    for (wire, token, is_row) in [(&row_wire, &row, true), (&output, &output, false)] {
        for stride in 1..=wire.len() {
            let mut decoder = Decoder::default();
            decoder.set_inspection(true);
            let mut seen = vec![];
            for chunk in wire.chunks(stride) {
                decoder.feed(chunk).unwrap();
                loop {
                    let record = decoder.next_record().unwrap();
                    if let Some(node) = decoder.take_inspection()
                        && (!is_row || node.name != "COLMETADATA")
                    {
                        evidence(&node, token);
                        seen.push(node);
                    }
                    if record.is_none() {
                        break;
                    }
                }
            }
            assert!(decoder.is_empty());
            // Together the root fragments cover the complete token, including
            // framing consumed on a call that yielded no semantic item.
            let mut cursor = 0;
            for node in seen {
                assert_eq!(node.range.start, cursor, "{stride}: {}", node.render());
                cursor = node.range.end;
            }
            assert_eq!(cursor, token.len(), "stride {stride}");
        }
    }
}
