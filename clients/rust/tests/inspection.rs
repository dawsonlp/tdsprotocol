//! Independent Python field ranges and exact bytes, plus damaged wire evidence.
use serde_json::Value as Json;
use tds_client::{
    inspection::{self, Basis, Node, RAW_LIMIT},
    packet,
    tokens::Decoder,
};
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn token(body: &[u8], metadata: Option<&[u8]>) -> Node {
    let mut decoder = Decoder::default();
    decoder.set_inspection(true);
    if let Some(metadata) = metadata {
        decoder.feed(metadata).unwrap();
        decoder.next_record().unwrap().unwrap();
        decoder.take_inspection();
    }
    // A token is reconstructed independently of every possible byte fragment.
    for (i, byte) in body.iter().enumerate() {
        decoder.feed(&[*byte]).unwrap();
        let record = decoder.next_record().unwrap();
        if i + 1 != body.len() {
            assert!(record.is_none());
            assert!(decoder.take_inspection().is_none());
        } else {
            assert!(record.is_some());
        }
    }
    decoder.take_inspection().unwrap()
}
fn invariants(node: &Node, body: &[u8]) {
    assert!(node.range.end <= body.len());
    assert!(node.raw.len() <= RAW_LIMIT);
    if !node.sensitive {
        assert_eq!(
            node.raw,
            body[node.range.clone()]
                .iter()
                .take(RAW_LIMIT)
                .copied()
                .collect::<Vec<_>>()
        );
    }
    for child in &node.children {
        assert_eq!(node.basis, child.basis);
        assert!(child.range.start >= node.range.start && child.range.end <= node.range.end);
        invariants(child, body);
    }
}
#[test]
fn field_ranges_and_bytes_match_pythons_inspection_definitions() {
    let cases: Vec<Json> =
        serde_json::from_str(include_str!("fixtures/inspection/python.json")).unwrap();
    for case in cases {
        let bytes = unhex(case["body"].as_str().unwrap());
        let node = match case["family"].as_str().unwrap() {
            "packet" => packet::inspect_header(&bytes).unwrap(),
            "login" => inspection::message(packet::LOGIN, &bytes).unwrap(),
            "prelogin" => inspection::message(packet::HELLO, &bytes).unwrap(),
            "token" => token(&bytes, None),
            "row" => token(&bytes, Some(&unhex(case["metadata"].as_str().unwrap()))),
            _ => unreachable!(),
        };
        assert!(node.issue.is_none(), "{node:?}");
        if case["family"] != "login" {
            invariants(&node, &bytes);
        }
        for field in case["fields"].as_array().unwrap() {
            let path = field["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap())
                .collect::<Vec<_>>();
            let found = node
                .find(&path)
                .unwrap_or_else(|| panic!("missing {path:?} in {}", node.render()));
            assert_eq!(
                found.range,
                field["start"].as_u64().unwrap() as usize..field["end"].as_u64().unwrap() as usize,
                "{path:?}"
            );
            assert_eq!(found.raw, unhex(field["raw"].as_str().unwrap()), "{path:?}");
        }
        if let Some(version) = case["version"].as_u64() {
            assert_eq!(
                node.find(&["tds version"]).unwrap().shown,
                version.to_string()
            );
        }
    }
}

#[test]
fn malformed_token_keeps_a_located_prefix_and_disabled_inspection_builds_no_tree() {
    let mut decoder = Decoder::default();
    decoder.set_inspection(true);
    decoder.feed(&[0xad, 1, 0, 1]).unwrap();
    assert!(decoder.next_record().is_err());
    let tree = decoder.take_inspection().unwrap();
    assert!(tree.issue.is_some());
    assert_eq!(tree.find(&["interface"]).unwrap().range, 3..4);
    let done = [vec![0xfd], vec![0; 12]].concat();
    let mut decoder = Decoder::default();
    decoder.feed(&done).unwrap();
    assert!(decoder.next_record().unwrap().is_some());
    assert!(decoder.take_inspection().is_none());
}

#[test]
fn login_credentials_are_redacted_and_tree_raw_and_rendering_are_bounded() {
    let bytes = include_bytes!("fixtures/login7/password-change.bin");
    let node = inspection::message(packet::LOGIN, bytes).unwrap();
    assert!(node.issue.is_none());
    assert!(node.raw.is_empty());
    for name in ["password", "new password", "sspi"] {
        let child = node.find(&[name]).unwrap();
        assert!(child.sensitive);
        assert!(child.raw.iter().all(|b| *b == 0));
        assert_eq!(child.shown, "[redacted]");
    }
    let body = tds_client::Batch::new("🦀".repeat(10000))
        .encode_request(&tds_client::requests::Context {
            column_encryption: false,
            enclaves: false,
            transaction: 0,
            outstanding: 1,
        })
        .unwrap()
        .body;
    let node = inspection::message(packet::BATCH, &body).unwrap();
    invariants(&node, &body);
    assert_eq!(node.basis, Basis::Message);
    assert_eq!(node.raw.len(), RAW_LIMIT);
    assert!(node.find(&["sql"]).unwrap().shown.len() < 1100);
    assert!(node.render().len() < 3000);
}
use tds_client::Request;

#[test]
fn null_bitmap_cells_have_zero_byte_spans_and_keep_the_bitmap_evidence() {
    let metadata = unhex("8101000000000001002604016100");
    let node = token(&[0xd2, 1], Some(&metadata));
    assert_eq!(node.name, "NBCROW");
    assert_eq!(node.find(&["null bitmap"]).unwrap().raw, [1]);
    let null = node.find(&["cell 1"]).unwrap();
    assert_eq!(null.range, 2..2);
    assert!(null.raw.is_empty());
    assert_eq!(null.shown, "None");
}

#[test]
fn replay_inspection_masks_credential_spans_and_preserves_existing_diagnostics() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use tds_client::replay::{self, Content};
    let login = include_bytes!("fixtures/login7/password-change.bin");
    let lines = packet::split(packet::LOGIN, login, 19)
        .unwrap()
        .chunks(19)
        .map(|b| {
            serde_json::json!({"t":0,"packet":"send","channel":null,"bytes":STANDARD.encode(b)})
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    let secret_ranges = [44, 86].map(|at| {
        let start = usize::from(u16::from_le_bytes(login[at..at + 2].try_into().unwrap()));
        let n = usize::from(u16::from_le_bytes(
            login[at + 2..at + 4].try_into().unwrap(),
        ));
        start..start + n * 2
    });
    fn check(node: &Node, ranges: &[std::ops::Range<usize>]) {
        for (index, byte) in node.raw.iter().enumerate() {
            if ranges
                .iter()
                .any(|r| r.contains(&(node.range.start + index)))
            {
                assert_eq!(*byte, 0);
            }
        }
        for child in &node.children {
            check(child, ranges);
        }
    }
    let mut trees = 0;
    let inspected = replay::replay_with_inspection(lines.as_bytes(), true, |item| {
        match item.content {
            Content::Packet { body, .. } => assert!(body.is_none()),
            Content::Inspection(node) => {
                if node.basis == Basis::Message {
                    trees += 1;
                    check(&node, &secret_ranges);
                } else {
                    assert_eq!(node.basis, Basis::Packet);
                    assert_eq!(node.raw.len(), 8);
                }
            }
            _ => {}
        }
        Ok(())
    })
    .unwrap();
    let plain = replay::replay(lines.as_bytes(), |item| {
        assert!(!matches!(item.content, Content::Inspection(_)));
        Ok(())
    })
    .unwrap();
    assert_eq!(trees, 1);
    assert_eq!(inspected.issues, plain.issues);
    assert_eq!(inspected.records, plain.records);
    assert_eq!(inspected.messages, plain.messages);
    // A body cut before LAST yields header evidence and a diagnostic, never an
    // aggregate credential body or an invented complete LOGIN7 tree.
    let mut saw_login = false;
    replay::replay_with_inspection(lines.lines().next().unwrap().as_bytes(), true, |item| {
        if let Content::Inspection(node) = item.content {
            saw_login |= node.name == "LOGIN7";
        }
        Ok(())
    })
    .unwrap();
    assert!(!saw_login);
}
