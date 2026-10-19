//! Reproducible malformed-input exploration, complementary to exact fixtures.
//! This is a finite seeded corpus, not a claim of exhaustive fuzz coverage.
use tds_client::{inspection, packet, requests::decode, tokens::Decoder};

fn nodes(node: &inspection::Node, length: usize) {
    assert!(node.range.start <= node.range.end);
    assert!(node.range.end <= length);
    assert!(node.raw.len() <= inspection::RAW_LIMIT);
    assert!(node.raw.len() <= node.range.len());
    for child in &node.children {
        nodes(child, length);
    }
}
#[test]
fn seeded_malformed_messages_and_fragmented_tokens_never_panic_or_escape_bounds() {
    let mut seed = 0x5444_535f_5041_5253_u64;
    for case in 0..2048 {
        let length = case % 257;
        let bytes: Vec<_> = (0..length)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        for kind in [
            packet::BATCH,
            packet::RPC,
            packet::TRANSACTION,
            packet::BULK,
            packet::LOGIN,
            packet::HELLO,
        ] {
            if kind == packet::BULK {
                let _ = decode::bulk(&bytes);
            } else if matches!(kind, packet::BATCH | packet::RPC | packet::TRANSACTION) {
                let _ = decode::request(kind, &bytes);
            }
            if let Some(node) = inspection::message(kind, &bytes) {
                nodes(&node, bytes.len());
            }
        }
        let mut decoder = Decoder::default();
        decoder.set_inspection(true);
        let mut failed = false;
        for chunk in bytes.chunks(1 + case % 17) {
            decoder.feed(chunk).unwrap();
            loop {
                let result = decoder.next_record();
                if let Some(node) = decoder.take_inspection() {
                    nodes(&node, bytes.len());
                }
                match result {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            if failed {
                break;
            }
        }
    }
}
