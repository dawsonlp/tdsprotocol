use tds_client::{Record, tokens::Decoder};
fn short(s: &str, b: &mut Vec<u8>) {
    b.push(s.encode_utf16().count() as u8);
    b.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
}
fn classification(version: u8) -> Vec<u8> {
    let mut b = vec![0xa3, 1, 0];
    short("Private", &mut b);
    short("label-id", &mut b);
    b.extend([1, 0]);
    short("Financial", &mut b);
    short("type-id", &mut b);
    if version == 2 {
        b.extend(20_u32.to_le_bytes());
    }
    b.extend([1, 0, 1, 0, 0, 0, 0, 0]);
    if version == 2 {
        b.extend(20_u32.to_le_bytes());
    }
    b
}
#[test]
fn classification_versions_and_browse_tokens_decode_across_every_byte() {
    for version in [1, 2] {
        let bytes = classification(version);
        for stride in 1..=bytes.len() {
            let mut d = Decoder::default();
            d.set_classification_version(version).unwrap();
            let mut records = Vec::new();
            for part in bytes.chunks(stride) {
                d.feed(part).unwrap();
                while let Some(r) = d.next_record().unwrap() {
                    records.push(r);
                }
            }
            let Record::Classification(c) = &records[0] else {
                panic!()
            };
            assert_eq!(
                c.columns[0][0].label.as_ref().unwrap().name,
                "Private".into()
            );
            assert_eq!(c.rank, (version == 2).then_some(20));
            assert!(d.is_empty());
        }
    }
    let mut d = Decoder::default();
    d.feed(&classification(2)).unwrap();
    assert!(d.next_record().is_err());
    let bytes = [0xa5, 7, 0, 1, 1, 0x20, 1, b'n', 0, 0]; // trailing incomplete column entry in a bounded token
    let mut d = Decoder::default();
    d.feed(&bytes).unwrap();
    assert!(d.next_record().is_err());
}
