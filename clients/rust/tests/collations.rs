use tds_client::{Collation, SqlText, SqlTextBytes};
fn digest(bytes: impl IntoIterator<Item = u8>) -> String {
    let mut n = 0xcbf29ce484222325_u64;
    for b in bytes {
        n = (n ^ u64::from(b)).wrapping_mul(0x100000001b3);
    }
    format!("{n:016x}")
}
fn for_page(page: u16) -> Collation {
    // The production resolver is tested too: select a server locale or SQL sort
    // whose advertised page matches, rather than exposing private codec tables.
    if page == 65001 {
        return Collation([9, 4, 0, 4, 0]);
    }
    for sort in 1..=255 {
        let c = Collation([9, 4, 0, 0, sort]);
        if c.code_page().ok() == Some(page) {
            return c;
        }
    }
    for locale in 0..=0xffff_u32 {
        let b = locale.to_le_bytes();
        let c = Collation([b[0], b[1], b[2], b[3], 0]);
        if c.code_page().ok() == Some(page) {
            return c;
        }
    }
    panic!("no collation for page {page}")
}
#[test]
fn sql_code_pages_match_python_on_every_byte_pair_and_streaming_boundary() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/collations/python.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let page = case["page"].as_u64().unwrap() as u16;
        let collation = for_page(page);
        let bytes: Vec<u8> = if let Some(raw) = case["raw"].as_str() {
            raw.as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect()
        } else {
            (0..=255_u8)
                .flat_map(|a| (0..=255_u8).flat_map(move |b| [a, b]))
                .collect()
        };
        let raw = SqlTextBytes { bytes, collation };
        let text = raw.decode().unwrap();
        assert_eq!(
            text.0.len() as u64,
            case["units"].as_u64().unwrap(),
            "page {page}"
        );
        assert_eq!(
            digest(text.0.iter().flat_map(|u| u.to_le_bytes())),
            case["decoded"].as_str().unwrap(),
            "page {page}"
        );
        let encoded = SqlTextBytes::from_text(collation, &text).unwrap();
        assert_eq!(
            digest(encoded.bytes),
            case["encoded"].as_str().unwrap(),
            "page {page}"
        );
        for stride in [1, 2, 3, 7, 257] {
            let mut decoder = collation.decoder().unwrap();
            let mut streamed = Vec::new();
            for part in raw.bytes.chunks(stride) {
                streamed.extend(decoder.decode(part, false).0);
            }
            streamed.extend(decoder.decode(&[], true).0);
            assert_eq!(streamed, text.0, "page {page}, stride {stride}");
        }
    }
}
#[test]
fn unknown_collations_unicode_only_and_unrepresentable_text_never_guess_or_replace() {
    let unknown = Collation([0xff; 5]);
    // Clear UTF-8 before testing an unknown locale/sort combination.
    let unknown = Collation([unknown.0[0], unknown.0[1], unknown.0[2], 0, 255]);
    assert!(unknown.code_page().is_err());
    assert!(unknown.decode(b"hello").is_err());
    let unicode_only = Collation([0x39, 0x04, 0, 0, 0]); // Hindi, code page zero.
    assert_eq!(unicode_only.code_page().unwrap(), 0);
    assert!(unicode_only.decode(b"hello").is_err());
    assert!(unicode_only.encode(&"hello".into()).is_err());
    let latin = for_page(1252);
    assert_eq!(latin.decode(&[0x80]).unwrap(), "€".into());
    assert!(latin.encode(&"🦀".into()).is_err());
    assert!(latin.encode(&SqlText(vec![0xd800])).is_err());
    let utf8 = for_page(65001);
    assert!(utf8.encode(&SqlText(vec![0xdc00])).is_err());
    assert_eq!(utf8.encode(&SqlText(vec![0xdcff])).unwrap(), vec![0xff]);
    assert_eq!(utf8.decode(&[0xff]).unwrap(), SqlText(vec![0xdcff]));
}
