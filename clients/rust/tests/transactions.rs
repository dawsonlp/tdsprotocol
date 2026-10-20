use tds_client::{
    Isolation as I, Request, SqlText, Transaction as T,
    requests::Context,
    transactions::{Begin, End},
};
fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn transaction_messages_match_python_exactly_and_refuse_unencodable_inputs() {
    let requests = vec![
        T::CoordinatorAddress,
        T::Propagate(b"cookie".to_vec()),
        T::Promote,
        T::Begin(Begin::default()),
        T::Begin(Begin {
            isolation: I::Serializable,
            name: "a🦀".into(),
        }),
        T::Save("before".into()),
        T::Save("".into()),
        T::Commit(End::default()),
        T::Rollback(End {
            name: "before".into(),
            begin: None,
        }),
        T::Commit(End {
            name: "outer".into(),
            begin: Some(Begin {
                isolation: I::Snapshot,
                name: "next".into(),
            }),
        }),
        T::Rollback(End {
            begin: Some(Begin::default()),
            ..End::default()
        }),
        T::Begin(Begin {
            name: SqlText(vec![0xd800]),
            ..Begin::default()
        }),
    ];
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/transactions/python.json")).unwrap();
    for (i, case) in cases.as_array().unwrap().iter().enumerate() {
        let context = Context {
            column_encryption: false,
            enclaves: false,
            transaction: case["transaction"].as_u64().unwrap(),
            outstanding: case["outstanding"].as_u64().unwrap() as u32,
        };
        let encoded = requests[i % requests.len()]
            .encode_request(&context)
            .unwrap();
        assert_eq!(encoded.kind, 0x0e);
        assert_eq!(encoded.body, hex(case["body"].as_str().unwrap()));
    }
    let context = Context {
        column_encryption: false,
        enclaves: false,
        transaction: 0,
        outstanding: 1,
    };
    assert!(
        T::Save("x".repeat(128).as_str().into())
            .encode_request(&context)
            .is_err()
    );
    assert!(
        T::Propagate(vec![0; 65536])
            .encode_request(&context)
            .is_err()
    );
}
