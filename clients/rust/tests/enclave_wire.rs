use base64::{Engine, engine::general_purpose::STANDARD};
use tds_client::{
    requests::{Context, decode},
    *,
};
#[test]
fn version_two_batch_and_rpc_packages_match_python_and_roundtrip_inspection() {
    let f: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/azure/enclave.json")).unwrap();
    let context = Context {
        transaction: 0,
        outstanding: 1,
        column_encryption: true,
        enclaves: true,
    };
    let mut call = Call::new(Builtin::SpExecuteSql, vec![]);
    call.enclave_package = b"package".to_vec();
    for (name, request) in [
        (
            "batch",
            Batch::new("SELECT 1")
                .with_enclave(b"package".to_vec())
                .encode_request(&context)
                .unwrap(),
        ),
        ("rpc", call.encode_request(&context).unwrap()),
    ] {
        assert_eq!(
            request.body,
            STANDARD.decode(f[name].as_str().unwrap()).unwrap()
        );
        let parsed = decode::request_with_enclaves(request.kind, &request.body, true).unwrap();
        match parsed {
            decode::Request::Batch {
                enclave_package, ..
            } => assert_eq!(enclave_package, b"package"),
            decode::Request::Rpc { calls, .. } => assert_eq!(calls[0].enclave_package, b"package"),
            _ => panic!("wrong request"),
        }
        assert!(
            tds_client::inspection::message_with_enclaves(request.kind, &request.body, true, true)
                .unwrap()
                .issue
                .is_none()
        );
    }
    let empty = Batch::new("SELECT 1").encode_request(&context).unwrap();
    assert_eq!(&empty.body[22..24], &[0, 0]);
    assert!(
        Batch::new("SQL")
            .with_enclave(vec![0; 65536])
            .encode_request(&context)
            .is_err()
    );
    let maximum_without_package = (1_048_576 - 22) / 2; // documented 1 MiB codec bound.
    assert!(
        Batch::new("x".repeat(maximum_without_package))
            .encode_request(&context)
            .is_err()
    );
}
