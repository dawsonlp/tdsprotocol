//! A01 wire comparison uses Python's actual encoders and public artificial data.
//! Session acceptance, provider behavior and SDK integration are separate gates.
use serde_json::Value;
use tds_client::fedauth::{self, Workflow};

#[test]
fn unsupported_diagnostic_feature_requests_match_python_production_encodings() {
    use tds_client::{azure_features::AzureFeatureProbes, login7::Login};
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/azure/feature_probes.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let mut probes = AzureFeatureProbes::default();
        match case["id"].as_u64().unwrap() {
            5 => probes.global_transactions = true,
            8 => probes.azure_sql_support = true,
            11 => probes.dns_caching = true,
            15 => probes.enhanced_routing = true,
            _ => panic!(),
        }
        let login = Login {
            azure_feature_probes: probes,
            ..Login::default()
        }
        .encode()
        .unwrap();
        let at = u16::from_le_bytes(login[56..58].try_into().unwrap()) as usize;
        let at = u32::from_le_bytes(login[at..at + 4].try_into().unwrap()) as usize;
        assert_eq!(&login[at..], unhex(case["encoded"].as_str().unwrap()));
    }
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn federated_feature_and_token_messages_match_python() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/azure/wire.json")).unwrap();
    assert_eq!(fixture["schema"], 1);
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 24);
    for case in cases {
        let expected = unhex(case["expected"].as_str().unwrap());
        let nonce = case["nonce"]
            .as_str()
            .map(|text| <[u8; 32]>::try_from(unhex(text)).unwrap());
        let actual = match case["kind"].as_str().unwrap() {
            "upfront" => fedauth::upfront_feature(
                case["token"].as_str().unwrap(),
                case["echo"].as_bool().unwrap(),
                nonce.as_ref(),
            )
            .unwrap(),
            "message" => {
                fedauth::token_message(case["token"].as_str().unwrap(), nonce.as_ref()).unwrap()
            }
            "deferred" => {
                let workflow = match case["workflow"].as_u64().unwrap() {
                    1 => Workflow::Password,
                    2 => Workflow::Integrated,
                    3 => Workflow::Interactive,
                    _ => panic!("fixture workflow"),
                };
                fedauth::deferred_feature(workflow, case["echo"].as_bool().unwrap())
                    .to_vec()
                    .into()
            }
            _ => panic!("fixture kind"),
        };
        assert_eq!(*actual, expected, "{}", case["id"]);
    }
}

#[test]
fn supplementary_unicode_counts_utf16_bytes_and_nonce_has_no_length_prefix() {
    // One supplementary character is two UTF-16 code units, four wire bytes.
    let nonce = [0xa5; 32];
    let feature = fedauth::upfront_feature("🔑", true, Some(&nonce)).unwrap();
    assert_eq!(&feature[..9], &[3, 4, 0, 0, 0, 0x3d, 0xd8, 0x11, 0xdd]);
    assert_eq!(&feature[9..], &nonce);
    let message = fedauth::token_message("🔑", Some(&nonce)).unwrap();
    assert_eq!(u32::from_le_bytes(message[..4].try_into().unwrap()), 40);
    assert_eq!(u32::from_le_bytes(message[4..8].try_into().unwrap()), 4);
    assert_eq!(&message[8..12], &feature[5..9]);
    assert_eq!(&message[12..], &nonce);
}

#[test]
fn fedauthinfo_fields_and_refusals_match_python_at_every_fragment_boundary() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/azure/wire.json")).unwrap();
    for case in fixture["info_cases"].as_array().unwrap() {
        let bytes = unhex(case["token"].as_str().unwrap());
        for split in 0..bytes.len() {
            let mut decoder = tds_client::tokens::Decoder::default();
            decoder.feed(&bytes[..split]).unwrap();
            assert!(decoder.next_record().unwrap().is_none());
            decoder.feed(&bytes[split..]).unwrap();
            if let Some(reason) = case["error"].as_str() {
                // Python refuses this token (strict parsing, PY-AZ-01); so must Rust.
                assert!(
                    decoder.next_record().is_err(),
                    "{} split {split}: Python refused it: {reason}",
                    case["id"]
                );
                continue;
            }
            let tds_client::Record::FedAuthInfo(info) = decoder.next_record().unwrap().unwrap()
            else {
                panic!()
            };
            assert_eq!(
                info.sts_url, case["sts_url"],
                "{} split {split}",
                case["id"]
            );
            assert_eq!(
                info.resource, case["resource"],
                "{} split {split}",
                case["id"]
            );
            assert!(decoder.is_empty());
        }
    }
    let mut decoder = tds_client::tokens::Decoder::default();
    decoder
        .feed(&[0xee, 4, 0, 0, 0, 255, 255, 255, 255])
        .unwrap();
    assert!(
        decoder.next_record().is_err(),
        "complete bounded token with an impossible directory"
    );
}
