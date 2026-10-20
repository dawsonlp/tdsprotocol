#![cfg(feature = "encryption")]
#[path = "support/enclave.rs"]
mod enclave;
mod support;
use aws_lc_rs::digest::{SHA256, digest};
use enclave::{bytes, fixture, peer_key, read_call, root_from_parameters};
use std::time::Duration;
use tds_client::{
    encryption::{self, WrappedKey},
    requests::decode,
    *,
};
fn acknowledgement() -> Vec<u8> {
    vec![
        0xe3, 8, 0, 7, 5, 9, 4, 0xd0, 0, 0x34, 0, 0xae, 4, 8, 0, 0, 0, 2, 3, b'V', 0, b'B', 0,
        b'S', 0, 0xff,
    ]
}
#[tokio::test]
async fn facade_authorizes_keys_shares_counter_and_recreates_session_after_invalidation() {
    let (listener, mut options) = support::listener().await;
    options.enclave_attestation = Some(EnclaveAttestation::None);
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, login) = support::Peer::await_login(socket, false).await;
        let pointer = u16::from_le_bytes(login[56..58].try_into().unwrap()) as usize;
        let mut at = u32::from_le_bytes(login[pointer..pointer + 4].try_into().unwrap()) as usize;
        while login[at] != 4 {
            assert_ne!(login[at], 255);
            at += 5 + u32::from_le_bytes(login[at + 1..at + 5].try_into().unwrap()) as usize;
        }
        assert_eq!(&login[at + 1..at + 6], &[1, 0, 0, 0, 2]);
        peer.accept_login(0x74000004, false, &acknowledgement())
            .await;
        let (kind, body) = peer.message().await;
        assert_eq!(kind, packet::BATCH);
        assert!(
            matches!(decode::request_with_enclaves(kind,&body,true).unwrap(),decode::Request::Batch {enclave_package,..} if enclave_package.is_empty())
        );
        peer.reply(&support::done(0)).await;
        let f = fixture();
        let mut session = None;
        for (index, counter) in [1_i64, 2, 1].into_iter().enumerate() {
            let (kind, body) = peer.message().await;
            assert_eq!(kind, packet::RPC);
            let describe = read_call(&body);
            assert!(describe.enclave_package.is_empty());
            if index != 1 {
                assert_eq!(describe.parameters.len(), 3);
                assert!(matches!(
                    describe.parameters[2].type_info.sql_type,
                    SqlType::Binary {
                        length: 116,
                        varying: true
                    }
                ));
                let Some(Value::Binary(parameters)) = describe.parameters[2].value.as_ref() else {
                    panic!("attestation")
                };
                session = Some(peer_key(root_from_parameters(parameters)));
            } else {
                assert_eq!(describe.parameters.len(), 2);
            }
            peer.reply_in_packets(&bytes(&f, "description"), 31).await;
            let (kind, body) = peer.message().await;
            assert_eq!(kind, packet::RPC);
            let call = read_call(&body);
            assert_eq!(&call.enclave_package[..8], b"session1");
            let key = encryption::ColumnKey {
                database_id: 0,
                key_id: 0,
                version: 0,
                metadata_version: [0; 8],
                values: vec![WrappedKey {
                    provider: "peer".into(),
                    path: "".into(),
                    algorithm: "RSA_OAEP".into(),
                    encrypted: vec![1],
                }],
            };
            let guard = session.as_ref().unwrap().exchange().unwrap();
            let plain = guard
                .decrypt(&key, &call.enclave_package[8..])
                .await
                .unwrap();
            let plain = plain.as_bytes();
            assert_eq!(
                i64::from_le_bytes(plain[16..24].try_into().unwrap()),
                counter
            );
            let expected = digest(
                &SHA256,
                &f["statement"]
                    .as_str()
                    .unwrap()
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>(),
            );
            assert_eq!(&plain[24..56], expected.as_ref());
            assert_eq!(&plain[56..60], &5_u32.to_le_bytes());
            assert_eq!(&plain[60..68], b"version1");
            assert_eq!(&plain[68..70], &7_u16.to_le_bytes());
            assert_eq!(&plain[70..], bytes(&f, "column_root"));
            let Some(Value::Encrypted(cipher)) = call.parameters[2].value.as_ref() else {
                panic!("encrypted parameter")
            };
            let cek = peer_key(bytes(&f, "column_root").try_into().unwrap());
            let g = cek.exchange().unwrap();
            assert_eq!(
                g.decrypt(&key, &cipher.0).await.unwrap().as_bytes(),
                &7_i64.to_le_bytes()
            );
            peer.reply(&support::done(0)).await;
        }
        peer.expect_eof().await; // Stay connected until the client closes.
    });
    let connection = Connection::connect(options).await.unwrap();
    let policies = encryption::Policies {
        master: encryption::Policy::Time(Duration::from_secs(60)),
        column: encryption::Policy::Time(Duration::from_secs(60)),
        ..Default::default()
    };
    let encrypted = connection
        .encrypted(
            vec![
                encryption::LocalKeyStore::new(
                    "TDS_TEST",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/encryption"),
                )
                .unwrap(),
            ],
            policies,
        )
        .await
        .unwrap();
    let f = fixture();
    let mut channel = encrypted.serial_channel().await.unwrap();
    for index in 0..3 {
        if index == 2 {
            encrypted.invalidate_keys();
            assert_eq!(encrypted.statistics().live_columns, 0);
        }
        channel
            .execute(
                f["statement"].as_str().unwrap(),
                "@v int",
                vec![Param::new(
                    "@v",
                    SqlType::Integer {
                        size: IntegerSize::Int,
                    },
                    Some(Value::Integer(7)),
                )],
            )
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
    }
    assert_eq!(encrypted.statistics().unwraps, 2);
    assert_eq!(encrypted.statistics().metadata_verifications, 3);
    assert_eq!(encrypted.statistics().authorized_keys, 3);
    assert_eq!(encrypted.statistics().enclave_packages, 3);
    channel.close().await.unwrap();
    encrypted.close().await;
    connection.close().await.unwrap();
    peer.await.unwrap();
}

fn error(number: i32) -> Vec<u8> {
    let mut body = number.to_le_bytes().to_vec();
    body.extend([1, 16]);
    body.extend(5_u16.to_le_bytes());
    body.extend("stale".encode_utf16().flat_map(u16::to_le_bytes));
    body.extend([0, 0]);
    body.extend(1_u32.to_le_bytes());
    let mut token = vec![0xaa];
    token.extend((body.len() as u16).to_le_bytes());
    token.extend(body);
    token.extend(support::done(2));
    token
}
#[tokio::test]
async fn enclave_stale_refusal_is_redescribed_once_and_second_refusal_is_returned() {
    for final_number in [0, 33195, 50000] {
        let (listener, mut options) = support::listener().await;
        options.enclave_attestation = Some(EnclaveAttestation::None);
        let peer = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut peer, _) = support::Peer::await_login(socket, false).await;
            peer.accept_login(0x74000004, false, &acknowledgement())
                .await;
            assert_eq!(peer.message().await.0, packet::BATCH);
            peer.reply(&support::done(0)).await;
            let f = fixture();
            for attempt in 1..=2 {
                let (_, body) = peer.message().await;
                let describe = read_call(&body);
                assert_eq!(describe.parameters.len(), 3);
                peer.reply(&bytes(&f, "description")).await;
                let (_, body) = peer.message().await;
                let call = read_call(&body);
                assert!(!call.enclave_package.is_empty());
                peer.reply(&if attempt == 1 {
                    error(33195)
                } else if final_number != 0 {
                    error(final_number)
                } else {
                    support::done(0)
                })
                .await;
            }
            peer.expect_eof().await; // Stay connected until the client closes.
        });
        let connection = Connection::connect(options).await.unwrap();
        let encrypted = connection
            .encrypted(
                vec![
                    encryption::LocalKeyStore::new(
                        "TDS_TEST",
                        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/encryption"),
                    )
                    .unwrap(),
                ],
                Default::default(),
            )
            .await
            .unwrap();
        let mut channel = encrypted.serial_channel().await.unwrap();
        let f = fixture();
        let mut response = channel
            .execute(
                f["statement"].as_str().unwrap(),
                "@v int",
                vec![Param::new(
                    "@v",
                    SqlType::Integer {
                        size: IntegerSize::Int,
                    },
                    Some(Value::Integer(7)),
                )],
            )
            .await
            .unwrap();
        let result = response.finish().await;
        if final_number == 0 {
            result.unwrap();
        } else {
            assert!(
                matches!(result.unwrap_err().kind,ErrorKind::ServerErrors(ref errors) if errors[0].number==final_number)
            );
        }
        drop(response);
        channel.close().await.unwrap();
        encrypted.close().await;
        connection.close().await.unwrap();
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn unsigned_enclave_key_is_refused_before_application_sql() {
    let (listener, mut options) = support::listener().await;
    options.enclave_attestation = Some(EnclaveAttestation::None);
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = support::Peer::await_login(socket, false).await;
        peer.accept_login(0x74000004, false, &acknowledgement())
            .await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(&support::done(0)).await;
        assert_eq!(peer.message().await.0, packet::RPC);
        peer.reply(&bytes(&fixture(), "description_denied")).await;
        // A harmless application-controlled raw batch proves no attempted
        // encrypted statement was queued after authorization failed.
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(&support::done(0)).await;
        peer.expect_eof().await; // Stay connected until the client closes.
    });
    let connection = Connection::connect(options).await.unwrap();
    let encrypted = connection
        .encrypted(
            vec![
                encryption::LocalKeyStore::new(
                    "TDS_TEST",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/encryption"),
                )
                .unwrap(),
            ],
            Default::default(),
        )
        .await
        .unwrap();
    let mut channel = encrypted.serial_channel().await.unwrap();
    let f = fixture();
    let result = channel
        .execute(
            f["statement"].as_str().unwrap(),
            "@v int",
            vec![Param::new(
                "@v",
                SqlType::Integer {
                    size: IntegerSize::Int,
                },
                Some(Value::Integer(7)),
            )],
        )
        .await;
    assert!(
        matches!(result,Err(ref e) if matches!(e.kind,ErrorKind::Encryption(encryption::Error::Authentication)))
    );
    drop(result);
    assert_eq!(encrypted.statistics().unwrap_attempts, 0);
    channel
        .exchange(Batch::new("SELECT 1"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    channel.close().await.unwrap();
    encrypted.close().await;
    connection.close().await.unwrap();
    peer.await.unwrap();
}

/// Part B (B-11): enclave key release dispatches by provider name. A provider
/// named MSSQL_CERTIFICATE_STORE verifies Python's enclave-permission signature
/// and its column key reaches the package. (Native CNG signing is checked on
/// Windows by certstore_native/certstore_live.)
#[tokio::test]
async fn certificate_store_named_keys_are_verified_and_released_to_the_enclave() {
    let (listener, mut options) = support::listener().await;
    options.enclave_attestation = Some(EnclaveAttestation::None);
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = support::Peer::await_login(socket, false).await;
        peer.accept_login(0x74000004, false, &acknowledgement())
            .await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(&support::done(0)).await;
        let f = fixture();
        let (kind, body) = peer.message().await;
        assert_eq!(kind, packet::RPC);
        let describe = read_call(&body);
        let Some(Value::Binary(parameters)) = describe.parameters[2].value.as_ref() else {
            panic!("attestation")
        };
        let session = peer_key(root_from_parameters(parameters));
        peer.reply(&bytes(&f, "description_certstore")).await;
        let (_, body) = peer.message().await;
        let call = read_call(&body);
        let key = encryption::ColumnKey {
            database_id: 0,
            key_id: 0,
            version: 0,
            metadata_version: [0; 8],
            values: vec![WrappedKey {
                provider: "peer".into(),
                path: "".into(),
                algorithm: "RSA_OAEP".into(),
                encrypted: vec![1],
            }],
        };
        let guard = session.exchange().unwrap();
        let plain = guard
            .decrypt(&key, &call.enclave_package[8..])
            .await
            .unwrap();
        assert_eq!(&plain.as_bytes()[70..], bytes(&f, "column_root"));
        peer.reply(&support::done(0)).await;
        peer.expect_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let encrypted = connection
        .encrypted(
            vec![
                encryption::LocalKeyStore::new(
                    "MSSQL_CERTIFICATE_STORE",
                    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/encryption"),
                )
                .unwrap(),
            ],
            Default::default(),
        )
        .await
        .unwrap();
    let mut channel = encrypted.serial_channel().await.unwrap();
    channel
        .execute(
            fixture()["statement"].as_str().unwrap(),
            "@v int",
            vec![Param::new(
                "@v",
                SqlType::Integer {
                    size: IntegerSize::Int,
                },
                Some(Value::Integer(7)),
            )],
        )
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    channel.close().await.unwrap();
    assert_eq!(encrypted.statistics().metadata_verifications, 1);
    assert_eq!(encrypted.statistics().authorized_keys, 1);
    encrypted.close().await;
    connection.close().await.unwrap();
    peer.await.unwrap();
}
