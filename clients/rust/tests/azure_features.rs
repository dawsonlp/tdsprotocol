//! Explicit unsupported requests warn; positive negotiation never grants a
//! usable session. Controlled TLS peers are not Azure interoperability evidence.
#![cfg(feature = "tokio")]
mod support;
use std::sync::{Arc, Mutex};
use tds_client::{
    Batch, Connection, ErrorKind, Execution, ProtocolVersion, Step,
    azure_features::{AzureFeature, AzureFeatureProbes},
    observe::{Level, Observer},
    packet,
};

fn selection(feature: AzureFeature) -> AzureFeatureProbes {
    let mut probes = AzureFeatureProbes::default();
    match feature {
        AzureFeature::GlobalTransactions => probes.global_transactions = true,
        AzureFeature::AzureSqlSupport => probes.azure_sql_support = true,
        AzureFeature::DnsCaching => probes.dns_caching = true,
        AzureFeature::EnhancedRouting => probes.enhanced_routing = true,
    }
    probes
}
fn ack(id: u8, data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xae, id];
    bytes.extend((data.len() as u32).to_le_bytes());
    bytes.extend(data);
    bytes.push(0xff);
    bytes
}
fn feature_list(login: &[u8]) -> &[u8] {
    let extension = u16::from_le_bytes(login[56..58].try_into().unwrap()) as usize;
    let start = u32::from_le_bytes(login[extension..extension + 4].try_into().unwrap()) as usize;
    &login[start..]
}

#[tokio::test]
async fn four_probes_warn_and_only_disabled_or_absent_acknowledgements_allow_sql() {
    tokio::time::timeout(std::time::Duration::from_secs(30), run_matrix())
        .await
        .unwrap();
}
async fn run_matrix() {
    for feature in [
        AzureFeature::GlobalTransactions,
        AzureFeature::AzureSqlSupport,
        AzureFeature::DnsCaching,
        AzureFeature::EnhancedRouting,
    ] {
        for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
            for mars in [false, true] {
                for enabled in [None, Some(0), Some(1)] {
                    let (listener, mut options) = support::listener().await;
                    options.version = version;
                    options.mars = mars;
                    options.azure_feature_probes = selection(feature);
                    let warnings = options.azure_feature_probes.warnings();
                    assert_eq!(warnings.len(), 1);
                    assert_eq!(warnings[0].feature, feature);
                    let events = Arc::new(Mutex::new(Vec::new()));
                    let seen = events.clone();
                    options.observe = Some(Observer::new(Level::Full, move |event| {
                        seen.lock().unwrap().push(event.clone());
                        Ok(())
                    }));
                    let server = tokio::spawn(async move {
                        let (socket, _) = listener.accept().await.unwrap();
                        let (mut peer, login) = support::Peer::await_login_protocol(
                            socket,
                            mars,
                            include_bytes!("fixtures/test-server.pem"),
                            version,
                        )
                        .await;
                        assert!(feature_list(&login).windows(5).any(|b| b[0] == feature.id()
                            && u32::from_le_bytes(b[1..5].try_into().unwrap())
                                == u32::from(feature.id() == 8)));
                        let extra =
                            enabled.map_or_else(Vec::new, |value| ack(feature.id(), &[value]));
                        if enabled == Some(1) {
                            // No LOGINACK is needed: stop at enabled FEATUREEXTACK.
                            peer.reply_in_packets(&extra, 9).await;
                            peer.expect_eof().await;
                        } else {
                            peer.accept_login(0x74000004, mars, &extra).await;
                            if mars {
                                use tds_client::mars::{self, Frame};
                                let syn = peer.frame().await;
                                assert_eq!(syn.flags, mars::SYN);
                                peer.send_frame(Frame {
                                    channel: syn.channel,
                                    flags: mars::ACK,
                                    sequence: 0,
                                    window: 4,
                                    body: vec![],
                                })
                                .await;
                                loop {
                                    let data = peer.frame().await;
                                    if data.flags == mars::DATA {
                                        assert_eq!(data.body[0], packet::BATCH);
                                        break;
                                    }
                                }
                                peer.send_frame(Frame {
                                    channel: syn.channel,
                                    flags: mars::DATA,
                                    sequence: 1,
                                    window: 4,
                                    body: packet::split(packet::REPLY, &support::done(0), 4096)
                                        .unwrap(),
                                })
                                .await;
                                loop {
                                    let fin = peer.frame().await;
                                    if fin.flags == mars::FIN {
                                        peer.send_frame(Frame {
                                            channel: syn.channel,
                                            flags: mars::FIN,
                                            sequence: 1,
                                            window: 4,
                                            body: vec![],
                                        })
                                        .await;
                                        break;
                                    }
                                }
                            } else {
                                assert_eq!(peer.message().await.0, packet::BATCH);
                                peer.reply(&support::done(0)).await;
                            }
                            use tokio::io::AsyncReadExt;
                            let mut bytes = [0; 4096];
                            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                                loop {
                                    match peer.socket.read(&mut bytes).await {
                                        Ok(0) => break,
                                        Err(error)
                                            if error.kind()
                                                == std::io::ErrorKind::ConnectionReset =>
                                        {
                                            break;
                                        }
                                        Ok(_) => {}
                                        Err(error) => panic!("peer close: {error}"),
                                    }
                                }
                            })
                            .await
                            .unwrap();
                        }
                    });
                    let result = Connection::connect(options).await;
                    if enabled == Some(1) {
                        let error = result.err().unwrap();
                        assert!(
                            matches!(error.cause().kind, ErrorKind::UnsupportedFeatureEnabled(value) if value == feature)
                        );
                        assert_eq!(error.cause().step, Step::Login);
                        assert_eq!(error.cause().execution, Execution::NotSent);
                    } else {
                        let connection = result.unwrap();
                        let session = connection.session().await.unwrap();
                        assert_eq!(session.feature_warnings, warnings);
                        assert_eq!(
                            session.features.get(&feature.id()).cloned(),
                            enabled.map(|v| vec![v])
                        );
                        let mut channel = connection.serial_channel().await.unwrap();
                        channel
                            .exchange(Batch::new("SELECT 1"))
                            .await
                            .unwrap()
                            .finish()
                            .await
                            .unwrap();
                        channel.close().await.unwrap();
                        connection.close().await.unwrap();
                    }
                    server.await.unwrap();
                    let events = events.lock().unwrap();
                    let warnings: Vec<_> = events.iter().filter(|e| e.kind == "warning").collect();
                    assert_eq!(warnings.len(), 1);
                    assert!(
                        matches!(warnings[0].inspection, Some(tds_client::observe::Inspection::FeatureWarning(value)) if value.feature == feature)
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn malformed_duplicate_and_unrequested_acknowledgements_fail_closed() {
    for (requested, extra) in [
        (true, ack(11, &[])),
        (true, ack(11, &[2])),
        (true, ack(11, &[0, 0])),
        (true, [ack(11, &[0]), ack(11, &[0])].concat()),
        (false, ack(11, &[1])),
    ] {
        let (listener, mut options) = support::listener().await;
        options.azure_feature_probes.dns_caching = requested;
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut peer, _) = support::Peer::await_login(socket, false).await;
            peer.reply(&extra).await;
            peer.expect_eof().await;
        });
        let error = Connection::connect(options).await.err().unwrap();
        assert!(matches!(error.cause().kind, ErrorKind::Malformed { .. }));
        server.await.unwrap();
    }
}

#[test]
fn changing_probe_settings_changes_pool_configuration_and_defaults_do_not_warn() {
    use tds_client::config::ConnectionConfig;
    let a = ConnectionConfig::new("sql.test", 1433, "user", "");
    assert!(a.azure_feature_probes.warnings().is_empty());
    let mut b = a.clone();
    b.azure_feature_probes.dns_caching = true;
    assert!(!b.compatible_with(&a));
}

#[tokio::test]
async fn enabled_feature_never_enters_pool_or_retries_with_the_request_removed() {
    let (listener, mut options) = support::listener().await;
    options.azure_feature_probes.dns_caching = true;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (mut peer, _) = support::Peer::await_login(socket, false).await;
        peer.reply(&ack(11, &[1])).await;
        peer.expect_eof().await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), listener.accept())
                .await
                .is_err()
        );
    });
    let pool = tds_client::Pool::new(options, 1).unwrap();
    let error = pool.acquire().await.err().unwrap();
    assert!(matches!(
        error.cause().kind,
        ErrorKind::UnsupportedFeatureEnabled(AzureFeature::DnsCaching)
    ));
    assert_eq!(pool.in_use(), 0);
    server.await.unwrap();
    pool.close().await.unwrap();
}
