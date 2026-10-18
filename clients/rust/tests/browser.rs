//! Controlled UDP evidence; a Linux SQL Server container has no Browser service.
#![cfg(feature = "tokio")]
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use tds_client::browser::{self, Encoding, Options, Problem};
use tokio::{
    net::UdpSocket,
    time::{Instant, timeout},
};

#[tokio::test]
async fn unicast_instance_machine_and_dac_use_the_exact_requests() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let options = Options {
        port: socket.local_addr().unwrap().port(),
        ..Options::default()
    };
    let server = tokio::spawn(async move {
        let mut bytes = [0; 256];
        for (expected, reply) in [
            (
                b"\x04YUKONSTD\0".as_slice(),
                include_bytes!("fixtures/browser/instance.bin").as_slice(),
            ),
            (
                b"\x03",
                include_bytes!("fixtures/browser/machine.bin").as_slice(),
            ),
            (
                b"\x0f\x01YUKONSTD\0",
                include_bytes!("fixtures/browser/dac.bin").as_slice(),
            ),
        ] {
            let (n, sender) = socket.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..n], expected);
            socket.send_to(reply, sender).await.unwrap();
        }
    });
    let instance = browser::instance("127.0.0.1", "YUKONSTD", &options)
        .await
        .unwrap();
    assert_eq!(instance.tcp_port().unwrap(), Some(57137));
    assert_eq!(instance.address, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert_eq!(
        browser::machine("127.0.0.1", &options).await.unwrap().len(),
        3
    );
    assert_eq!(
        browser::dac_port("127.0.0.1", "YUKONSTD", &options)
            .await
            .unwrap(),
        57138
    );
    server.await.unwrap();
}
#[tokio::test]
async fn broadcast_collects_valid_replies_until_the_original_deadline() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let options = Options {
        port: socket.local_addr().unwrap().port(),
        timeout_ms: 60,
        ..Options::default()
    };
    let server = tokio::spawn(async move {
        let mut bytes = [0; 256];
        let (n, sender) = socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..n], [2]);
        for reply in [
            b"\x05\0\0".as_slice(),
            include_bytes!("fixtures/browser/machine.bin"),
            include_bytes!("fixtures/browser/instance.bin"),
        ] {
            socket.send_to(reply, sender).await.unwrap();
        }
    });
    let began = Instant::now();
    let found = browser::broadcast(Ipv4Addr::LOCALHOST, &options)
        .await
        .unwrap();
    assert!(began.elapsed() >= Duration::from_millis(60));
    assert_eq!(found.len(), 4);
    assert!(
        found
            .iter()
            .all(|i| i.address == Some(Ipv4Addr::LOCALHOST.into()))
    );
    server.await.unwrap();
}
#[tokio::test]
async fn no_reply_and_malformed_reply_preserve_request_context_and_bytes() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let options = Options {
        port: socket.local_addr().unwrap().port(),
        timeout_ms: 25,
        ..Options::default()
    };
    let error = browser::instance("127.0.0.1", "MISSING", &options)
        .await
        .unwrap_err();
    assert!(matches!(error.problem, Problem::Timeout));
    assert_eq!(error.instance.as_deref(), Some("MISSING"));
    assert!(error.reply.is_none());
    let server = tokio::spawn(async move {
        let mut bytes = [0; 256];
        // The unanswered request remains in this socket's queue.
        socket.recv_from(&mut bytes).await.unwrap();
        let (_, sender) = socket.recv_from(&mut bytes).await.unwrap();
        socket.send_to(b"\x05\x02\0;;", sender).await.unwrap();
    });
    let error = browser::machine("127.0.0.1", &options).await.unwrap_err();
    assert!(matches!(error.problem, Problem::Malformed { .. }));
    assert_eq!(error.reply.as_deref(), Some(b"\x05\x02\0;;".as_slice()));
    assert!(error.to_string().contains("CLNT_UCAST_EX"));
    server.await.unwrap();
}
#[tokio::test]
async fn invalid_names_send_nothing_and_an_instance_request_requires_one_instance() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let options = Options {
        port: socket.local_addr().unwrap().port(),
        encoding: Encoding::Ascii,
        ..Options::default()
    };
    assert!(
        browser::instance("127.0.0.1", "Café", &options)
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(20), socket.recv_from(&mut [0; 256]))
            .await
            .is_err()
    );
    let server = tokio::spawn(async move {
        let (_, sender) = socket.recv_from(&mut [0; 256]).await.unwrap();
        socket
            .send_to(include_bytes!("fixtures/browser/machine.bin"), sender)
            .await
            .unwrap();
    });
    assert!(matches!(
        browser::instance("127.0.0.1", "YUKONSTD", &options)
            .await
            .unwrap_err()
            .problem,
        Problem::InstanceCount(3)
    ));
    server.await.unwrap();
}
#[tokio::test]
async fn a_broadcast_with_no_answers_returns_no_instances() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let options = Options {
        port: socket.local_addr().unwrap().port(),
        timeout_ms: 20,
        ..Options::default()
    };
    assert!(
        browser::broadcast(Ipv4Addr::LOCALHOST, &options)
            .await
            .unwrap()
            .is_empty()
    );
}
