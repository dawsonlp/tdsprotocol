//! Independent MARS progress and adversarial framing through verified TLS.
#![cfg(feature = "tokio")]
mod support;
use std::time::Duration;
use support::{Peer, done, listener};
use tds_client::{
    Batch, Connection, ErrorKind, Record, Step,
    mars::{self, Frame},
    packet,
};

fn frame(channel: u16, flags: u8, sequence: u32, window: u32, body: Vec<u8>) -> Frame {
    Frame {
        channel,
        flags,
        sequence,
        window,
        body,
    }
}
fn data(channel: u16, sequence: u32, body: &[u8]) -> Frame {
    let mut bytes = packet::split(packet::REPLY, body, 4096).unwrap();
    if body.first() == Some(&0x81) {
        bytes[1] = 0;
    } // metadata/row prefix, message not finished
    frame(channel, mars::DATA, sequence, 4, bytes)
}
async fn syn(peer: &mut Peer, id: u16) {
    let f = peer.frame().await;
    assert_eq!((f.channel, f.flags, f.sequence), (id, mars::SYN, 0));
}
fn row(n: i32) -> Vec<u8> {
    let mut bytes = vec![0x81, 1, 0, 0, 0, 0, 0, 0, 0, 0x38, 0, 0xd1];
    bytes.extend(n.to_le_bytes());
    bytes
}

#[tokio::test]
async fn blocked_sender_leaves_mailbox_and_sibling_reader_free() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (listener, mut options) = listener().await;
        options.mars = true;
        let (blocked, waiting) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut peer = Peer::login_mars(listener).await;
            syn(&mut peer, 0).await;
            syn(&mut peer, 1).await;
            for n in 1..=4 {
                let f = peer.frame().await;
                assert_eq!((f.channel, f.sequence), (0, n));
                assert_eq!(f.body[1] & 1, 0);
            }
            blocked.send(()).unwrap();
            let f = peer.frame().await;
            assert_eq!((f.channel, f.flags), (1, mars::DATA));
            // Autocommit sends one in ALL_HEADERS, even with two active MARS exchanges.
            assert_eq!(u32::from_le_bytes(f.body[26..30].try_into().unwrap()), 1);
            peer.send_frame(data(1, 1, &done(0))).await;
            peer.send_frame(frame(0, mars::ACK, 0, 32, vec![])).await;
            loop {
                let f = peer.frame().await;
                if f.channel == 0 && f.flags == mars::DATA && f.body[1] & 1 != 0 {
                    break;
                }
            }
            peer.send_frame(frame(
                0,
                mars::DATA,
                1,
                32,
                packet::split(packet::REPLY, &done(0), 4096).unwrap(),
            ))
            .await;
            peer.drain_to_eof().await;
        });
        let connection = Connection::connect(options).await.unwrap();
        let mut first = connection.serial_channel().await.unwrap();
        let mut second = connection.serial_channel().await.unwrap();
        let sender = tokio::spawn(async move {
            let mut response = first
                .exchange(Batch::new(format!("/* {} */ SELECT 1", "x".repeat(20000))))
                .await
                .unwrap();
            response.finish().await.unwrap();
        });
        waiting.await.unwrap();
        let mut response = second.exchange(Batch::new("SELECT 2")).await.unwrap();
        response.finish().await.unwrap();
        drop(response);
        sender.await.unwrap();
        connection.close().await.unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn receive_credit_counts_frames_when_tds_packets_are_split_or_combined() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (listener, mut options) = listener().await;
        options.mars = true;
        let server = tokio::spawn(async move {
            let mut peer = Peer::login_mars(listener).await;
            syn(&mut peer, 0).await;
            assert_eq!(peer.frame().await.flags, mars::DATA);
            let bytes = packet::split(packet::REPLY, &done(0), 4096).unwrap();
            for (i, part) in [&bytes[..2], &bytes[2..4], &bytes[4..6], &bytes[6..]]
                .iter()
                .enumerate()
            {
                let f = frame(0, mars::DATA, i as u32 + 1, 4, part.to_vec())
                    .encode()
                    .unwrap();
                // Exercise transport fragmentation independently of SMP and TDS.
                for byte in f {
                    peer.send_raw_plain(&[byte]).await;
                }
            }
            let ack = peer.frame().await;
            assert_eq!((ack.flags, ack.window), (mars::ACK, 7));
            assert_eq!(peer.frame().await.flags, mars::DATA);
            let mut bytes = packet::split(packet::REPLY, &done(1), 4096).unwrap();
            bytes[1] = 0;
            bytes.extend(packet::split(packet::REPLY, &done(0), 4096).unwrap());
            peer.send_frame(frame(0, mars::DATA, 5, 4, bytes)).await;
            peer.drain_to_eof().await;
        });
        let connection = Connection::connect(options).await.unwrap();
        let mut ch = connection.serial_channel().await.unwrap();
        ch.exchange(Batch::new("first"))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        let mut response = ch.exchange(Batch::new("second")).await.unwrap();
        response.finish().await.unwrap();
        assert_eq!(response.snapshot().completions().count(), 2);
        drop(response);
        connection.close().await.unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fatal_error_fans_out_one_cause_with_each_channels_own_partial_record() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (listener, mut options) = listener().await;
        options.mars = true;
        let (send_fatal, wait_fatal) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut peer = Peer::login_mars(listener).await;
            syn(&mut peer, 0).await;
            syn(&mut peer, 1).await;
            assert_eq!(peer.frame().await.channel, 0);
            assert_eq!(peer.frame().await.channel, 1);
            peer.send_frame(data(0, 1, &row(11))).await;
            peer.send_frame(data(1, 1, &row(22))).await;
            wait_fatal.await.unwrap();
            let mut body = include_bytes!("fixtures/responses/messages.bin")[..51].to_vec();
            body[0] = 0xaa;
            body[8] = 20;
            peer.send_frame(data(0, 2, &body)).await;
            peer.drain_to_eof().await;
        });
        let connection = Connection::connect(options).await.unwrap();
        let mut a = connection.serial_channel().await.unwrap();
        let mut b = connection.serial_channel().await.unwrap();
        let mut ar = a.exchange(Batch::new("a")).await.unwrap();
        let mut br = b.exchange(Batch::new("b")).await.unwrap();
        for response in [&mut ar, &mut br] {
            while !matches!(response.next().await.unwrap(), Some(Record::Row(_))) {}
        }
        send_fatal.send(()).unwrap();
        let (ae, be) = tokio::join!(ar.fetch(), br.fetch());
        let ae = ae.unwrap_err();
        let be = be.unwrap_err();
        for error in [&ae, &be] {
            assert!(matches!(error.cause().kind,ErrorKind::Server(ref m) if m.severity==20));
            assert!(!error.response.as_ref().unwrap().ended);
        }
        assert_eq!(ae.response.as_ref().unwrap().errors().count(), 1);
        assert_eq!(be.response.as_ref().unwrap().errors().count(), 0);
        assert_eq!(ae.response.as_ref().unwrap().result_sets()[0].rows_read, 1);
        assert_eq!(be.response.as_ref().unwrap().result_sets()[0].rows_read, 1);
        connection.close().await.unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn channel_close_deadline_applies_while_its_request_waits_for_credit() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (listener, mut options) = listener().await;
        options.mars = true;
        options.cleanup_timeout = Duration::from_millis(50);
        let (blocked, waiting) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut peer = Peer::login_mars(listener).await;
            syn(&mut peer, 0).await;
            syn(&mut peer, 1).await;
            for _ in 0..4 {
                assert_eq!(peer.frame().await.channel, 0);
            }
            blocked.send(()).unwrap();
            peer.drain_to_eof().await;
        });
        let connection = Connection::connect(options).await.unwrap();
        let mut a = connection.serial_channel().await.unwrap();
        let mut b = connection.serial_channel().await.unwrap();
        let close = a.close_handle();
        let sender = tokio::spawn(async move {
            a.exchange(Batch::new("x".repeat(20000)))
                .await
                .err()
                .unwrap()
        });
        waiting.await.unwrap();
        let error = close.close().await.unwrap_err();
        let ErrorKind::Cleanup { cleanup, .. } = error.kind else {
            panic!("cleanup pair")
        };
        assert!(matches!(cleanup.cause().kind, ErrorKind::Timeout));
        let error = sender.await.unwrap();
        assert_eq!(error.step, Step::Cleanup);
        assert!(matches!(error.cause().kind, ErrorKind::Timeout));
        assert!(connection.is_closed());
        assert!(b.exchange(Batch::new("never")).await.is_err());
        connection.close().await.unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_sequence_discards_siblings_and_abandonment_never_preserves_them() {
    for malformed in [true, false] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (listener, mut options) = listener().await;
            options.mars = true;
            let (ready, waiting) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut peer = Peer::login_mars(listener).await;
                syn(&mut peer, 0).await;
                syn(&mut peer, 1).await;
                assert_eq!(peer.frame().await.channel, 0);
                assert_eq!(peer.frame().await.channel, 1);
                ready.send(()).unwrap();
                if malformed {
                    peer.send_frame(data(0, 2, &done(0))).await;
                }
                peer.drain_to_eof().await;
            });
            let connection = Connection::connect(options).await.unwrap();
            let mut a = connection.serial_channel().await.unwrap();
            let mut b = connection.serial_channel().await.unwrap();
            let mut ar = a.exchange(Batch::new("a")).await.unwrap();
            let mut br = b.exchange(Batch::new("b")).await.unwrap();
            waiting.await.unwrap();
            if malformed {
                let (a, b) = tokio::join!(ar.next(), br.next());
                for e in [a.unwrap_err(), b.unwrap_err()] {
                    assert!(matches!(
                        e.cause().kind,
                        ErrorKind::Malformed {
                            field: "MARS sequence",
                            ..
                        }
                    ));
                }
            } else {
                drop(ar);
                assert!(br.next().await.is_err());
            }
            assert!(connection.is_closed());
            connection.close().await.unwrap();
            server.await.unwrap();
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn peer_fin_revokes_only_its_channel_and_completes_the_fin_exchange() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (listener, mut options) = listener().await;
        options.mars = true;
        let server = tokio::spawn(async move {
            let mut peer = Peer::login_mars(listener).await;
            syn(&mut peer, 0).await;
            syn(&mut peer, 1).await;
            assert_eq!(peer.frame().await.channel, 0);
            peer.send_frame(frame(0, mars::FIN, 0, 4, vec![])).await;
            let mut answered = false;
            while !answered {
                let f = peer.frame().await;
                match (f.channel, f.flags) {
                    (0, mars::FIN) => answered = true,
                    _ => panic!("expected client's FIN"),
                }
            }
            assert_eq!(peer.frame().await.channel, 1);
            peer.send_frame(data(1, 1, &done(0))).await;
            peer.drain_to_eof().await;
        });
        let connection = Connection::connect(options).await.unwrap();
        let mut a = connection.serial_channel().await.unwrap();
        let mut b = connection.serial_channel().await.unwrap();
        let mut response = a.exchange(Batch::new("closed by peer")).await.unwrap();
        assert!(matches!(
            response.next().await.unwrap_err().cause().kind,
            ErrorKind::Closed
        ));
        drop(response);
        assert!(!connection.is_closed());
        b.exchange(Batch::new("sibling"))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        connection.close().await.unwrap();
        server.await.unwrap();
    })
    .await
    .unwrap();
}
