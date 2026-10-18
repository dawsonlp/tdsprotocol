//! RPC completion/retention and structured iteration through a controlled peer.
#![cfg(feature = "tokio")]
mod support;
use support::{Peer, done, listener};
use tds_client::{Batch, Call, Connection, ErrorKind, Unread, Value};
fn output(status: u8) -> Vec<u8> {
    let mut bytes = vec![
        0xac, 0, 0, 2, b'@', 0, b'x', 0, status, 0, 0, 0, 0, 0, 0, 0x26, 4, 4,
    ];
    bytes.extend(42_i32.to_le_bytes());
    bytes
}
fn returned(kind: u8, status: u16) -> Vec<u8> {
    let mut bytes = done(status);
    bytes[0] = kind;
    bytes
}
fn rows() -> Vec<u8> {
    let mut bytes = vec![0x81, 1, 0, 0, 0, 0, 0, 0, 0, 0x38, 1, b'v', 0];
    for value in [1_i32, 2, 3] {
        bytes.push(0xd1);
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend(returned(0xff, 1));
    bytes
}
#[tokio::test]
async fn returns_refuse_or_keep_or_discard_without_inventing_lost_rows() {
    for unread in [Unread::Keep, Unread::Discard] {
        let (listener, options) = listener().await;
        let server = tokio::spawn(async move {
            let mut peer = Peer::login(listener).await;
            assert_eq!(peer.message().await.0, tds_client::packet::RPC);
            let mut bytes = rows();
            bytes.extend([0x79, 23, 0, 0, 0]);
            bytes.extend(output(1));
            bytes.extend(output(2));
            bytes.extend(returned(0xfe, 0));
            peer.reply_in_packets(&bytes, 17).await;
            peer.drain_to_eof().await;
        });
        let connection = Connection::connect(options).await.unwrap();
        let mut channel = connection.serial_channel().await.unwrap();
        let mut response = channel
            .exchange(Call::new("artificial", vec![]))
            .await
            .unwrap();
        assert!(matches!(
            response.returns(Unread::Refuse).await.unwrap_err().kind,
            ErrorKind::NotYetRead(_)
        ));
        let returned = response.returns(unread).await.unwrap();
        assert_eq!(returned[0].status, Some(23));
        assert_eq!(returned[0].outputs[0].value, Some(Value::Integer(42)));
        assert_eq!(
            returned[0].function_result.as_ref().unwrap().value,
            Some(Value::Integer(42))
        );
        assert_eq!(
            response.snapshot().result_sets()[0].rows().is_ok(),
            unread == Unread::Keep
        );
        drop(response);
        connection.close().await.unwrap();
        server.await.unwrap();
    }
}
#[tokio::test]
async fn structured_iteration_streams_rows_and_advancing_sets_discards_unread_rows() {
    let (listener, options) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, tds_client::packet::RPC);
        // This peer really omits metadata. Some SQL Server procedures still
        // send it despite NO_METADATA, so a live flag-only test is insufficient.
        let mut set = vec![0x81, 0xff, 0xff];
        set.extend(&rows()[13..]);
        let mut bytes = set.clone();
        bytes.extend(set);
        bytes.extend(done(0));
        peer.reply_in_packets(&bytes, 19).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let columns = vec![tds_client::tokens::Column {
        user_type: 0,
        flags: 0,
        type_info: tds_client::TypeInfo {
            sql_type: tds_client::SqlType::Integer {
                size: tds_client::IntegerSize::Int,
            },
            code: 0x38,
            max_length: None,
            legacy: None,
            clr_assembly: None,
            json_utf8: false,
        },
        name: "v".into(),
    }];
    let mut request = Call::new("two sets", vec![]);
    request.options.no_metadata = true;
    request.columns = vec![columns.clone(), columns];
    let mut response = channel.exchange(request).await.unwrap();
    {
        let mut first = response.next_result_set().await.unwrap().unwrap();
        assert_eq!(
            first.next_row().await.unwrap(),
            Some(vec![Some(Value::Integer(1))])
        );
    }
    let mut second = response.next_result_set().await.unwrap().unwrap();
    assert_eq!(
        second.next_row().await.unwrap(),
        Some(vec![Some(Value::Integer(1))])
    );
    second.finish().await.unwrap();
    drop(second);
    assert!(response.next_result_set().await.unwrap().is_none());
    let snapshot = response.snapshot();
    assert_eq!(
        snapshot
            .result_sets()
            .iter()
            .map(|s| s.rows_read)
            .collect::<Vec<_>>(),
        [3, 3]
    );
    assert!(snapshot.result_sets().iter().all(|s| s.rows().is_err()));
    drop(response);
    connection.close().await.unwrap();
    server.await.unwrap();
}
#[tokio::test]
async fn canceling_rpc_retains_completed_returns_and_the_actual_acknowledgement() {
    let (listener, options) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, tds_client::packet::RPC);
        assert_eq!(peer.message().await.0, tds_client::packet::ATTENTION);
        let mut bytes = vec![0x79, 23, 0, 0, 0];
        bytes.extend(output(1));
        bytes.extend(returned(0xfe, 1));
        bytes.extend(done(0x20));
        peer.reply(&bytes).await;
        peer.message().await;
        peer.reply(&done(0)).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel
        .exchange(Call::new("artificial", vec![]))
        .await
        .unwrap();
    response.cancel_handle().cancel();
    let error = response.finish().await.unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Canceled));
    let kept = error.response.unwrap();
    assert!(kept.canceled);
    assert_eq!(kept.returns()[0].status, Some(23));
    assert!(kept.completions().last().unwrap().acknowledges_cancel());
    drop(response);
    channel
        .exchange(Batch::new("after"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn rejected_parameter_is_not_sent_even_when_a_mars_sibling_is_executing() {
    use tds_client::{
        Execution, IntegerSize, Param, SqlType,
        mars::{self, Frame},
        packet,
    };
    let (listener, mut options) = listener().await;
    options.mars = true;
    let (release, ready) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut peer = Peer::login_mars(listener).await;
        let first = peer.frame().await;
        assert_eq!(first.flags, mars::SYN);
        assert_eq!(peer.frame().await.flags, mars::DATA);
        assert_eq!(peer.frame().await.flags, mars::SYN);
        ready.await.unwrap();
        peer.send_frame(Frame {
            flags: mars::DATA,
            channel: first.channel,
            sequence: 1,
            window: 4,
            body: packet::split(packet::REPLY, &done(0), 4096).unwrap(),
        })
        .await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let mut first = connection.serial_channel().await.unwrap();
    let mut response = first.exchange(Batch::new("held")).await.unwrap();
    let mut second = connection.serial_channel().await.unwrap();
    let error = second
        .exchange(Call::new(
            "artificial",
            vec![Param::new(
                "@x",
                SqlType::Integer {
                    size: IntegerSize::Tiny,
                },
                Some(Value::Integer(-1)),
            )],
        ))
        .await
        .err()
        .unwrap();
    assert!(matches!(error.kind, ErrorKind::Parameter(_)));
    assert_eq!(error.execution, Execution::NotSent);
    assert!(!connection.is_closed());
    release.send(()).unwrap();
    response.finish().await.unwrap();
    drop(response);
    connection.close().await.unwrap();
    server.await.unwrap();
}
