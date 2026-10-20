//! The owned encoder is checked against Python in tables.rs. Here the actual
//! sender must produce the same bytes across table boundaries and RPC separators.
#![cfg(feature = "tokio")]
mod support;
use support::{Peer, done, listener};
use tds_client::{
    Batch, Call, Calls, Connection, IntegerSize, Param, Request, SqlType, StreamedCall,
    StreamedCalls, TableType, Value,
};
fn int() -> SqlType {
    SqlType::Integer {
        size: IntegerSize::Int,
    }
}
#[tokio::test]
async fn produced_tables_preserve_following_parameters_and_batched_call_offsets() {
    let table = TableType::new("dbo", "lines", vec![int().into()]);
    let rows = vec![vec![Some(Value::Integer(7))], vec![None]];
    let make = |rows| {
        Call::new(
            "artificial",
            vec![
                Param::table("@t", table.clone(), rows),
                Param::new("@after", int(), Some(Value::Integer(19))),
            ],
        )
    };
    let expected = Calls(vec![make(Some(rows.clone())), make(Some(vec![]))])
        .encode_request(&tds_client::requests::Context {
            column_encryption: false,
            enclaves: false,
            transaction: 0,
            outstanding: 1,
        })
        .unwrap()
        .body;
    let request = StreamedCalls(vec![
        StreamedCall::new(make(None)).table_source(0, rows.into_iter()),
        StreamedCall::new(make(None)).table_source(0, vec![].into_iter()),
    ]);
    let (listener, options) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        let (kind, body) = peer.message().await;
        assert_eq!(kind, tds_client::packet::RPC);
        assert_eq!(body, expected);
        peer.reply(&done(0)).await;
        assert_eq!(peer.message().await.0, tds_client::packet::BATCH);
        peer.reply(&done(0)).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(options).await.unwrap();
    let mut ch = connection.serial_channel().await.unwrap();
    ch.exchange(request).await.unwrap().finish().await.unwrap();
    ch.exchange(Batch::new("again"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}
