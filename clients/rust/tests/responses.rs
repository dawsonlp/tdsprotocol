//! Reading-policy parity with Python, using its unchanged SQL Server captures.
//! The verified TLS peer supplies transport; captures preserve server provenance.
#![cfg(feature = "tokio")]
mod support;

use support::{Peer, done, listener};
use tds_client::Value::Integer as Int;
use tds_client::{Batch, Connection, ErrorKind, Item, Record, RowsNotAvailable, packet};

const COUNTS: &[u8] = include_bytes!("fixtures/responses/counts.bin");
const NOCOUNT: &[u8] = include_bytes!("fixtures/responses/nocount.bin");
const FAILS: &[u8] = include_bytes!("fixtures/responses/statement_fails.bin");
const ENDS: &[u8] = include_bytes!("fixtures/responses/batch_ends.bin");
const MESSAGES: &[u8] = include_bytes!("fixtures/responses/messages.bin");
const NULL_BITMAP: &[u8] = include_bytes!("fixtures/responses/null_bitmap.bin");
const DATABASE: &[u8] = include_bytes!("fixtures/responses/use_database.bin");

#[tokio::test]
async fn captures_keep_the_same_record_with_one_byte_or_whole_packet_bodies() {
    let (listener, config) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        for body in [
            COUNTS,
            NOCOUNT,
            FAILS,
            ENDS,
            MESSAGES,
            NULL_BITMAP,
            DATABASE,
        ] {
            for size in [4096, 9] {
                assert_eq!(peer.message().await.0, packet::BATCH);
                peer.reply_in_packets(body, size).await;
            }
        }
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    for body in [
        COUNTS,
        NOCOUNT,
        FAILS,
        ENDS,
        MESSAGES,
        NULL_BITMAP,
        DATABASE,
    ] {
        let mut previous = None;
        for _ in 0..2 {
            let mut response = channel
                .exchange(Batch::new("capture replay"))
                .await
                .unwrap();
            let fetched = match response.fetch().await {
                Ok(fetched) => fetched,
                Err(error) => {
                    assert!(matches!(error.kind, ErrorKind::ServerErrors(_)));
                    *error.response.unwrap()
                }
            };
            assert!(fetched.ended);
            if let Some(previous) = previous {
                assert_eq!(fetched, previous);
            }
            if body == COUNTS {
                assert_eq!(
                    fetched
                        .completions()
                        .map(|d| d.row_count)
                        .collect::<Vec<_>>(),
                    [Some(3), Some(2), Some(3), Some(3)]
                );
                assert_eq!(
                    fetched.result_sets()[0].rows().unwrap(),
                    &[vec![Some(Int(1))], vec![Some(Int(3))], vec![Some(Int(4))]]
                );
            } else if body == NOCOUNT {
                assert!(fetched.completions().all(|done| done.row_count.is_none()));
            } else if body == FAILS {
                assert_eq!(fetched.errors().next().unwrap().number, 8134);
                assert_eq!(fetched.result_sets().len(), 3);
                assert_eq!(
                    fetched.result_sets()[2].rows().unwrap(),
                    &[vec![Some(Int(2))]]
                );
                assert!(fetched.result_sets()[1].rows().unwrap().is_empty());
            } else if body == ENDS {
                assert_eq!(fetched.errors().next().unwrap().number, 245);
                assert_eq!(fetched.result_sets().len(), 2);
                assert_eq!(
                    fetched.result_sets()[0].rows().unwrap(),
                    &[vec![Some(Int(1))]]
                );
            } else if body == MESSAGES {
                assert_eq!(
                    fetched
                        .messages()
                        .map(|m| (m.number, m.severity))
                        .collect::<Vec<_>>(),
                    [(0, 0), (50000, 0)]
                );
                assert!(matches!(
                    fetched.sequence(),
                    [
                        Item::Message(_),
                        Item::Completion(_),
                        Item::Message(_),
                        Item::Completion(_),
                        Item::ResultSet(0),
                        Item::Completion(_)
                    ]
                ));
            } else if body == NULL_BITMAP {
                assert_eq!(
                    fetched.result_sets()[0].rows().unwrap()[0],
                    [
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        Some(Int(42))
                    ]
                );
            } else {
                assert!(
                    fetched
                        .sequence()
                        .iter()
                        .any(|i| matches!(i, Item::Announcement(_)))
                );
            }
            let mut replayed_rows = 0;
            while let Some(record) = response.next().await.unwrap() {
                if matches!(record, Record::Row(_)) {
                    replayed_rows += 1;
                }
            }
            assert_eq!(
                replayed_rows,
                fetched
                    .result_sets()
                    .iter()
                    .map(|set| set.rows_read)
                    .sum::<usize>()
            );
            assert_eq!(response.snapshot(), fetched);
            previous = Some(fetched);
        }
    }
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn fetch_after_streaming_keeps_the_live_tail_but_does_not_invent_complete_rows() {
    let (listener, config) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        // A subsequent untouched set must still be fetchable after the first
        // set's first row has passed. Clear MORE only on the last completion.
        let mut body = COUNTS.to_vec();
        body[COUNTS.len() - 12] |= 1;
        body.extend(NULL_BITMAP);
        peer.reply(&body).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel.exchange(Batch::new("partial fetch")).await.unwrap();
    loop {
        if let Some(Record::Row(row)) = response.next().await.unwrap() {
            assert_eq!(row, [Some(Int(1))]);
            break;
        }
    }
    assert!(matches!(
        response.snapshot().result_sets()[0].rows(),
        Err(RowsNotAvailable::StillArriving)
    ));
    let fetched = response.fetch().await.unwrap();
    assert!(matches!(
        fetched.result_sets()[0].rows(),
        Err(RowsNotAvailable::NotRetained { rows_read: 3 })
    ));
    assert_eq!(fetched.result_sets()[1].rows().unwrap().len(), 1);
    let mut tail = Vec::new();
    while let Some(record) = response.next().await.unwrap() {
        if let Record::Row(row) = record {
            tail.push(row);
        }
    }
    assert_eq!(&tail[..2], &[vec![Some(Int(3))], vec![Some(Int(4))]]);
    assert_eq!(tail.len(), 3);
    assert_eq!(response.fetch().await.unwrap(), fetched);
    response.finish().await.unwrap();
    drop(response);
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
    // Independent data remain usable after channel and connection destruction.
    assert_eq!(fetched.result_sets()[1].rows().unwrap().len(), 1);
}

#[tokio::test]
async fn finish_discards_rows_retains_the_record_and_never_sends_attention() {
    let (listener, config) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(COUNTS).await;
        // Attention would fail this assertion: finish must drain normally.
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(&done(0)).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel.exchange(Batch::new("finish")).await.unwrap();
    response.finish().await.unwrap();
    let record = response.snapshot();
    assert_eq!(record.completions().count(), 4);
    assert!(matches!(
        record.result_sets()[0].rows(),
        Err(RowsNotAvailable::NotRetained { rows_read: 3 })
    ));
    assert!(response.next().await.unwrap().is_none());
    drop(response);
    channel
        .exchange(Batch::new("reuse"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn an_error_read_past_is_reported_once_by_finish_with_the_whole_record() {
    let (listener, config) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(FAILS).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel
        .exchange(Batch::new("checked finish"))
        .await
        .unwrap();
    loop {
        if let Some(Record::Error(error)) = response.next().await.unwrap() {
            assert_eq!(error.number, 8134);
            break;
        }
    }
    let error = response.finish().await.unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::ServerErrors(ref errors) if errors.len() == 1 && errors[0].number == 8134)
    );
    let record = error.response.unwrap();
    assert!(record.ended);
    assert_eq!(record.result_sets().len(), 3);
    assert_eq!(record.result_sets()[2].rows_read, 1);
    response.finish().await.unwrap();
    assert!(response.next().await.unwrap().is_none());
    drop(response);
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn streaming_reports_sql_errors_after_the_final_record_once() {
    let (listener, config) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(FAILS).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel.exchange(Batch::new("stream")).await.unwrap();
    let mut rows = Vec::new();
    let mut final_done = false;
    loop {
        match response.next().await {
            Ok(Some(Record::Row(row))) => rows.push(row),
            Ok(Some(Record::Done(done))) => final_done |= done.is_final(),
            Ok(Some(_)) => {}
            Err(error) => {
                assert!(matches!(error.kind, ErrorKind::ServerErrors(_)));
                assert!(final_done);
                assert_eq!(error.response.unwrap().result_sets().len(), 3);
                break;
            }
            Ok(None) => panic!("SQL error was silently ignored"),
        }
    }
    assert_eq!(rows, [vec![Some(Int(1))], vec![Some(Int(2))]]);
    assert!(response.next().await.unwrap().is_none());
    response.finish().await.unwrap();
    drop(response);
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn cancel_keeps_drained_metadata_and_the_actual_acknowledgement() {
    let (listener, config) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        assert_eq!(peer.message().await.0, packet::ATTENTION);
        peer.reply(COUNTS).await;
        peer.reply(&done(0x20)).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel.exchange(Batch::new("cancel")).await.unwrap();
    response.cancel_handle().cancel();
    let error = response.finish().await.unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Canceled));
    let record = error.response.unwrap();
    assert!(record.ended && record.canceled);
    assert!(record.completions().last().unwrap().acknowledges_cancel());
    assert_eq!(record.result_sets()[0].rows_read, 3);
    assert!(record.result_sets()[0].rows().is_err());
    response.finish().await.unwrap();
    drop(response);
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn truncated_message_attaches_an_honest_incomplete_record() {
    let (listener, config) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        peer.reply(&COUNTS[..COUNTS.len() - 13]).await;
        peer.expect_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel.exchange(Batch::new("truncated")).await.unwrap();
    let error = response.fetch().await.unwrap_err();
    assert!(matches!(error.cause().kind, ErrorKind::Malformed { .. }));
    let record = error.response.unwrap();
    assert!(!record.ended);
    assert_eq!(record.completions().count(), 3);
    assert_eq!(record.result_sets()[0].rows().unwrap().len(), 3);
    assert!(connection.is_closed());
    drop(response);
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn fatal_server_error_keeps_its_record_and_discards_the_connection() {
    let (listener, config) = listener().await;
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        // A synthetic fatal ERROR, based on the first INFO capture. Change its
        // token and severity explicitly; do not alter the shared capture itself.
        let mut body = MESSAGES[..51].to_vec();
        body[0] = 0xaa;
        body[8] = 20;
        peer.reply(&body).await;
        peer.expect_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel.exchange(Batch::new("fatal")).await.unwrap();
    let error = response.fetch().await.unwrap_err();
    assert!(matches!(error.cause().kind, ErrorKind::Server(ref message) if message.severity == 20));
    let record = error.response.unwrap();
    assert!(!record.ended);
    assert_eq!(record.errors().next().unwrap().severity, 20);
    assert!(connection.is_closed());
    drop(response);
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn external_cancellation_during_fetch_preserves_kept_rows_and_the_live_tail() {
    let (listener, config) = listener().await;
    let (began, reading) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut peer = Peer::login(listener).await;
        assert_eq!(peer.message().await.0, packet::BATCH);
        began.send(()).unwrap();
        assert_eq!(peer.message().await.0, packet::ATTENTION);
        peer.reply(COUNTS).await;
        peer.reply(&done(0x20)).await;
        peer.drain_to_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel
        .exchange(Batch::new("cancel fetched response"))
        .await
        .unwrap();
    let cancel = response.cancel_handle();
    let error = {
        let fetching = response.fetch();
        tokio::pin!(fetching);
        // Poll fetch first so KEEP is selected before delegated cancellation.
        tokio::select! {
            biased;
            result = &mut fetching => panic!("response ended before cancellation: {result:?}"),
            _ = reading => {},
        }
        cancel.cancel();
        fetching.await.unwrap_err()
    };
    assert!(matches!(error.kind, ErrorKind::Canceled));
    let record = error.response.unwrap();
    assert!(record.ended && record.canceled);
    assert_eq!(
        record.result_sets()[0].rows().unwrap(),
        &[vec![Some(Int(1))], vec![Some(Int(3))], vec![Some(Int(4))]]
    );
    assert!(record.completions().last().unwrap().acknowledges_cancel());
    let mut rows = Vec::new();
    while let Some(item) = response.next().await.unwrap() {
        if let Record::Row(row) = item {
            rows.push(row);
        }
    }
    assert_eq!(rows.len(), 3);
    response.finish().await.unwrap();
    drop(response);
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn procedure_return_statuses_remain_ordered_and_survive_fetch() {
    let (listener, config) = support::listener().await;
    let server = tokio::spawn(async move {
        let mut peer = support::Peer::login(listener).await;
        assert_eq!(peer.message().await.0, tds_client::packet::BATCH);
        let mut body = Vec::new();
        for status in [-7_i32, 9] {
            body.push(0x79);
            body.extend(status.to_le_bytes());
            let mut completion = support::done(1);
            completion[0] = 0xfe; // DONEPROC, more follows
            body.extend(completion);
        }
        body.extend(support::done(0));
        peer.reply(&body).await;
        peer.expect_eof().await;
    });
    let connection = Connection::connect(config).await.unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel
        .exchange(tds_client::Batch::new(
            "EXEC procedure_one; EXEC procedure_two",
        ))
        .await
        .unwrap();
    let fetched = response.fetch().await.unwrap();
    let statuses: Vec<_> = fetched
        .sequence()
        .iter()
        .filter_map(|item| {
            if let tds_client::Item::ReturnStatus(value) = item {
                Some(*value)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(statuses, [-7, 9]);
    assert_eq!(fetched.completions().count(), 3);
    assert_eq!(
        response.next().await.unwrap(),
        Some(tds_client::Record::ReturnStatus(-7))
    );
    response.finish().await.unwrap();
    drop(response);
    channel.close().await.unwrap();
    connection.close().await.unwrap();
    server.await.unwrap();
}
