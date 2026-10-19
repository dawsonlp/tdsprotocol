#![cfg(feature = "tokio")]
mod support;
use tds_client::{Batch, Cell, Chunk, Connection, ProtocolVersion, Value};

const SQL: &str = "SELECT CAST(7 AS int) AS n, REPLICATE(CAST(N'ab🦀' AS nvarchar(max)),400000) AS u, CONVERT(varbinary(max), REPLICATE(CAST('xyz' AS varchar(max)),700000)) AS b, CAST(NULL AS nvarchar(max)) AS nil, CAST(N'' AS nvarchar(max)) AS empty; SELECT CAST('<x>hello</x>' AS xml) AS x; SELECT CAST('legacy' AS text), CAST(N'old🦀' AS ntext), CAST(0x010203 AS image); SELECT 42 AS last";
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn large_borrowed_readers_discard_tails_fetch_and_materialize_in_all_modes() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            let mut response = channel.exchange(Batch::new(SQL)).await.unwrap();
            {
                let mut set = response.next_result_set().await.unwrap().unwrap();
                let mut row = set.streamed_row().await.unwrap().unwrap();
                assert!(matches!(
                    row.next_value().await.unwrap(),
                    Some(Cell::Scalar(Value::Integer(7)))
                ));
                {
                    let Some(Cell::Stream(mut value)) = row.next_value().await.unwrap() else {
                        panic!()
                    };
                    let mut count = 0;
                    while let Some(chunk) = value.next_chunk().await.unwrap() {
                        let Chunk::Unicode(text) = chunk else {
                            panic!()
                        };
                        assert!(text.0.len() <= 32768);
                        count += text.0.len();
                    }
                    assert_eq!(count, 1600000);
                }
                {
                    // Drop one value early: the next cell must drain its tail.
                    let Some(Cell::Stream(mut value)) = row.next_value().await.unwrap() else {
                        panic!()
                    };
                    assert!(matches!(
                        value.next_chunk().await.unwrap(),
                        Some(Chunk::Binary(_))
                    ));
                }
                assert!(matches!(row.next_value().await.unwrap(), Some(Cell::Null)));
                {
                    let Some(Cell::Stream(mut value)) = row.next_value().await.unwrap() else {
                        panic!()
                    };
                    assert!(value.next_chunk().await.unwrap().is_none());
                }
                assert!(row.next_value().await.unwrap().is_none());
            }
            {
                // Drop row and set before reading XML: the next set drains it.
                let mut set = response.next_result_set().await.unwrap().unwrap();
                let mut row = set.streamed_row().await.unwrap().unwrap();
                assert!(matches!(
                    row.next_value().await.unwrap(),
                    Some(Cell::Stream(_))
                ));
            }
            {
                let mut set = response.next_result_set().await.unwrap().unwrap();
                let row = set.next_row().await.unwrap().unwrap();
                assert_eq!(row.len(), 3);
                assert!(matches!(&row[0], Some(Value::Text(t)) if t.bytes == b"legacy"));
                assert_eq!(row[1], Some(Value::Unicode("old🦀".into())));
                assert_eq!(row[2], Some(Value::Binary(vec![1, 2, 3])));
            }
            let fetched = response.fetch().await.unwrap();
            assert!(fetched.result_sets()[0].rows().is_err());
            assert!(fetched.result_sets()[1].rows().is_err());
            assert!(fetched.result_sets()[2].rows().is_err());
            assert_eq!(
                fetched.result_sets()[3].rows().unwrap(),
                [vec![Some(Value::Integer(42))]]
            );
            drop(response);
            let fetched = channel
                .exchange(Batch::new(SQL))
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            let row = &fetched.result_sets()[0].rows().unwrap()[0];
            assert!(matches!(&row[1], Some(Value::Unicode(t)) if t.0.len() == 1600000));
            assert!(matches!(&row[2], Some(Value::Binary(b)) if b.len() == 2100000));
            assert_eq!(row[3], None);
            assert_eq!(row[4], Some(Value::Unicode("".into())));
            assert_eq!(
                fetched.result_sets()[1].rows().unwrap()[0][0],
                Some(Value::Unicode("<x>hello</x>".into()))
            );
            connection.close().await.unwrap();
        }
    }
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn fetch_after_partial_row_does_not_reconstruct_it_and_replays_later_rows() {
    let connection = Connection::connect(support::docker_options())
        .await
        .unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    let mut response = channel.exchange(Batch::new("SELECT REPLICATE(CAST(N'x' AS nvarchar(max)), 600000) UNION ALL SELECT N'next'; SELECT 99")).await.unwrap();
    {
        let mut set = response.next_result_set().await.unwrap().unwrap();
        let mut row = set.streamed_row().await.unwrap().unwrap();
        let Some(Cell::Stream(mut value)) = row.next_value().await.unwrap() else {
            panic!()
        };
        assert!(value.next_chunk().await.unwrap().is_some());
    }
    let fetched = response.fetch().await.unwrap();
    assert_eq!(fetched.result_sets()[0].rows_read, 2);
    assert!(fetched.result_sets()[0].rows().is_err());
    assert_eq!(
        fetched.result_sets()[1].rows().unwrap(),
        [vec![Some(Value::Integer(99))]]
    );
    // Fetch retains the live unread suffix too, even when the set could not
    // become a complete owned result because an earlier row had streamed past.
    assert_eq!(
        response.next().await.unwrap(),
        Some(tds_client::Record::Row(vec![Some(Value::Unicode(
            "next".into()
        ))]))
    );
    response.finish().await.unwrap();
    connection.close().await.unwrap();
}

struct Pieces(std::collections::VecDeque<std::io::Result<Chunk>>);
impl tds_client::Source for Pieces {
    fn next_chunk(&mut self) -> tds_client::SourceRead<'_> {
        Box::pin(async { self.0.pop_front().transpose() })
    }
}
fn pieces(chunks: Vec<Chunk>) -> Pieces {
    Pieces(chunks.into_iter().map(Ok).collect())
}
fn rpc_source(
    _connection: &tds_client::Connection,
    collation: tds_client::Collation,
    sql: &str,
) -> tds_client::Call {
    tds_client::Call::new(
        tds_client::Builtin::SpExecuteSql,
        vec![
            tds_client::Param::new(
                "@stmt",
                tds_client::SqlType::CharacterMax {
                    unicode: true,
                    collation,
                },
                Some(Value::Unicode(sql.into())),
            ),
            tds_client::Param::new(
                "@params",
                tds_client::SqlType::CharacterMax {
                    unicode: true,
                    collation,
                },
                Some(Value::Unicode(
                    "@a varbinary(max), @u nvarchar(max) OUTPUT".into(),
                )),
            ),
            tds_client::Param::new("@a", tds_client::SqlType::BinaryMax, None),
            tds_client::Param::new(
                "@u",
                tds_client::SqlType::CharacterMax {
                    unicode: true,
                    collation,
                },
                None,
            )
            .output(),
        ],
    )
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn outgoing_sources_and_large_outputs_cross_packets_and_cleanup_failures() {
    use tds_client::{Collation, ErrorKind, StreamedCall};
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let connection = Connection::connect(options).await.unwrap();
            let collation = Collation(
                connection
                    .session()
                    .await
                    .unwrap()
                    .collation
                    .try_into()
                    .unwrap(),
            );
            let mut channel = connection.serial_channel().await.unwrap();
            let call = rpc_source(
                &connection,
                collation,
                "SELECT DATALENGTH(@a), DATALENGTH(@u); SET @u=REPLICATE(CAST(N'z' AS nvarchar(max)),700000)",
            );
            let request = StreamedCall::new(call)
                .source(
                    2,
                    pieces((0..50).map(|_| Chunk::Binary(vec![42; 65536])).collect()),
                )
                .source(
                    3,
                    pieces(vec![
                        Chunk::Unicode("".into()),
                        Chunk::Unicode("hi🦀".into()),
                    ]),
                );
            let fetched = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                let mut response = channel.exchange(request).await.unwrap();
                response.fetch().await.unwrap()
            })
            .await
            .expect("streamed request timeout");
            assert_eq!(
                fetched.result_sets()[0].rows().unwrap()[0],
                vec![Some(Value::Integer(3276800)), Some(Value::Integer(8))]
            );
            assert!(
                matches!(&fetched.returns()[0].output_named(&"@u".into()).unwrap().value, Some(Value::Unicode(t)) if t.0.len() == 700000)
            );
            for partial in [false, true] {
                let mut chunks = std::collections::VecDeque::new();
                if partial {
                    chunks.push_back(Ok(Chunk::Binary(vec![1; 100000])));
                }
                chunks.push_back(Err(std::io::Error::other("source stopped")));
                let request = StreamedCall::new(rpc_source(
                    &connection,
                    collation,
                    "THROW 51001,'must not execute',1",
                ))
                .source(2, Pieces(chunks));
                let error = match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    channel.exchange(request),
                )
                .await
                .expect("cleanup timeout")
                {
                    Ok(_) => panic!("source must fail"),
                    Err(e) => e,
                };
                assert!(matches!(error.cause().kind, ErrorKind::Io(_)), "{error:?}");
                if partial {
                    assert!(error.response.as_ref().unwrap().ended);
                    assert!(
                        error
                            .response
                            .as_ref()
                            .unwrap()
                            .errors()
                            .all(|e| e.number != 51001)
                    );
                }
                channel
                    .exchange(Batch::new("SELECT 1"))
                    .await
                    .unwrap()
                    .finish()
                    .await
                    .unwrap();
            }
            let request = StreamedCall::new(rpc_source(&connection, collation, "SELECT 2")).source(
                2,
                pieces(vec![
                    Chunk::Binary(vec![1; 100000]),
                    Chunk::Unicode("wrong".into()),
                ]),
            );
            let error = match channel.exchange(request).await {
                Ok(_) => panic!(),
                Err(e) => e,
            };
            assert!(
                matches!(error.cause().kind, ErrorKind::Parameter(_)),
                "{error:?}"
            );
            channel
                .exchange(Batch::new("SELECT 3"))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            connection.close().await.unwrap();
        }
    }
}
struct Paused {
    gate: Option<tokio::sync::oneshot::Receiver<()>>,
    produced: bool,
}
impl tds_client::Source for Paused {
    fn next_chunk(&mut self) -> tds_client::SourceRead<'_> {
        Box::pin(async move {
            if let Some(gate) = self.gate.take() {
                let _ = gate.await;
            }
            if self.produced {
                return Ok(None);
            }
            self.produced = true;
            Ok(Some(Chunk::Binary(vec![7; 200000])))
        })
    }
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn slow_source_lends_executor_to_mars_sibling_and_channel_close() {
    use tds_client::{Collation, StreamedCall};
    let mut options = support::docker_options();
    options.mars = true;
    let connection = Connection::connect(options).await.unwrap();
    let collation = Collation(
        connection
            .session()
            .await
            .unwrap()
            .collation
            .try_into()
            .unwrap(),
    );
    let mut slow = connection.serial_channel().await.unwrap();
    let mut fast = connection.serial_channel().await.unwrap();
    let (release, gate) = tokio::sync::oneshot::channel();
    let call = StreamedCall::new(rpc_source(&connection, collation, "SELECT DATALENGTH(@a)"))
        .source(
            2,
            Paused {
                gate: Some(gate),
                produced: false,
            },
        );
    let (a, b) = tokio::join!(
        async {
            slow.exchange(call).await.unwrap().finish().await.unwrap();
        },
        async {
            let kept = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                fast.exchange(Batch::new("SELECT 42"))
                    .await
                    .unwrap()
                    .fetch()
                    .await
                    .unwrap()
            })
            .await
            .unwrap();
            assert_eq!(
                kept.result_sets()[0].rows().unwrap()[0][0],
                Some(Value::Integer(42))
            );
            release.send(()).unwrap();
        }
    );
    let _ = (a, b);
    let close = slow.close_handle();
    let (_release, gate) = tokio::sync::oneshot::channel();
    let call = StreamedCall::new(rpc_source(&connection, collation, "SELECT 9")).source(
        2,
        Paused {
            gate: Some(gate),
            produced: false,
        },
    );
    let (a, b) = tokio::join!(
        async {
            assert!(slow.exchange(call).await.is_err());
        },
        async {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            close.close().await.unwrap();
        }
    );
    let _ = (a, b);
    fast.exchange(Batch::new("SELECT 99"))
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    connection.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn stalled_large_reader_preserves_mars_sibling_progress_and_cancel_reuse() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        let mut options = support::docker_options();
        options.version = version;
        options.mars = true;
        let connection = Connection::connect(options).await.unwrap();
        let mut slow = connection.serial_channel().await.unwrap();
        let mut fast = connection.serial_channel().await.unwrap();
        let mut response = slow
            .exchange(Batch::new(
                "SELECT REPLICATE(CAST(N'x' AS nvarchar(max)), 2500000)",
            ))
            .await
            .unwrap();
        {
            let mut set = response.next_result_set().await.unwrap().unwrap();
            let mut row = set.streamed_row().await.unwrap().unwrap();
            let Some(Cell::Stream(mut value)) = row.next_value().await.unwrap() else {
                panic!()
            };
            assert!(value.next_chunk().await.unwrap().is_some());
        }
        let fetched = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            fast.exchange(Batch::new("SELECT 42"))
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(
            fetched.result_sets()[0].rows().unwrap()[0][0],
            Some(Value::Integer(42))
        );
        response.close().await.unwrap();
        slow.exchange(Batch::new("SELECT 99"))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        connection.close().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn owned_large_inputs_include_legacy_xml_and_raw_collated_text() {
    use tds_client::{Builtin, Call, Collation, Param, SqlTextBytes, SqlType};
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let connection = Connection::connect(options).await.unwrap();
            let collation = Collation(
                connection
                    .session()
                    .await
                    .unwrap()
                    .collation
                    .try_into()
                    .unwrap(),
            );
            let mut channel = connection.serial_channel().await.unwrap();
            let u = SqlType::CharacterMax {
                unicode: true,
                collation,
            };
            let cases = [
                (
                    SqlType::BinaryMax,
                    Value::Binary(vec![0x5a; 2100000]),
                    "varbinary(max)",
                ),
                (
                    u.clone(),
                    Value::Unicode("owned🦀".repeat(200000).as_str().into()),
                    "nvarchar(max)",
                ),
                (
                    SqlType::CharacterMax {
                        unicode: false,
                        collation,
                    },
                    Value::Text(SqlTextBytes {
                        bytes: b"raw ASCII".to_vec(),
                        collation,
                    }),
                    "varchar(max)",
                ),
                (
                    SqlType::Xml { schema: None },
                    Value::Unicode("<x>hi</x>".into()),
                    "xml",
                ),
                (
                    SqlType::LegacyText {
                        unicode: true,
                        collation,
                    },
                    Value::Unicode("old🦀".into()),
                    "ntext",
                ),
                (
                    SqlType::LegacyText {
                        unicode: false,
                        collation,
                    },
                    Value::Text(SqlTextBytes {
                        bytes: b"old ASCII".to_vec(),
                        collation,
                    }),
                    "text",
                ),
                (
                    SqlType::LegacyImage,
                    Value::Binary(vec![0, 1, 255]),
                    "image",
                ),
            ];
            for (ty, value, declaration) in cases {
                let params = vec![
                    Param::new("@stmt", u.clone(), Some(Value::Unicode("SELECT @p".into()))),
                    Param::new(
                        "@params",
                        u.clone(),
                        Some(Value::Unicode(format!("@p {declaration}").as_str().into())),
                    ),
                    Param::new("@p", ty, Some(value.clone())),
                ];
                let fetched = channel
                    .exchange(Call::new(Builtin::SpExecuteSql, params))
                    .await
                    .unwrap()
                    .fetch()
                    .await
                    .unwrap();
                assert_eq!(
                    fetched.result_sets()[0].rows().unwrap()[0][0],
                    Some(value),
                    "{declaration}"
                );
            }
            connection.close().await.unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn batched_sources_preserve_offsets_returns_and_cleanup_after_late_production_error() {
    use tds_client::{Call, Param, SqlType, StreamedCall, StreamedCalls};
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            channel.exchange(Batch::new("CREATE PROCEDURE #streamed_batch @b varbinary(max) AS BEGIN SELECT DATALENGTH(@b) AS n; RETURN 17; END")).await.unwrap().finish().await.unwrap();
            let call = |n: usize| {
                StreamedCall::new(Call::new(
                    "#streamed_batch",
                    vec![Param::new("@b", SqlType::BinaryMax, None)],
                ))
                .source(0, pieces(vec![Chunk::Binary(vec![7; n])]))
            };
            let fetched = channel
                .exchange(StreamedCalls(vec![call(1500000), call(1700000)]))
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(
                fetched
                    .returns()
                    .iter()
                    .map(|r| r.status)
                    .collect::<Vec<_>>(),
                [Some(17), Some(17)]
            );
            assert_eq!(
                fetched.result_sets()[0].rows().unwrap()[0][0],
                Some(Value::Integer(1500000))
            );
            assert_eq!(
                fetched.result_sets()[1].rows().unwrap()[0][0],
                Some(Value::Integer(1700000))
            );
            let bad = StreamedCall::new(Call::new(
                "#streamed_batch",
                vec![Param::new("@b", SqlType::BinaryMax, None)],
            ))
            .source(
                0,
                Pieces(
                    [
                        Ok(Chunk::Binary(vec![1; 100000])),
                        Err(std::io::Error::other("later source failed")),
                    ]
                    .into(),
                ),
            );
            let error = match channel
                .exchange(StreamedCalls(vec![call(100000), bad]))
                .await
            {
                Ok(_) => panic!(),
                Err(e) => e,
            };
            assert!(
                matches!(error.cause().kind, tds_client::ErrorKind::Io(_)),
                "{error:?}"
            );
            assert!(error.response.unwrap().ended);
            channel
                .exchange(Batch::new("SELECT 42"))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            connection.close().await.unwrap();
        }
    }
}
