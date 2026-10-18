#![cfg(feature = "tokio")]
mod support;
use tds_client::{
    Batch, Builtin, Call, Collation, Connection, Param, ProtocolVersion, SqlType, Value,
};
async fn fetch(channel: &mut tds_client::SerialChannel, sql: &str) -> tds_client::FetchedResponse {
    channel
        .exchange(Batch::new(sql))
        .await
        .unwrap()
        .fetch()
        .await
        .unwrap()
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn explicit_collation_views_match_the_server_across_all_supported_pages() {
    let samples = [
        (437, "café"),
        (850, "café"),
        (874, "ไทย"),
        (932, "日本語"),
        (936, "中文"),
        (949, "한글"),
        (950, "中文"),
        (1250, "Łódź"),
        (1251, "Привет"),
        (1252, "café"),
        (1253, "Ελλάδα"),
        (1254, "İstanbul"),
        (1255, "שלום"),
        (1256, "العربية"),
        (1257, "Rīga"),
        (1258, "Viêt"),
        (65001, "🦀café日本"),
    ];
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            for (page, sample) in samples {
                let selected = fetch(&mut channel, &format!("SELECT TOP(1) name FROM sys.fn_helpcollations() WHERE CONVERT(int,COLLATIONPROPERTY(name,'CodePage'))={page} ORDER BY name")).await;
                let Some(Value::Unicode(name)) = &selected.result_sets()[0].rows().unwrap()[0][0]
                else {
                    panic!()
                };
                let name = name.to_string().unwrap();
                assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
                let returned = fetch(&mut channel, &format!("SELECT CAST(N'{sample}' COLLATE {name} AS varchar(200)),CAST(N'{sample}' COLLATE {name} AS varchar(max))")).await;
                for value in &returned.result_sets()[0].rows().unwrap()[0] {
                    let Some(Value::Text(raw)) = value else {
                        panic!("page {page}: {value:?}")
                    };
                    assert_eq!(raw.collation.code_page().unwrap(), page);
                    assert_eq!(raw.decode().unwrap(), sample.into(), "{name}");
                    let encoded = raw.collation.encode(&sample.into()).unwrap();
                    assert_eq!(raw.bytes, encoded, "{name}");
                    // Decode only application-owned chunks, never advance the
                    // parent response through this pure character view.
                    let mut decoder = raw.collation.decoder().unwrap();
                    let mut units = Vec::new();
                    for byte in &raw.bytes {
                        units.extend(decoder.decode(&[*byte], false).0);
                    }
                    units.extend(decoder.decode(&[], true).0);
                    assert_eq!(units, sample.encode_utf16().collect::<Vec<_>>());
                }
            }
            connection.close().await.unwrap();
        }
    }
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn native_json_rows_outputs_and_sources_follow_negotiated_result_encoding() {
    use std::collections::VecDeque;
    use tds_client::{Chunk, Source, SourceRead, StreamedCall};
    struct Pieces(VecDeque<Chunk>);
    impl Source for Pieces {
        fn next_chunk(&mut self) -> SourceRead<'_> {
            Box::pin(async { Ok(self.0.pop_front()) })
        }
    }
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            for utf8 in [false, true] {
                let mut options = support::docker_options();
                options.version = version;
                options.mars = mars;
                options.utf8_support = utf8;
                let connection = Connection::connect(options.clone()).await.unwrap();
                assert_eq!(connection.session().await.unwrap().features[&13], vec![1]);
                let mut channel = connection.serial_channel().await.unwrap();
                let text = SqlType::CharacterMax {
                    unicode: true,
                    collation: Collation(
                        connection
                            .session()
                            .await
                            .unwrap()
                            .collation
                            .try_into()
                            .unwrap(),
                    ),
                };
                let original = r#"{"note":"é🦀","n":42}"#;
                let call = Call::new(
                    Builtin::SpExecuteSql,
                    vec![
                        Param::new(
                            "@stmt",
                            text.clone(),
                            Some(Value::Unicode(
                                "SELECT @j AS j,CAST(NULL AS json) AS n".into(),
                            )),
                        ),
                        Param::new(
                            "@params",
                            text.clone(),
                            Some(Value::Unicode("@j json OUTPUT".into())),
                        ),
                        Param::new("@j", SqlType::Json, Some(Value::Unicode(original.into())))
                            .output(),
                    ],
                );
                let result = channel.exchange(call).await.unwrap().fetch().await.unwrap();
                assert_eq!(
                    result.result_sets()[0].rows().unwrap()[0],
                    vec![Some(Value::Unicode(original.into())), None]
                );
                assert_eq!(result.result_sets()[0].columns[0].type_info.json_utf8, utf8);
                let output = result.returns()[0].output_named(&"@j".into()).unwrap();
                assert_eq!(output.value, Some(Value::Unicode(original.into())));
                assert_eq!(output.type_info.json_utf8, utf8);
                let call = Call::new(
                    Builtin::SpExecuteSql,
                    vec![
                        Param::new(
                            "@stmt",
                            text.clone(),
                            Some(Value::Unicode("SELECT @j".into())),
                        ),
                        Param::new("@params", text, Some(Value::Unicode("@j json".into()))),
                        Param::new("@j", SqlType::Json, None),
                    ],
                );
                let note = "é🦀".repeat(100000);
                let request = StreamedCall::new(call).source(
                    2,
                    Pieces(VecDeque::from([
                        Chunk::Unicode("{\"note\":\"".into()),
                        Chunk::Unicode(note.as_str().into()),
                        Chunk::Unicode("\"}".into()),
                    ])),
                );
                let mut response = channel.exchange(request).await.unwrap();
                let mut received = Vec::new();
                {
                    let mut set = response.next_result_set().await.unwrap().unwrap();
                    let mut row = set.streamed_row().await.unwrap().unwrap();
                    let Some(tds_client::Cell::Stream(mut value)) = row.next_value().await.unwrap()
                    else {
                        panic!()
                    };
                    while let Some(chunk) = value.next_chunk().await.unwrap() {
                        let Chunk::Unicode(text) = chunk else {
                            panic!()
                        };
                        // No UTF-8 fragment or UTF-16 surrogate pair leaks through
                        // the logical text-chunk boundary.
                        assert!(text.to_string().is_ok());
                        received.extend(text.0);
                    }
                }
                response.finish().await.unwrap();
                assert_eq!(
                    String::from_utf16(&received).unwrap(),
                    format!("{{\"note\":\"{note}\"}}")
                );
                connection.close().await.unwrap();
                options.json_support = false;
                let connection = Connection::connect(options).await.unwrap();
                assert!(
                    !connection
                        .session()
                        .await
                        .unwrap()
                        .features
                        .contains_key(&13)
                );
                let mut channel = connection.serial_channel().await.unwrap();
                let fallback =
                    fetch(&mut channel, "SELECT CAST(N'{\"note\":\"é🦀\"}' AS json)").await;
                assert!(!matches!(
                    fallback.result_sets()[0].columns[0].type_info.sql_type,
                    SqlType::Json
                ));
                let text = match &fallback.result_sets()[0].rows().unwrap()[0][0] {
                    Some(Value::Unicode(text)) => text.clone(),
                    Some(Value::Text(raw)) => raw.decode().unwrap(),
                    other => panic!("unexpected JSON fallback: {other:?}"),
                };
                assert_eq!(text, "{\"note\":\"é🦀\"}".into());
                connection.close().await.unwrap();
            }
        }
    }
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn clr_named_serializations_round_trip_as_owned_bytes_and_sources() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            let original=fetch(&mut channel,"SELECT hierarchyid::Parse('/1/2/') AS h, geometry::Point(1,2,0).STBuffer(10) AS g, geography::Point(10,20,4326) AS p, CAST(NULL AS hierarchyid) AS nil").await;
            let set = &original.result_sets()[0];
            let row = &set.rows().unwrap()[0];
            assert!(set.columns.iter().all(|c| {
                matches!(c.type_info.sql_type, SqlType::Clr(_))
                    && c.type_info
                        .clr_assembly
                        .as_ref()
                        .is_some_and(|a| !a.0.is_empty())
            }));
            assert_eq!(row[3], None);
            let collation = Collation(
                connection
                    .session()
                    .await
                    .unwrap()
                    .collation
                    .try_into()
                    .unwrap(),
            );
            let text = SqlType::CharacterMax {
                unicode: true,
                collation,
            };
            let mut params = vec![
                Param::new(
                    "@stmt",
                    text.clone(),
                    Some(Value::Unicode("SELECT @h,@g,@p,@nil".into())),
                ),
                Param::new(
                    "@params",
                    text,
                    Some(Value::Unicode(
                        "@h hierarchyid,@g geometry,@p geography,@nil hierarchyid".into(),
                    )),
                ),
            ];
            for (index, name) in ["@h", "@g", "@p", "@nil"].iter().enumerate() {
                params.push(Param::new(
                    *name,
                    set.columns[index].type_info.sql_type.clone(),
                    row[index].clone(),
                ));
            }
            let kept = channel
                .exchange(Call::new(Builtin::SpExecuteSql, params.clone()))
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(kept.result_sets()[0].rows().unwrap(), set.rows().unwrap());
            struct Bytes(Option<Vec<u8>>);
            impl tds_client::Source for Bytes {
                fn next_chunk(&mut self) -> tds_client::SourceRead<'_> {
                    Box::pin(async { Ok(self.0.take().map(tds_client::Chunk::Binary)) })
                }
            }
            let Some(Value::Binary(bytes)) = params[3].value.take_scalar() else {
                panic!()
            };
            let source = tds_client::StreamedCall::new(Call::new(Builtin::SpExecuteSql, params))
                .source(3, Bytes(Some(bytes)));
            let kept = channel
                .exchange(source)
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(kept.result_sets()[0].rows().unwrap(), set.rows().unwrap());
            connection.close().await.unwrap();
        }
    }
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn sql_variants_round_trip_with_declared_base_types_and_nulls() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            let original=fetch(&mut channel,"SELECT CAST(CAST(-123 AS bigint) AS sql_variant),CAST(CAST(1.230 AS decimal(38,3)) AS sql_variant),CAST(N'🦀' AS sql_variant),CAST(0x00FF AS sql_variant),CAST(NULL AS sql_variant),CAST(CAST('2020-01-02T03:04:05.0000001' AS datetime2(7)) AS sql_variant)").await;
            let row = &original.result_sets()[0].rows().unwrap()[0];
            let collation = Collation(
                connection
                    .session()
                    .await
                    .unwrap()
                    .collation
                    .try_into()
                    .unwrap(),
            );
            let text = SqlType::CharacterMax {
                unicode: true,
                collation,
            };
            let mut params=vec![Param::new("@stmt",text.clone(),Some(Value::Unicode("SELECT @a,@b,@c,@d,@e,@f".into()))),Param::new("@params",text,Some(Value::Unicode("@a sql_variant,@b sql_variant,@c sql_variant,@d sql_variant,@e sql_variant,@f sql_variant".into())))];
            for (index, name) in ["@a", "@b", "@c", "@d", "@e", "@f"].iter().enumerate() {
                params.push(Param::new(*name, SqlType::Variant, row[index].clone()));
            }
            let kept = channel
                .exchange(Call::new(Builtin::SpExecuteSql, params))
                .await
                .unwrap()
                .fetch()
                .await
                .unwrap();
            assert_eq!(&kept.result_sets()[0].rows().unwrap()[0], row);
            connection.close().await.unwrap();
        }
    }
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn browse_metadata_preserves_base_tables_aliases_keys_and_hidden_columns() {
    let connection = Connection::connect(support::docker_options())
        .await
        .unwrap();
    let mut channel = connection.serial_channel().await.unwrap();
    fetch(
        &mut channel,
        "CREATE TABLE #browse(id int PRIMARY KEY,n nvarchar(20)); INSERT #browse VALUES(1,N'one')",
    )
    .await;
    let kept = fetch(
        &mut channel,
        "SELECT n AS label, 42 AS expression FROM #browse FOR BROWSE",
    )
    .await;
    let set = &kept.result_sets()[0];
    assert!(set.tables.as_ref().is_some_and(|ts| !ts.is_empty()));
    let info = set.column_info.as_ref().unwrap();
    assert!(
        info.iter()
            .any(|c| c.base_name.as_ref() == Some(&"n".into()))
    );
    assert!(info.iter().any(|c| c.status & 4 != 0));
    assert!(info.iter().any(|c| c.status & 0x10 != 0));
    assert_eq!(
        set.rows().unwrap()[0][0],
        Some(Value::Unicode("one".into()))
    );
    connection.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn native_vectors_use_negotiated_versions_and_preserve_exact_float_bits() {
    use tds_client::{SqlVector, VectorElement};
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let connection = Connection::connect(options.clone()).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            let features = connection.session().await.unwrap().features;
            assert!([1, 2].contains(&features[&14][0]));
            assert_eq!(features[&10], vec![1]);
            let original = fetch(
                &mut channel,
                "SELECT CAST(N'[1,2.5,3]' AS vector(3)),CAST(NULL AS vector(3))",
            )
            .await;
            let set = &original.result_sets()[0];
            let row = &set.rows().unwrap()[0];
            assert_eq!(
                set.columns[0].type_info.sql_type,
                SqlType::Vector {
                    dimensions: 3,
                    element: VectorElement::Float32
                }
            );
            assert!(
                matches!(&row[0],Some(Value::Vector(SqlVector::Float32(v))) if v[1].to_float()==2.5)
            );
            assert_eq!(row[1], None);
            let text = SqlType::CharacterMax {
                unicode: true,
                collation: Collation(
                    connection
                        .session()
                        .await
                        .unwrap()
                        .collation
                        .try_into()
                        .unwrap(),
                ),
            };
            let params = vec![
                Param::new(
                    "@stmt",
                    text.clone(),
                    Some(Value::Unicode("SELECT @v".into())),
                ),
                Param::new("@params", text, Some(Value::Unicode("@v vector(3)".into()))),
                Param::new(
                    "@v",
                    set.columns[0].type_info.sql_type.clone(),
                    row[0].clone(),
                ),
            ];
            assert_eq!(
                channel
                    .exchange(Call::new(Builtin::SpExecuteSql, params))
                    .await
                    .unwrap()
                    .fetch()
                    .await
                    .unwrap()
                    .result_sets()[0]
                    .rows()
                    .unwrap()[0][0],
                row[0]
            );
            let half = channel
                .exchange(Batch::new("SELECT CAST(N'[1,2.5]' AS vector(2,float16))"))
                .await
                .unwrap()
                .fetch()
                .await;
            if features[&14][0] < 2 {
                assert!(half.is_err());
            } else {
                assert!(matches!(
                    &half.unwrap().result_sets()[0].rows().unwrap()[0][0],
                    Some(Value::Vector(SqlVector::Float16(_)))
                ));
            }
            connection.close().await.unwrap();
            options.vector_support = 0;
            let connection = Connection::connect(options).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            let fallback = fetch(&mut channel, "SELECT CAST(N'[1,2.5,3]' AS vector(3))").await;
            assert!(
                !connection
                    .session()
                    .await
                    .unwrap()
                    .features
                    .contains_key(&14)
            );
            // Without native vector negotiation SQL Server returns JSON text.
            // Its declared character encoding follows UTF-8 negotiation, so do
            // not mistake a varchar fallback for a native vector or nvarchar.
            let text = match &fallback.result_sets()[0].rows().unwrap()[0][0] {
                Some(Value::Text(text)) => String::from_utf8(text.bytes.clone()).unwrap(),
                Some(Value::Unicode(text)) => text.to_string().unwrap(),
                other => panic!("unexpected vector fallback: {other:?}"),
            };
            assert!(text.starts_with('[') && text.ends_with(']'));
            assert!(text.contains("2.5"));
            connection.close().await.unwrap();
        }
    }
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn sensitivity_classification_retains_named_labels_and_negotiated_ranks() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let table = format!("tds_rust_class_{}_{stamp}", std::process::id());
    let options = support::docker_options();
    let admin = Connection::connect(options.clone()).await.unwrap();
    let mut setup = admin.serial_channel().await.unwrap();
    let outcome=async {
        setup.exchange(Batch::new(format!("CREATE TABLE dbo.[{table}](n int); INSERT dbo.[{table}] VALUES(42); ADD SENSITIVITY CLASSIFICATION TO dbo.[{table}].n WITH (LABEL='Private',LABEL_ID='label-id',INFORMATION_TYPE='Financial',INFORMATION_TYPE_ID='type-id',RANK=HIGH)"))).await?.finish().await?;
        for version in [ProtocolVersion::V7_4,ProtocolVersion::V8_0]{for mars in [false,true]{for class_version in [1,2]{
            let mut config=options.clone();config.version=version;config.mars=mars;config.data_classification=class_version;
            let connection=Connection::connect(config).await?;let mut channel=connection.serial_channel().await?;
            let result=channel.exchange(Batch::new(format!("SELECT n FROM dbo.[{table}]"))).await?.fetch().await?;
            let c=result.result_sets()[0].classification.as_ref().unwrap();assert_eq!(c.labels[0].name,"Private".into());
            assert_eq!(c.columns[0][0].information_type.as_ref().unwrap().name,"Financial".into());
            assert_eq!(c.rank.is_some(),class_version==2);connection.close().await?;
        }}}
        Ok::<_,tds_client::Error>(())
    }.await;
    admin.close().await.unwrap();
    let cleanup = Connection::connect(options).await.unwrap();
    fetch(
        &mut cleanup.serial_channel().await.unwrap(),
        &format!("DROP TABLE IF EXISTS dbo.[{table}]"),
    )
    .await;
    cleanup.close().await.unwrap();
    outcome.unwrap();
}
