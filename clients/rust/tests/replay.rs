//! Independent Python bodies plus damaged/interleaved recording evidence.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value as Json, json};
use tds_client::{
    Record, Request, Value, packet,
    replay::{self, Content, Direction, Issue, Message},
    requests::{Context, ParamValue, decode},
};
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn packets(direction: &str, channel: Option<u64>, kind: u8, body: &[u8], size: usize) -> Vec<Json> {
    packet::split(kind,body,size).unwrap().chunks(size).map(|bytes|json!({"t":1,"packet":direction,"channel":channel,"bytes":STANDARD.encode(bytes)})).collect()
}
fn read(lines: &[Json]) -> (replay::Summary, Vec<replay::Item>) {
    let text = lines
        .iter()
        .map(Json::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let mut items = vec![];
    let summary = replay::replay(text.as_bytes(), |item| {
        items.push(item);
        Ok(())
    })
    .unwrap();
    (summary, items)
}
fn done(status: u16) -> Vec<u8> {
    let mut b = vec![0xfd];
    b.extend(status.to_le_bytes());
    b.extend([0; 10]);
    b
}

#[test]
fn python_safe_login_evidence_preserves_negotiation_without_authentication_bytes() {
    let login = tds_client::login7::Login {
        integrated_security: true,
        sspi: tds_client::auth::Token::new(vec![1]).unwrap(),
        ..Default::default()
    }
    .encode()
    .unwrap();
    let mut safe = vec![0xed, 1, 0, 0, 0xae, 10, 1, 0, 0, 0, 0, 0xff];
    safe.extend(done(0));
    let mut lines = packets("send", None, packet::LOGIN, &login, 4096);
    lines.extend(packets(
        "receive",
        None,
        packet::REPLY,
        &vec![0; safe.len()],
        17,
    ));
    lines.push(json!({"t":2,"event":"receive","text":"← login reply",
        "safe_login_tokens":STANDARD.encode(&safe)}));
    let (summary, items) = read(&lines);
    assert_eq!(summary.records, 3);
    assert!(items.iter().any(|item| matches!(&item.content,
        Content::Record(record) if matches!(record.as_ref(), Record::FeatureAck(features)
            if features == &vec![(10,vec![0])]))));
    assert!(items.iter().any(|item| matches!(&item.content,
        Content::Diagnostic{issue:Issue::Incomplete,description,..} if description.contains("redacted"))));
    assert!(!items.iter().any(|item| matches!(
        &item.content,
        Content::Diagnostic {
            issue: Issue::Malformed,
            ..
        }
    )));
}

#[test]
fn integrated_security_recordings_withhold_tokens_and_explain_redacted_replies() {
    let login = tds_client::login7::Login {
        integrated_security: true,
        sspi: tds_client::auth::Token::new(b"initial-secret-token".to_vec()).unwrap(),
        ..Default::default()
    }
    .encode()
    .unwrap();
    let mut lines = packets("send", None, packet::LOGIN, &login, 4096);
    let mut challenge = vec![0xed, 19, 0];
    challenge.extend(b"server-secret-token");
    lines.extend(packets("receive", None, packet::REPLY, &challenge, 4096));
    lines.extend(packets(
        "send",
        None,
        packet::SSPI,
        b"client-secret-token",
        4096,
    ));
    let mut ack = vec![0xad, 10, 0, 1];
    ack.extend(0x74000004_u32.to_be_bytes());
    ack.extend([0, 16, 0, 0, 1]);
    ack.extend(done(0));
    lines.extend(packets("receive", None, packet::REPLY, &ack, 4096));
    let (_, items) = read(&lines);
    assert!(
        items
            .iter()
            .filter_map(|i| match &i.content {
                Content::Packet { body, .. } => Some(body),
                _ => None,
            })
            .all(Option::is_none)
    );
    for item in &items {
        if let Content::Record(record) = &item.content
            && let Record::Sspi(token) = record.as_ref()
        {
            assert!(token.as_bytes().iter().all(|b| *b == 0));
        }
    }
    let mut redacted = packets("send", None, packet::LOGIN, &login, 4096);
    redacted.extend(packets("receive", None, packet::REPLY, &[0; 80], 4096));
    let (_, items) = read(&redacted);
    assert!(items.iter().any(|i| matches!(&i.content,Content::Diagnostic{issue:Issue::Incomplete,description,..} if description.contains("redacted"))));
    assert!(!items.iter().any(|i| matches!(
        &i.content,
        Content::Diagnostic {
            issue: Issue::Malformed,
            ..
        }
    )));
}
#[test]
fn omitted_metadata_is_missing_evidence_instead_of_malformed_wire() {
    let mut body = vec![0x81, 0xff, 0xff];
    body.extend(done(0));
    let (_, items) = read(&packets("receive", Some(3), packet::REPLY, &body, 4096));
    assert!(items.iter().any(|item| matches!(&item.content, Content::Diagnostic { issue: Issue::Incomplete, description, .. } if description.contains("NO_METADATA"))));
    assert!(!items.iter().any(|item| matches!(
        &item.content,
        Content::Diagnostic {
            issue: Issue::Malformed,
            ..
        }
    )));
    assert!(
        !items
            .iter()
            .any(|item| matches!(&item.content, Content::Record(_)))
    );
}
fn call(parameter: &[u8]) -> Vec<u8> {
    let mut b = tds_client::Batch::new("")
        .encode_request(&Context {
            column_encryption: false,
            enclaves: false,
            transaction: 0,
            outstanding: 1,
        })
        .unwrap()
        .body;
    b.extend([1, 0, b'p', 0, 0, 0, 0, 0]); // name p, flags, positional name, status
    b.extend(parameter);
    b
}
#[test]
fn python_rpc_and_transaction_bodies_decode_with_exact_flags_and_values() {
    let cases: Json = serde_json::from_str(include_str!("fixtures/rpc/python.json")).unwrap();
    for (index, case) in cases.as_array().unwrap().iter().enumerate() {
        let decode::Request::Rpc { headers, calls } =
            decode::request(packet::RPC, &unhex(case.as_str().unwrap())).unwrap()
        else {
            panic!()
        };
        assert_eq!(headers[0].kind, 2);
        if index == 0 {
            assert_eq!(calls[0].options, 5);
            assert_eq!(calls[0].parameters[0].status, 1);
            assert_eq!(
                calls[0].parameters[0].value,
                ParamValue::Scalar(Some(Value::Integer(42)))
            );
            assert_eq!(calls[0].parameters[2].status, 2);
        }
        if index == 1 {
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].procedure, decode::Procedure::Number(10));
        }
        if index == 2 {
            assert_eq!(calls[0].options, 2);
        }
    }
    let cases: Json =
        serde_json::from_str(include_str!("fixtures/transactions/python.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let body = unhex(case["body"].as_str().unwrap());
        let decode::Request::Transaction { operation, .. } =
            decode::request(packet::TRANSACTION, &body).unwrap()
        else {
            panic!()
        };
        let encoded = operation
            .encode_request(&Context {
                column_encryption: false,
                enclaves: false,
                transaction: case["transaction"].as_u64().unwrap(),
                outstanding: case["outstanding"].as_u64().unwrap() as u32,
            })
            .unwrap();
        assert_eq!(encoded.body, body);
    }
}
#[test]
fn python_large_input_layouts_and_table_rows_are_read_without_result_framing() {
    let cases: Json = serde_json::from_str(include_str!("fixtures/large/python.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let body = call(&unhex(case["parameter"].as_str().unwrap()));
        let decode::Request::Rpc { calls, .. } = decode::request(packet::RPC, &body).unwrap()
        else {
            panic!()
        };
        let ParamValue::Scalar(value) = &calls[0].parameters[0].value else {
            panic!()
        };
        let raw = match value {
            None => None,
            Some(Value::Unicode(v)) => {
                Some(v.0.iter().flat_map(|u| u.to_le_bytes()).collect::<Vec<_>>())
            }
            Some(Value::Text(v)) => Some(v.bytes.clone()),
            Some(Value::Binary(v)) => Some(v.clone()),
            _ => panic!(),
        };
        assert_eq!(raw, case["raw"].as_str().map(unhex), "{}", case["name"]);
    }
    let cases: Json = serde_json::from_str(include_str!("fixtures/tables/python.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let body = unhex(case["body"].as_str().unwrap());
        let decode::Request::Rpc { calls, .. } = decode::request(packet::RPC, &body).unwrap()
        else {
            panic!()
        };
        let parameter = &calls[0].parameters[0];
        let ParamValue::Table(rows) = &parameter.value else {
            panic!()
        };
        assert_eq!(
            rows.as_ref().map(|r| r.len() as u64),
            case["count"].as_u64()
        );
        assert_eq!(
            parameter.status & 2 != 0,
            case["default"].as_bool().unwrap()
        );
        if let Some(rows) = rows
            && !rows.is_empty()
        {
            assert_eq!(rows[0][0], Some(Value::Integer(7)));
            assert_eq!(
                rows[0][1],
                Some(Value::Unicode(tds_client::SqlText(vec![
                    0xe9, 0xd83e, 0xdd80, 0xd800
                ])))
            );
        }
        if case["hints"] == true && rows.is_some() {
            let tds_client::SqlType::Table(t) = &parameter.type_info.sql_type else {
                panic!()
            };
            assert_eq!(t.send_order, vec![3, 2, 1]);
            assert_eq!(t.unique, vec![2]);
            assert!(t.columns[0].server_default);
        }
        // Every truncated input body must be refused, never silently shortened.
        for end in body.iter().position(|b| *b == 0xf3).unwrap() + 1..body.len() {
            assert!(
                decode::request(packet::RPC, &body[..end]).is_err(),
                "accepted prefix {end}"
            );
        }
    }
}
#[test]
fn interleaved_logical_channels_wait_for_real_attention_ack_and_keep_recorded_events() {
    let batch = tds_client::Batch::new("SELECT 1")
        .encode_request(&Context {
            column_encryption: false,
            enclaves: false,
            transaction: 0,
            outstanding: 1,
        })
        .unwrap()
        .body;
    let mut lines = packets("send", Some(70000), packet::BATCH, &batch, 13);
    lines.extend(packets("send", Some(90000), packet::BATCH, &batch, 13));
    lines.extend(packets("send", Some(70000), packet::ATTENTION, &[], 13));
    lines.extend(packets("receive", Some(70000), packet::REPLY, &done(0), 13));
    lines.push(
        json!({"t":0.5,"event":"receive","text":"arbitrary recorded wording","took":{"wire":0.1}}),
    );
    lines.extend(packets("receive", Some(90000), packet::REPLY, &done(0), 13));
    let (summary, items) = read(&lines);
    assert_eq!(summary.issues, 1);
    assert!(items.iter().any(|i| i.channel == Some(70000)
        && matches!(
            i.content,
            Content::Diagnostic {
                issue: Issue::Incomplete,
                ..
            }
        )));
    assert!(items.iter().any(|i|i.time==0.5&&matches!(&i.content,Content::Event{text,took,..} if text.to_string().unwrap()=="arbitrary recorded wording"&&took.is_some())));
    lines.extend(packets(
        "receive",
        Some(70000),
        packet::REPLY,
        &done(0x20),
        13,
    ));
    assert_eq!(read(&lines).0.issues, 0);
}
#[test]
fn feature_context_is_shared_but_metadata_readers_are_per_channel() {
    for utf8 in [false, true] {
        for classification in [1, 2] {
            let mut features = vec![
                0xae,
                10,
                1,
                0,
                0,
                0,
                u8::from(utf8),
                9,
                2,
                0,
                0,
                0,
                classification,
                1,
                0xff,
            ];
            features.extend(done(0));
            let mut lines = packets("receive", None, packet::REPLY, &features, 13);
            let text = "é🦀";
            let data = if utf8 {
                text.as_bytes().to_vec()
            } else {
                text.encode_utf16().flat_map(u16::to_le_bytes).collect()
            };
            let mut plp = (data.len() as u64).to_le_bytes().to_vec();
            plp.extend((data.len() as u32).to_le_bytes());
            plp.extend(data);
            plp.extend([0; 4]);
            let mut response = vec![0x81, 1, 0, 0, 0, 0, 0, 0, 0, 0xf4, 0, 0xd1];
            response.extend(plp);
            response.extend(done(0));
            lines.extend(packets("receive", Some(17), packet::REPLY, &response, 13));
            let (summary, items) = read(&lines);
            assert_eq!(summary.issues, 0, "{items:#?}");
            let units = items
                .iter()
                .filter_map(|i| match &i.content {
                    Content::Record(r) => match r.as_ref() {
                        Record::ValueChunk(tds_client::Chunk::Unicode(v)) => Some(v.0.clone()),
                        _ => None,
                    },
                    _ => None,
                })
                .flatten()
                .collect::<Vec<_>>();
            assert_eq!(units, text.encode_utf16().collect::<Vec<_>>());
        }
    }
}
#[test]
fn malformed_recordings_preserve_prefix_and_never_echo_json_or_credentials() {
    let login = tds_client::login7::Login {
        password: "do not expose me".into(),
        new_password: "replacement secret".into(),
        ..Default::default()
    }
    .encode()
    .unwrap();
    for size in [9, 31, 4096] {
        let mut lines = packets("send", None, packet::LOGIN, &login, size);
        lines.extend(packets("receive", None, packet::REPLY, &done(0), 4096));
        let (summary, items) = read(&lines);
        assert_eq!(summary.issues, 0);
        assert!(
            items
                .iter()
                .filter(|i| i.direction == Some(Direction::Send))
                .all(|i| !matches!(&i.content, Content::Packet { body: Some(_), .. }))
        );
        assert!(
            items
                .iter()
                .any(|i| matches!(i.content, Content::Message(Message::Login(_))))
        );
        let shown = format!("{items:?}");
        assert!(!shown.contains("do not expose me") && !shown.contains("replacement secret"));
    }
    let mut items = vec![];
    let text = "{\"t\":0,\"event\":\"x\",\"text\":\"prefix\"}\n{secret-invalid-json";
    let summary = replay::replay(text.as_bytes(), |i| {
        items.push(i);
        Ok(())
    })
    .unwrap();
    assert_eq!(summary.issues, 1);
    assert_eq!(items[0].line, 1);
    assert_eq!(items[1].line, 2);
    assert!(!format!("{items:?}").contains("secret-invalid-json"));
    let mut lines = packets(
        "receive",
        Some(9),
        packet::REPLY,
        &[0x79, 42, 0, 0, 0, 0x99],
        4096,
    );
    lines.extend(packets("receive", Some(9), packet::REPLY, &done(0), 4096));
    let (summary, items) = read(&lines);
    assert!(summary.issues > 0);
    assert!(items.iter().any(|i| matches!(
        i.content,
        Content::Diagnostic {
            issue: Issue::Unsupported,
            offset: Some(5),
            ..
        }
    )));
    assert!(
        items.iter().any(
            |i| matches!(&i.content,Content::Record(r) if r.as_ref()==&Record::ReturnStatus(42))
        )
    );
    assert!(
        !items.iter().any(
            |i| matches!(&i.content,Content::Record(r) if matches!(r.as_ref(),Record::Done(_)))
        )
    );
}
#[test]
fn truncated_packets_messages_values_and_unknown_formats_have_distinct_diagnostics() {
    let mut invalid = vec![];
    let summary = replay::replay(&b"\xff\n"[..], |item| {
        invalid.push(item);
        Ok(())
    })
    .unwrap();
    assert_eq!(summary.issues, 1);
    assert!(matches!(
        invalid[0].content,
        Content::Diagnostic {
            issue: Issue::Malformed,
            offset: Some(0),
            ..
        }
    ));
    let mut lines = packets("receive", None, packet::REPLY, &done(0), 9);
    lines.pop();
    assert!(read(&lines).1.iter().any(|i| matches!(
        i.content,
        Content::Diagnostic {
            issue: Issue::Incomplete,
            ..
        }
    )));
    let lines = packets("receive", None, packet::REPLY, &[0x79, 1], 4096);
    assert!(read(&lines).0.issues > 0);
    for value in [
        json!({"t":0,"packet":"receive","channel":null,"bytes":"!"}),
        json!({"t":0,"packet":"send","channel":-1,"bytes":""}),
        json!({"t":0,"unknown":true}),
    ] {
        assert_eq!(read(&[value]).0.issues, 1);
    }
    let output = replay::replay("{\"t\":0,\"start\":\"a\"}\n".as_bytes(), |_| {
        Err(std::io::Error::other("output failed"))
    });
    assert!(output.is_err());
}
#[test]
fn sql_bytes_are_decoded_without_using_recorded_human_text() {
    let mut lines = vec![json!({"t":0,"event":"send","text":"unrelated label"})];
    let body = tds_client::Batch::new("SELECT N'é🦀'")
        .encode_request(&Context {
            column_encryption: false,
            enclaves: false,
            transaction: 0,
            outstanding: 1,
        })
        .unwrap()
        .body;
    lines.extend(packets("send", Some(42), packet::BATCH, &body, 9));
    lines.extend(packets("receive", Some(42), packet::REPLY, &done(0), 9));
    let (summary, items) = read(&lines);
    assert_eq!(summary.issues, 0);
    assert!(items.iter().any(|i|i.direction==Some(Direction::Send)&&matches!(&i.content,Content::Message(Message::Request(decode::Request::Batch{sql,..})) if sql.to_string().unwrap()=="SELECT N'é🦀'")));
}

#[test]
fn python_event_text_preserves_lone_surrogates_pairs_and_literal_escape_sequences() {
    let source = r#"{"t":0,"event":"token","text":"\ud800 \udc00 🦀 \\ud800","took":"0.1s"}"#;
    let mut items = vec![];
    let summary = replay::replay(source.as_bytes(), |i| {
        items.push(i);
        Ok(())
    })
    .unwrap();
    assert_eq!(summary.issues, 1); // No packet evidence was supplied.
    let Content::Event { text, .. } = &items[0].content else {
        panic!()
    };
    let mut expected = vec![0xd800, 32, 0xdc00, 32, 0xd83e, 0xdd80, 32];
    expected.extend("\\ud800".encode_utf16());
    assert_eq!(text.0, expected);
}

#[test]
fn invalid_or_duplicate_negotiation_retires_later_decoding_instead_of_guessing() {
    for features in [
        vec![0xae, 10, 1, 0, 0, 0, 2, 0xff],
        vec![0xae, 10, 1, 0, 0, 0, 1, 10, 1, 0, 0, 0, 1, 0xff],
    ] {
        let mut lines = packets("receive", None, packet::REPLY, &features, 13);
        lines.extend(packets("receive", Some(1), packet::REPLY, &done(0), 13));
        let (summary, items) = read(&lines);
        assert!(summary.issues > 0);
        assert!(!items.iter().any(|i| i.channel == Some(1)
            && matches!(&i.content,Content::Record(r) if matches!(r.as_ref(),Record::Done(_)))));
    }
    let mut body = vec![0x79, 42, 0, 0, 0];
    body.extend(done(0));
    body.push(0x79);
    body.extend(9_i32.to_le_bytes());
    let (_, items) = read(&packets("receive", Some(1), packet::REPLY, &body, 10));
    assert!(items.iter().any(|i| matches!(
        i.content,
        Content::Diagnostic {
            issue: Issue::Malformed,
            offset: Some(18),
            ..
        }
    )));
}
