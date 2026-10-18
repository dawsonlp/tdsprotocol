//! The actual Rust producer/TVP conversation, replayed by the public reader.
#![cfg(feature = "tokio")]
mod support;
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};
use tds_client::{
    Batch, Call, Connection, IntegerSize, Param, ProtocolVersion, SqlType, StreamedCall,
    TableColumn, TableType, Value,
    capture::Capture,
    replay::{self, Content, Message},
    requests::{ParamValue, decode},
};
#[derive(Clone, Default)]
struct Output(Arc<Mutex<Vec<u8>>>);
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
async fn batch(
    ch: &mut tds_client::SerialChannel,
    sql: impl Into<String>,
) -> tds_client::Result<()> {
    ch.exchange(Batch::new(sql)).await?.finish().await
}
#[tokio::test]
#[ignore = "requires Docker SQL Server and test CA"]
async fn real_owned_and_produced_tables_replay_with_exact_inputs_outputs_and_channel_identity() {
    for version in [ProtocolVersion::V7_4, ProtocolVersion::V8_0] {
        for mars in [false, true] {
            let mut options = support::docker_options();
            options.version = version;
            options.mars = mars;
            let output = Output::default();
            let captured = output.clone();
            options.capture_factory = Some(Arc::new(move || Ok(Capture::new(captured.clone()))));
            let connection = Connection::connect(options.clone()).await.unwrap();
            let mut channel = connection.serial_channel().await.unwrap();
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let name = format!("tds_replay_{}_{stamp}", std::process::id());
            let integer = SqlType::Integer {
                size: IntegerSize::Int,
            };
            let outcome=async{
            batch(&mut channel,format!("CREATE TYPE dbo.[{name}] AS TABLE(id int IDENTITY,a int,b nvarchar(max),c AS(a*2))")).await?;
            batch(&mut channel,format!("CREATE PROCEDURE dbo.[{name}_p] @t dbo.[{name}] READONLY,@out int OUTPUT AS SELECT a,b FROM @t ORDER BY a; SET @out=42; RETURN 17")).await?;
            let collation=tds_client::Collation(connection.session().await?.collation.try_into().unwrap());
            let mut table=TableType::new("dbo",name.as_str(),vec![TableColumn::default_value(integer.clone()),integer.clone().into(),SqlType::CharacterMax{unicode:true,collation}.into(),TableColumn::default_value(integer.clone())]);
            table.send_order=vec![4,3,2,1];
            let rows=vec![vec![Some(Value::Integer(7)),Some(Value::Unicode("é🦀".repeat(10000).as_str().into()))],vec![Some(Value::Integer(9)),None]];
            for produced in [false,true]{
                let call=Call::new(format!("dbo.{name}_p"),vec![Param::table("@t",table.clone(),(!produced).then(||rows.clone())),Param::new("@out",integer.clone(),Some(Value::Integer(0))).output()]);
                let result=if produced{channel.exchange(StreamedCall::new(call).table_source(0,rows.clone().into_iter())).await?.fetch().await?}else{channel.exchange(call).await?.fetch().await?};
                assert_eq!(result.result_sets()[0].rows().unwrap(),rows);
            }
            Ok::<_,tds_client::Error>(rows)
        }.await;
            connection.close().await.unwrap();
            // Cleanup uses an independent connection even if the recorded one fails.
            options.capture_factory = None;
            let cleanup = Connection::connect(options).await.unwrap();
            let mut ch = cleanup.serial_channel().await.unwrap();
            batch(
                &mut ch,
                format!(
                    "DROP PROCEDURE IF EXISTS dbo.[{name}_p]; DROP TYPE IF EXISTS dbo.[{name}]"
                ),
            )
            .await
            .unwrap();
            cleanup.close().await.unwrap();
            let rows = outcome.unwrap();
            let bytes = output.0.lock().unwrap().clone();
            let mut table_calls = 0;
            let mut returns = 0;
            let summary = replay::replay(bytes.as_slice(), |item| {
                match item.content {
                    Content::Diagnostic { description, .. } => {
                        panic!("replay diagnostic: {description}")
                    }
                    Content::Message(Message::Request(decode::Request::Rpc { calls, .. })) => {
                        for call in calls {
                            for parameter in call.parameters {
                                if let ParamValue::Table(Some(actual)) = parameter.value {
                                    assert_eq!(actual, rows);
                                    table_calls += 1;
                                }
                            }
                        }
                    }
                    Content::Record(record) => {
                        if let tds_client::Record::OutputValue(value) = record.as_ref() {
                            assert_eq!(value.value, Some(Value::Integer(42)));
                            returns += 1;
                        }
                    }
                    _ => {}
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(summary.issues, 0);
            assert_eq!(table_calls, 2);
            assert_eq!(returns, 2);
        }
    }
}
