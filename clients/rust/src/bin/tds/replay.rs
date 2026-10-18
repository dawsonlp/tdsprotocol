//! CLI presentation only; the public offline reader owns decoding.
use std::{
    fs::File,
    io::{self, BufReader, Write},
    path::Path,
};
use tds_client::{
    observe::Level,
    replay::{self, Content, Message},
};

pub(super) fn run(path: &Path, level: Level) -> super::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let summary = replay::replay(BufReader::new(File::open(path)?), |item| {
        let label = format!(
            "{:>8.3}s line {} {:?} channel {:?}",
            item.time, item.line, item.direction, item.channel
        );
        if let Content::Diagnostic {
            issue,
            offset,
            description,
        } = &item.content
        {
            writeln!(output, "{label} {issue:?} at {offset:?}: {description}")?;
            return Ok(());
        }
        if level == Level::Off {
            return Ok(());
        }
        if level == Level::Full {
            return writeln!(output, "{label} {:#?}", item.content);
        }
        match &item.content {
            Content::Start(start) => writeln!(output, "{label} recording start {start}"),
            Content::Event { kind, text, took } => writeln!(
                output,
                "{label} recorded {kind}: {}{}",
                text.to_string()
                    .unwrap_or_else(|_| format!("UTF-16 {:?}", text.0)),
                took.as_ref().map_or(String::new(), |v| format!(" · {v}"))
            ),
            Content::Packet { .. } => Ok(()),
            Content::Message(message) => match message {
                Message::Request(tds_client::requests::decode::Request::Batch { sql, .. }) => {
                    writeln!(
                        output,
                        "{label} decoded SQL batch: {} UTF-16 units",
                        sql.0.len()
                    )
                }
                Message::Request(tds_client::requests::decode::Request::Rpc { calls, .. }) => {
                    for call in calls {
                        writeln!(
                            output,
                            "{label} decoded RPC {:?}: {} parameters",
                            call.procedure,
                            call.parameters.len()
                        )?;
                    }
                    Ok(())
                }
                Message::RequestBulk(records) => {
                    writeln!(output, "{label} decoded bulk: {} records", records.len())
                }
                _ => writeln!(output, "{label} decoded {message:?}"),
            },
            Content::Record(record) => match record.as_ref() {
                tds_client::Record::ValueChunk(chunk) => writeln!(
                    output,
                    "{label} decoded value chunk: {} payload bytes",
                    chunk.byte_len()
                ),
                tds_client::Record::Row(row) => {
                    writeln!(output, "{label} decoded row: {} columns", row.len())
                }
                tds_client::Record::OutputValue(value) => writeln!(
                    output,
                    "{label} decoded output {:?}: {:?}",
                    value.name, value.type_info.sql_type
                ),
                tds_client::Record::Cell(_) => writeln!(output, "{label} decoded cell"),
                _ => writeln!(output, "{label} decoded {record:?}"),
            },
            Content::Diagnostic { .. } => unreachable!(),
        }
    })?;
    writeln!(
        output,
        "Replay: {} packets, {} messages, {} response records, {} issues. End of recording does not prove session closure.",
        summary.packets, summary.messages, summary.records, summary.issues
    )?;
    if summary.issues != 0 {
        return Err("recording has replay issues; valid prefix is shown above".into());
    }
    Ok(())
}
