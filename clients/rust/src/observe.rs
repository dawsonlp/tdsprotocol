//! Observation carries information, never protocol authority.
//!
//! The core queues owned descriptions; the shell invokes callbacks only after
//! the core step returns. Off allocates no descriptions. Outline and Full have
//! the same lines; Full additionally exposes packet bytes and decoded records.
//! Per-field inspection trees and their reference links are a later layer.

use crate::{Record, packet};
use std::{io, sync::Arc, time::Duration};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Level {
    #[default]
    Off,
    Outline,
    Full,
}

#[derive(Clone, Debug)]
pub enum Inspection {
    /// Exact header/body, except credential bytes are always zeroed here.
    Packet {
        header: [u8; 8],
        body: Vec<u8>,
    },
    Record(Record),
}

#[derive(Clone, Debug)]
pub struct Event {
    pub kind: &'static str,
    pub text: String,
    pub channel: Option<u64>,
    /// Monotonic time since this physical connection's observation began.
    pub elapsed: Duration,
    pub inspection: Option<Inspection>,
}

/// A short synchronous callback. It must not block or reenter the connection.
/// A returned error disables it; the error is inspectable on the connection.
/// Panics unwind the driver and safely discard its connection.
#[derive(Clone)]
pub struct Observer {
    pub level: Level,
    callback: Arc<Callback>,
}
type Callback = dyn Fn(&Event) -> io::Result<()> + Send + Sync;
impl Observer {
    pub fn new(
        level: Level,
        callback: impl Fn(&Event) -> io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self {
            level,
            callback: Arc::new(callback),
        }
    }
    pub fn emit(&self, event: &Event) -> io::Result<()> {
        (self.callback)(event)
    }
}

/// The core retains bytes only until the shell delivers the current step.
/// No callback, socket, task or clock is stored here.
#[derive(Default)]
pub(crate) struct Observations {
    pub level: Level,
    pub capture: bool,
    pub keep_password: bool,
    pending: Vec<Trace>,
    incoming: packet::Unpacker,
}
pub enum Trace {
    Event(Box<Event>),
    Packet {
        direction: &'static str,
        channel: Option<u64>,
        bytes: Vec<u8>,
    },
}
impl Observations {
    pub fn enabled(&self) -> bool {
        self.level != Level::Off || self.capture
    }
    pub fn event(
        &mut self,
        kind: &'static str,
        text: impl FnOnce() -> String,
        channel: Option<u64>,
        inspection: Option<Inspection>,
    ) {
        if self.enabled() {
            self.pending.push(Trace::Event(Box::new(Event {
                kind,
                text: text(),
                channel,
                elapsed: Duration::ZERO,
                inspection: if self.level == Level::Full {
                    inspection
                } else {
                    None
                },
            })));
        }
    }
    pub fn record(&mut self, channel: Option<u64>, record: &Record) {
        let inspection = (self.level == Level::Full).then(|| Inspection::Record(record.clone()));
        self.event(
            "token",
            || match record {
                Record::RowStart => "ROW · streamed".into(),
                Record::Cell(_) => "CELL".into(),
                Record::ValueStart { .. } => "VALUE · start".into(),
                Record::ValueChunk(chunk) => format!("VALUE · {} bytes", chunk.byte_len()),
                Record::ValueEnd => "VALUE · end".into(),
                Record::RowEnd => "ROW · end".into(),
                Record::Row(row) => format!("ROW · {} columns", row.len()),
                Record::Columns(columns) => format!("COLMETADATA · {} columns", columns.len()),
                Record::Done(done) => format!(
                    "{:?} completion · status {:#x} · rows {:?}",
                    done.kind, done.status, done.row_count
                ),
                Record::Error(message) => {
                    format!("ERROR · {} · severity {}", message.number, message.severity)
                }
                Record::Message(message) => format!("INFO · {}", message.number),
                Record::Environment(_) => "ENVCHANGE".into(),
                Record::LoginAck { .. } => "LOGINACK".into(),
                Record::Classification(_) => "DATACLASSIFICATION".into(),
                Record::Tables(_) => "TABNAME".into(),
                Record::ColumnInfo(_) => "COLINFO".into(),
                Record::Order(_) => "ORDER".into(),
                Record::FeatureAck(_) => "FEATUREEXTACK".into(),
                Record::SessionState(_) => "SESSIONSTATE".into(),
                Record::ReturnStatus(status) => format!("RETURNSTATUS · {status}"),
                Record::OutputValue(output) => {
                    format!("RETURNVALUE · parameter {}", output.ordinal)
                }
            },
            channel,
            inspection,
        );
    }
    pub fn message(&mut self, direction: &'static str, what: &str, channel: Option<u64>) {
        self.event(
            direction,
            || {
                format!(
                    "{} {what}{}",
                    if direction == "send" { "→" } else { "←" },
                    channel.map_or(String::new(), |id| format!(" · channel {id}"))
                )
            },
            channel,
            None,
        );
    }
    pub fn packet(
        &mut self,
        direction: &'static str,
        channel: Option<u64>,
        bytes: &[u8],
        view: &[u8],
    ) {
        if self.capture {
            self.pending.push(Trace::Packet {
                direction,
                channel,
                bytes: bytes.to_vec(),
            });
        }
        let inspection = (self.level == Level::Full).then(|| Inspection::Packet {
            header: view[..packet::HEADER].try_into().unwrap(),
            body: view[packet::HEADER..].to_vec(),
        });
        self.event(
            "packet",
            || {
                format!(
                    "{} TDS packet · type {:#04x} · {} B",
                    if direction == "send" { "→" } else { "←" },
                    view[0],
                    view.len()
                )
            },
            channel,
            inspection,
        );
    }
    pub fn take(&mut self) -> Vec<Trace> {
        std::mem::take(&mut self.pending)
    }
    pub fn reset_input(&mut self) {
        self.incoming = packet::Unpacker::default();
    }
    pub fn received(&mut self, channel: Option<u64>, packet: &packet::Packet) {
        if self.enabled() {
            let bytes = [packet.header.as_slice(), &packet.body].concat();
            self.packet("receive", channel, &bytes, &bytes);
        }
    }
    pub fn received_bytes(&mut self, channel: Option<u64>, bytes: &[u8]) -> crate::Result<()> {
        if self.enabled() {
            self.incoming.feed(bytes)?;
            while let Some(packet) = self.incoming.next_packet()? {
                self.received(channel, &packet);
            }
        }
        Ok(())
    }
    pub fn sent(
        &mut self,
        kind: u8,
        body: &[u8],
        bytes: &[u8],
        size: usize,
        channel: Option<u64>,
    ) -> crate::Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        let redacted;
        let view = if kind == packet::LOGIN {
            redacted = packet::split(kind, &crate::capture::without_password(kind, body), size)?;
            redacted.as_slice()
        } else {
            bytes
        };
        for (raw, safe) in bytes.chunks(size).zip(view.chunks(size)) {
            self.packet(
                "send",
                channel,
                if self.keep_password { raw } else { safe },
                safe,
            );
        }
        Ok(())
    }
}
