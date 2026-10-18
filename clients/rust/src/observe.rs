//! Observation carries information, never protocol authority.
//!
//! The core queues owned descriptions; the shell invokes callbacks only after
//! the core step returns. Off allocates no descriptions. Outline and Full have
//! the same lines; Full additionally exposes packet bytes, decoded records and
//! selected field trees with bounded raw bytes and protocol references.

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
impl Inspection {
    pub fn render(&self) -> String {
        match self {
            Self::Record(record) => crate::inspection::shown(record),
            Self::Packet { header, body } => format!(
                "header {header:02x?}; body {} bytes: {:02x?}{}",
                body.len(),
                &body[..body.len().min(32)],
                if body.len() > 32 { " …" } else { "" }
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    pub kind: &'static str,
    pub text: String,
    pub channel: Option<u64>,
    /// Monotonic time since this physical connection's observation began.
    pub elapsed: Duration,
    pub inspection: Option<Inspection>,
    /// Additional field trees at Full only. Empty at Outline/Off.
    pub fields: Vec<crate::inspection::Node>,
    /// Present on a completed response event; event text remains unchanged.
    pub timing: Option<crate::response::Timing>,
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
    pub column_encryption: bool,
    pending: Vec<Trace>,
    incoming: packet::Unpacker,
    bodies: std::collections::BTreeMap<(bool, Option<u64>), Body>,
    expect_prelogin: bool,
    token_fields: std::collections::BTreeMap<Option<u64>, crate::inspection::Node>,
}
#[derive(Default)]
struct Body {
    bytes: Vec<u8>,
    length: usize,
    omitted: bool,
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
    pub fn timing(&mut self, timing: crate::response::Timing) {
        if self.enabled()
            && let Some(Trace::Event(event)) = self.pending.last_mut()
        {
            event.timing = Some(timing);
        }
    }
    pub fn fields(
        &mut self,
        direction: &'static str,
        channel: Option<u64>,
        node: crate::inspection::Node,
    ) {
        if self.level != Level::Full {
            return;
        }
        if !matches!(self.pending.last(), Some(Trace::Event(event)) if event.channel == channel) {
            // A malformed token can fail before it produces a semantic record.
            self.event(
                "inspection",
                || format!("{direction} field diagnostic"),
                channel,
                None,
            );
        }
        if let Some(Trace::Event(event)) = self.pending.last_mut() {
            event.fields.push(node);
        }
    }
    pub fn token_fields(&mut self, channel: Option<u64>, node: crate::inspection::Node) {
        self.token_fields.insert(channel, node);
    }
    fn message_fields(&mut self, direction: &'static str, channel: Option<u64>, bytes: &[u8]) {
        if self.level != Level::Full {
            return;
        }
        if let Ok(node) = packet::inspect_header(&bytes[..8]) {
            self.fields(direction, channel, node);
        }
        let send = direction == "send";
        let kind = bytes[0];
        let prelogin_reply = !send && self.expect_prelogin && kind == packet::REPLY;
        if !(send
            && matches!(
                kind,
                packet::HELLO
                    | packet::LOGIN
                    | packet::BATCH
                    | packet::RPC
                    | packet::TRANSACTION
                    | packet::BULK
                    | packet::ATTENTION
            ))
            && !prelogin_reply
        {
            return;
        }
        let key = (send, channel);
        let body = self.bodies.entry(key).or_default();
        body.length = body.length.saturating_add(bytes.len() - 8);
        if body.length <= crate::wire::MAX_PENDING {
            body.bytes.extend_from_slice(&bytes[8..]);
        } else {
            body.omitted = true;
            body.bytes.clear();
        }
        if bytes[1] & 1 == 0 {
            return;
        }
        let body = self.bodies.remove(&key).unwrap();
        if prelogin_reply {
            self.expect_prelogin = false;
        }
        if body.omitted {
            self.fields(
                direction,
                channel,
                crate::inspection::omitted_message(body.length),
            );
        } else if let Some(node) = crate::inspection::message_with_encryption(
            if prelogin_reply { packet::HELLO } else { kind },
            &body.bytes,
            self.column_encryption,
        ) {
            if send && kind == packet::HELLO {
                self.expect_prelogin = true;
            }
            self.fields(direction, channel, node);
        }
    }
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
                fields: Vec::new(),
                timing: None,
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
        if let Some(node) = self.token_fields.remove(&channel) {
            self.fields("receive", channel, node);
        }
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
        self.message_fields(direction, channel, view);
    }
    pub fn take(&mut self) -> Vec<Trace> {
        std::mem::take(&mut self.pending)
    }
    pub fn reset_input(&mut self) {
        self.incoming = packet::Unpacker::default();
        self.bodies.clear();
        self.expect_prelogin = false;
        self.token_fields.clear();
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
