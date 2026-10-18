//! One physical connection, one JSON-lines recording (Python D-12 format).
//! Query text and result data remain in the recording. Credentials are zeroed
//! unless explicitly requested. Each line is flushed; this is not fsync durability.
//!
//! Capture is deliberately not Clone. A pool uses a factory returning a new
//! writer with a distinct output for every new physical connection. Pool loans
//! keep using that transport's recording. The driver owns and drops its writer.

use crate::{observe::Event, packet};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
    time::Duration,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub struct Capture {
    writer: Box<dyn Write + Send>,
    pub(crate) keep_password: bool,
    started: bool,
    origin: Option<Duration>,
    held: Vec<Vec<u8>>,
}
impl Capture {
    pub fn new(writer: impl Write + Send + 'static) -> Self {
        Self {
            writer: Box::new(writer),
            keep_password: false,
            started: false,
            origin: None,
            held: Vec::new(),
        }
    }
    /// Exclusive creation prevents a factory from truncating an earlier recording.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self::new(
            OpenOptions::new().write(true).create_new(true).open(path)?,
        ))
    }
    pub fn keep_password(mut self, keep: bool) -> Self {
        self.keep_password = keep;
        self
    }
    fn line(&mut self, value: Value) -> io::Result<()> {
        serde_json::to_writer(&mut self.writer, &value)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }
    fn start(&mut self) -> io::Result<()> {
        if !self.started {
            self.line(json!({"t":0, "start":OffsetDateTime::now_utc().format(&Rfc3339).map_err(io::Error::other)?}))?;
            self.started = true;
        }
        Ok(())
    }
    pub fn event(&mut self, event: &Event) -> io::Result<()> {
        self.start()?;
        let origin = *self.origin.get_or_insert(event.elapsed);
        let mut line = json!({"t":event.elapsed.saturating_sub(origin).as_secs_f64(), "event":event.kind, "text":event.text});
        if let Some(timing) = event.timing {
            let took = timing.summary();
            if !took.is_empty() {
                line["took"] = Value::String(took);
            }
        }
        self.line(line)
    }
    pub fn packet(
        &mut self,
        at: Duration,
        direction: &str,
        channel: Option<u64>,
        bytes: &[u8],
    ) -> io::Result<()> {
        if bytes.len() < packet::HEADER {
            return Err(io::Error::other("truncated capture packet"));
        }
        if direction == "send"
            && matches!(bytes[0], packet::LOGIN | 0x08 | 0x11)
            && !self.keep_password
        {
            self.held.push(bytes.to_vec());
            if bytes[1] & 1 == 0 {
                return Ok(());
            }
            let packets = std::mem::take(&mut self.held);
            let body: Vec<_> = packets
                .iter()
                .flat_map(|p| p[packet::HEADER..].iter().copied())
                .collect();
            let redacted = without_password(bytes[0], &body);
            let mut offset = 0;
            for mut packet in packets {
                let size = packet.len() - packet::HEADER;
                packet[packet::HEADER..].copy_from_slice(&redacted[offset..offset + size]);
                self.write_packet(at, direction, channel, &packet)?;
                offset += size;
            }
            return Ok(());
        }
        self.write_packet(at, direction, channel, bytes)
    }
    fn write_packet(
        &mut self,
        at: Duration,
        direction: &str,
        channel: Option<u64>,
        bytes: &[u8],
    ) -> io::Result<()> {
        self.start()?;
        let origin = *self.origin.get_or_insert(at);
        self.line(json!({"t":at.saturating_sub(origin).as_secs_f64(), "packet":direction, "channel":channel, "bytes":STANDARD.encode(bytes)}))
    }
}

/// Redact the complete LOGIN7 before splitting it into packets: a password may
/// straddle any packet boundary. Unsupported authentication is never advertised.
pub(crate) fn without_password(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut view = body.to_vec();
    if matches!(kind, 0x08 | 0x11) {
        view.fill(0);
    }
    if kind == packet::LOGIN {
        for field in [0x2c, 0x56, 0x4e] {
            if body.len() >= field + 4 {
                let at = usize::from(u16::from_le_bytes([body[field], body[field + 1]]));
                let count = usize::from(u16::from_le_bytes([body[field + 2], body[field + 3]]));
                let len = if field == 0x4e {
                    if count == 0xffff && body.len() >= 94 {
                        u32::from_le_bytes(body[90..94].try_into().unwrap()) as usize
                    } else {
                        count
                    }
                } else {
                    count * 2
                };
                let end = at.saturating_add(len).min(view.len());
                if at <= end {
                    view[at..end].fill(0);
                }
            }
        }
        // LOGIN7's extension table can hold a federated token, even when a
        // manually supplied recording contains authentication this client cannot send.
        if body.len() >= 60 && u16::from_le_bytes([body[58], body[59]]) == 4 {
            let pointer = usize::from(u16::from_le_bytes([body[56], body[57]]));
            if let Some(bytes) = body.get(pointer..pointer.saturating_add(4)) {
                let mut at = u32::from_le_bytes(bytes.try_into().unwrap()) as usize;
                while at.saturating_add(5) <= body.len() && body[at] != 0xff {
                    let length =
                        u32::from_le_bytes(body[at + 1..at + 5].try_into().unwrap()) as usize;
                    let end = at.saturating_add(5).saturating_add(length).min(body.len());
                    if body[at] == 2 && length > 1 && at + 6 <= end {
                        view[at + 6..end].fill(0);
                    }
                    at = end;
                }
            }
        }
    }
    view
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
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
    #[test]
    fn whole_login_redaction_preserves_every_header_and_split_boundary() {
        let login = crate::login7::Login {
            user: "test".into(),
            password: "a password crossing packets".into(),
            database: "test".into(),
            host_name: String::new(),
            server_name: String::new(),
            process_id: 0,
            ..crate::login7::Login::default()
        }
        .encode()
        .unwrap();
        let expected = without_password(packet::LOGIN, &login);
        assert_ne!(login, expected);
        for keep in [false, true] {
            for size in [9, 31, 4096] {
                let out = Output::default();
                let mut capture = Capture::new(out.clone()).keep_password(keep);
                let wire = packet::split(packet::LOGIN, &login, size).unwrap();
                for bytes in wire.chunks(size) {
                    capture
                        .packet(Duration::from_secs(17), "send", None, bytes)
                        .unwrap();
                }
                let bytes = out.0.lock().unwrap().clone();
                let lines: Vec<Value> = String::from_utf8(bytes)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                assert_eq!(lines[0]["t"], 0);
                let mut body: Vec<u8> = Vec::new();
                for (line, original) in lines[1..].iter().zip(wire.chunks(size)) {
                    assert_eq!(line["t"], 0.0);
                    let bytes = STANDARD.decode(line["bytes"].as_str().unwrap()).unwrap();
                    assert_eq!(&bytes[..8], &original[..8]);
                    body.extend(&bytes[8..]);
                }
                assert_eq!(body, if keep { &login } else { &expected }.as_slice());
            }
        }
    }
    #[test]
    fn buffered_flush_failure_is_returned_and_create_never_truncates() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("flush failed"))
            }
        }
        assert!(
            Capture::new(Broken)
                .packet(Duration::ZERO, "receive", None, &[4, 1, 0, 8, 0, 0, 1, 0])
                .is_err()
        );
        let path = std::env::temp_dir().join(format!(
            "tds-capture-create-{}-{}.jsonl",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::write(&path, b"retain").unwrap();
        assert_eq!(
            Capture::create(&path).err().unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"retain");
        std::fs::remove_file(path).unwrap();
    }
}
