//! Offline evidence without connection authority. Recorded events and decoded
//! bytes are separate outputs. See design K for compatibility and failure rules.
use crate::{Error, ErrorKind, Record, SqlText, packet, requests::decode, tokens, wire::Reader};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value as Json;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, BufRead},
};
mod json;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    Send,
    Receive,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Issue {
    Malformed,
    Incomplete,
    Unsupported,
}
#[derive(Clone, Debug)]
pub struct Item {
    pub line: usize,
    pub time: f64,
    pub direction: Option<Direction>,
    pub channel: Option<u64>,
    pub content: Content,
}
#[derive(Clone, Debug)]
pub enum Content {
    Start(String),
    Event {
        kind: String,
        text: SqlText,
        took: Option<Json>,
    },
    /// Credential-bearing message bodies are withheld, including partial ones.
    Packet {
        header: [u8; 8],
        body: Option<Vec<u8>>,
    },
    Message(Message),
    Record(Box<Record>),
    Inspection(crate::inspection::Node),
    Diagnostic {
        issue: Issue,
        offset: Option<usize>,
        description: String,
    },
}
#[derive(Clone, Debug)]
pub enum Message {
    Prelogin(Vec<(u8, Vec<u8>)>),
    TlsHandshake { bytes: usize },
    Authentication { bytes: usize },
    Login(Login),
    Request(decode::Request),
    RequestBulk(Vec<Record>),
}
pub use crate::login7::Identity as Login;
#[derive(Clone, Copy, Debug, Default)]
pub struct Summary {
    pub packets: usize,
    pub messages: usize,
    pub records: usize,
    pub issues: usize,
}
#[derive(Default)]
struct Stream {
    packets: packet::Unpacker,
    body: Vec<u8>,
    decoder: tokens::Decoder,
    failed: bool,
    fed: usize,
    pending_response: bool,
    canceling: bool,
    final_seen: bool,
}
struct Replay<F> {
    emit: F,
    summary: Summary,
    streams: BTreeMap<(Direction, Option<u64>), Stream>,
    utf8: bool,
    column_encryption: bool,
    enclaves: bool,
    classification: u8,
    features: BTreeSet<u8>,
    context_known: bool,
    hello_reply: bool,
    integrated_login: bool,
    start_seen: bool,
    line: usize,
    time: f64,
    inspect: bool,
}
impl<F: FnMut(Item) -> io::Result<()>> Replay<F> {
    fn item(&mut self, key: Option<(Direction, Option<u64>)>, content: Content) -> io::Result<()> {
        (self.emit)(Item {
            line: self.line,
            time: self.time,
            direction: key.map(|k| k.0),
            channel: key.and_then(|k| k.1),
            content,
        })
    }
    fn issue(
        &mut self,
        key: Option<(Direction, Option<u64>)>,
        issue: Issue,
        offset: Option<usize>,
        description: impl Into<String>,
    ) -> io::Result<()> {
        self.summary.issues += 1;
        self.item(
            key,
            Content::Diagnostic {
                issue,
                offset,
                description: description.into(),
            },
        )
    }
    fn error(&mut self, key: (Direction, Option<u64>), error: Error) -> io::Result<()> {
        let (issue, offset) = match error.kind {
            ErrorKind::Incomplete { offset, .. } => (Issue::Incomplete, Some(offset)),
            ErrorKind::Malformed { offset, .. } => (Issue::Malformed, Some(offset)),
            ErrorKind::Unsupported(_) => (Issue::Unsupported, None),
            _ => (Issue::Malformed, None),
        };
        self.issue(Some(key), issue, offset, error.to_string())
    }
    fn line(&mut self, line: Json, exact_text: Option<SqlText>) -> io::Result<bool> {
        if ["start", "event", "packet"]
            .iter()
            .filter(|k| line.get(**k).is_some())
            .count()
            != 1
        {
            self.issue(
                None,
                Issue::Malformed,
                None,
                "recording line must have exactly one content kind",
            )?;
            return Ok(false);
        }
        let Some(t) = line
            .get("t")
            .and_then(Json::as_f64)
            .filter(|t| t.is_finite() && *t >= 0.0)
        else {
            self.issue(
                None,
                Issue::Malformed,
                None,
                "missing or invalid recording time",
            )?;
            return Ok(false);
        };
        self.time = t;
        if let Some(start) = line.get("start") {
            if self.start_seen || !start.is_string() {
                self.issue(
                    None,
                    Issue::Malformed,
                    None,
                    "invalid/repeated physical recording start",
                )?;
                return Ok(false);
            }
            self.start_seen = true;
            self.item(None, Content::Start(start.as_str().unwrap().to_owned()))?;
        } else if let Some(kind) = line.get("event").and_then(Json::as_str) {
            let Some(text) = line.get("text").and_then(Json::as_str) else {
                self.issue(None, Issue::Malformed, None, "recorded event has no text")?;
                return Ok(false);
            };
            self.item(
                None,
                Content::Event {
                    kind: kind.to_owned(),
                    text: exact_text.unwrap_or_else(|| text.into()),
                    took: line.get("took").cloned(),
                },
            )?;
            if kind == "receive"
                && text.starts_with("← login reply")
                && let Some(encoded) = line.get("safe_login_tokens")
            {
                let Some(encoded) = encoded.as_str() else {
                    self.issue(
                        None,
                        Issue::Malformed,
                        None,
                        "safe login evidence must be base64 text",
                    )?;
                    return Ok(false);
                };
                if !self.integrated_login || encoded.len() > 88_000 {
                    self.issue(
                        None,
                        Issue::Malformed,
                        None,
                        "unexpected or oversized safe login evidence",
                    )?;
                    return Ok(false);
                }
                let Ok(body) = STANDARD.decode(encoded) else {
                    self.issue(
                        None,
                        Issue::Malformed,
                        None,
                        "invalid safe login evidence encoding",
                    )?;
                    return Ok(false);
                };
                if body.len() > 65_536 {
                    self.issue(
                        None,
                        Issue::Malformed,
                        None,
                        "oversized safe login evidence",
                    )?;
                    return Ok(false);
                }
                let key = (Direction::Receive, None);
                let mut stream = self.streams.remove(&key).unwrap_or_default();
                // Supplemental typed evidence preserves non-secret negotiation
                // records. Raw wire payload remains withheld; authentication
                // tokens are unavailable, not reconstructed from their zeros.
                self.response(
                    key,
                    &mut stream,
                    &packet::Packet {
                        header: [0; 8],
                        kind: packet::REPLY,
                        status: 1,
                        last: true,
                        session_id: 0,
                        body,
                    },
                )?;
                self.streams.insert(key, stream);
            }
        } else if let Some(direction) = line.get("packet").and_then(Json::as_str) {
            let direction = match direction {
                "send" => Direction::Send,
                "receive" => Direction::Receive,
                _ => {
                    self.issue(None, Issue::Malformed, None, "invalid packet direction")?;
                    return Ok(false);
                }
            };
            let channel = match line.get("channel") {
                Some(Json::Null) => None,
                Some(n) if n.as_u64().is_some() => n.as_u64(),
                _ => {
                    self.issue(None, Issue::Malformed, None, "invalid logical channel")?;
                    return Ok(false);
                }
            };
            let Some(bytes) = line
                .get("bytes")
                .and_then(Json::as_str)
                .and_then(|s| STANDARD.decode(s).ok())
            else {
                self.issue(
                    Some((direction, channel)),
                    Issue::Malformed,
                    None,
                    "invalid packet base64",
                )?;
                return Ok(false);
            };
            return self.packet((direction, channel), &bytes);
        } else {
            self.issue(None, Issue::Unsupported, None, "unknown recording line")?;
            return Ok(false);
        }
        Ok(true)
    }
    fn packet(&mut self, key: (Direction, Option<u64>), bytes: &[u8]) -> io::Result<bool> {
        // One capture line is exactly one TDS packet, not a socket fragment.
        if bytes.len() < 8 || usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) != bytes.len() {
            self.issue(
                Some(key),
                Issue::Malformed,
                Some(2),
                "capture line is not one complete TDS packet",
            )?;
            return Ok(false);
        }
        let mut stream = self.streams.remove(&key).unwrap_or_default();
        let parsed = stream
            .packets
            .feed(bytes)
            .and_then(|()| stream.packets.next_packet());
        let packet = match parsed {
            Ok(Some(packet)) => packet,
            Ok(None) => {
                self.issue(Some(key), Issue::Incomplete, None, "packet is incomplete")?;
                return Ok(false);
            }
            Err(error) => {
                self.error(key, error)?;
                self.streams.insert(key, stream);
                return Ok(false);
            }
        };
        self.summary.packets += 1;
        if self.inspect {
            self.item(
                Some(key),
                Content::Inspection(
                    packet::inspect_header(&packet.header).expect("validated header"),
                ),
            )?;
        }
        let credential = (key.0 == Direction::Send
            && matches!(packet.kind, packet::LOGIN | 0x08 | 0x11))
            || (key.0 == Direction::Receive && self.integrated_login);
        self.item(
            Some(key),
            Content::Packet {
                header: packet.header,
                body: (!credential).then(|| packet.body.clone()),
            },
        )?;
        if key.0 == Direction::Receive
            && self.integrated_login
            && packet.body.iter().all(|b| *b == 0)
        {
            if packet.last {
                self.issue(
                    Some(key),
                    Issue::Incomplete,
                    None,
                    "integrated login payload was redacted; authentication cannot be reconstructed",
                )?;
                stream.pending_response = false;
                stream.fed = 0;
            }
            self.streams.insert(key, stream);
            return Ok(true);
        }
        if !stream.failed {
            if key.0 == Direction::Receive && packet.kind == packet::REPLY && !self.hello_reply {
                self.response(key, &mut stream, &packet)?;
            } else {
                stream.body.extend_from_slice(&packet.body);
                if packet.last {
                    let body = std::mem::take(&mut stream.body);
                    if self.inspect
                        && let Some(node) = crate::inspection::message_with_enclaves(
                            if key.0 == Direction::Receive && self.hello_reply {
                                packet::HELLO
                            } else {
                                packet.kind
                            },
                            &body,
                            self.column_encryption,
                            self.enclaves,
                        )
                    {
                        self.item(Some(key), Content::Inspection(node))?;
                    }
                    match self.message(key, packet.kind, &body) {
                        Ok(Some(message)) => self.item(Some(key), Content::Message(message))?,
                        Ok(None) => {}
                        Err(error) => {
                            self.error(key, error)?;
                            stream.failed = true;
                        }
                    }
                }
            }
        }
        if packet.last {
            self.summary.messages += 1;
        }
        self.streams.insert(key, stream);
        Ok(true)
    }
    fn response(
        &mut self,
        key: (Direction, Option<u64>),
        stream: &mut Stream,
        packet: &packet::Packet,
    ) -> io::Result<()> {
        stream.pending_response = true;
        if !self.context_known {
            self.issue(
                Some(key),
                Issue::Unsupported,
                None,
                "response encoding context is unknown after earlier negotiation failure",
            )?;
            stream.failed = true;
            return Ok(());
        }
        stream.decoder.set_utf8_support(self.utf8);
        stream.decoder.set_column_encryption(self.column_encryption);
        stream.decoder.set_inspection(self.inspect);
        if let Err(error) = stream
            .decoder
            .set_classification_version(self.classification)
        {
            self.error(key, error)?;
            stream.failed = true;
            return Ok(());
        }
        if let Err(error) = stream.decoder.feed(&packet.body) {
            self.error(key, error)?;
            stream.failed = true;
            return Ok(());
        }
        stream.fed += packet.body.len();
        loop {
            let offset = stream.fed - stream.decoder.buffered_bytes();
            let decoded = stream.decoder.next_record();
            let missing_columns = matches!(
                &decoded,
                Err(Error {
                    kind: ErrorKind::Malformed {
                        field: "omitted column metadata without saved columns",
                        ..
                    },
                    ..
                })
            );
            if let Some(mut node) = stream.decoder.take_inspection() {
                if missing_columns {
                    node.issue = Some("saved column metadata is absent from this recording".into());
                }
                self.item(Some(key), Content::Inspection(node))?;
            }
            match decoded {
                Ok(None) => break,
                Err(mut error) => {
                    if missing_columns {
                        self.issue(Some(key), Issue::Incomplete, Some(offset), "column metadata was omitted by NO_METADATA and is absent from this recording")?;
                        stream.failed = true;
                        break;
                    }
                    if matches!(error.kind, ErrorKind::Unsupported(_)) {
                        self.issue(
                            Some(key),
                            Issue::Unsupported,
                            Some(offset),
                            error.to_string(),
                        )?;
                        stream.failed = true;
                        break;
                    }
                    match &mut error.kind {
                        ErrorKind::Malformed { offset: at, .. }
                        | ErrorKind::Incomplete { offset: at, .. } => *at += offset,
                        _ => {}
                    }
                    self.error(key, error)?;
                    stream.failed = true;
                    break;
                }
                Ok(Some(mut record)) => {
                    if let Record::Sspi(token) = &record {
                        record = Record::Sspi(
                            crate::auth::Token::new(vec![0; token.as_bytes().len()])
                                .expect("bounded token"),
                        );
                    }
                    if stream.final_seen {
                        self.issue(
                            Some(key),
                            Issue::Malformed,
                            Some(offset),
                            "records follow final DONE before the message boundary",
                        )?;
                        stream.failed = true;
                        break;
                    }
                    if let Record::FeatureAck(features) = &record {
                        for (id, data) in features {
                            if !self.features.insert(*id) {
                                self.issue(
                                    Some(key),
                                    Issue::Malformed,
                                    Some(offset),
                                    "duplicate feature acknowledgement",
                                )?;
                                stream.failed = true;
                                self.context_known = false;
                                break;
                            }
                            match *id {
                                10 if data.len() == 1 && data[0] <= 1 => self.utf8 = data[0] != 0,
                                9 if data.len() == 2
                                    && (1..=2).contains(&data[0])
                                    && data[1] <= 1 =>
                                {
                                    self.classification = if data[1] == 1 { data[0] } else { 0 }
                                }
                                9 | 10 => {
                                    self.issue(
                                        Some(key),
                                        Issue::Malformed,
                                        Some(offset),
                                        "invalid feature acknowledgement",
                                    )?;
                                    stream.failed = true;
                                    self.context_known = false;
                                }
                                4 if matches!(data.first(), Some(1 | 2)) => {
                                    self.column_encryption = true;
                                    self.enclaves = data[0] == 2;
                                }
                                4 => {
                                    self.issue(
                                        Some(key),
                                        Issue::Malformed,
                                        Some(offset),
                                        "invalid column encryption acknowledgement",
                                    )?;
                                    stream.failed = true;
                                }
                                _ => {}
                            }
                        }
                        stream.decoder.set_utf8_support(self.utf8);
                        stream.decoder.set_column_encryption(self.column_encryption);
                        if let Err(error) = stream
                            .decoder
                            .set_classification_version(self.classification)
                        {
                            self.error(key, error)?;
                            stream.failed = true;
                        }
                    }
                    if let Record::Done(done) = &record
                        && done.is_final()
                        && (!stream.canceling || done.acknowledges_cancel())
                    {
                        stream.final_seen = true;
                        self.integrated_login = false;
                    }
                    self.summary.records += 1;
                    self.item(Some(key), Content::Record(Box::new(record)))?;
                    if stream.failed {
                        break;
                    }
                }
            }
        }
        if packet.last && !stream.failed {
            if !stream.decoder.is_empty() {
                self.issue(
                    Some(key),
                    Issue::Incomplete,
                    Some(stream.fed),
                    "message ended inside a response token/value",
                )?;
                stream.failed = true;
            } else if stream.final_seen {
                stream.pending_response = false;
                stream.canceling = false;
                stream.final_seen = false;
            }
        }
        if packet.last {
            stream.fed = 0;
        }
        Ok(())
    }
    fn message(
        &mut self,
        key: (Direction, Option<u64>),
        kind: u8,
        body: &[u8],
    ) -> crate::Result<Option<Message>> {
        if kind == packet::HELLO || (key.0 == Direction::Receive && self.hello_reply) {
            if key.0 == Direction::Receive {
                self.hello_reply = false;
            }
            if body.len() >= 3 && (0x14..=0x17).contains(&body[0]) && body[1] == 3 {
                return Ok(Some(Message::TlsHandshake { bytes: body.len() }));
            }
            if key.0 == Direction::Send {
                self.hello_reply = true;
            }
            return prelogin(body).map(|v| Some(Message::Prelogin(v)));
        }
        if key.0 != Direction::Send {
            return Err(Error::new(ErrorKind::Unsupported("server packet type")));
        }
        if kind == packet::LOGIN {
            self.integrated_login = body.get(25).is_some_and(|flags| flags & 0x80 != 0)
                || crate::login7::has_federated_feature(body);
            self.hello_reply = false;
            self.streams
                .entry((Direction::Receive, key.1))
                .or_default()
                .pending_response = true;
            return login(&crate::capture::without_password(kind, body))
                .map(|v| Some(Message::Login(v)));
        }
        if matches!(kind, packet::SSPI | 0x08) {
            return Ok(Some(Message::Authentication { bytes: body.len() }));
        }
        self.integrated_login = false;
        let response = self.streams.entry((Direction::Receive, key.1)).or_default();
        response.pending_response = true;
        if kind == packet::ATTENTION {
            response.canceling = true;
            response.final_seen = false;
        }
        if kind == 7 {
            return decode::bulk_with_encryption(body, self.column_encryption)
                .map(|v| Some(Message::RequestBulk(v)));
        }
        decode::request_with_enclaves(kind, body, self.enclaves).map(|v| Some(Message::Request(v)))
    }
    fn finish(&mut self) -> io::Result<()> {
        if self.summary.packets == 0 && self.summary.issues == 0 {
            self.issue(
                None,
                Issue::Incomplete,
                None,
                "recording contains no packet evidence",
            )?;
        }
        let keys = self.streams.keys().copied().collect::<Vec<_>>();
        for key in keys {
            let stream = &self.streams[&key];
            let unfinished_message = !stream.packets.is_empty();
            let unfinished_response = key.0 == Direction::Receive && stream.pending_response;
            if unfinished_message {
                self.issue(
                    Some(key),
                    Issue::Incomplete,
                    None,
                    "recording ended before the message's last packet",
                )?;
            }
            if unfinished_response {
                self.issue(
                    Some(key),
                    Issue::Incomplete,
                    None,
                    "recording contains no final response proof for the outstanding request",
                )?;
            }
        }
        Ok(())
    }
}
/// Replay one physical recording. Format/protocol issues are emitted and counted;
/// reader/callback I/O errors return immediately. No network APIs are used.
/// A zero issue count means the available evidence decoded, not that the server
/// closed or that all SQL/bulk/transaction obligations can be inferred.
///
/// ```no_run
/// use std::{fs::File, io::BufReader};
/// let summary = tds_client::replay::replay(
///     BufReader::new(File::open("conversation.jsonl")?),
///     |item| { println!("{item:?}"); Ok(()) },
/// )?;
/// assert_eq!(summary.issues, 0);
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn replay(
    input: impl BufRead,
    emit: impl FnMut(Item) -> io::Result<()>,
) -> io::Result<Summary> {
    replay_with_inspection(input, false, emit)
}
/// Replay with optional field trees. Base evidence/diagnostics are identical to
/// `replay`; false builds no trees. True additionally emits `Content::Inspection`.
pub fn replay_with_inspection(
    mut input: impl BufRead,
    inspect: bool,
    emit: impl FnMut(Item) -> io::Result<()>,
) -> io::Result<Summary> {
    let mut reader = Replay {
        emit,
        summary: Summary::default(),
        streams: BTreeMap::new(),
        utf8: false,
        column_encryption: false,
        enclaves: false,
        classification: 0,
        features: BTreeSet::new(),
        context_known: true,
        hello_reply: false,
        integrated_login: false,
        start_seen: false,
        line: 0,
        time: 0.0,
        inspect,
    };
    let mut bytes = vec![];
    loop {
        bytes.clear();
        if input.read_until(b'\n', &mut bytes)? == 0 {
            break;
        }
        reader.line += 1;
        let line = match std::str::from_utf8(&bytes) {
            Ok(line) => line,
            Err(error) => {
                reader.issue(
                    None,
                    Issue::Malformed,
                    Some(error.valid_up_to()),
                    "recording line is not UTF-8 (contents withheld)",
                )?;
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let (value, text) = match json::line(line) {
            Ok(value) => value,
            Err(offset) => {
                reader.issue(
                    None,
                    Issue::Malformed,
                    Some(offset),
                    "invalid JSON recording line (contents withheld)",
                )?;
                break;
            }
        };
        if !reader.line(value, text)? {
            break;
        }
    }
    reader.finish()?;
    Ok(reader.summary)
}
fn login(body: &[u8]) -> crate::Result<Login> {
    crate::login7::read(&mut Reader::new(body))
}
fn prelogin(body: &[u8]) -> crate::Result<Vec<(u8, Vec<u8>)>> {
    crate::prelogin::read(&mut Reader::new(body))
}
