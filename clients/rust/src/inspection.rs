//! Bounded explanations of wire evidence, with explicitly local byte ranges.
//! Names and references belong to protocol definitions, never to the printer.
use std::{fmt, ops::Range};

pub const RAW_LIMIT: usize = 8192;
const SHOWN_LIMIT: usize = 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Basis {
    Packet,
    Message,
    Token,
}

/// Ranges include the start and exclude the end. Descendants share the root's
/// coordinate basis. `raw` is a bounded prefix; its length need not equal span.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub basis: Basis,
    pub range: Range<usize>,
    pub raw: Vec<u8>,
    pub shown: String,
    pub children: Vec<Node>,
    /// Repository-relative reference page, optionally with an anchor.
    pub source: Option<&'static str>,
    pub sensitive: bool,
    pub issue: Option<String>,
}
impl Node {
    pub fn find(&self, path: &[&str]) -> Option<&Node> {
        let mut node = self;
        for name in path {
            node = node.children.iter().find(|n| n.name == *name)?;
        }
        Some(node)
    }
    pub(crate) fn new(
        name: impl Into<String>,
        basis: Basis,
        range: Range<usize>,
        bytes: &[u8],
    ) -> Self {
        Self {
            name: name.into(),
            basis,
            range,
            raw: bytes[..bytes.len().min(RAW_LIMIT)].to_vec(),
            shown: String::new(),
            children: vec![],
            source: None,
            sensitive: false,
            issue: None,
        }
    }
    pub(crate) fn shift(&mut self, offset: usize) {
        self.range.start += offset;
        self.range.end += offset;
        for child in &mut self.children {
            child.shift(offset);
        }
    }
    pub(crate) fn basis(&mut self, basis: Basis) {
        self.basis = basis;
        for child in &mut self.children {
            child.basis(basis);
        }
    }
    /// A readable view with ranges, meaning, bounded hex and reference links.
    pub fn render(&self) -> String {
        fn write(node: &Node, depth: usize, out: &mut String) {
            use fmt::Write;
            let _ = writeln!(
                out,
                "{}{} [{:?} {}..{}] {}{}{}",
                "  ".repeat(depth),
                node.name,
                node.basis,
                node.range.start,
                node.range.end,
                node.shown,
                node.source.map_or(String::new(), |s| format!(" <{s}>")),
                node.issue
                    .as_ref()
                    .map_or(String::new(), |s| format!(" · {s}"))
            );
            if node.children.is_empty() && !node.raw.is_empty() {
                let _ = write!(out, "{}raw:", "  ".repeat(depth + 1));
                if node.sensitive {
                    out.push_str(" [redacted]");
                } else {
                    for byte in node.raw.iter().take(32) {
                        let _ = write!(out, " {byte:02x}");
                    }
                    if node.raw.len() > 32 || node.range.len() > node.raw.len() {
                        out.push_str(" …");
                    }
                }
                out.push('\n');
            }
            for child in &node.children {
                write(child, depth + 1, out);
            }
        }
        let mut out = String::new();
        write(self, 0, &mut out);
        out
    }
}
pub(crate) fn shown(value: &impl fmt::Debug) -> String {
    struct Limited(String, bool);
    impl fmt::Write for Limited {
        fn write_str(&mut self, text: &str) -> fmt::Result {
            let room = SHOWN_LIMIT.saturating_sub(self.0.len());
            let mut end = text.len().min(room);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            self.0.push_str(&text[..end]);
            self.1 |= end != text.len();
            if self.1 { Err(fmt::Error) } else { Ok(()) }
        }
    }
    let mut out = Limited(String::new(), false);
    let _ = fmt::write(&mut out, format_args!("{value:?}"));
    if out.1 {
        out.0.push('…');
    }
    out.0
}

/// Inspect the selected whole message definitions. Unsupported families return
/// None; malformed supported inputs retain their decoded prefix and issue.
/// LOGIN7 always masks credentials, irrespective of a capture's keep setting.
pub fn message(kind: u8, bytes: &[u8]) -> Option<Node> {
    message_with_encryption(kind, bytes, false)
}
/// Negotiated version-one context is required to inspect encrypted bulk data.
pub fn message_with_encryption(kind: u8, bytes: &[u8], encrypted: bool) -> Option<Node> {
    use crate::{packet, wire::Reader};
    if matches!(
        kind,
        packet::HELLO
            | packet::LOGIN
            | packet::BATCH
            | packet::RPC
            | packet::TRANSACTION
            | packet::BULK
    ) && bytes.len() > crate::wire::MAX_PENDING
    {
        return Some(omitted_message(bytes.len()));
    }
    let (name, source) = match kind {
        packet::HELLO
            if !(bytes.len() >= 3 && (0x14..=0x17).contains(&bytes[0]) && bytes[1] == 3) =>
        {
            ("PRELOGIN", "docs/design/3-reference/prelogin.md")
        }
        packet::LOGIN => ("LOGIN7", "docs/design/3-reference/login7.md"),
        packet::BATCH => ("SQL batch", "docs/design/3-reference/requests.md"),
        packet::RPC => ("RPC", "docs/design/3-reference/requests.md"),
        packet::TRANSACTION => ("transaction manager", "docs/design/3-reference/requests.md"),
        packet::BULK => ("bulk data", "docs/design/3-reference/requests.md"),
        packet::ATTENTION => ("Attention", "docs/design/3-reference/requests.md"),
        _ => return None,
    };
    let redacted;
    let bytes = if kind == packet::LOGIN {
        redacted = crate::capture::without_password(kind, bytes);
        redacted.as_slice()
    } else {
        bytes
    };
    let mut r = Reader::new(bytes);
    r.inspect(true);
    let result = match kind {
        packet::HELLO => crate::prelogin::read(&mut r).map(|_| ()),
        packet::LOGIN => crate::login7::read(&mut r).map(|_| ()),
        packet::BULK => crate::requests::decode::bulk_reader(&mut r, encrypted).map(|_| ()),
        _ => crate::requests::decode::request_reader(kind, &mut r).map(|_| ()),
    };
    let mut node = r.node(name, Basis::Message, source).unwrap();
    if let Err(error) = result {
        node.issue = Some(error.to_string());
    }
    if kind == packet::LOGIN {
        // Never retain the aggregate credential-bearing payload, including
        // unrecognized extensions and manually supplied unmasked recordings.
        node.raw.clear();
        node.sensitive = true;
    }
    Some(node)
}
pub(crate) fn omitted_message(length: usize) -> Node {
    let mut node = Node::new("message", Basis::Message, 0..length, &[]);
    node.shown = "field inspection omitted above 1 MiB; wire evidence remains available".into();
    node
}
