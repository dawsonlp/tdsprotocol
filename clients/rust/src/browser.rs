//! SQL Server Browser discovery (MC-SQLR), independent of TDS connections.
//!
//! A request is one UDP datagram; unicast receives one reply, broadcast gathers
//! replies until its deadline. The server does not name its text encoding. ASCII
//! is the default; UTF-8 and Windows-1252 are explicit alternatives here. Other
//! code pages remain unsupported until the shared text-codec slice exists.
//!
//! Reference: `docs/design/3-reference/browser.md`, MC-SQLR §§2.2, 3.2 and 4;
//! Python baseline: `tds.browser`. Never connect automatically to an advertised
//! endpoint: choosing to use that address/port belongs to the application.

use std::{fmt, net::IpAddr};

pub const PORT: u16 = 1434;
pub const TIMEOUT_MS: u64 = 1000;
const PROTOCOLS: [&str; 7] = ["tcp", "np", "via", "rpc", "spx", "adsp", "bv"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Message {
    Broadcast = 2,
    Machine = 3,
    Instance = 4,
    Dac = 15,
}
impl Message {
    #[cfg(feature = "tokio")]
    fn name(self) -> &'static str {
        match self {
            Self::Broadcast => "CLNT_BCAST_EX",
            Self::Machine => "CLNT_UCAST_EX",
            Self::Instance => "CLNT_UCAST_INST",
            Self::Dac => "CLNT_UCAST_DAC",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    Broadcast,
    Machine,
    Instance(&'a str),
    Dac(&'a str),
}
impl<'a> Request<'a> {
    fn message(self) -> Message {
        match self {
            Self::Broadcast => Message::Broadcast,
            Self::Machine => Message::Machine,
            Self::Instance(_) => Message::Instance,
            Self::Dac(_) => Message::Dac,
        }
    }
    fn instance(self) -> Option<&'a str> {
        match self {
            Self::Instance(name) | Self::Dac(name) => Some(name),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Encoding {
    #[default]
    Ascii,
    Utf8,
    Windows1252,
}
// The five undefined bytes are errors, matching Python's strict cp1252 codec.
const CP1252: [Option<char>; 32] = [
    Some('€'),
    None,
    Some('‚'),
    Some('ƒ'),
    Some('„'),
    Some('…'),
    Some('†'),
    Some('‡'),
    Some('ˆ'),
    Some('‰'),
    Some('Š'),
    Some('‹'),
    Some('Œ'),
    None,
    Some('Ž'),
    None,
    None,
    Some('‘'),
    Some('’'),
    Some('“'),
    Some('”'),
    Some('•'),
    Some('–'),
    Some('—'),
    Some('˜'),
    Some('™'),
    Some('š'),
    Some('›'),
    Some('œ'),
    None,
    Some('ž'),
    Some('Ÿ'),
];
impl Encoding {
    fn encode(self, text: &str) -> Result<Vec<u8>, Problem> {
        if self == Self::Utf8 {
            return Ok(text.as_bytes().to_vec());
        }
        text.char_indices()
            .map(|(offset, c)| {
                let n = c as u32;
                if n < 128 || (self == Self::Windows1252 && (160..=255).contains(&n)) {
                    return Ok(n as u8);
                }
                if self == Self::Windows1252
                    && let Some(i) = CP1252.iter().position(|entry| *entry == Some(c))
                {
                    return Ok(128 + i as u8);
                }
                Err(Problem::Encoding {
                    encoding: self,
                    offset,
                })
            })
            .collect()
    }
    fn decode(self, bytes: &[u8]) -> Result<String, Problem> {
        if self == Self::Utf8 {
            return String::from_utf8(bytes.to_vec()).map_err(|e| Problem::Encoding {
                encoding: self,
                offset: e.utf8_error().valid_up_to(),
            });
        }
        bytes
            .iter()
            .enumerate()
            .map(|(offset, b)| {
                if *b < 128 || (self == Self::Windows1252 && *b >= 160) {
                    return Ok(char::from(*b));
                }
                if self == Self::Windows1252
                    && let Some(c) = CP1252[usize::from(*b - 128)]
                {
                    return Ok(c);
                }
                Err(Problem::Encoding {
                    encoding: self,
                    offset,
                })
            })
            .collect()
    }
}

#[derive(Debug)]
pub enum Problem {
    InvalidName(&'static str),
    InvalidTimeout,
    Malformed { offset: usize, field: &'static str },
    Encoding { encoding: Encoding, offset: usize },
    InstanceCount(usize),
    Timeout,
    Io(std::io::Error),
}
impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(why) => f.write_str(why),
            Self::InvalidTimeout => f.write_str("Browser timeout exceeds the clock's range"),
            Self::Malformed { offset, field } => write!(f, "malformed {field} at byte {offset}"),
            Self::Encoding { encoding, offset } => write!(f, "text is not {encoding:?} at byte {offset}; select the server's shared encoding explicitly"),
            Self::InstanceCount(n) => write!(f, "reply describes {n} instances, expected one"),
            Self::Timeout => f.write_str("no reply before the deadline; no Browser answers, UDP may be blocked, or the instance is unknown (MC-SQLR sends no negative reply)"),
            Self::Io(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for Problem {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Io(error) = self {
            Some(error)
        } else {
            None
        }
    }
}
fn malformed(offset: usize, field: &'static str) -> Problem {
    Problem::Malformed { offset, field }
}

/// Endpoints remain in wire order. No TCP endpoint means None, not port 1433.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub server_name: String,
    pub instance_name: String,
    pub is_clustered: bool,
    pub version: String,
    pub protocols: Vec<(String, String)>,
    pub address: Option<IpAddr>,
}
impl Instance {
    pub fn tcp_port(&self) -> Result<Option<u16>, std::num::ParseIntError> {
        self.protocols
            .iter()
            .find(|(name, _)| name == "tcp")
            .map(|(_, value)| value.parse())
            .transpose()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Instances(Vec<Instance>),
    DacPort(u16),
}

/// Validate the complete name before sending anything. The bound counts encoded
/// bytes, not Unicode characters, and excludes its terminating zero.
pub fn request(request: Request<'_>, encoding: Encoding) -> Result<Vec<u8>, Problem> {
    let mut bytes = vec![request.message() as u8];
    if matches!(request, Request::Dac(_)) {
        bytes.push(1);
    }
    if let Some(name) = request.instance() {
        let name = encoding.encode(name)?;
        if name.contains(&0) {
            return Err(Problem::InvalidName("instance name contains a zero byte"));
        }
        if name.len() > 32 {
            return Err(Problem::InvalidName(
                "instance name exceeds 32 encoded bytes",
            ));
        }
        bytes.extend(name);
        bytes.push(0);
    }
    Ok(bytes)
}

/// A reply is a complete datagram: truncated fields and trailing bytes are both
/// malformed. DAC's size is six for the whole datagram; others count text only.
pub fn read_reply(bytes: &[u8], asked: Message, encoding: Encoding) -> Result<Reply, Problem> {
    if bytes.len() < 3 {
        return Err(malformed(bytes.len(), "SVR_RESP header"));
    }
    if bytes[0] != 5 {
        return Err(malformed(0, "SVR_RESP tag"));
    }
    let size = usize::from(u16::from_le_bytes([bytes[1], bytes[2]]));
    if asked == Message::Dac {
        if size != 6 || bytes.len() != 6 {
            return Err(malformed(1, "DAC reply length"));
        }
        if bytes[3] != 1 {
            return Err(malformed(3, "DAC protocol version"));
        }
        return Ok(Reply::DacPort(u16::from_le_bytes([bytes[4], bytes[5]])));
    }
    if size != bytes.len() - 3 {
        return Err(malformed(1, "Browser text length"));
    }
    let text = encoding
        .decode(&bytes[3..])
        .map_err(|problem| match problem {
            Problem::Encoding { encoding, offset } => Problem::Encoding {
                encoding,
                offset: offset + 3,
            },
            problem => problem,
        })?;
    parse_instances(&text, encoding).map(Reply::Instances)
}

/// MC-SQLR's labels/protocol words are case-insensitive; their values are kept.
/// Banyan VINES holds all parts up to the next endpoint word, as in Python.
pub fn instances(text: &str) -> Result<Vec<Instance>, Problem> {
    parse_instances(text, Encoding::Utf8)
}
fn encoded_length(text: &str, encoding: Encoding) -> usize {
    match encoding {
        Encoding::Utf8 => text.len(),
        _ => text.chars().count(),
    }
}
fn parse_instances(text: &str, encoding: Encoding) -> Result<Vec<Instance>, Problem> {
    let text = text.strip_suffix(";;").ok_or_else(|| {
        malformed(
            3 + encoded_length(text, encoding),
            "instance terminator (;;)",
        )
    })?;
    let mut result = Vec::new();
    let mut offset = 3;
    for instance in text.split(";;") {
        let words: Vec<_> = instance.split(';').collect();
        let headings = ["ServerName", "InstanceName", "IsClustered", "Version"];
        if words.len() < 8
            || headings
                .iter()
                .enumerate()
                .any(|(i, h)| !words[i * 2].eq_ignore_ascii_case(h))
        {
            return Err(malformed(offset, "instance headings"));
        }
        let is_clustered = if words[5].eq_ignore_ascii_case("yes") {
            true
        } else if words[5].eq_ignore_ascii_case("no") {
            false
        } else {
            return Err(malformed(offset, "IsClustered Yes/No"));
        };
        let mut protocols: Vec<(String, String)> = Vec::new();
        let mut at = 8;
        while at < words.len() {
            let name = words[at].to_ascii_lowercase();
            at += 1;
            if !PROTOCOLS.contains(&name.as_str()) || protocols.iter().any(|(p, _)| *p == name) {
                return Err(malformed(offset, "unknown or duplicate endpoint"));
            }
            if at == words.len() {
                return Err(malformed(offset, "endpoint value"));
            }
            let start = at;
            at += 1;
            if name == "bv" {
                while at < words.len()
                    && !PROTOCOLS.iter().any(|p| words[at].eq_ignore_ascii_case(p))
                {
                    at += 1;
                }
            }
            protocols.push((name, words[start..at].join(";")));
        }
        result.push(Instance {
            server_name: words[1].into(),
            instance_name: words[3].into(),
            is_clustered,
            version: words[7].into(),
            protocols,
            address: None,
        });
        offset += encoded_length(instance, encoding) + 2;
    }
    Ok(result)
}

#[cfg(feature = "tokio")]
mod shell;
#[cfg(feature = "tokio")]
pub use shell::{BrowserError, Options, broadcast, dac_port, instance, machine};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requests_and_replies_match_the_python_mcsqlr_examples() {
        assert_eq!(request(Request::Machine, Encoding::Ascii).unwrap(), [3]);
        assert_eq!(request(Request::Broadcast, Encoding::Ascii).unwrap(), [2]);
        assert_eq!(
            request(Request::Instance("YUKONSTD"), Encoding::Ascii).unwrap(),
            b"\x04YUKONSTD\0"
        );
        assert_eq!(
            request(Request::Dac("YUKONSTD"), Encoding::Ascii).unwrap(),
            b"\x0f\x01YUKONSTD\0"
        );
        let Reply::Instances(found) = read_reply(
            include_bytes!("../tests/fixtures/browser/machine.bin"),
            Message::Machine,
            Encoding::Ascii,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(
            found
                .iter()
                .map(|i| i.instance_name.as_str())
                .collect::<Vec<_>>(),
            ["YUKONSTD", "YUKONDEV", "MSSQLSERVER"]
        );
        assert_eq!(found[0].tcp_port().unwrap(), Some(57137));
        assert_eq!(found[1].tcp_port().unwrap(), None);
        assert_eq!(
            found[2]
                .protocols
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>(),
            ["tcp", "np"]
        );
        assert_eq!(
            read_reply(
                include_bytes!("../tests/fixtures/browser/dac.bin"),
                Message::Dac,
                Encoding::Ascii
            )
            .unwrap(),
            Reply::DacPort(57138)
        );
    }
    #[test]
    fn every_short_datagram_wrong_length_tag_and_grammar_is_refused() {
        let bytes = include_bytes!("../tests/fixtures/browser/instance.bin");
        for cut in 0..bytes.len() {
            assert!(read_reply(&bytes[..cut], Message::Instance, Encoding::Ascii).is_err());
        }
        for bytes in [
            vec![4, 0, 0],
            vec![5, 3, 0, 1, 0, 0],
            vec![5, 6, 0, 2, 0, 0],
            vec![5, 6, 0, 1, 0, 0, 0],
        ] {
            assert!(read_reply(&bytes, Message::Dac, Encoding::Ascii).is_err());
        }
        for text in [
            "",
            ";;",
            "ServerName;A;InstanceName;B;IsClustered;Maybe;Version;1;;",
            "ServerName;A;InstanceName;B;IsClustered;No;Version;1;tcp;;",
            "ServerName;A;InstanceName;B;IsClustered;No;Version;1;tcp;1;tcp;2;;",
            "ServerName;A;InstanceName;B;IsClustered;No;Version;1;unknown;1;;",
        ] {
            assert!(instances(text).is_err(), "{text}");
        }
        let found = instances(
            "SERVERNAME;A;instancename;B;ISCLUSTERED;YES;version;1;BV;item;group;org;TCP;1433;;",
        )
        .unwrap();
        assert!(found[0].is_clustered);
        assert_eq!(
            found[0].protocols,
            [
                ("bv".into(), "item;group;org".into()),
                ("tcp".into(), "1433".into())
            ]
        );
    }
    #[test]
    fn encoded_name_limits_and_strict_codecs_preserve_the_python_values() {
        assert!(request(Request::Instance("Café"), Encoding::Ascii).is_err());
        assert_eq!(
            request(Request::Instance("Café"), Encoding::Windows1252).unwrap(),
            b"\x04Caf\xe9\0"
        );
        assert!(request(Request::Dac("a\0b"), Encoding::Ascii).is_err());
        assert!(request(Request::Instance(&"a".repeat(33)), Encoding::Ascii).is_err());
        assert!(request(Request::Instance(&"é".repeat(17)), Encoding::Utf8).is_err());
        assert!(request(Request::Instance(&"é".repeat(16)), Encoding::Utf8).is_ok());
        let expected = include_bytes!("../tests/fixtures/browser/cp1252.bin");
        for n in 0..=255_u8 {
            let scalar = u32::from_le_bytes(
                expected[usize::from(n) * 4..usize::from(n) * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            match Encoding::Windows1252.decode(&[n]) {
                Ok(text) => {
                    assert_eq!(text.chars().next().unwrap() as u32, scalar);
                    assert_eq!(Encoding::Windows1252.encode(&text).unwrap(), [n]);
                }
                Err(_) => assert_eq!(scalar, u32::MAX),
            }
        }
        assert!(Encoding::Utf8.decode(&[0xff]).is_err());
        let first = "ServerName;Café;InstanceName;B;IsClustered;No;Version;1;;";
        let payload = Encoding::Windows1252
            .encode(&format!("{first}bad;;"))
            .unwrap();
        let mut bytes = vec![5];
        bytes.extend((payload.len() as u16).to_le_bytes());
        bytes.extend(payload);
        assert!(
            matches!(read_reply(&bytes, Message::Machine, Encoding::Windows1252),
            Err(Problem::Malformed { offset, .. }) if offset == 3 + first.chars().count())
        );
        assert!(matches!(
            read_reply(&[5, 1, 0, 0x81], Message::Machine, Encoding::Windows1252),
            Err(Problem::Encoding { offset: 3, .. })
        ));
    }
}
