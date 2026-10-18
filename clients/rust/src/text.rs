//! Explicit SQL collation views over exact varchar bytes.
//!
//! SQL's character mappings differ from host codecs. The generated tables come
//! from Python's reviewed server corrections; unknown collations never guess.
//! Undecodable bytes use low-surrogate escapes in [`SqlText`], as in Python.
//! This view does not replace the original [`SqlTextBytes`] or its collation.
//!
//! ```
//! use tds_client::{Collation, SqlTextBytes};
//! let latin = Collation([9, 4, 0, 0, 52]); // SQL sort 52, Windows-1252.
//! let raw = SqlTextBytes::from_text(latin, &"café €".into())?;
//! assert_eq!(raw.bytes, b"caf\xe9 \x80");
//! assert_eq!(raw.decode()?.to_string()?, "café €");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
use crate::{Collation, Error, ErrorKind, Result, SqlText, SqlTextBytes};

struct Page {
    number: u16,
    offset: usize,
    pairs: bool,
    encode_offset: usize,
    encode_len: usize,
}
include!("text/tables.rs");

fn word(offset: usize) -> u32 {
    u32::from_le_bytes(DATA[offset..offset + 4].try_into().unwrap())
}
fn lookup(table: &[(u32, u16)], key: u32) -> Option<u16> {
    table
        .binary_search_by_key(&key, |entry| entry.0)
        .ok()
        .map(|i| table[i].1)
}
fn refused() -> Error {
    Error::new(ErrorKind::Parameter(
        "text has no exact SQL code-page encoding",
    ))
}

#[derive(Clone, Copy)]
enum Codec {
    Utf8,
    Legacy(&'static Page),
}
impl Codec {
    fn for_collation(collation: Collation) -> Result<Self> {
        let page = collation.code_page()?;
        if page == 65001 {
            return Ok(Self::Utf8);
        }
        PAGES
            .iter()
            .find(|entry| entry.number == page)
            .map(Self::Legacy)
            .ok_or_else(|| Error::new(ErrorKind::Unsupported("collation has no varchar code page")))
    }
    /// Return text plus consumed bytes. A non-final suffix is at most one DBCS
    /// lead or three UTF-8 bytes; the caller retains it for the next chunk.
    fn decode(self, bytes: &[u8], final_chunk: bool) -> (SqlText, usize) {
        let mut text = Vec::new();
        let mut used = 0;
        match self {
            Self::Utf8 => {
                while used < bytes.len() {
                    match std::str::from_utf8(&bytes[used..]) {
                        Ok(valid) => {
                            text.extend(valid.encode_utf16());
                            used = bytes.len();
                        }
                        Err(error) => {
                            let end = used + error.valid_up_to();
                            // from_utf8 identified this prefix as valid; keep
                            // the validation explicit rather than using unsafe.
                            text.extend(
                                std::str::from_utf8(&bytes[used..end])
                                    .unwrap()
                                    .encode_utf16(),
                            );
                            used = end;
                            let count = match error.error_len() {
                                Some(count) => count,
                                None if final_chunk => bytes.len() - used,
                                None => break,
                            };
                            text.extend(
                                bytes[used..used + count]
                                    .iter()
                                    .map(|b| 0xdc00 + u16::from(*b)),
                            );
                            used += count;
                        }
                    }
                }
            }
            Self::Legacy(page) => {
                while used < bytes.len() {
                    let first = bytes[used];
                    let lead = page.pairs && DATA[page.offset + usize::from(first)] != 0;
                    if lead && used + 1 == bytes.len() && !final_chunk {
                        break;
                    }
                    if lead && used + 1 < bytes.len() {
                        let pair = usize::from(first) * 256 + usize::from(bytes[used + 1]);
                        match word(page.offset + 1280 + pair * 4) {
                            u32::MAX => {} // Invalid pair: reprocess the second byte.
                            0xffff_fffe => {
                                text.extend([
                                    0xdc00 + u16::from(first),
                                    0xdc00 + u16::from(bytes[used + 1]),
                                ]);
                                used += 2;
                                continue;
                            }
                            cp => {
                                text.push(cp as u16);
                                used += 2;
                                continue;
                            }
                        }
                    }
                    text.push(if lead {
                        0xdc00 + u16::from(first)
                    } else {
                        word(page.offset + 256 + usize::from(first) * 4) as u16
                    });
                    used += 1;
                }
            }
        }
        (SqlText(text), used)
    }
    fn encode(self, text: &SqlText) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for unit in char::decode_utf16(text.0.iter().copied()) {
            let cp = match unit {
                Ok(c) => c as u32,
                Err(e) => u32::from(e.unpaired_surrogate()),
            };
            match self {
                Self::Utf8 => {
                    if (0xdc80..=0xdcff).contains(&cp) {
                        bytes.push((cp - 0xdc00) as u8);
                    } else {
                        let c = char::from_u32(cp).ok_or_else(refused)?;
                        let mut buf = [0; 4];
                        bytes.extend(c.encode_utf8(&mut buf).as_bytes());
                    }
                }
                Self::Legacy(page) => {
                    let (mut lo, mut hi) = (0, page.encode_len);
                    while lo < hi {
                        let mid = lo + (hi - lo) / 2;
                        if word(page.encode_offset + mid * 8) < cp {
                            lo = mid + 1;
                        } else {
                            hi = mid;
                        }
                    }
                    let offset = page.encode_offset + lo * 8;
                    if lo == page.encode_len || word(offset) != cp {
                        return Err(refused());
                    }
                    let count = usize::from(DATA[offset + 4]);
                    bytes.extend(&DATA[offset + 5..offset + 5 + count]);
                }
            }
        }
        Ok(bytes)
    }
}

impl Collation {
    /// Server-derived code page. Zero identifies a Unicode-only collation;
    /// decoding/encoding varchar under it is refused.
    pub fn code_page(self) -> Result<u16> {
        if self.is_utf8() {
            return Ok(65001);
        }
        let page = if self.sort_id() != 0 {
            lookup(SORT, u32::from(self.sort_id()))
        } else {
            lookup(LOCALE, self.locale_id())
        };
        page.ok_or_else(|| {
            Error::new(ErrorKind::Unsupported(
                "unknown SQL collation; regenerate server mappings",
            ))
        })
    }
    pub fn decode(self, bytes: &[u8]) -> Result<SqlText> {
        Ok(Codec::for_collation(self)?.decode(bytes, true).0)
    }
    pub fn encode(self, text: &SqlText) -> Result<Vec<u8>> {
        Codec::for_collation(self)?.encode(text)
    }
    pub fn decoder(self) -> Result<TextDecoder> {
        Ok(TextDecoder {
            codec: Codec::for_collation(self)?,
            held: Vec::new(),
        })
    }
}

impl SqlTextBytes {
    pub fn decode(&self) -> Result<SqlText> {
        self.collation.decode(&self.bytes)
    }
    pub fn from_text(collation: Collation, text: &SqlText) -> Result<Self> {
        Ok(Self {
            bytes: collation.encode(text)?,
            collation,
        })
    }
}

/// Holds an incomplete character, never a whole value. Call with `final_chunk`
/// at value end to flush a trailing invalid byte as a surrogate escape. Feed
/// this view only chunks from one value with its declared collation.
pub struct TextDecoder {
    codec: Codec,
    held: Vec<u8>,
}
impl TextDecoder {
    pub fn decode(&mut self, bytes: &[u8], final_chunk: bool) -> SqlText {
        let mut input = std::mem::take(&mut self.held);
        input.extend(bytes);
        let (text, used) = self.codec.decode(&input, final_chunk);
        self.held.extend(&input[used..]);
        text
    }
}

/// Native JSON results use UTF-8 with Python's surrogatepass behavior: valid
/// encoded UTF-16 surrogate units are preserved, other invalid UTF-8 is an
/// error. This differs deliberately from varchar's byte-escape view above.
pub(crate) fn json_part(bytes: &[u8], final_chunk: bool) -> Result<(SqlText, usize)> {
    let mut units = Vec::new();
    let mut used = 0;
    while used < bytes.len() {
        let first = bytes[used];
        let count = match first {
            0..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Err(Error::malformed(used, "JSON UTF-8 leading byte")),
        };
        let available = (bytes.len() - used).min(count);
        let part = &bytes[used..used + available];
        if part[1..].iter().any(|b| !(0x80..=0xbf).contains(b))
            || (available > 1
                && ((first == 0xe0 && part[1] < 0xa0)
                    || (first == 0xf0 && part[1] < 0x90)
                    || (first == 0xf4 && part[1] > 0x8f)))
        {
            return Err(Error::malformed(used, "JSON UTF-8 continuation/range"));
        }
        if available < count {
            if final_chunk {
                return Err(Error::malformed(used, "incomplete JSON UTF-8 character"));
            }
            break;
        }
        let mut cp = if count == 1 {
            u32::from(first)
        } else {
            u32::from(first & (0x7f >> count))
        };
        if count > 1 {
            for byte in &part[1..] {
                cp = (cp << 6) | u32::from(byte & 0x3f);
            }
        }
        if cp <= 0xffff {
            units.push(cp as u16);
        } else {
            let cp = cp - 0x10000;
            units.extend([0xd800 + (cp >> 10) as u16, 0xdc00 + (cp & 0x3ff) as u16]);
        }
        used += count;
    }
    Ok((SqlText(units), used))
}
