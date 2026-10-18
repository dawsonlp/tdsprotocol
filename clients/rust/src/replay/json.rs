//! Python JSON strings can contain lone UTF-16 surrogates. Keep recorded text
//! as SqlText, just like SQL text; never round it through a Rust String.
//! For structural JSON parsing only, replace lone escape digits with FFFD at
//! the same byte positions. The exact top-level text is returned separately.
use crate::SqlText;
use serde_json::Value;

pub(super) fn line(source: &str) -> Result<(Value, Option<SqlText>), usize> {
    let bytes = source.as_bytes();
    let mut normalized = bytes.to_vec();
    let mut i = 0;
    let mut depth = 0_usize;
    let mut text_key = false;
    let mut exact_text = None;
    while i < bytes.len() {
        match bytes[i] {
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b'"' => {
                i += 1;
                let mut units = vec![];
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        let escape = *bytes.get(i + 1).ok_or(i)?;
                        if escape == b'u' {
                            let unit = hex(bytes, i)?;
                            units.push(unit);
                            if (0xd800..=0xdbff).contains(&unit)
                                && let Ok(low) = hex(bytes, i + 6)
                                && (0xdc00..=0xdfff).contains(&low)
                            {
                                units.push(low);
                                i += 12;
                                continue;
                            }
                            if (0xd800..=0xdfff).contains(&unit) {
                                normalized[i + 2..i + 6].copy_from_slice(b"fffd");
                            }
                            i += 6;
                        } else {
                            units.push(match escape {
                                b'"' => 34,
                                b'\\' => 92,
                                b'/' => 47,
                                b'b' => 8,
                                b'f' => 12,
                                b'n' => 10,
                                b'r' => 13,
                                b't' => 9,
                                _ => return Err(i),
                            });
                            i += 2;
                        }
                    } else {
                        let ch = source[i..].chars().next().ok_or(i)?;
                        if ch < ' ' {
                            return Err(i);
                        }
                        units.extend(ch.encode_utf16(&mut [0; 2]).iter().copied());
                        i += ch.len_utf8();
                    }
                }
                if i == bytes.len() {
                    return Err(i);
                }
                i += 1;
                if depth == 1 {
                    let is_key =
                        bytes[i..].iter().find(|b| !b.is_ascii_whitespace()) == Some(&b':');
                    if is_key {
                        text_key = units == [116, 101, 120, 116];
                    } else if text_key {
                        exact_text = Some(SqlText(units));
                        text_key = false;
                    }
                }
            }
            _ => i += 1,
        }
    }
    let value = serde_json::from_slice(&normalized).map_err(|e| e.column().saturating_sub(1))?;
    Ok((value, exact_text))
}
fn hex(bytes: &[u8], at: usize) -> Result<u16, usize> {
    if bytes.get(at..at + 2) != Some(b"\\u") {
        return Err(at);
    }
    let digits = bytes.get(at + 2..at + 6).ok_or(at)?;
    let mut unit = 0_u16;
    for digit in digits {
        unit = unit * 16
            + u16::from(match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return Err(at),
            });
    }
    Ok(unit)
}
