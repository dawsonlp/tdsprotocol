//! Incremental large-value framing. Only the small wire suffix is retained here;
//! whole values are assembled by explicit owners (fetch and output parameters).
use crate::{Error, Result, SqlText, SqlTextBytes, SqlType, Value, wire::Reader};

/// Owned payload, never a second right to advance a response. Unicode chunks
/// preserve exact UTF-16, including unpaired surrogates, without splitting a pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Chunk {
    Binary(Vec<u8>),
    Unicode(SqlText),
    Text(SqlTextBytes),
}
impl Chunk {
    /// Bytes in the owned payload. Unicode is UTF-16, independent of a JSON
    /// value's negotiated wire encoding; this is not a wire-byte counter.
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Binary(bytes) => bytes.len(),
            Self::Unicode(text) => text.0.len() * 2,
            Self::Text(text) => text.bytes.len(),
        }
    }
}

pub(crate) enum Piece {
    Chunk(Chunk),
    End,
}
pub(crate) struct Decoder {
    pub total_length: Option<u64>,
    sql_type: SqlType,
    plp: bool,
    remaining: u64,
    received: u64,
    ended: bool,
    suffix: Vec<u8>,
    json_utf8: bool,
    held_high: Option<u16>,
}
impl Decoder {
    /// Parse the complete value header transactionally. None is SQL NULL.
    pub fn start(info: &crate::TypeInfo, r: &mut Reader<'_>) -> Result<Option<Self>> {
        let sql_type = &info.sql_type;
        let plp = !matches!(sql_type, SqlType::LegacyText { .. } | SqlType::LegacyImage);
        let total_length = if plp {
            match r.u64()? {
                u64::MAX => return Ok(None),
                n if n == u64::MAX - 1 => None,
                n => Some(n),
            }
        } else {
            let pointer = usize::from(r.u8()?);
            if pointer == 0 {
                return Ok(None);
            }
            r.take(pointer + 8)?; // Text pointer and timestamp precede the byte count.
            Some(u64::from(r.u32()?))
        };
        Ok(Some(Self {
            total_length,
            sql_type: sql_type.clone(),
            plp,
            remaining: if plp { 0 } else { total_length.unwrap() },
            received: 0,
            ended: false,
            suffix: Vec::new(),
            json_utf8: info.json_utf8,
            held_high: None,
        }))
    }
    pub fn next(&mut self, r: &mut Reader<'_>) -> Result<Piece> {
        loop {
            if !self.ended && self.remaining == 0 {
                if self.plp {
                    self.remaining = u64::from(r.u32()?);
                    self.ended = self.remaining == 0;
                    if let Some(total) = self.total_length
                        && self.remaining > total.saturating_sub(self.received)
                    {
                        return Err(Error::malformed(r.offset, "PLP chunk exceeds total length"));
                    }
                } else {
                    self.ended = true;
                }
                if self.ended && self.total_length.is_some_and(|n| n != self.received) {
                    return Err(Error::malformed(r.offset, "PLP total length mismatch"));
                }
            }
            if self.ended {
                if let Some(chunk) = self.typed(&[], true)? {
                    return Ok(Piece::Chunk(chunk));
                }
                return Ok(Piece::End);
            }
            // Never demand the whole advertised chunk. A server may split it
            // across any number of packets, including odd UTF-16 byte offsets.
            let count = self.remaining.min(r.remaining() as u64) as usize;
            if count == 0 {
                r.take(1)?;
                unreachable!();
            }
            let bytes = r.take(count)?;
            self.remaining -= count as u64;
            self.received = self
                .received
                .checked_add(count as u64)
                .ok_or_else(|| Error::malformed(r.offset, "large value length overflow"))?;
            if let Some(chunk) = self.typed(bytes, false)? {
                return Ok(Piece::Chunk(chunk));
            }
        }
    }
    fn typed(&mut self, bytes: &[u8], end: bool) -> Result<Option<Chunk>> {
        if self.json_utf8 {
            self.suffix.extend_from_slice(bytes);
            let (part, used) = crate::text::json_part(&self.suffix, end)?;
            self.suffix.drain(..used);
            let mut units: Vec<u16> = self.held_high.take().into_iter().collect();
            units.extend(part.0);
            if !end && units.last().is_some_and(|n| (0xd800..=0xdbff).contains(n)) {
                self.held_high = units.pop();
            }
            return Ok((!units.is_empty()).then_some(Chunk::Unicode(SqlText(units))));
        }
        if self.sql_type.is_unicode() {
            self.suffix.extend_from_slice(bytes);
            if end && !self.suffix.len().is_multiple_of(2) {
                return Err(Error::malformed(0, "odd large Unicode byte length"));
            }
            let mut count = self.suffix.len() / 2;
            if !end && count > 0 {
                let tail =
                    u16::from_le_bytes([self.suffix[2 * count - 2], self.suffix[2 * count - 1]]);
                if (0xd800..=0xdbff).contains(&tail) {
                    count -= 1;
                }
            }
            if count == 0 {
                return Ok(None);
            }
            let units = self.suffix[..count * 2]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes(*b))
                .collect();
            self.suffix.drain(..count * 2);
            Ok(Some(Chunk::Unicode(SqlText(units))))
        } else if bytes.is_empty() {
            Ok(None)
        } else {
            Ok(Some(match self.sql_type {
                SqlType::CharacterMax { collation, .. } | SqlType::LegacyText { collation, .. } => {
                    Chunk::Text(SqlTextBytes {
                        bytes: bytes.to_vec(),
                        collation,
                    })
                }
                _ => Chunk::Binary(bytes.to_vec()),
            }))
        }
    }
}

/// An explicitly materialized value. This is not used by the forward chunk path.
pub(crate) fn empty(sql_type: &SqlType) -> Value {
    if sql_type.is_unicode() {
        Value::Unicode(SqlText(Vec::new()))
    } else if let SqlType::CharacterMax { collation, .. } | SqlType::LegacyText { collation, .. } =
        sql_type
    {
        Value::Text(SqlTextBytes {
            bytes: Vec::new(),
            collation: *collation,
        })
    } else {
        Value::Binary(Vec::new())
    }
}
pub(crate) fn append(value: &mut Value, chunk: Chunk) -> Result<()> {
    match (value, chunk) {
        (Value::Binary(bytes), Chunk::Binary(part)) => bytes.extend(part),
        (Value::Unicode(text), Chunk::Unicode(part)) => text.0.extend(part.0),
        (Value::Text(text), Chunk::Text(part)) if text.collation == part.collation => {
            text.bytes.extend(part.bytes)
        }
        _ => return Err(Error::malformed(0, "large value chunk type")),
    }
    Ok(())
}
