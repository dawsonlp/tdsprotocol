//! Checked byte access. Definitions, not this reader, assign meaning to bytes.
//! An incomplete read changes no external protocol state; callers may retry it.

use crate::{Error, ErrorKind, Result};

pub(crate) const MAX_PENDING: usize = 1024 * 1024;

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pub offset: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
    pub fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or_else(|| Error::malformed(self.offset, "length"))?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            Error::new(ErrorKind::Incomplete {
                offset: self.offset,
                needed: n,
            })
        })?;
        self.offset = end;
        Ok(value)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn be16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn be32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    pub fn end(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::malformed(self.offset, "trailing bytes"))
        }
    }
}

pub(crate) fn append(pending: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    if data.len() > MAX_PENDING.saturating_sub(pending.len()) {
        return Err(Error::new(ErrorKind::Limit(
            "pending protocol bytes (1 MiB)",
        )));
    }
    pending.extend_from_slice(data);
    Ok(())
}

pub(crate) fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
