//! An eight-byte header frames each piece of a TDS message.
//! Reference: `docs/design/3-reference/packet.md`; MS-TDS v20260617 §2.2.3.
//! Input may end anywhere, including inside the header. LAST ends a message,
//! not necessarily an exchange. Packet numbers are ignored on receive.

use crate::{Error, ErrorKind, Result, wire};

pub const HEADER: usize = 8;
pub const DEFAULT_SIZE: usize = 4096;
pub const MAX_SIZE: usize = 32767;
pub const BATCH: u8 = 0x01;
pub const RPC: u8 = 0x03;
pub const REPLY: u8 = 0x04;
pub const ATTENTION: u8 = 0x06;
pub const TRANSACTION: u8 = 0x0e;
pub const LOGIN: u8 = 0x10;
pub const HELLO: u8 = 0x12;

#[derive(Debug)]
pub struct Packet {
    pub header: [u8; HEADER],
    pub kind: u8,
    pub status: u8,
    pub last: bool,
    pub session_id: u16,
    pub body: Vec<u8>,
}

#[derive(Default)]
pub struct Unpacker {
    pending: Vec<u8>,
    kind: Option<u8>,
}
impl Unpacker {
    pub fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        wire::append(&mut self.pending, bytes)
    }
    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        if self.pending.len() < HEADER {
            return Ok(None);
        }
        let h = &self.pending[..HEADER];
        let n = usize::from(u16::from_be_bytes([h[2], h[3]]));
        if !(HEADER..=MAX_SIZE).contains(&n) {
            return Err(Error::malformed(2, "packet length"));
        }
        if h[1] & !0x1b != 0 || h[7] != 0 {
            return Err(Error::malformed(1, "packet flags/reserved byte"));
        }
        if let Some(kind) = self.kind
            && h[0] != kind
        {
            return Err(Error::malformed(0, "packet type changed inside message"));
        }
        if self.pending.len() < n {
            return Ok(None);
        }
        let packet = Packet {
            header: h.try_into().unwrap(),
            kind: h[0],
            status: h[1],
            last: h[1] & 1 != 0,
            session_id: u16::from_be_bytes([h[4], h[5]]),
            body: self.pending[HEADER..n].to_vec(),
        };
        self.kind = if packet.last { None } else { Some(packet.kind) };
        self.pending.drain(..n);
        Ok(Some(packet))
    }
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.kind.is_none()
    }
}

pub fn split(kind: u8, body: &[u8], size: usize) -> Result<Vec<u8>> {
    if !(HEADER + 1..=MAX_SIZE).contains(&size) {
        return Err(Error::malformed(0, "packet size"));
    }
    if body.len() > wire::MAX_PENDING {
        return Err(Error::new(ErrorKind::Limit("outgoing message (1 MiB)")));
    }
    let room = size - HEADER;
    let count = body.len().div_ceil(room).max(1);
    let mut out = Vec::with_capacity(body.len() + count * HEADER);
    for i in 0..count {
        let chunk = &body[(i * room).min(body.len())..((i + 1) * room).min(body.len())];
        out.extend_from_slice(&[kind, u8::from(i + 1 == count)]);
        let length = u16::try_from(HEADER + chunk.len())
            .map_err(|_| Error::malformed(0, "packet length"))?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&[0, 0, (i.wrapping_add(1) & 255) as u8, 0]);
        out.extend_from_slice(chunk);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_fragment_boundary_and_one_byte_feeds() {
        let data: Vec<u8> = (0..127).collect();
        let encoded = split(REPLY, &data, 31).unwrap();
        for boundary in 0..=encoded.len() {
            let mut u = Unpacker::default();
            let mut actual = Vec::new();
            let mut ends = 0;
            for fragment in [&encoded[..boundary], &encoded[boundary..]] {
                u.feed(fragment).unwrap();
                while let Some(p) = u.next_packet().unwrap() {
                    actual.extend(p.body);
                    ends += usize::from(p.last);
                }
            }
            assert_eq!(actual, data);
            assert_eq!(ends, 1);
            assert!(u.is_empty());
        }
        let mut u = Unpacker::default();
        let mut actual = Vec::new();
        for b in encoded {
            u.feed(&[b]).unwrap();
            while let Some(p) = u.next_packet().unwrap() {
                actual.extend(p.body);
            }
        }
        assert_eq!(actual, data);
    }
    #[test]
    fn malformed_lengths_and_changed_message_type_fail() {
        for n in [0_u16, 7, 32768, 65535] {
            let mut u = Unpacker::default();
            let mut h = vec![REPLY, 1];
            h.extend(n.to_be_bytes());
            h.extend([0; 4]);
            u.feed(&h).unwrap();
            assert!(u.next_packet().is_err());
        }
        let mut u = Unpacker::default();
        let bytes = split(REPLY, &[1, 2], 9).unwrap();
        u.feed(&bytes[..9]).unwrap();
        u.next_packet().unwrap();
        let mut rest = bytes[9..].to_vec();
        rest[0] = HELLO;
        u.feed(&rest).unwrap();
        assert!(u.next_packet().is_err());
    }
}
