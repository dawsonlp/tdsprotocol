//! Session multiplexing beneath TDS packets, above TLS plaintext.
//! Reference: MC-SMP v20251031 §§2.2, 3.1.4–3.1.5.
//!
//! Credit counts DATA frames, not TDS packets or tokens. Each receiver holds at
//! most four unconsumed frames. Only consuming a frame returns its credit; an
//! idle application therefore cannot make a sibling's receive queue grow.
//! Sequence/window arithmetic wraps at 2^32. Channel ids are never reused by
//! the connection, and FIN state stays here until the peer finishes its half.

use crate::{Error, ErrorKind, Result, wire};
use std::collections::{BTreeMap, VecDeque};

pub const HEADER: usize = 16;
pub const WINDOW: u32 = 4;
pub const SYN: u8 = 1;
pub const ACK: u8 = 2;
pub const FIN: u8 = 4;
pub const DATA: u8 = 8;

pub struct Frame {
    pub flags: u8,
    pub channel: u16,
    pub sequence: u32,
    pub window: u32,
    pub body: Vec<u8>,
}
impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let length = self
            .body
            .len()
            .checked_add(HEADER)
            .filter(|length| *length <= wire::MAX_PENDING)
            .ok_or_else(|| Error::new(ErrorKind::Limit("MARS frame (1 MiB)")))?;
        if !matches!(self.flags, SYN | ACK | FIN | DATA)
            || (self.flags != DATA && !self.body.is_empty())
        {
            return Err(Error::malformed(1, "MARS flags/payload"));
        }
        let mut bytes = vec![0x53, self.flags];
        bytes.extend(self.channel.to_le_bytes());
        bytes.extend((length as u32).to_le_bytes());
        bytes.extend(self.sequence.to_le_bytes());
        bytes.extend(self.window.to_le_bytes());
        bytes.extend(&self.body);
        Ok(bytes)
    }
}
#[derive(Default)]
pub struct Decoder {
    pending: Vec<u8>,
}
impl Decoder {
    pub fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        wire::append(&mut self.pending, bytes)
    }
    pub fn next_frame(&mut self) -> Result<Option<Frame>> {
        if self.pending.len() < HEADER {
            return Ok(None);
        }
        let h = &self.pending[..HEADER];
        let length = u32::from_le_bytes(h[4..8].try_into().unwrap()) as usize;
        if h[0] != 0x53 {
            return Err(Error::malformed(0, "MARS identifier"));
        }
        if !matches!(h[1], SYN | ACK | FIN | DATA) {
            return Err(Error::malformed(1, "MARS flags"));
        }
        if length < HEADER || (h[1] != DATA && length != HEADER) {
            return Err(Error::malformed(4, "MARS length"));
        }
        // A transport allocation bound, not an SMP protocol maximum.
        if length > wire::MAX_PENDING {
            return Err(Error::new(ErrorKind::Limit("MARS frame (1 MiB)")));
        }
        if self.pending.len() < length {
            return Ok(None);
        }
        let frame = Frame {
            flags: h[1],
            channel: u16::from_le_bytes(h[2..4].try_into().unwrap()),
            sequence: u32::from_le_bytes(h[8..12].try_into().unwrap()),
            window: u32::from_le_bytes(h[12..16].try_into().unwrap()),
            body: self.pending[HEADER..length].to_vec(),
        };
        self.pending.drain(..length);
        Ok(Some(frame))
    }
}

fn ahead(value: u32, previous: u32) -> bool {
    let distance = value.wrapping_sub(previous);
    distance != 0 && distance < (1 << 31)
}
struct Channel {
    sent: u32,
    received: u32,
    consumed: u32,
    send_window: u32,
    receive_window: u32,
    incoming: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
    fin_sent: bool,
    fin_received: bool,
}
impl Default for Channel {
    fn default() -> Self {
        Self {
            sent: 0,
            received: 0,
            consumed: 0,
            send_window: WINDOW,
            receive_window: WINDOW,
            incoming: VecDeque::new(),
            outgoing: VecDeque::new(),
            fin_sent: false,
            fin_received: false,
        }
    }
}
impl Channel {
    fn frame(&self, id: u16, flags: u8, body: Vec<u8>) -> Result<Vec<u8>> {
        Frame {
            flags,
            channel: id,
            sequence: self.sent,
            window: self.receive_window,
            body,
        }
        .encode()
    }
    fn pump(&mut self, id: u16) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        while !self.fin_sent && ahead(self.send_window, self.sent) {
            let Some(body) = self.outgoing.pop_front() else {
                break;
            };
            self.sent = self.sent.wrapping_add(1);
            out.push(self.frame(id, DATA, body)?);
        }
        Ok(out)
    }
}
pub(crate) struct Consumed {
    pub data: Vec<u8>,
    pub acknowledgement: Option<Vec<u8>>,
}
#[derive(Default)]
pub(crate) struct Multiplexer {
    decoder: Decoder,
    channels: BTreeMap<u16, Channel>,
}
impl Multiplexer {
    pub fn has_application_data(&self) -> bool {
        self.channels
            .values()
            .any(|c| !c.incoming.is_empty() || !c.outgoing.is_empty())
    }
    pub fn is_quiescent(&self) -> bool {
        self.channels.is_empty() && self.decoder.pending.is_empty()
    }

    pub fn open(&mut self, id: u16) -> Result<Vec<u8>> {
        let channel = Channel::default();
        let syn = channel.frame(id, SYN, Vec::new())?;
        self.channels.insert(id, channel);
        Ok(syn)
    }
    pub fn close(&mut self, id: u16) -> Result<Option<Vec<u8>>> {
        let Some(channel) = self.channels.get_mut(&id) else {
            return Ok(None);
        };
        if channel.fin_sent {
            return Ok(None);
        }
        channel.fin_sent = true;
        channel.incoming.clear();
        channel.outgoing.clear();
        let fin = channel.frame(id, FIN, Vec::new())?;
        if channel.fin_received {
            self.channels.remove(&id);
        }
        Ok(Some(fin))
    }
    pub fn peer_closed(&self, id: u16) -> bool {
        self.channels.get(&id).is_none_or(|c| c.fin_received)
    }
    pub fn sending(&self, id: u16) -> bool {
        self.channels
            .get(&id)
            .is_some_and(|c| !c.outgoing.is_empty())
    }
    pub fn queue(
        &mut self,
        id: u16,
        packets: impl Iterator<Item = Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>> {
        let channel = self
            .channels
            .get_mut(&id)
            .ok_or_else(|| Error::new(ErrorKind::Closed))?;
        if channel.fin_sent || channel.fin_received {
            return Err(Error::new(ErrorKind::Closed));
        }
        channel.outgoing.extend(packets);
        channel.pump(id)
    }
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.decoder.feed(bytes)?;
        let mut out = Vec::new();
        while let Some(frame) = self.decoder.next_frame()? {
            let channel = self
                .channels
                .get_mut(&frame.channel)
                .ok_or_else(|| Error::malformed(2, "unknown MARS channel"))?;
            if frame.flags == SYN {
                return Err(Error::malformed(1, "server initiated MARS channel"));
            }
            if channel.fin_received {
                return Err(Error::malformed(1, "MARS frame after peer FIN"));
            }
            // DATA already in flight can arrive after our FIN; SMP says ignore it.
            if frame.flags == DATA && channel.fin_sent {
                continue;
            }
            let expected = channel
                .received
                .wrapping_add(u32::from(frame.flags == DATA));
            if !channel.fin_sent && frame.sequence != expected {
                return Err(Error::malformed(8, "MARS sequence"));
            }
            if frame.window != channel.send_window && !ahead(frame.window, channel.send_window) {
                return Err(Error::malformed(12, "MARS send window moved backwards"));
            }
            if ahead(frame.window, channel.send_window) {
                channel.send_window = frame.window;
            }
            match frame.flags {
                DATA => {
                    if !ahead(channel.receive_window, channel.received)
                        || channel.incoming.len() >= WINDOW as usize
                    {
                        return Err(Error::malformed(8, "MARS receive window exceeded"));
                    }
                    channel.received = frame.sequence;
                    channel.incoming.push_back(frame.body);
                }
                FIN => {
                    channel.fin_received = true;
                }
                ACK => {}
                _ => unreachable!(),
            }
            out.extend(channel.pump(frame.channel)?);
            if channel.fin_sent && channel.fin_received {
                self.channels.remove(&frame.channel);
            }
        }
        Ok(out)
    }
    pub fn consume(&mut self, id: u16) -> Result<Option<Consumed>> {
        let Some(channel) = self.channels.get_mut(&id) else {
            return Ok(None);
        };
        let Some(data) = channel.incoming.pop_front() else {
            return Ok(None);
        };
        channel.consumed = channel.consumed.wrapping_add(1);
        let ack = if channel.receive_window.wrapping_sub(channel.consumed) < WINDOW / 2 {
            channel.receive_window = channel.consumed.wrapping_add(WINDOW);
            Some(channel.frame(id, ACK, Vec::new())?)
        } else {
            None
        };
        Ok(Some(Consumed {
            data,
            acknowledgement: ack,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn data(id: u16, seq: u32) -> Vec<u8> {
        Frame {
            flags: DATA,
            channel: id,
            sequence: seq,
            window: WINDOW,
            body: vec![42],
        }
        .encode()
        .unwrap()
    }
    #[test]
    fn fragmented_headers_lengths_and_flags() {
        let bytes = data(7, 1);
        for cut in 0..=bytes.len() {
            let mut decoder = Decoder::default();
            decoder.feed(&bytes[..cut]).unwrap();
            if cut < bytes.len() {
                assert!(decoder.next_frame().unwrap().is_none());
            }
            decoder.feed(&bytes[cut..]).unwrap();
            assert_eq!(decoder.next_frame().unwrap().unwrap().body, [42]);
        }
        for length in [0_u32, 15, u32::MAX] {
            let mut bad = bytes.clone();
            bad[4..8].copy_from_slice(&length.to_le_bytes());
            let mut d = Decoder::default();
            d.feed(&bad).unwrap();
            assert!(d.next_frame().is_err());
        }
        for flag in [0, 3, 6, 16] {
            let mut bad = bytes.clone();
            bad[1] = flag;
            let mut d = Decoder::default();
            d.feed(&bad).unwrap();
            assert!(d.next_frame().is_err());
        }
    }
    #[test]
    fn credit_is_per_consumed_frame_and_siblings_are_independent() {
        let mut m = Multiplexer::default();
        m.open(1).unwrap();
        m.open(2).unwrap();
        let output = m.queue(1, (0..6).map(|_| vec![1])).unwrap();
        assert_eq!(output.len(), 4);
        assert!(m.sending(1));
        for n in 1..=4 {
            m.feed(&data(1, n)).unwrap();
        }
        m.feed(&data(2, 1)).unwrap();
        assert_eq!(m.consume(2).unwrap().unwrap().data, [42]);
        assert!(m.consume(1).unwrap().unwrap().acknowledgement.is_none());
        assert!(m.consume(1).unwrap().unwrap().acknowledgement.is_none());
        assert!(m.consume(1).unwrap().unwrap().acknowledgement.is_some());
        let ack = Frame {
            flags: ACK,
            channel: 1,
            sequence: 4,
            window: 6,
            body: vec![],
        }
        .encode()
        .unwrap();
        assert_eq!(m.feed(&ack).unwrap().len(), 2);
        assert!(!m.sending(1));
        let mut bad = Multiplexer::default();
        bad.open(1).unwrap();
        assert!(bad.feed(&data(1, 2)).is_err());
        let mut bad = Multiplexer::default();
        bad.open(1).unwrap();
        for n in 1..=4 {
            bad.feed(&data(1, n)).unwrap();
        }
        assert!(bad.feed(&data(1, 5)).is_err());
    }
    #[test]
    fn wraparound_and_fin_handshake() {
        let mut m = Multiplexer::default();
        m.open(1).unwrap();
        let c = m.channels.get_mut(&1).unwrap();
        c.sent = u32::MAX;
        c.send_window = 2;
        c.received = u32::MAX;
        c.consumed = u32::MAX;
        c.receive_window = 3;
        assert_eq!(m.queue(1, std::iter::once(vec![1])).unwrap().len(), 1);
        m.feed(&data(1, 0)).unwrap();
        assert!(m.consume(1).unwrap().is_some());
        m.close(1).unwrap();
        m.feed(&data(1, 1)).unwrap(); // In-flight DATA after FIN is ignored.
        let fin = Frame {
            flags: FIN,
            channel: 1,
            sequence: 0,
            window: 4,
            body: vec![],
        }
        .encode()
        .unwrap();
        m.feed(&fin).unwrap();
        assert!(!m.channels.contains_key(&1));
    }
}
