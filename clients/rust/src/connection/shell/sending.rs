//! The shell owns producers and awaits them without blocking socket, close or
//! sibling work. The core receives only framed bytes. One packet per turn and
//! at most one queued MARS packet bound driver buffering independently of size.
use super::*;
use crate::requests::source::{Producer, SourceAt};
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
};

type Produced = (Box<dyn Producer>, Result<Option<Vec<u8>>>);
type Producing = Pin<Box<dyn Future<Output = Produced> + Send>>;
pub(super) struct Sending {
    kind: u8,
    body: Vec<u8>,
    at: usize,
    sources: VecDeque<SourceAt>,
    producing: Option<Producing>,
    piece: Vec<u8>,
    piece_at: usize,
    payload: Vec<u8>,
    number: u8,
    pub started: bool,
}
pub(super) struct SendAbort {
    pub cause: Error,
    pub deadline: Instant,
}
impl Sending {
    pub fn new(kind: u8, body: Vec<u8>, sources: Vec<SourceAt>) -> Self {
        Self {
            kind,
            body,
            at: 0,
            sources: sources.into(),
            producing: None,
            piece: Vec::new(),
            piece_at: 0,
            payload: Vec::new(),
            number: 1,
            started: false,
        }
    }
    fn packet(&mut self, last: bool, ignore: bool) -> Vec<u8> {
        let payload = if ignore {
            Vec::new()
        } else {
            std::mem::take(&mut self.payload)
        };
        let mut packet = vec![self.kind, u8::from(last) | if ignore { 2 } else { 0 }];
        packet.extend(((payload.len() + 8) as u16).to_be_bytes());
        packet.extend([0, 0, self.number, 0]);
        packet.extend(payload);
        self.number = self.number.wrapping_add(1);
        self.started = true;
        packet
    }
    /// No await and no I/O. Start a future only at its precise insertion point.
    /// Return at most one packet, retaining at most one source chunk plus a packet.
    fn advance(&mut self, room: usize) -> (Option<Vec<u8>>, bool) {
        loop {
            if self.payload.len() == room {
                return (Some(self.packet(false, false)), false);
            }
            if self.piece_at < self.piece.len() {
                let count = (room - self.payload.len()).min(self.piece.len() - self.piece_at);
                self.payload
                    .extend_from_slice(&self.piece[self.piece_at..self.piece_at + count]);
                self.piece_at += count;
                if self.piece_at == self.piece.len() {
                    self.piece.clear();
                    self.piece_at = 0;
                }
                continue;
            }
            let boundary = self.sources.front().map_or(self.body.len(), |s| s.offset);
            if self.at < boundary {
                let count = (room - self.payload.len()).min(boundary - self.at);
                self.payload
                    .extend_from_slice(&self.body[self.at..self.at + count]);
                self.at += count;
                continue;
            }
            if let Some(source) = self.sources.front_mut() {
                if self.producing.is_none() {
                    // Temporarily transfer source ownership into its own future;
                    // no borrowed producer escapes or is canceled on a wakeup.
                    let mut source = source.source.take().unwrap();
                    self.producing = Some(Box::pin(async move {
                        let produced = source.next().await;
                        (source, produced)
                    }));
                }
                return (None, false);
            }
            return (Some(self.packet(true, false)), true);
        }
    }
    fn produced(&mut self, (source, result): Produced) -> Result<()> {
        self.producing = None;
        let head = self.sources.front_mut().unwrap();
        head.source = Some(source);
        match result? {
            Some(bytes) => self.piece = bytes,
            None => {
                self.piece = self.sources.pop_front().unwrap().end;
            }
        }
        self.piece_at = 0;
        Ok(())
    }
}
fn poll_sources(
    channels: &mut BTreeMap<u64, DriverChannel>,
    cx: &mut Context<'_>,
) -> Poll<Vec<(u64, Produced)>> {
    let mut ready = Vec::new();
    // Poll each producer once per turn. One eager source cannot starve another.
    for (&id, channel) in channels {
        if let Some(sending) = &mut channel.sending
            && let Some(future) = &mut sending.producing
            && let Poll::Ready(produced) = future.as_mut().poll(cx)
        {
            ready.push((id, produced));
        }
    }
    if ready.is_empty() {
        Poll::Pending
    } else {
        Poll::Ready(ready)
    }
}
impl Driver {
    pub(super) async fn poll_sources_once(&mut self) -> Result<()> {
        let ready = poll_fn(|cx| {
            Poll::Ready(match poll_sources(&mut self.channels, cx) {
                Poll::Ready(value) => value,
                Poll::Pending => Vec::new(),
            })
        })
        .await;
        for (id, produced) in ready {
            self.source_result(id, produced)?;
        }
        Ok(())
    }
    pub(super) async fn await_source(
        channels: &mut BTreeMap<u64, DriverChannel>,
    ) -> Vec<(u64, Produced)> {
        poll_fn(|cx| poll_sources(channels, cx)).await
    }
    pub(super) fn source_result(&mut self, id: u64, produced: Produced) -> Result<()> {
        if let Err(error) = self
            .channels
            .get_mut(&id)
            .unwrap()
            .sending
            .as_mut()
            .unwrap()
            .produced(produced)
        {
            self.abort_sender(id, error)?;
        }
        Ok(())
    }
    pub(super) fn pump_senders(&mut self) -> Result<bool> {
        let mut progress = false;
        let ids = self.channels.keys().copied().collect::<Vec<_>>();
        for id in ids {
            if self.channels[&id].sending.is_none() {
                continue;
            }
            if self.channels[&id]
                .active
                .as_ref()
                .unwrap()
                .control
                .request()
                .is_some()
            {
                self.abort_sender(id, Error::canceled())?;
                continue;
            }
            if self.core.channel_sending(id) {
                continue;
            } // Await MARS credit before producing more.
            let channel = self.channels.get_mut(&id).unwrap();
            let sending = channel.sending.as_mut().unwrap();
            let first = !sending.started;
            let (packet, done) = sending.advance(self.core.session().packet_size - 8);
            if let Some(packet) = packet {
                progress = true;
                self.core.send_request_packet(
                    id,
                    channel.active.as_ref().unwrap().control.exchange,
                    packet,
                    first,
                )?;
            }
            if done {
                channel.sending = None;
            }
        }
        Ok(progress)
    }
    fn abort_sender(&mut self, id: u64, cause: Error) -> Result<()> {
        let channel = self.channels.get_mut(&id).unwrap();
        let mut sending = channel.sending.take().unwrap(); // Drops a pending source future, never detaches it.
        let exchange = channel.active.as_ref().unwrap().control.exchange;
        if !sending.started {
            self.core.abandon_unsent(id, exchange)?;
            let error = cause.at(Step::Exchange, Execution::NotSent).with_response(
                channel
                    .active
                    .as_ref()
                    .unwrap()
                    .control
                    .retention()
                    .record
                    .clone(),
            );
            channel.complete(Completion::Normal);
            if let Some(reply) = channel.begin.take() {
                let _ = reply.send(Err(error));
            }
        } else {
            let packet = sending.packet(true, true); // IGNORE + EOM discards the partial RPC.
            let deadline = channel
                .active
                .as_ref()
                .unwrap()
                .control
                .request()
                .and_then(|r| r.deadline)
                .or_else(|| Instant::now().checked_add(self.endpoint.cleanup_timeout));
            let Some(deadline) = deadline else {
                return Err(Error::cleanup(
                    cause,
                    Error::new(ErrorKind::Limit("source cleanup timeout")),
                ));
            };
            // Install the original cause before attempting the cleanup write:
            // an immediate TLS/write failure must not replace the producer error.
            channel.aborting = Some(SendAbort { cause, deadline });
            self.core.send_request_packet(id, exchange, packet, false)?;
        }
        Ok(())
    }
}
