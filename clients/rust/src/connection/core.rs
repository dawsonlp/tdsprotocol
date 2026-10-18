//! Connection protocol without sockets, task scheduling, or clock acquisition.
//! Reference: `docs/design/3-reference/connect.md`; MS-TDS v20260617 §3.2.
//!
//! The shell supplies received bytes and certificate-validation time, performs
//! returned writes, and invokes channel procedures. TLS consumes and produces
//! memory buffers here. Under 7.4 its handshake records travel *inside* PRELOGIN
//! packets; after the handshake, complete TDS packets travel *inside* TLS.
//!
//! The registry, not a response destructor, decides whether a channel is busy.
//! Channel/exchange identities never grant SQL Server permissions.

#[cfg(test)]
use crate::Batch;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore,
    pki_types::{ServerName, UnixTime},
    time_provider::TimeProvider,
};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read, Write},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use super::ProtocolVersion;
use crate::{
    Error, ErrorKind, Execution, Record, Request, Result, Step,
    login7::{Login, TDS_7_4},
    mars::Multiplexer,
    observe::{Level, Observations, Trace},
    packet::{self, Unpacker},
    prelogin,
    session::Session,
    tokens::Decoder,
    wire,
};

#[derive(Debug)]
struct SuppliedTime(AtomicU64);
impl TimeProvider for SuppliedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            self.0.load(Ordering::Relaxed),
        )))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    SecureFirst,
    Hello,
    Handshake,
    Login,
    Ready,
}

#[derive(Default)]
struct ResponseStream {
    packets: Unpacker,
    decoder: Decoder,
    message_end: bool,
    terminal: Option<Record>,
    session_id: u16,
    timing: crate::response::Timing,
    first_packet_seen: bool,
}
impl ResponseStream {
    fn decoded(
        &mut self,
        observations: &mut Observations,
        channel: Option<u64>,
    ) -> Result<Option<Record>> {
        self.decoder
            .set_inspection(observations.level == Level::Full);
        let result = self.decoder.next_record();
        if let Some(node) = self.decoder.take_inspection() {
            if !matches!(result, Ok(Some(_))) {
                observations.fields("receive", channel, node);
            } else {
                observations.token_fields(channel, node);
            }
        }
        result
    }
    /// Deliver final completion only after its enclosing message also ends.
    /// A final token may precede an empty LAST packet; extra payload is invalid.
    fn next_token(
        &mut self,
        canceling: bool,
        observations: &mut Observations,
        channel: Option<u64>,
        record_packets: bool,
        elapsed: Option<Duration>,
    ) -> Result<Option<Record>> {
        loop {
            if self.terminal.is_some() {
                if !self.decoder.is_empty() {
                    return Err(Error::malformed(0, "data after final completion"));
                }
                if self.message_end {
                    self.message_end = false;
                    return Ok(self.terminal.take());
                }
            } else if let Some(record) = self.decoded(observations, channel)? {
                if matches!(&record,Record::Done(done) if
                    if canceling { done.acknowledges_cancel() } else { done.is_final() })
                {
                    self.terminal = Some(record);
                    continue;
                }
                return Ok(Some(record));
            } else if self.message_end {
                // An Attention acknowledgement can be a later message, after
                // the ordinary response has already ended. Do not free the
                // channel at that ordinary final DONE. A partial token at EOM
                // remains malformed, even while canceling.
                if canceling && self.decoder.is_empty() {
                    self.message_end = false;
                    continue;
                }
                return Err(Error::malformed(
                    0,
                    "message ended before a complete terminal token",
                ));
            }
            let Some(packet) = self.packets.next_packet()? else {
                return Ok(None);
            };
            if record_packets {
                observations.received(channel, &packet);
            }
            if packet.kind != packet::REPLY {
                return Err(Error::malformed(0, "response packet type"));
            }
            if !self.first_packet_seen {
                self.first_packet_seen = true;
                self.timing.first_packet = elapsed;
            }
            self.session_id = packet.session_id;
            self.decoder.feed(&packet.body)?;
            self.message_end = packet.last;
        }
    }
    fn configure_features(&mut self, features: &BTreeMap<u8, Vec<u8>>) -> Result<()> {
        self.decoder
            .set_column_encryption(features.get(&4).is_some_and(|v| v == &[1]));
        self.decoder
            .set_utf8_support(features.get(&10).is_some_and(|v| v == &[1]));
        self.decoder
            .set_classification_version(features.get(&9).filter(|v| v[1] == 1).map_or(0, |v| v[0]))
    }
    fn is_empty(&self) -> bool {
        self.packets.is_empty()
            && self.decoder.is_empty()
            && !self.message_end
            && self.terminal.is_none()
    }
}
#[derive(Default)]
struct ChannelState {
    pending_bulk: bool,
    opening_bulk: bool,
    exchange_failed: bool,
    wire_id: u16,
    exchange: Option<u64>,
    canceling: bool,
    request_label: &'static str,
    request_kind: u8,
    stream: ResponseStream,
}

pub struct ConnectionCore {
    version: ProtocolVersion,
    phase: Phase,
    login: Option<Login>,
    tls: ClientConnection,
    time: Arc<SuppliedTime>,
    stream: ResponseStream,
    hello_body: Vec<u8>,
    output: Vec<u8>,
    login_ack: bool,
    channels: BTreeMap<u64, ChannelState>,
    last_channel: Option<u64>,
    mars: bool,
    mux: Multiplexer,
    next_wire: u32,
    wire_channels: BTreeMap<u16, u64>,
    recovery_requested: bool,
    feature_requests: BTreeMap<u8, Vec<u8>>,
    initial_states: Option<Vec<u8>>,
    recovery: Option<crate::session::Recovery>,
    failure: Option<(Step, Execution)>,
    session: Session,
    login_session: Option<Session>,
    reset_pending: bool,
    login_route: Option<crate::tokens::RoutingChange>,
    observations: Observations,
    elapsed: Option<Duration>,
}

impl ConnectionCore {
    /// `roots` is explicit: there is no implicit insecure mode or trust store.
    /// `now` comes from the shell. Tests can supply certificate-validation time.
    pub fn new(
        login: Login,
        roots: RootCertStore,
        server_name: ServerName<'static>,
        now: u64,
        version: ProtocolVersion,
    ) -> Result<Self> {
        Self::new_with_mars(login, roots, server_name, now, version, false)
    }
    /// MARS is negotiated in PRELOGIN and starts only after successful LOGIN7.
    pub fn new_with_mars(
        login: Login,
        roots: RootCertStore,
        server_name: ServerName<'static>,
        now: u64,
        version: ProtocolVersion,
        mars: bool,
    ) -> Result<Self> {
        let time = Arc::new(SuppliedTime(AtomicU64::new(now)));
        // Use rustls's standard aws-lc provider explicitly, without mutating the
        // application's global provider. TDS 7.4 on SQL Server uses TLS <= 1.2.
        let versions = match version {
            ProtocolVersion::V7_4 => vec![&rustls::version::TLS12],
            ProtocolVersion::V8_0 => vec![&rustls::version::TLS13, &rustls::version::TLS12],
        };
        let mut config = ClientConfig::builder_with_details(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            time.clone(),
        )
        .with_protocol_versions(&versions)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        if version == ProtocolVersion::V8_0 {
            config.alpn_protocols = vec![b"tds/8.0".to_vec()];
        }
        let mut tls = ClientConnection::new(Arc::new(config), server_name)?;
        let mut output = Vec::new();
        if version == ProtocolVersion::V8_0 {
            while tls.wants_write() {
                tls.write_tls(&mut output)?;
            }
        } else {
            output = packet::split(
                packet::HELLO,
                &prelogin::encode_with_mars(mars),
                packet::DEFAULT_SIZE,
            )?;
        }
        let feature_requests = login.requested_features()?;
        let recovery_requested = login.session_recovery;
        Ok(Self {
            version,
            phase: if version == ProtocolVersion::V8_0 {
                Phase::SecureFirst
            } else {
                Phase::Hello
            },
            login: Some(login),
            tls,
            time,
            stream: ResponseStream::default(),
            hello_body: Vec::new(),
            output,
            login_ack: false,
            channels: BTreeMap::new(),
            last_channel: None,
            mars,
            mux: Multiplexer::default(),
            next_wire: 0,
            wire_channels: BTreeMap::new(),
            recovery_requested,
            feature_requests,
            initial_states: None,
            recovery: None,
            failure: None,
            session: Session::default(),
            login_session: None,
            reset_pending: false,
            login_route: None,
            observations: Observations::default(),
            elapsed: None,
        })
    }
    pub fn step(&self) -> Step {
        if let Some((step, _)) = self.failure {
            return step;
        }
        match self.phase {
            Phase::SecureFirst => Step::Secure,
            Phase::Hello => Step::Hello,
            Phase::Handshake => Step::Secure,
            Phase::Login => Step::Login,
            Phase::Ready if self.is_canceling() => Step::Cleanup,
            Phase::Ready if self.is_busy() => Step::Exchange,
            Phase::Ready => Step::Ready,
        }
    }
    pub fn execution(&self) -> Execution {
        if let Some((_, execution)) = self.failure {
            return execution;
        }
        if self.is_busy() {
            Execution::PossiblyExecuted
        } else {
            Execution::NotSent
        }
    }
    pub fn is_ready(&self) -> bool {
        self.failure.is_none() && self.phase == Phase::Ready
    }
    pub fn is_busy(&self) -> bool {
        self.channels
            .values()
            .any(|channel| channel.exchange.is_some())
    }
    pub fn is_canceling(&self) -> bool {
        self.channels.values().any(|channel| channel.canceling)
    }
    pub(crate) fn pending_bulk(&self, id: u64) -> bool {
        self.channels.get(&id).is_some_and(|c| c.pending_bulk)
    }
    pub fn channel_busy(&self, id: u64) -> bool {
        self.channels.get(&id).is_some_and(|c| c.exchange.is_some())
    }
    pub fn channel_canceling(&self, id: u64) -> bool {
        self.channels.get(&id).is_some_and(|c| c.canceling)
    }
    pub fn channel_sending(&self, id: u64) -> bool {
        self.mars
            && self
                .channels
                .get(&id)
                .is_some_and(|c| self.mux.sending(c.wire_id))
    }
    pub fn channel_peer_closed(&self, id: u64) -> bool {
        self.mars
            && self
                .channels
                .get(&id)
                .is_some_and(|c| self.mux.peer_closed(c.wire_id))
    }
    pub fn mars_enabled(&self) -> bool {
        self.mars
    }

    pub fn set_time(&self, unix_seconds: u64) {
        self.time.0.store(unix_seconds, Ordering::Relaxed);
    }
    /// Configure descriptions only between exchanges. No application callback is
    /// invoked here. Drain `take_observations` after each step, before sending its
    /// bytes or publishing a result, so recording failure can revoke the driver.
    pub fn configure_observation(
        &mut self,
        level: Level,
        capture: bool,
        keep_password: bool,
    ) -> Result<()> {
        if self.is_busy() {
            return Err(Error::new(ErrorKind::State(
                "observation can change only between exchanges",
            )));
        }
        self.observations.level = level;
        self.observations.reset_input();
        self.observations.capture = capture;
        self.observations.keep_password = keep_password;
        Ok(())
    }
    pub fn take_observations(&mut self) -> Vec<Trace> {
        self.observations.take()
    }
    /// Supply monotonic time since this physical epoch began. No clock is read
    /// by the core. A caller that supplies no time receives unknown milestones.
    pub fn set_elapsed(&mut self, elapsed: Duration) {
        self.elapsed = Some(elapsed);
    }
    /// Latest milestones for this channel's current or most recent exchange.
    pub fn channel_timing(&self, id: u64) -> Option<crate::response::Timing> {
        self.channels.get(&id).map(|channel| channel.stream.timing)
    }
    pub fn disable_observer(&mut self) {
        self.observations.level = Level::Off;
    }
    pub fn observe_request_sent(&mut self, id: u64) {
        self.channels.get_mut(&id).unwrap().stream.timing.sent = self.elapsed;
        // Attention is announced by send_channel, including private drains that
        // have no public Begin reply. A public bulk abort must not announce it
        // twice: saved replay pairs one event with one physical message.
        if self.channels[&id].request_kind == packet::ATTENTION {
            return;
        }
        self.observations.message(
            "send",
            self.channels[&id].request_label,
            self.mars.then_some(id),
        );
    }
    /// The constructor produced the first flight before configuration existed.
    /// The shell calls this once, before taking that flight's bytes.
    pub fn observe_start(&mut self) -> Result<()> {
        if !self.observations.enabled() {
            return Ok(());
        }
        let step = self.step();
        self.observations
            .event("step", || format!("{step:?}"), None, None);
        if self.version == ProtocolVersion::V7_4 {
            let body = prelogin::encode_with_mars(self.mars);
            self.observations.sent(
                packet::HELLO,
                &body,
                &self.output,
                packet::DEFAULT_SIZE,
                None,
            )?;
            self.observations.message("send", "hello", None);
        }
        Ok(())
    }
    pub fn take_output(&mut self) -> Vec<u8> {
        if self.failure.is_some() {
            self.output.clear();
        }
        std::mem::take(&mut self.output)
    }
    pub fn session(&self) -> &Session {
        &self.session
    }
    #[cfg(feature = "encryption")]
    pub(crate) fn reuse_reset_pending(&self) -> bool {
        self.reset_pending
    }
    pub fn is_failed(&self) -> bool {
        self.failure.is_some()
    }
    #[cfg(feature = "tokio")]
    pub(crate) fn has_output(&self) -> bool {
        !self.output.is_empty()
    }
    fn fail(&mut self, error: Error) -> Error {
        let position = (self.step(), self.execution());
        self.failure = Some(position);
        self.output.clear();
        error.at(position.0, position.1)
    }

    /// Feed transport bytes; the shell annotates any error with `step()`.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        if self.is_failed() {
            return Err(Error::new(ErrorKind::Closed).at(self.step(), self.execution()));
        }
        let before = self.step();
        self.feed_inner(bytes).map_err(|e| self.fail(e))?;
        let step = self.step();
        if step != before {
            self.observations
                .event("step", || format!("{step:?}"), None, None);
        }
        Ok(())
    }
    fn feed_inner(&mut self, bytes: &[u8]) -> Result<()> {
        if self.version == ProtocolVersion::V8_0 {
            self.feed_tls(bytes, self.phase != Phase::SecureFirst)?;
            match self.phase {
                Phase::SecureFirst if !self.tls.is_handshaking() => {
                    if self.tls.alpn_protocol() != Some(b"tds/8.0") {
                        return Err(Error::new(ErrorKind::Unsupported(
                            "TDS 8.0 ALPN was not accepted",
                        )));
                    }
                    let mut records = Vec::new();
                    self.drain_tls(&mut records)?;
                    self.output.extend(records);
                    self.phase = Phase::Hello;
                    self.send(packet::HELLO, &prelogin::encode_with_mars(self.mars))?;
                }
                Phase::SecureFirst => {
                    let mut records = Vec::new();
                    self.drain_tls(&mut records)?;
                    self.output.extend(records);
                }
                Phase::Hello => {
                    while let Some(packet) = self.stream.packets.next_packet()? {
                        if packet.kind != packet::REPLY {
                            return Err(Error::malformed(0, "PRELOGIN reply type"));
                        }
                        wire::append(&mut self.hello_body, &packet.body)?;
                        if packet.last {
                            self.observations.message("receive", "hello reply", None);
                            prelogin::check_reply_with_mars(
                                &std::mem::take(&mut self.hello_body),
                                true,
                                self.mars,
                            )?;
                            self.begin_login()?;
                            break;
                        }
                    }
                }
                Phase::Login => self.read_login()?,
                Phase::Ready => {}
                Phase::Handshake => {
                    return Err(Error::new(ErrorKind::State(
                        "TDS 8.0 cannot tunnel its TLS handshake",
                    )));
                }
            }
            return Ok(());
        }
        match self.phase {
            Phase::Hello | Phase::Handshake => {
                self.stream.packets.feed(bytes)?;
                while let Some(packet) = self.stream.packets.next_packet()? {
                    self.observations.received(None, &packet);
                    let expected = if self.phase == Phase::Hello {
                        packet::REPLY
                    } else {
                        packet::HELLO
                    };
                    if packet.kind != expected {
                        return Err(Error::malformed(0, "connect packet type"));
                    }
                    wire::append(&mut self.hello_body, &packet.body)?;
                    if !packet.last {
                        continue;
                    }
                    let message = std::mem::take(&mut self.hello_body);
                    if self.phase == Phase::Hello {
                        self.observations.message("receive", "hello reply", None);
                        prelogin::check_reply_with_mars(&message, false, self.mars)?;
                        self.phase = Phase::Handshake;
                    } else {
                        self.observations.message(
                            "receive",
                            "TLS handshake in hello packets",
                            None,
                        );
                        self.feed_tls(&message, false)?;
                    }
                    let mut records = Vec::new();
                    self.drain_tls(&mut records)?;
                    if !records.is_empty() {
                        let packets = packet::split(packet::HELLO, &records, packet::DEFAULT_SIZE)?;
                        self.observations.sent(
                            packet::HELLO,
                            &records,
                            &packets,
                            packet::DEFAULT_SIZE,
                            None,
                        )?;
                        self.observations
                            .message("send", "TLS handshake in hello packets", None);
                        self.output.extend(packets);
                    }
                    if self.phase == Phase::Handshake && !self.tls.is_handshaking() {
                        if !self.stream.packets.is_empty() {
                            return Err(Error::malformed(0, "bytes after TLS handshake envelope"));
                        }
                        self.begin_login()?;
                        break;
                    }
                }
            }
            Phase::Login | Phase::Ready => {
                self.feed_tls(bytes, true)?;
                if self.phase == Phase::Login {
                    self.read_login()?;
                }
            }
            Phase::SecureFirst => {
                return Err(Error::new(ErrorKind::State(
                    "TDS 7.4 requires PRELOGIN before TLS",
                )));
            }
        }
        Ok(())
    }

    fn begin_login(&mut self) -> Result<()> {
        self.phase = Phase::Login;
        self.session.tls_version = self.tls.protocol_version();
        let login = self
            .login
            .take()
            .ok_or_else(|| Error::new(ErrorKind::State("login already consumed")))?;
        self.send(packet::LOGIN, &login.encode()?)
    }

    fn drain_tls(&mut self, target: &mut Vec<u8>) -> Result<()> {
        while self.tls.wants_write() {
            if self.tls.write_tls(target)? == 0 {
                return Err(Error::new(ErrorKind::State("TLS output made no progress")));
            }
        }
        Ok(())
    }
    fn feed_tls(&mut self, bytes: &[u8], application: bool) -> Result<()> {
        let mut cursor = Cursor::new(bytes);
        while (cursor.position() as usize) < bytes.len() {
            if self.tls.read_tls(&mut cursor)? == 0 {
                return Err(Error::new(ErrorKind::Closed));
            }
            let io = self.tls.process_new_packets()?;
            if io.peer_has_closed() {
                return Err(Error::new(ErrorKind::Closed));
            }
            if application {
                let mut plain = [0; 16384];
                loop {
                    match self.tls.reader().read(&mut plain) {
                        Ok(0) => break,
                        Ok(n) => self.feed_application(&plain[..n])?,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
        if application {
            let mut records = Vec::new();
            self.drain_tls(&mut records)?;
            self.output.extend(records);
        }
        Ok(())
    }
    fn feed_application(&mut self, bytes: &[u8]) -> Result<()> {
        if self.phase != Phase::Ready || !self.mars {
            self.observations.received_bytes(None, bytes)?;
        }
        if self.phase != Phase::Ready {
            return self.stream.packets.feed(bytes);
        }
        if self.mars {
            let frames = self.mux.feed(bytes)?;
            self.send_frames(frames)
        } else if let Some(channel) = self.channels.values_mut().next() {
            channel.stream.packets.feed(bytes)
        } else {
            Err(Error::malformed(0, "unsolicited response without channel"))
        }
    }
    fn send_frames(&mut self, frames: impl IntoIterator<Item = Vec<u8>>) -> Result<()> {
        for frame in frames {
            if self.observations.enabled() && frame[1] == crate::mars::DATA {
                let wire = u16::from_le_bytes([frame[2], frame[3]]);
                let id = *self
                    .wire_channels
                    .get(&wire)
                    .ok_or_else(|| Error::malformed(2, "unknown outgoing wire channel"))?;
                self.observations
                    .packet("send", Some(id), &frame[16..], &frame[16..]);
            }
            self.encrypt(&frame)?;
        }
        Ok(())
    }
    fn encrypt(&mut self, bytes: &[u8]) -> Result<()> {
        self.tls.writer().write_all(bytes)?;
        let mut records = Vec::new();
        self.drain_tls(&mut records)?;
        self.output.extend(records);
        Ok(())
    }
    fn send_channel(&mut self, id: u64, kind: u8, body: &[u8]) -> Result<()> {
        let mut plain = packet::split(kind, body, self.session.packet_size)?;
        if matches!(kind, packet::BATCH | packet::RPC | packet::TRANSACTION) && self.reset_pending {
            plain[1] |= 0x08; // RESETCONNECTION: first packet only, after successful encoding.
            self.reset_pending = false;
        }
        if !self.mars {
            self.observations
                .sent(kind, body, &plain, self.session.packet_size, None)?;
            for packet in plain.chunks(self.session.packet_size) {
                self.encrypt(packet)?;
            }
            if kind == packet::ATTENTION {
                self.observations.message("send", "attention", None);
            }
            return Ok(());
        }
        let frames = self.mux.queue(
            self.channels[&id].wire_id,
            plain.chunks(self.session.packet_size).map(<[u8]>::to_vec),
        )?;
        if kind == packet::ATTENTION {
            self.observations.message("send", "attention", Some(id));
        }
        self.send_frames(frames)
    }
    fn send(&mut self, kind: u8, body: &[u8]) -> Result<()> {
        let plain = packet::split(kind, body, self.session.packet_size)?;
        self.observations
            .sent(kind, body, &plain, self.session.packet_size, None)?;
        self.observations.message(
            "send",
            if kind == packet::HELLO {
                "hello"
            } else {
                "log in"
            },
            None,
        );
        // Preserve packet boundaries through encryption. SQL Server 2025 closes
        // a 7.4 connection when arbitrarily split TLS records cut across packets.
        // See Packet > Edge cases and Python's Link.plain. Drain TLS after EACH
        // packet, not after the concatenated message. The >64 KiB live request
        // guards this observed interoperability constraint.
        for packet in plain.chunks(self.session.packet_size) {
            self.tls.writer().write_all(packet)?;
            let mut records = Vec::new();
            self.drain_tls(&mut records)?;
            self.output.extend(records);
        }
        Ok(())
    }

    fn apply(&mut self, record: &Record) -> Result<()> {
        if let Record::Environment(change) = record {
            if let crate::tokens::EnvironmentChange::Bytes { kind: 18, new, old } = change {
                if !new.is_empty() || !old.is_empty() {
                    return Err(Error::malformed(0, "reset acknowledgement"));
                }
                let login = self
                    .login_session
                    .as_ref()
                    .ok_or_else(|| Error::malformed(0, "reset before login"))?;
                self.session.restore(login);
                if let Some(recovery) = &mut self.recovery {
                    recovery.reset();
                }
            } else {
                self.session.apply(change)?;
            }
        }
        if let Record::SessionState(change) = record {
            self.recovery
                .as_mut()
                .ok_or_else(|| Error::malformed(0, "SESSIONSTATE without negotiated recovery"))?
                .follow(change);
        }
        Ok(())
    }
    fn read_login(&mut self) -> Result<()> {
        while let Some(record) =
            self.stream
                .next_token(false, &mut self.observations, None, false, None)?
        {
            self.observations.record(None, &record);
            self.session.session_id = self.stream.session_id;
            if let Record::Environment(crate::tokens::EnvironmentChange::Routing(route)) = &record {
                if route.old_length != 0 {
                    return Err(Error::malformed(0, "routing old value"));
                }
                self.login_route = Some(route.clone());
            } else {
                self.apply(&record)?;
            }
            match record {
                Record::FeatureAck(features) => {
                    for (id, data) in features {
                        if !self.feature_requests.contains_key(&id)
                            || self.session.features.contains_key(&id)
                        {
                            return Err(Error::malformed(
                                0,
                                "unrequested or duplicate feature acknowledgement",
                            ));
                        }
                        if id == 1 {
                            self.initial_states = Some(data.clone());
                        } else {
                            let valid = match id {
                                4 => data == [1],
                                9 => {
                                    data.len() == 2
                                        && [1, 2].contains(&data[0])
                                        && data[0] <= self.feature_requests[&id][0]
                                        && data[1] <= 1
                                }
                                10 => data.len() == 1 && data[0] <= 1,
                                13 => data == [1],
                                14 => {
                                    data.len() == 1
                                        && data[0] != 0
                                        && data[0] <= self.feature_requests[&id][0]
                                }
                                _ => false,
                            };
                            if !valid {
                                return Err(Error::malformed(
                                    0,
                                    "invalid feature acknowledgement version",
                                ));
                            }
                        }
                        if id == 4 {
                            self.observations.column_encryption = true;
                        }
                        self.session.features.insert(id, data);
                    }
                }
                Record::LoginAck {
                    version,
                    server_version,
                    ..
                } => {
                    if version != TDS_7_4 {
                        return Err(Error::new(ErrorKind::Unsupported("server TDS version")));
                    }
                    if self.login_ack {
                        return Err(Error::malformed(0, "duplicate LOGINACK"));
                    }
                    self.login_ack = true;
                    self.session.server_version = Some(server_version);
                }
                Record::Error(message) => {
                    return Err(Error::new(ErrorKind::Server(Box::new(message))));
                }
                Record::Done(done) if done.is_final() => {
                    if !self.login_ack || done.has_error() || done.acknowledges_cancel() {
                        return Err(Error::malformed(
                            0,
                            "login completion without successful LOGINACK",
                        ));
                    }
                    if let Some(route) = self.login_route.take() {
                        if route.protocol != 0 {
                            return Err(Error::new(ErrorKind::Unsupported(
                                "routing protocol is not TCP",
                            )));
                        }
                        let server = route
                            .server
                            .to_string()
                            .map_err(|_| Error::malformed(0, "routing server UTF-16"))?;
                        if route.port == 0 || server.is_empty() || server.contains('\0') {
                            return Err(Error::malformed(0, "routing target"));
                        }
                        self.observations.message("receive", "login reply", None);
                        return Err(Error::new(ErrorKind::Routed(crate::Route {
                            server,
                            port: route.port,
                        })));
                    }
                    self.observations.message("receive", "login reply", None);
                    self.login_session = Some(self.session.clone());
                    if let Some(bytes) = self.initial_states.take() {
                        self.recovery =
                            Some(crate::session::Recovery::new(self.session.clone(), &bytes)?);
                    }
                    self.phase = Phase::Ready;
                    return Ok(());
                }
                Record::Environment(_) | Record::Message(_) => {}
                _ => return Err(Error::malformed(0, "unexpected login token")),
            }
        }
        Ok(())
    }
    /// Encode only server-reported reconstructible state. A reset awaiting its
    /// first batch means the recoverable state is the original login baseline.
    pub fn recovery_data(&self) -> Result<Vec<u8>> {
        if self
            .channels
            .values()
            .any(|c| c.pending_bulk || c.opening_bulk)
        {
            return Err(Error::new(ErrorKind::SessionNotRecovered {
                reason: "an unfinished bulk conversation cannot be recovered".into(),
                cause: None,
            }));
        }

        let recovery = self.recovery.as_ref().ok_or_else(|| {
            Error::new(ErrorKind::SessionNotRecovered {
                reason: if self.recovery_requested {
                    "server did not acknowledge session recovery"
                } else {
                    "login did not request session recovery"
                }
                .into(),
                cause: None,
            })
        })?;
        if let Some(reason) = recovery.refusal() {
            return Err(Error::new(ErrorKind::SessionNotRecovered {
                reason,
                cause: None,
            }));
        }
        recovery.data(&self.session, self.reset_pending)
    }
    /// A new protocol core adopts continuing session state, not old responses.
    /// Callers open surviving logical ids in order, allocating fresh wire ids.
    pub fn adopt_recovery(&mut self, old: &Self) -> Result<()> {
        if !self.is_ready() || self.recovery.is_none() {
            return Err(Error::new(ErrorKind::SessionNotRecovered {
                reason: "server logged in without agreeing to recover the session".into(),
                cause: None,
            }));
        }
        self.recovery = old.recovery.as_ref().map(crate::session::Recovery::adopted);
        self.login_session.clone_from(&old.login_session);
        self.reset_pending = old.reset_pending;
        Ok(())
    }
    pub fn observe_recovery(&mut self, done: bool) {
        self.observations.event(
            "step",
            || {
                if done {
                    "recovered · session state restored".into()
                } else {
                    "recover · new physical connection".into()
                }
            },
            None,
            None,
        );
    }

    /// Pool return never cleans an active exchange implicitly. The shell first
    /// revokes descendants and closes idle channels, then drains FIN obligations.
    pub fn can_release(&self) -> bool {
        self.is_ready()
            && !self.is_busy()
            && self
                .channels
                .values()
                .all(|c| !c.pending_bulk && c.stream.is_empty())
            && (!self.mars || !self.mux.has_application_data())
    }
    pub fn release_complete(&self) -> bool {
        self.can_release()
            && self.channels.is_empty()
            && self.stream.is_empty()
            && (!self.mars || self.mux.is_quiescent())
            && self.output.is_empty()
    }
    pub fn prepare_reuse(&mut self) -> Result<()> {
        if !self.release_complete() {
            return Err(Error::new(ErrorKind::State("connection is not quiescent")));
        }
        if self.mars && self.last_channel == Some(u64::from(u16::MAX)) {
            return Err(Error::new(ErrorKind::Limit("MARS channel identities")));
        }
        self.reset_pending = true;
        Ok(())
    }
    pub fn open_channel(&mut self, id: u64) -> Result<()> {
        if !self.is_ready() {
            return Err(Error::new(ErrorKind::Closed));
        }
        if self.last_channel.is_some_and(|last| id <= last) {
            return Err(Error::new(ErrorKind::State(
                "channel lifetime identity must increase",
            )));
        }
        if !self.mars && !self.channels.is_empty() {
            return Err(Error::new(ErrorKind::State(
                "one serial channel is allowed without MARS",
            )));
        }
        let wire_id = if self.mars {
            let wire_id = u16::try_from(self.next_wire)
                .map_err(|_| Error::new(ErrorKind::Limit("MARS channel identities")))?;
            let syn = self.mux.open(wire_id)?;
            self.encrypt(&syn).map_err(|e| self.fail(e))?;
            self.next_wire += 1;
            self.wire_channels.insert(wire_id, id);
            wire_id
        } else {
            0
        };
        self.channels.insert(
            id,
            ChannelState {
                wire_id,
                ..ChannelState::default()
            },
        );
        self.channels
            .get_mut(&id)
            .unwrap()
            .stream
            .configure_features(&self.session.features)?;
        self.last_channel = Some(id);
        self.observations.event(
            "channel",
            || format!("open serial channel {id}"),
            Some(id),
            None,
        );
        Ok(())
    }
    pub fn close_channel(&mut self, id: u64) -> Result<()> {
        self.check(id, None)?;
        if self.channel_busy(id) || self.pending_bulk(id) {
            return Err(Error::new(ErrorKind::State(
                "cannot release an unfinished exchange or bulk continuation",
            )));
        }
        let channel = self.channels.remove(&id).unwrap();
        self.observations.event(
            "channel",
            || format!("close serial channel {id}"),
            Some(id),
            None,
        );
        if self.mars
            && let Some(fin) = self.mux.close(channel.wire_id)?
        {
            self.encrypt(&fin).map_err(|e| self.fail(e))?;
        }
        Ok(())
    }
    fn check(&self, id: u64, exchange: Option<u64>) -> Result<()> {
        if !self.is_ready() {
            return Err(Error::new(ErrorKind::Closed));
        }
        let channel = self
            .channels
            .get(&id)
            .ok_or_else(|| Error::new(ErrorKind::Closed))?;
        if exchange.is_some() && channel.exchange != exchange {
            return Err(Error::new(ErrorKind::State("stale exchange authority")));
        }
        Ok(())
    }
    pub(crate) fn request_context(&mut self, id: u64) -> Result<crate::requests::Context> {
        self.check(id, None)?;
        if self.channel_busy(id) {
            return Err(Error::new(ErrorKind::State(
                "channel has an unread response",
            )));
        }
        if !self.channels[&id].stream.is_empty() {
            return Err(self.fail(Error::malformed(0, "unsolicited response bytes")));
        }
        let outstanding = self
            .channels
            .values()
            .filter(|c| c.exchange.is_some())
            .count()
            + 1;
        Ok(crate::requests::Context {
            column_encryption: self.session.features.get(&4).is_some_and(|v| v == &[1]),
            transaction: self.session.transaction,
            outstanding: outstanding as u32,
        })
    }
    pub fn begin(&mut self, id: u64, exchange: u64, request: &dyn Request) -> Result<()> {
        let context = self.request_context(id)?;
        let encoded = request.encode_request(&context)?;
        self.begin_encoded(id, exchange, request.label(), encoded, false)
            .map(|_| ())
    }
    pub(crate) fn begin_encoded(
        &mut self,
        id: u64,
        exchange: u64,
        label: &'static str,
        encoded: crate::requests::Encoded,
        streaming: bool,
    ) -> Result<Vec<u8>> {
        self.request_context(id)?;
        use crate::requests::Continuation;
        let continuation = encoded.continuation;
        let continues = matches!(
            continuation,
            Continuation::BulkRows | Continuation::AbortBulk
        );
        if self.pending_bulk(id) != continues {
            return Err(Error::new(ErrorKind::State(
                "bulk requests must continue their prepared channel",
            )));
        }
        // All static validation precedes commitment; sources are polled in the shell.
        let channel = self.channels.get_mut(&id).unwrap();
        channel.exchange = Some(exchange);
        channel.canceling = continuation == Continuation::AbortBulk;
        channel.opening_bulk = continuation == Continuation::OpensBulk;
        channel.exchange_failed = false;
        channel.request_label = label;
        channel.request_kind = encoded.kind;
        channel.stream.timing = crate::response::Timing::default();
        channel.stream.first_packet_seen = false;
        channel.stream.decoder.set_metadata(encoded.metadata);
        if streaming {
            return Ok(encoded.body);
        }
        self.send_channel(id, encoded.kind, &encoded.body)
            .map_err(|e| self.fail(e))?;
        Ok(Vec::new())
    }
    #[cfg(feature = "tokio")]
    pub(crate) fn abandon_unsent(&mut self, id: u64, exchange: u64) -> Result<()> {
        self.check(id, Some(exchange))?;
        let channel = self.channels.get_mut(&id).unwrap();
        channel.exchange = None;
        channel.stream = ResponseStream::default();
        channel.stream.configure_features(&self.session.features)?;
        Ok(())
    }
    /// Exactly one already framed packet, with bounded queued MARS output.
    #[cfg(feature = "tokio")]
    pub(crate) fn send_request_packet(
        &mut self,
        id: u64,
        exchange: u64,
        mut bytes: Vec<u8>,
        first: bool,
    ) -> Result<()> {
        self.check(id, Some(exchange))?;
        if first && self.reset_pending {
            bytes[1] |= 8;
            self.reset_pending = false;
        }
        if self.mars {
            let frames = self
                .mux
                .queue(self.channels[&id].wire_id, std::iter::once(bytes))?;
            self.send_frames(frames).map_err(|e| self.fail(e))
        } else {
            self.observations.packet("send", None, &bytes, &bytes);
            self.encrypt(&bytes).map_err(|e| self.fail(e))
        }
    }
    /// Only a complete request may receive Attention. With MARS the shell waits
    /// for the queued request packets to acquire credit and reach the socket.
    /// Abandoning that wait discards the whole connection, including siblings.
    pub fn cancel(&mut self, id: u64, exchange: u64) -> Result<bool> {
        if self
            .channels
            .get(&id)
            .is_none_or(|c| c.exchange != Some(exchange))
        {
            return Ok(false);
        }
        self.check(id, Some(exchange))?;
        if self.channel_sending(id) {
            return Ok(false);
        }
        if !self.channels[&id].canceling {
            self.channels.get_mut(&id).unwrap().canceling = true;
            self.send_channel(id, packet::ATTENTION, &[])
                .map_err(|e| self.fail(e))?;
        }
        Ok(true)
    }
    fn read_channel(&mut self, id: u64) -> Result<Option<Record>> {
        loop {
            let channel = self.channels.get_mut(&id).unwrap();
            if let Some(record) = channel.stream.next_token(
                channel.canceling,
                &mut self.observations,
                Some(id),
                self.mars,
                self.elapsed,
            )? {
                self.observations.record(Some(id), &record);
                self.session.session_id = channel.stream.session_id;
                return Ok(Some(record));
            }
            if !self.mars {
                return Ok(None);
            }
            let wire_id = channel.wire_id;
            let Some(consumed) = self.mux.consume(wire_id)? else {
                return if self.mux.peer_closed(wire_id) {
                    Err(Error::new(ErrorKind::Closed))
                } else {
                    Ok(None)
                };
            };
            self.channels
                .get_mut(&id)
                .unwrap()
                .stream
                .packets
                .feed(&consumed.data)?;
            if let Some(ack) = consumed.acknowledgement {
                self.encrypt(&ack)?;
            }
        }
    }
    /// A peer FIN ends only its SMP session. The driver revokes that lifetime
    /// and reports any incomplete exchange; siblings retain their own streams.
    pub fn retire_peer_closed(&mut self, id: u64) -> Result<()> {
        self.check(id, None)?;
        if !self.channel_peer_closed(id) {
            return Err(Error::new(ErrorKind::State("MARS peer is still open")));
        }
        self.channels.get_mut(&id).unwrap().exchange = None;
        self.close_channel(id)
    }
    pub fn next_record(&mut self, id: u64, exchange: u64) -> Result<Option<Record>> {
        self.check(id, Some(exchange))?;
        let Some(record) = self.read_channel(id).map_err(|e| self.fail(e))? else {
            return Ok(None);
        };
        let canceling = self.channels[&id].canceling;
        self.channels.get_mut(&id).unwrap().exchange_failed |= matches!(&record, Record::Error(_))
            || matches!(&record, Record::Done(done) if done.has_error());
        if !canceling && matches!(&record,Record::Done(done) if done.acknowledges_cancel()) {
            return Err(self.fail(Error::malformed(0, "unsolicited Attention acknowledgement")));
        }
        self.apply(&record).map_err(|e| self.fail(e))?;
        if let Record::Error(message) = &record
            && message.severity >= 20
        {
            return Err(self.fail(Error::new(ErrorKind::Server(Box::new(message.clone())))));
        }
        let ended = matches!(&record,Record::Done(done) if
            if canceling { done.acknowledges_cancel() } else { done.is_final() });
        if ended {
            let channel = self.channels.get_mut(&id).unwrap();
            channel.pending_bulk = channel.opening_bulk && !canceling && !channel.exchange_failed;
            channel.opening_bulk = false;
            channel.exchange = None;
            channel.canceling = false;
            channel.stream.timing.ended = self.elapsed;
            let timing = channel.stream.timing;
            self.observations.message(
                "receive",
                if canceling {
                    "cancel acknowledged"
                } else {
                    "response"
                },
                self.mars.then_some(id),
            );
            self.observations.timing(timing);
        }
        Ok(Some(record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timing_requires_complete_packets_and_terminal_message_proof_at_every_level() {
        for level in [Level::Off, Level::Outline, Level::Full] {
            let mut core = ready_core();
            core.configure_observation(level, false, false).unwrap();
            core.channels.insert(
                1,
                ChannelState {
                    exchange: Some(1),
                    ..Default::default()
                },
            );
            core.set_elapsed(Duration::from_millis(10));
            core.observe_request_sent(1);
            let mut first = done(0);
            first[1] = 0; // Terminal token is not yet the message boundary.
            core.channels
                .get_mut(&1)
                .unwrap()
                .stream
                .packets
                .feed(&first[..7])
                .unwrap();
            core.set_elapsed(Duration::from_millis(15));
            assert!(core.next_record(1, 1).unwrap().is_none());
            assert_eq!(core.channel_timing(1).unwrap().first_packet, None);
            core.channels
                .get_mut(&1)
                .unwrap()
                .stream
                .packets
                .feed(&first[7..])
                .unwrap();
            core.set_elapsed(Duration::from_millis(20));
            assert!(core.next_record(1, 1).unwrap().is_none());
            assert_eq!(core.channel_timing(1).unwrap().ended, None);
            core.channels
                .get_mut(&1)
                .unwrap()
                .stream
                .packets
                .feed(&packet::split(packet::REPLY, &[], 4096).unwrap())
                .unwrap();
            core.set_elapsed(Duration::from_millis(35));
            assert!(core.next_record(1, 1).unwrap().is_some());
            let timing = core.channel_timing(1).unwrap();
            assert_eq!(timing.until_first_packet(), Some(Duration::from_millis(10)));
            assert_eq!(timing.until_end(), Some(Duration::from_millis(25)));
            let traces = core.take_observations();
            if level == Level::Off {
                assert!(traces.is_empty());
            } else {
                assert!(
                    traces
                        .iter()
                        .any(|t| matches!(t, Trace::Event(e) if e.timing == Some(timing)))
                );
            }
            core.begin(1, 2, &Batch::new("next")).unwrap();
            assert_eq!(
                core.channel_timing(1),
                Some(crate::response::Timing::default())
            );
        }
    }
    #[test]
    fn cancel_timing_waits_for_ack_and_never_invents_an_unsent_milestone() {
        let mut core = ready_core();
        core.channels.insert(
            1,
            ChannelState {
                exchange: Some(1),
                canceling: true,
                ..Default::default()
            },
        );
        core.set_elapsed(Duration::from_secs(2));
        core.channels
            .get_mut(&1)
            .unwrap()
            .stream
            .packets
            .feed(&done(0))
            .unwrap();
        assert!(core.next_record(1, 1).unwrap().is_some());
        assert_eq!(core.channel_timing(1).unwrap().ended, None);
        core.set_elapsed(Duration::from_secs(4));
        core.channels
            .get_mut(&1)
            .unwrap()
            .stream
            .packets
            .feed(&done(0x20))
            .unwrap();
        assert!(core.next_record(1, 1).unwrap().is_some());
        let timing = core.channel_timing(1).unwrap();
        assert_eq!(timing.sent, None);
        assert_eq!(timing.first_packet, Some(Duration::from_secs(2)));
        assert_eq!(timing.ended, Some(Duration::from_secs(4)));
        assert_eq!(timing.until_end(), None);
        assert_eq!(timing.summary(), "");
    }
    #[test]
    fn a_missing_first_packet_clock_is_not_reconstructed_from_later_packets() {
        let mut core = ready_core();
        core.channels.insert(
            1,
            ChannelState {
                exchange: Some(1),
                ..Default::default()
            },
        );
        let mut first = done(0);
        first[1] = 0;
        core.channels
            .get_mut(&1)
            .unwrap()
            .stream
            .packets
            .feed(&first)
            .unwrap();
        assert!(core.next_record(1, 1).unwrap().is_none());
        core.set_elapsed(Duration::from_secs(8));
        core.channels
            .get_mut(&1)
            .unwrap()
            .stream
            .packets
            .feed(&packet::split(packet::REPLY, &[], 4096).unwrap())
            .unwrap();
        assert!(core.next_record(1, 1).unwrap().is_some());
        assert_eq!(core.channel_timing(1).unwrap().first_packet, None);
        let reversed = crate::response::Timing {
            sent: Some(Duration::from_secs(9)),
            ended: Some(Duration::from_secs(8)),
            ..Default::default()
        };
        assert_eq!(reversed.until_end(), None);
    }
    #[test]
    fn sibling_channels_have_independent_exchange_clocks() {
        let mut core = ready_core();
        core.mars = true;
        for id in [1, 2] {
            core.channels.insert(
                id,
                ChannelState {
                    exchange: Some(id),
                    ..Default::default()
                },
            );
            core.set_elapsed(Duration::from_secs(id));
            core.observe_request_sent(id);
            core.channels
                .get_mut(&id)
                .unwrap()
                .stream
                .packets
                .feed(&done(0))
                .unwrap();
        }
        core.set_elapsed(Duration::from_secs(4));
        assert!(core.next_record(2, 2).unwrap().is_some());
        assert_eq!(core.channel_timing(1).unwrap().first_packet, None);
        core.set_elapsed(Duration::from_secs(8));
        assert!(core.next_record(1, 1).unwrap().is_some());
        assert_eq!(
            core.channel_timing(2).unwrap().until_end(),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            core.channel_timing(1).unwrap().until_end(),
            Some(Duration::from_secs(7))
        );
    }
    fn core() -> ConnectionCore {
        ConnectionCore::new(
            Login {
                user: "test".into(),
                password: "dummy".into(),
                database: "tds_test".into(),
                host_name: String::new(),
                server_name: "localhost".into(),
                process_id: 0,
                ..Login::default()
            },
            RootCertStore::empty(),
            ServerName::try_from("localhost").unwrap(),
            0,
            ProtocolVersion::V7_4,
        )
        .unwrap()
    }
    fn ready_core() -> ConnectionCore {
        // State tests bypass the handshake; live tests prove actual verified TLS.
        let mut core = core();
        core.phase = Phase::Ready;
        core.output.clear();
        core
    }
    fn done(status: u16) -> Vec<u8> {
        let mut body = vec![0xfd];
        body.extend(status.to_le_bytes());
        body.extend([0; 10]);
        packet::split(packet::REPLY, &body, 4096).unwrap()
    }
    #[test]
    fn feature_acknowledgements_preserve_downgrades_and_reject_invalid_or_unrequested_values() {
        fn login_reply(
            requested: &[(u8, Vec<u8>)],
            acknowledged: &[(u8, Vec<u8>)],
        ) -> Result<ConnectionCore> {
            let mut core = core();
            core.phase = Phase::Login;
            core.feature_requests = requested.iter().cloned().collect();
            core.login_ack = true; // This test isolates FEATUREEXTACK validation.
            let mut body = vec![0xae];
            for (id, data) in acknowledged {
                body.push(*id);
                body.extend((data.len() as u32).to_le_bytes());
                body.extend(data);
            }
            body.push(0xff);
            body.extend([0xfd, 0, 0, 0, 0]);
            body.extend([0; 8]);
            core.stream
                .packets
                .feed(&packet::split(packet::REPLY, &body, 4096)?)?;
            core.read_login()?;
            Ok(core)
        }
        let requested = [
            (4, vec![1]),
            (9, vec![2]),
            (10, vec![1]),
            (13, vec![1]),
            (14, vec![2]),
        ];
        let acknowledged = [
            (4, vec![1]),
            (9, vec![1, 0]),
            (10, vec![0]),
            (13, vec![1]),
            (14, vec![1]),
        ];
        let core = login_reply(&requested, &acknowledged).unwrap();
        assert!(core.is_ready());
        assert_eq!(core.session.features, acknowledged.into_iter().collect());
        assert!(
            login_reply(&requested, &[])
                .unwrap()
                .session
                .features
                .is_empty()
        );
        for invalid in [
            vec![(4, vec![0])],
            vec![(4, vec![2])],
            vec![(4, vec![1, 0])],
            vec![(9, vec![2])],
            vec![(9, vec![2, 2])],
            vec![(9, vec![0, 1])],
            vec![(10, vec![])],
            vec![(10, vec![2])],
            vec![(14, vec![0])],
            vec![(14, vec![3])],
            vec![(13, vec![0])],
            vec![(13, vec![2])],
            vec![(14, vec![1, 0])],
            vec![(14, vec![1]), (14, vec![1])],
            vec![(99, vec![1])],
        ] {
            assert!(login_reply(&requested, &invalid).is_err(), "{invalid:?}");
        }
        assert!(login_reply(&[(14, vec![1])], &[(14, vec![2])]).is_err());
        assert!(login_reply(&[], &[(10, vec![1])]).is_err());
    }
    #[test]
    fn channel_lifetimes_never_reuse_ids_and_mars_refuses_wire_id_exhaustion() {
        let mut core = ready_core();
        core.mars = true;
        core.open_channel(0).unwrap();
        core.open_channel(1).unwrap();
        core.close_channel(0).unwrap();
        assert!(core.open_channel(0).is_err());
        core.next_wire = u32::from(u16::MAX);
        core.open_channel(u64::from(u16::MAX)).unwrap();
        assert!(matches!(
            core.open_channel(65536).unwrap_err().kind,
            ErrorKind::Limit(_)
        ));
        assert!(!core.is_failed());
        assert!(core.channels.contains_key(&1));
    }
    #[test]
    fn recovery_rebinds_logical_channels_and_recordings_use_logical_ids() {
        let mut old = ready_core();
        old.mars = true;
        old.recovery = Some(crate::session::Recovery::new(old.session.clone(), &[]).unwrap());
        old.open_channel(0).unwrap();
        old.close_channel(0).unwrap();
        old.open_channel(1).unwrap();
        old.open_channel(70000).unwrap();
        let mut new = ready_core();
        new.mars = true;
        new.recovery = Some(crate::session::Recovery::new(new.session.clone(), &[]).unwrap());
        new.adopt_recovery(&old).unwrap();
        new.configure_observation(Level::Off, true, false).unwrap();
        for id in [1, 70000] {
            new.open_channel(id).unwrap();
        }
        assert_eq!(new.channels[&1].wire_id, 0);
        assert_eq!(new.channels[&70000].wire_id, 1);
        assert!(new.close_channel(0).is_err()); // old id 0 cannot address new wire id 0
        new.begin(1, 9, &Batch::new("SELECT 1")).unwrap();
        let data = crate::mars::Frame {
            flags: crate::mars::DATA,
            channel: 0,
            sequence: 1,
            window: 4,
            body: done(0),
        }
        .encode()
        .unwrap();
        new.feed_application(&data).unwrap();
        assert!(matches!(
            new.next_record(1, 9).unwrap(),
            Some(Record::Done(_))
        ));
        let trace = new.take_observations();
        for direction in ["send", "receive"] {
            assert!(trace.iter().any(|t| matches!(t, Trace::Packet { direction: d, channel: Some(1), .. } if *d == direction)));
        }
        new.open_channel(70001).unwrap();
        assert_eq!(new.channels[&70001].wire_id, 2);
    }
    #[test]
    fn encoding_failure_keeps_the_reset_pending_and_emits_no_request() {
        let mut core = ready_core();
        core.reset_pending = true;
        core.open_channel(0).unwrap();
        assert!(
            core.begin(0, 1, &Batch::new("x".repeat(wire::MAX_PENDING)))
                .is_err()
        );
        assert!(core.reset_pending);
        assert!(!core.is_busy());
        assert!(core.take_output().is_empty());
        core.begin(0, 2, &Batch::new("SELECT 1")).unwrap();
        assert!(!core.reset_pending);
        assert!(core.is_busy());
    }
    #[test]
    fn attention_waits_past_normal_done_for_ack_in_a_later_message() {
        let mut core = ready_core();
        core.open_channel(1).unwrap();
        core.begin(1, 1, &Batch::new("SELECT 1")).unwrap();
        assert!(core.cancel(1, 1).unwrap());
        assert!(core.is_canceling());
        assert!(core.cancel(1, 1).unwrap()); // Repeated cancellation retains the same state.
        core.channels
            .get_mut(&1)
            .unwrap()
            .stream
            .packets
            .feed(&done(0))
            .unwrap();
        assert!(matches!(
            core.next_record(1, 1).unwrap(),
            Some(Record::Done(_))
        ));
        assert!(core.is_busy());
        assert!(core.next_record(1, 1).unwrap().is_none());
        assert!(core.begin(1, 2, &Batch::new("SELECT 2")).is_err());
        let ack = done(0x20);
        for byte in &ack[..ack.len() - 1] {
            core.channels
                .get_mut(&1)
                .unwrap()
                .stream
                .packets
                .feed(&[*byte])
                .unwrap();
            assert!(core.next_record(1, 1).unwrap().is_none());
        }
        assert!(core.is_busy());
        core.channels
            .get_mut(&1)
            .unwrap()
            .stream
            .packets
            .feed(&ack[ack.len() - 1..])
            .unwrap();
        assert!(
            matches!(core.next_record(1,1).unwrap(),Some(Record::Done(done)) if done.acknowledges_cancel())
        );
        assert!(!core.is_busy());
        assert!(!core.is_canceling());
        core.begin(1, 2, &Batch::new("SELECT 2")).unwrap();
        core.take_output();
        assert!(!core.cancel(1, 1).unwrap());
        assert!(!core.cancel(2, 2).unwrap());
        assert!(!core.is_canceling());
        assert!(core.take_output().is_empty());
    }
    #[test]
    fn ack_does_not_release_until_its_last_packet_and_unsolicited_ack_is_fatal() {
        let mut core = ready_core();
        core.open_channel(1).unwrap();
        core.begin(1, 1, &Batch::new("SELECT 1")).unwrap();
        core.cancel(1, 1).unwrap();
        let mut ack = done(0x20);
        ack[1] = 0;
        core.channels
            .get_mut(&1)
            .unwrap()
            .stream
            .packets
            .feed(&ack)
            .unwrap();
        assert!(core.next_record(1, 1).unwrap().is_none());
        assert!(core.is_busy());
        core.channels
            .get_mut(&1)
            .unwrap()
            .stream
            .packets
            .feed(&packet::split(packet::REPLY, &[], 4096).unwrap())
            .unwrap();
        assert!(core.next_record(1, 1).unwrap().is_some());
        assert!(!core.is_busy());
        core.begin(1, 2, &Batch::new("SELECT 2")).unwrap();
        core.channels
            .get_mut(&1)
            .unwrap()
            .stream
            .packets
            .feed(&done(0x20))
            .unwrap();
        assert!(core.next_record(1, 2).is_err());
        assert!(core.is_failed());
    }
    #[test]
    fn busy_state_and_exchange_identity_survive_without_a_response_guard() {
        let mut core = ready_core();
        core.open_channel(7).unwrap();
        assert!(core.open_channel(8).is_err());
        core.begin(7, 1, &Batch::new("SELECT 1")).unwrap();
        assert!(core.is_busy());
        assert!(core.close_channel(7).is_err());
        assert!(core.begin(7, 2, &Batch::new("SELECT 2")).is_err());
        assert!(core.next_record(7, 2).is_err());
        assert!(core.is_busy());
    }
    #[test]
    fn malformed_input_permanently_revokes_core_output_and_authority() {
        let mut core = core();
        assert!(core.feed(&[4, 1, 0, 7, 0, 0, 1, 0]).is_err());
        assert!(core.is_failed());
        assert!(core.take_output().is_empty());
        assert!(core.feed(&[]).is_err());
        assert!(core.open_channel(1).is_err());
    }
    #[test]
    fn fatal_server_error_is_retained_and_prevents_reuse() {
        let mut core = ready_core();
        core.channels.insert(
            1,
            ChannelState {
                exchange: Some(1),
                ..ChannelState::default()
            },
        );
        let mut error = vec![0xaa, 14, 0];
        error.extend(50000_u32.to_le_bytes());
        error.extend([1, 20, 0, 0, 0, 0]);
        error.extend(1_u32.to_le_bytes());
        core.channels
            .get_mut(&1)
            .unwrap()
            .stream
            .packets
            .feed(&packet::split(packet::REPLY, &error, 4096).unwrap())
            .unwrap();
        let failure = core.next_record(1, 1).unwrap_err();
        assert!(
            matches!(failure.kind,ErrorKind::Server(message) if message.number == 50000 && message.severity == 20)
        );
        assert!(core.is_failed());
        assert!(core.begin(1, 2, &Batch::new("SELECT 1")).is_err());
    }
    #[test]
    fn final_token_waits_for_last_packet_and_never_accepts_trailing_payload() {
        for trailing in [false, true] {
            let mut core = ready_core();
            core.channels.insert(
                1,
                ChannelState {
                    exchange: Some(1),
                    ..ChannelState::default()
                },
            );
            let mut done = vec![0xfd, 0, 0, 0, 0];
            done.extend(0_u64.to_le_bytes());
            let mut first = packet::split(packet::REPLY, &done, 4096).unwrap();
            first[1] = 0;
            core.channels
                .get_mut(&1)
                .unwrap()
                .stream
                .packets
                .feed(&first)
                .unwrap();
            assert!(core.next_record(1, 1).unwrap().is_none());
            assert!(core.is_busy());
            let body: &[u8] = if trailing { &[0] } else { &[] };
            core.channels
                .get_mut(&1)
                .unwrap()
                .stream
                .packets
                .feed(&packet::split(packet::REPLY, body, 4096).unwrap())
                .unwrap();
            if trailing {
                assert!(core.next_record(1, 1).is_err());
                assert!(core.is_failed());
            } else {
                assert!(matches!(
                    core.next_record(1, 1).unwrap(),
                    Some(Record::Done(_))
                ));
                assert!(!core.is_busy());
            }
        }
    }
    #[test]
    fn session_announcements_apply_before_reuse_and_empty_count_is_not_zero() {
        let mut core = ready_core();
        core.channels.insert(
            1,
            ChannelState {
                exchange: Some(1),
                ..ChannelState::default()
            },
        );
        // ENVCHANGE packet size: new "512", old "4096"; then final DONE, no count.
        let mut body = vec![0xe3, 17, 0, 4, 3];
        body.extend(wire::utf16("512"));
        body.push(4);
        body.extend(wire::utf16("4096"));
        body.extend([0xfd, 0, 0, 0, 0]);
        body.extend([0; 8]);
        core.channels
            .get_mut(&1)
            .unwrap()
            .stream
            .packets
            .feed(&packet::split(packet::REPLY, &body, 4096).unwrap())
            .unwrap();
        assert!(matches!(
            core.next_record(1, 1).unwrap(),
            Some(Record::Environment(_))
        ));
        assert_eq!(core.session().packet_size, 512);
        let Some(Record::Done(done)) = core.next_record(1, 1).unwrap() else {
            panic!("expected DONE");
        };
        assert_eq!(done.row_count, None);
        assert!(!core.is_busy());
    }
}
