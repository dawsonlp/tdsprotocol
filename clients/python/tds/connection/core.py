"""The connection manager's core: everything about a connection except the I/O.

Reference: Connect, and The Client §3. Checked against MS-TDS v20260617 §3.2, and MC-SMP for MARS.

Layers, outermost first:   socket bytes ─ TLS ─ MARS frames (when on) ─ packets ─ messages

This module never uses a socket, a clock or a task. The shell runs its procedures and performs
each action they yield, such as Send bytes, Read bytes (while connecting), Receive the next packet for a
serial channel, or AwaitWindow. TLS is in this module, not in the shell, because Python's TLS engine
runs entirely in memory (ssl.MemoryBIO): bytes go in, and bytes come out.
"""

from collections import deque
import enum
import os
import ssl
import time
import warnings
import dataclasses
from dataclasses import dataclass, field
from typing import Any, Callable, Generator

from .. import login7, logins, prelogin
from ..packet import DEFAULT_SIZE, Joiner, Message, Packet, PacketType, PacketWriter, Status, Unpacker, split
from ..prelogin import Encryption, OnOff
from ..requests import Context, Request
from ..response import ResponseReader
from ..session import INITIAL_STATES, RECOVERY, Recovery, SessionState
from ..tokens import TOKENS, DoneStatus, EnvKind, FedAuthInfoId, _fed_auth_info
from ..wire import Field, MalformedMessage, Node, Record, Struct, U8, U16, U32, kept

CLIENT_VERSION = {"major": 0, "minor": 1, "build": 1, "sub_build": 0}


# =========================================================================== what a procedure asks the shell to do


@dataclass(frozen=True)
class Send:
    """Write these bytes to the socket."""

    data: bytes


@dataclass(frozen=True)
class Read:
    """Return the next bytes from the socket. Used while connecting, before serial channels exist."""


@dataclass(frozen=True)
class Receive:
    """Return the next packet for this serial channel, or None if the server closed the channel."""

    channel: int


@dataclass(frozen=True)
class Produce:
    """Return the next piece from this source (an async iterator), or END once the source has no more (D-41)."""

    source: Any


END = object()  # a source has nothing more


@dataclass(frozen=True)
class Obtain:
    """Return what an application's function gives, called with these arguments and awaited if it is async. It is
    used for a login's next token (D-55)."""

    fn: Any
    args: tuple = ()


@dataclass(frozen=True)
class AwaitWindow:
    """Resume the procedure once more frames have arrived from the server. The procedure is waiting for the server
    to raise this MARS channel's window, and it checks the window again each time it resumes."""

    channel: int


Action = Send | Read | Receive | AwaitWindow | Produce | Obtain


# ======================================================================== what the client shows (observe.py renders it)


class Level(enum.Enum):
    """How much the running client shows (D-12). An observer states its level. With no observer, the level is off."""

    OFF = "off"  # nothing: no events and no inspection trees. This is the optimized mode
    OUTLINE = "outline"  # one line per step, message and change, with its summary
    FULL = "full"  # the outline, plus every message opened to its fields and bytes


def milliseconds(seconds: float) -> str:
    """A duration for people to read: tenths of a millisecond below 10 ms, otherwise whole milliseconds."""
    ms = seconds * 1000
    return f"{ms:.1f} ms" if ms < 10 else f"{ms:.0f} ms"


def level_of(observe: Any) -> Level:
    """An observer's level: its `level` if it has one, FULL for a plain callable, and OFF for None."""
    return Level.OFF if observe is None else getattr(observe, "level", Level.FULL)


@dataclass
class Event:
    kind: str  # step · send · receive · tls · state · mars · channel · pool
    text: str  # one line, for the outline
    node: Node | None = None  # the inspection tree, when recording
    time: float = field(default_factory=time.perf_counter)  # when it happened, in seconds on a monotonic clock (D-12)
    took: str = ""  # durations, shown after the line. For a connect step, the time since connecting began. For a
    # response, the time to its first packet and to its end. Kept apart from `text`, so that lines from different runs
    # can be compared
    safe_login_tokens: bytes | None = None  # typed login evidence; SSPI payloads already zeroed


# =========================================================================== failures


class ConnectError(Exception):
    """Connecting failed. The error names the step, and what was expected or what arrived."""

    def __init__(self, step: str, problem: str):
        super().__init__(f"{step}: {problem}")
        self.step = step


class UnsupportedFeatureEnabled(ConnectError):
    """The server enabled a feature this login asked for but the driver does not implement (PY-AZ-06). The connection
    is closed before any SQL: a session would depend on behavior that nothing provides. There is no retry without the
    feature; leave it out of `features` to connect."""

    def __init__(self, feature: "login7.Feature"):
        super().__init__("log in", f"the server enabled {login7.UNSUPPORTED[feature]} ({feature.name}), which this "
                                   "driver does not implement; the connection is closed before any SQL")
        self.feature = feature


class CaptureError(Exception):
    """The requested recording is incomplete; this connection must not continue.

    The original writer error is available as `cause`, without exposing its text
    (which can contain application data) in the driver's own message.
    """

    def __init__(self, cause: Exception):
        super().__init__("saved conversation recording failed; the connection was discarded")
        self.cause = cause


LOGIN_HINTS = {  # what the driver knows that the server's message doesn't say (D-53)
    4064: "(The login's default database can't be opened: it may have been dropped or taken offline, or the login may "
          "have no user in it. Name a database with database=…, or have an administrator change the login's default: "
          "ALTER LOGIN … WITH DEFAULT_DATABASE = ….)",
    40613: "(Azure SQL: the database isn't available to this login. Microsoft gives a paused serverless database "
           "resuming, or a failover, as causes: retry after a pause. Observed too: a routed login naming a server the "
           "node doesn't know, which shows as server ''.)",
    18488: "(The login's password has expired, or must be changed before first use: connect(…, new_password=…) "
           "changes it as it logs in.)",
    18452: "(A Windows login SQL Server couldn't verify. It says “untrusted domain” for a wrong password or an "
           "unknown account too, not only for a domain it doesn't trust: observed with NTLM.)",
    18456: "(SQL Server tells the client only that the login failed; the reason, such as a wrong password, an unknown "
           "or disabled login, or a login without access, is in the server's error log, under this state.)",
}


class LoginRejected(ConnectError):
    """The server answered the login without a LOGINACK. The error carries the server's errors, each reported in
    full."""

    def __init__(self, errors: list[Record]):
        from ..response import report

        detail = "\n\n".join(report(e) + (f"\n{LOGIN_HINTS[e.number]}" if e.number in LOGIN_HINTS else "")
                               for e in errors) or "no LOGINACK, and no reason given"
        super().__init__("log in", f"the server rejected the login:\n\n{detail}")
        self.errors = errors


class Routed(ConnectError):
    """The server routed the login to another server. Raised when connect(follow_routing=False). Otherwise the driver
    follows the route, once (D-11)."""

    def __init__(self, server: str, port: int):
        super().__init__("log in", f"the server routes this login to {server}:{port}")
        self.server, self.port = server, port


class SessionNotRecovered(ConnectionError):
    """A broken connection's session couldn't be recovered (D-57). The error says which session, why, and what broke
    the connection."""


class SerialChannelMisuse(Exception):
    """A serial channel was used against its rules. These are programming errors, never the result of timing."""


class TooManySerialChannels(SerialChannelMisuse):  # D-20
    def __init__(self):
        super().__init__("this connection allows one serial channel, and it is open. For parallel work use another "
                         "connection; to interleave on this one, connect with MARS.")


class NotTheOwner(SerialChannelMisuse):  # D-21
    def __init__(self, channel: int):
        super().__init__(f"serial channel {channel} belongs to the task that opened it. Use it from that task, "
                         "hand it over explicitly, or open another connection for parallel work.")


class ExchangeInProgress(SerialChannelMisuse):  # D-22
    def __init__(self, channel: int):
        super().__init__(f"serial channel {channel} already has a request in progress; a channel carries one at a time.")


class ChannelClosed(ConnectionError):
    """Authority for this channel lifetime was revoked, including by another task."""

    def __init__(self, channel: int, response=None):
        super().__init__(f"serial channel {channel} is closed")
        self.channel, self.response = channel, response


class OutOfTurn(SerialChannelMisuse):  # D-50
    """A request sent out of order. Either a request that must follow another was sent without it, or a different
    request was sent where the following one must come."""

    def __init__(self, channel: int, open_: str | None, continues: str | None):
        if open_ is not None:
            what = (f"a {open_} is open on serial channel {channel}: its next request must continue it"
                    + (f", not continue a {continues}" if continues else ""))
        else:
            what = f"this request continues a {continues}, and none is open on serial channel {channel}"
        super().__init__(what + ". Sent out of turn, the server would close the connection.")


# =========================================================================== TLS, in memory


ALPN_TDS_8 = "tds/8.0"  # how a TLS handshake says TDS 8.0 (MS-TDS §2.1)


def verifies(context: ssl.SSLContext) -> bool:
    """Whether the context checks the server's certificate: who signed it, and the host it names."""
    return context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname


class Tls:
    """TLS without a socket. The server's bytes go in, and bytes for the server come out. The context is Python's own
    (D-10). By default it verifies the certificate against the system's trusted authorities and the host name."""

    def __init__(self, server_name: str, context: ssl.SSLContext | None, alpn: str | None = None):
        context = context or ssl.create_default_context()
        if alpn:
            context.set_alpn_protocols([alpn])
        self._in, self._out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self._engine = context.wrap_bio(self._in, self._out, server_hostname=server_name)

    def handshake(self, step: str) -> bool:
        """Take one handshake step. Returns True once the handshake is complete. A certificate that the context doesn't
        accept fails the step, with an error that says why and what the options are (D-10, D-53)."""
        try:
            self._engine.do_handshake()
            return True
        except ssl.SSLWantReadError:
            return False
        except ssl.SSLCertVerificationError as e:
            raise ConnectError(step, f"the server's certificate wasn't accepted: {e.verify_message}. To trust a "
                                     "private or self-signed authority, pass ssl_context=ssl.create_default_context("
                                     "cafile=…); for a certificate naming another host, server_hostname=…") from e
        except ssl.SSLError as e:
            raise ConnectError(step, f"the TLS handshake failed: {e.reason or e}") from e

    @property
    def alpn(self) -> str | None:
        return self._engine.selected_alpn_protocol()

    def take_output(self) -> bytes:
        return self._out.read()

    def feed(self, data: bytes) -> None:
        self._in.write(data)

    def encrypt(self, data: bytes) -> bytes:
        self._engine.write(data)
        return self._out.read()

    def decrypt(self, data: bytes) -> bytes:
        self._in.write(data)
        plain = bytearray()
        while True:
            try:
                chunk = self._engine.read(65536)
            except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
                break
            if not chunk:
                break
            plain += chunk
        return bytes(plain)

    def close(self) -> bytes:
        try:
            self._engine.unwrap()
        except (ssl.SSLWantReadError, ssl.SSLError):
            pass  # the driver doesn't wait for the server's close_notify
        return self._out.read()

    def describe(self) -> str:
        alpn = self._engine.selected_alpn_protocol()
        return f"{self._engine.version()} · {self._engine.cipher()[0]}{f' · ALPN {alpn}' if alpn else ''}"


# ====================================================================== MARS: one connection, several serial channels


class MarsFlags(enum.IntEnum):
    SYN = 0x01  # open a session
    ACK = 0x02  # raise the sender's window
    FIN = 0x04  # close a session
    DATA = 0x08  # carries packets


MARS_ID = 0x53
MARS_HEADER_SIZE = 16
MARS_MAX_FRAME = 1 << 20  # transport allocation bound, not a protocol maximum
MARS_MASK = (1 << 32) - 1


def _mars_ahead(value: int, previous: int) -> bool:
    return 0 < ((value - previous) & MARS_MASK) < (1 << 31)


MARS_WINDOW = 4  # how many data frames a side may send beyond what the other has acknowledged

MARS_HEADER = Struct("MARS frame", [
    Field("id", U8, fmt=lambda v: "MARS (0x53)" if v == MARS_ID else f"{v:#04x}"),
    Field("flags", U8, enum=MarsFlags),
    Field("session_id", U16),  # the serial channel
    Field("length", U32, fmt=lambda v: f"{v} bytes"),  # the whole frame, header included
    Field("sequence", U32),  # counts data frames; unchanged on SYN, ACK and FIN
    Field("window", U32),  # the highest sequence number the sender of this frame will accept
], source="MC-SMP §2.2.1",
    summary=lambda f: f"{f.flags.name} · channel {f.session_id} · seq {f.sequence} · window {f.window}")


@dataclass(frozen=True)
class MarsData:
    """One DATA frame, consumed by its owner before returning one unit of credit.

    SMP payload is a byte stream: a frame can contain part of a TDS packet, or
    several packets. Counting packets instead of frames can deadlock or overgrant.
    """
    body: bytes


@dataclass
class Channel:
    """A serial channel's state. Its public id identifies application authority;
    its wire_id identifies an SMP session on this physical connection only.
    Without MARS there is one channel, carried directly on the connection.
    """

    id: int
    owner: Any  # the task that opened it (D-21)
    unpacker: Unpacker
    wire_id: int | None = None  # SMP identity on this physical connection, independent of the public lifetime id
    busy: bool = False  # a request is being sent, or its response hasn't been read to its end (D-22)
    closed: bool = False
    closing: bool = False  # public authority revoked; cleanup still owns the exchange
    closed_by_server: bool = False  # MARS: the server closed it (FIN), as it does to each channel of an ending session
    reader: ResponseReader | None = None  # the response being read
    writer: PacketWriter | None = None  # the request being sent
    opening: str | None = None  # what the request in progress opens, if its response ends without error (D-50)
    open: str | None = None  # what is open: the channel's next request must continue it
    # MARS only
    sent: int = 0  # the sequence number of the last data frame the client sent
    received: int = 0  # the sequence number of the last data frame the client received
    consumed: int = 0  # DATA frames passed to the packet layer by the channel's owner
    send_window: int = MARS_WINDOW  # the server accepts the client's data frames up to this sequence number
    receive_window: int = MARS_WINDOW  # the client has told the server it may send up to this one
    packets: deque[Packet] = field(default_factory=deque)  # unpacked from a consumed DATA frame
    waiting: list[bytes] = field(default_factory=list)  # packets for the server, waiting for window credit


# =========================================================================== the link: bytes ⇄ messages


class Link:
    """Turns messages into socket bytes and back: packets, then MARS frames if MARS is on, then TLS if TLS is on."""

    def __init__(self, record: bool, observe: Callable[[Event], None]):
        self.record, self.observe, self.observing = record, observe, False
        self.capture: Callable[[str, int | None, bytes], None] | None = None  # every plaintext packet, for captures
        self.tls: Tls | None = None
        self.mars = False
        self.packet_size = DEFAULT_SIZE
        self.channels: dict[int, Channel] = {}
        self._wire_channels: dict[int, Channel] = {}
        self._next_wire_channel = 0  # never reuse a wire identity within one physical connection
        self.plain_channel = 0  # local lifetime identity; plain packets have no channel id
        self._plain = Unpacker(record)  # packets before MARS starts, or without MARS
        self._frames = bytearray()  # MARS bytes not yet a whole frame

    def open_channel(self, channel_id: int, owner: Any) -> Channel:
        """Bind an application lifetime to this link's fresh wire namespace.

        Recovery keeps application ids and owners, but a new TCP connection has
        no SMP sessions. Allocate its wire ids from zero, independently of how
        many application channels existed before the break.
        """
        if self.mars and self._next_wire_channel > 0xFFFF:
            raise SerialChannelMisuse("MARS wire identities are exhausted; open a new connection")
        channel = Channel(channel_id, owner, Unpacker(self.record))
        if self.mars:
            channel.wire_id = self._next_wire_channel
            self._next_wire_channel += 1
            self._wire_channels[channel.wire_id] = channel
        else:
            self.plain_channel = channel_id
        self.channels[channel_id] = channel
        return channel

    def _wrap(self, data: bytes) -> Send:
        return Send(self.tls.encrypt(data) if self.tls else data)

    def packets(self, kind: PacketType, body: bytes, first: Status = Status(0)) -> tuple[list[bytes], list[Node]]:
        return split(kind, body, self.packet_size, self.record, first)

    def plain(self, packets: list[bytes]) -> Send:
        """Packets sent as they are, without MARS. The connection itself is the one serial channel.
        Each packet is encrypted separately, so every TLS record holds exactly one packet. SQL Server
        expects packet boundaries and record boundaries to match."""
        if self.capture:
            for p in packets:
                self.capture("send", None, p)
        return Send(b"".join(self._wrap(p).data for p in packets))

    def can_send(self, channel: Channel) -> bool:
        """MARS flow control: the server accepts data frames up to the window it last announced."""
        return _mars_ahead(channel.send_window, channel.sent)

    def data(self, channel: Channel, packet: bytes) -> Send:
        """One packet in one MARS data frame. Callers check can_send first."""
        if not self.can_send(channel):  # an invariant, kept even under python -O
            raise RuntimeError(f"channel {channel.id}: data frame {channel.sent + 1} is beyond the server's window")
        channel.sent = (channel.sent + 1) & MARS_MASK
        if self.capture:
            self.capture("send", channel.id, packet)
        return self._wrap(self.frame(channel, MarsFlags.DATA, packet))

    def frame(self, channel: Channel, flags: MarsFlags, payload: bytes = b"") -> bytes:
        header, node = MARS_HEADER.encode({
            "id": MARS_ID, "flags": flags, "session_id": channel.wire_id, "length": MARS_HEADER_SIZE + len(payload),
            "sequence": channel.sent, "window": channel.receive_window}, self.record)
        if flags != MarsFlags.DATA:
            if self.observing:
                identity = f" · application channel {channel.id}" if channel.wire_id != channel.id else ""
                self.observe(Event("mars", f"→ MARS {node.shown}{identity}", node))
        return header + payload

    def channel_frame(self, channel: Channel, flags: MarsFlags) -> Send:
        return self._wrap(self.frame(channel, flags))

    def feed(self, raw: bytes) -> list[Send | tuple[int, Packet | MarsData | None]]:
        """Route plain packets or MARS DATA frames (None: the peer closed that channel),
        and send packets that were waiting for a raised window.

        MARS credit returns as the owner consumes DATA frames in _receive_packet,
        not as frames arrive. The server stays at most one window ahead. Decode
        TDS only after that boundary: its packets need not align with SMP frames.
        """
        data = self.tls.decrypt(raw) if self.tls else raw
        if not self.mars:
            packets = self._plain.feed(data)
            if self.capture:
                for p in packets:
                    self.capture("receive", None, p.raw)
            return [(self.plain_channel, p) for p in packets]
        out: list = []
        self._frames += data
        while len(self._frames) >= MARS_HEADER_SIZE:
            if self._frames[1] not in (1, 2, 4, 8):
                raise MalformedMessage("invalid MARS flags", 1)
            head = MARS_HEADER.decode(bytes(self._frames[:MARS_HEADER_SIZE]), self.record)
            if head.id != MARS_ID:
                raise MalformedMessage("expected a MARS frame (0x53)", 0, head.node)
            if head.length < MARS_HEADER_SIZE or (head.flags != MarsFlags.DATA and head.length != MARS_HEADER_SIZE):
                raise MalformedMessage("invalid MARS length", 4, head.node)
            if head.length > MARS_MAX_FRAME:
                raise MalformedMessage("MARS frame exceeds the 1 MiB transport bound", 4, head.node)
            if len(self._frames) < head.length:
                break  # the rest of this frame hasn't arrived yet
            payload = bytes(self._frames[MARS_HEADER_SIZE : head.length])
            del self._frames[: head.length]
            channel = self._wire_channels.get(head.session_id)
            if channel is None:
                raise MalformedMessage(f"a MARS frame for unknown channel {head.session_id}", 0, head.node)
            if channel.closed_by_server:
                raise MalformedMessage("MARS frame after peer FIN", 1, head.node)
            if head.flags == MarsFlags.SYN:
                raise MalformedMessage("the server tried to open a MARS session", 1, head.node)
            if channel.closed and head.flags == MarsFlags.DATA:
                continue  # DATA already in flight after our FIN: ignore, per MC-SMP §3.1.5.1.1
            expected = (channel.received + (head.flags == MarsFlags.DATA)) & MARS_MASK
            if not channel.closed and head.sequence != expected:
                raise MalformedMessage("invalid MARS sequence", 8, head.node)
            if head.window != channel.send_window and not _mars_ahead(head.window, channel.send_window):
                raise MalformedMessage("MARS send window moved backwards", 12, head.node)
            channel.send_window = head.window
            while channel.waiting and self.can_send(channel):
                out.append(self.data(channel, channel.waiting.pop(0)))
            if head.flags != MarsFlags.DATA:
                if self.observing:
                    identity = f" · application channel {channel.id}" if channel.wire_id != channel.id else ""
                    self.observe(Event("mars", f"← MARS {head.node.shown}{identity}", head.node))
            match head.flags:
                case MarsFlags.DATA:
                    if not _mars_ahead(channel.receive_window, channel.received):
                        raise MalformedMessage("MARS receive window exceeded", 8, head.node)
                    channel.received = head.sequence
                    out.append((channel.id, MarsData(payload)))
                case MarsFlags.FIN:
                    channel.closed = channel.closed_by_server = True
                    out.append((channel.id, None))
        return out


# =========================================================================== the connection


@dataclass
class Options:
    host: str
    port: int
    user: str
    password: str = field(repr=False)
    database: str = ""
    app_name: str = "tds (python)"
    host_name: str = ""
    tds_version: str = "7.4"  # "8.0": TLS first, always encrypted (D-10)
    ssl_context: Any = None  # Python's ssl.SSLContext; None: the default, which verifies the certificate (D-10)
    server_hostname: str | None = None  # the name the certificate must carry, if not the host connected to
    features: tuple = login7.DEFAULT_FEATURES  # what the login asks for (D-8)
    language: str = ""  # the session's language; empty: the login's own default (D-9)
    read_only_intent: bool = False  # a routing hint for availability groups, not enforcement (D-9)
    login: Any = None  # a WindowsLogin, EntraToken or EntraLogin (D-55); None: a SQL Server login, user and password
    new_password: str = field(default="", repr=False)  # a SQL Server login's new password, set as it logs in
    login_server_name: str = ""  # LOGIN7's server name, if not `host`. After routing, it is "server,port" as routed.
    # MS-TDS doesn't say which name to send. Azure SQL's nodes refuse the name the application asked for (40613,
    # observed)
    mars: bool = False
    odbc: bool = True  # LOGIN7's ODBC flag: the session starts with ODBC's defaults (D-9). On by default.
    record: bool = True  # build inspection trees; False is the optimized mode


class ConnectionCore:
    """One connection: its link, session state and serial channels, and the procedures that use them."""

    def __init__(self, options: Options, observe: Callable[[Event], None] | None = None):
        self.options = options
        self.link = Link(options.record, lambda event: None)
        self._next_channel = 0  # never reuse a public lifetime, even without MARS
        self._joiner = Joiner()  # joins packets into messages while connecting
        self._observer: Callable[[Event], None] | None = None
        self._capture: Any = None
        self._capture_owner = object()  # a physical lifetime, not a reusable channel/session id
        self._capture_failure: CaptureError | None = None
        self._authenticating = False  # redact incoming raw Windows-login packets
        self._authentication_rounds = 0
        self._authentication_message_size = 0
        self.observation_error: Exception | None = None
        self._on_capture_failure: Callable[[CaptureError], None] = lambda failure: None
        self.set_observe(observe)
        self._on_session_change: Callable[[Record], None] = lambda change: None
        self._on_failure: Callable[[BaseException], None] = lambda failure: None
        self.session = SessionState()
        self.server: Record | None = None  # the LOGINACK
        self.features: dict = {}  # the features the server accepted (FEATUREEXTACK), with each one's data
        self._requested: set = set()  # the features this login asked for
        self.session_id = 0  # the server's id for this session (the packet header's session id)
        self.reset_pending = False  # the next request resets the session (the connection was given back, D-36)
        self.failure: BaseException | None = None  # why the connection can't continue, once it can't
        self._login: SessionState | None = None  # the session as login established it: what a reset returns to
        self.negotiated: dict = {}  # what later responses are read with, as agreed at login (D-8)
        self._pending: list[Message] = []  # messages read while connecting
        self.step = "start"  # the current connect step: start (the TCP connection), hello, secure, log in, ready
        self.recovery: Recovery | None = None  # what recovering the session needs, if the server agreed to it (D-57)
        self.broken_while_idle = False  # it broke with no request in progress: an exchange may recover it
        self.in_flight_when_broken: list[str] = []  # requests in progress when it broke, if any: never sent again

    def set_observe(self, observe: Callable[[Event], None] | None) -> None:
        """Who sees the running client, and how much (D-12). It can change only between exchanges, because a request
        in progress was described at one level, and its response must be read at the same level."""
        busy = [c.id for c in self.link.channels.values() if c.busy]
        if busy:
            raise SerialChannelMisuse(f"observability can't change while serial channel {busy[0]} has a request in "
                                      "flight: change it between exchanges")
        self._observer = observe if level_of(observe) is not Level.OFF else None
        self.observation_error = None
        self._route()

    def set_capture(self, capture: Any) -> None:
        """Write the conversation to a capture (D-12): every event and every plaintext packet. It can start or stop
        only between exchanges."""
        busy = [c.id for c in self.link.channels.values() if c.busy]
        if busy:
            raise SerialChannelMisuse(f"a capture can't start or stop while serial channel {busy[0]} has a request in "
                                      "flight: change it between exchanges")
        if capture is not None and (claim := getattr(capture, "_claim", None)) is not None:
            claim(self._capture_owner)  # reject sharing before changing the current route
        self._capture = capture
        self.link.capture = self._capture_packet if capture is not None else None
        self._route()

    def _route(self) -> None:
        """Send events to the observer, the capture, or both. A capture needs every event's line, not its tree."""
        observer, capture = self._observer, self._capture
        self.observing = observer is not None or capture is not None  # with neither, no event is built
        self.observe = self._emit
        record = level_of(observer) is Level.FULL  # only full keeps inspection trees
        self.options.record = self.link.record = record
        self.link.observe, self.link.observing = self.observe, self.observing
        for unpacker in (self.link._plain, self._joiner._unpacker, *(c.unpacker for c in self.link.channels.values())):
            unpacker.record = record

    def _emit(self, event: Event) -> None:
        if self._capture_failure is not None:
            raise self._capture_failure
        if self._observer is not None:
            try:
                self._observer(event)
            except Exception as failure:
                self.observation_error, self._observer = failure, None
                self.observing = self.link.observing = self._capture is not None
                # Keep this exchange's decoding mode: changing it halfway through
                # a response can change the inspection record already being built.
        if self._capture is not None:
            try:
                self._capture(event)
            except Exception as failure:
                self._capture_failed(failure)

    def _capture_packet(self, direction: str, channel: int | None, packet: bytes) -> None:
        if self._capture_failure is not None:
            raise self._capture_failure
        try:
            if self._authenticating and direction == "receive" and not getattr(self._capture, "keep_password", False):
                masked = packet[:8] + bytes(len(packet) - 8)
                if (redacted := getattr(self._capture, "redacted_authentication_packet", None)) is not None:
                    redacted(direction, channel, masked)
                else:
                    self._capture.packet(direction, channel, masked)
            else:
                self._capture.packet(direction, channel, packet)
        except Exception as failure:
            self._capture_failed(failure)

    def _capture_failed(self, cause: Exception) -> None:
        failure = CaptureError(cause)
        self.failure = self._capture_failure = failure
        self._on_capture_failure(failure)  # the shell closes the socket synchronously
        raise failure from cause

    # ----------------------------------------------------------------------- connect: hello → secure → log in → ready

    def connect(self, recovery: bytes | None = None) -> Generator[Action, Any, None]:
        """Connect and log in. `recovery`: a broken connection's session, for the login to recover (D-57)."""
        o = self.options
        self._began = time.perf_counter()  # each step shows its time since connecting began (D-12)
        strict = o.tds_version == "8.0"
        if strict:  # TDS 8.0: TLS before anything else, with the TDS version given by ALPN (MS-TDS §2.1)
            yield from self._secure_first()

        self._step("hello")
        federated = isinstance(o.login, (logins.EntraToken, logins.EntraLogin))
        hello = {"version": CLIENT_VERSION, "encryption": Encryption.ON, "instance": prelogin.INSTANCE_MATCH,
                 "thread_id": 0, "mars": OnOff.ON if o.mars else OnOff.OFF}
        if federated:  # the hello asks if the server requires federated authentication. The login echoes the answer
            hello["fed_auth_required"] = 1
        yield from self._send("hello", PacketType.HELLO, prelogin.PRELOGIN, {"options": hello})
        reply = self._malformed_is_a_connect_error("hello", lambda message: self._decode(
            message, prelogin.PRELOGIN, "hello reply"), (yield from self._next_message("hello"))).options
        if reply.get("instance", prelogin.INSTANCE_MATCH) != prelogin.INSTANCE_MATCH:
            raise ConnectError("hello", "reached the wrong server instance")
        # Under 8.0 the hello's encryption values are ignored, because TLS is already running (MS-TDS §2.2.6.5)
        if not strict and prelogin.outcome(Encryption.ON, reply.encryption) != "full":  # D-10: whole connection
            raise ConnectError("hello", f"the server answered encryption {reply.encryption.name.lower()}, "
                                        "so the connection can't be fully encrypted. tds_version='8.0' starts with "
                                        "TLS instead, if the server supports it")
        if o.mars and reply.get("mars") != OnOff.ON:
            raise ConnectError("hello", "MARS was requested, but the server didn't agree to it")
        fed_auth_echo = federated and reply.get("fed_auth_required") == 1
        nonce = reply.get("nonce")  # if the server sent one, a federated login echoes it
        if not strict:
            yield from self._secure_in_hello()

        self._step("log in", self._login_kind())
        login, exchange = o.login, None
        user, password, windows_auth = o.user, o.password, b""
        flags_2 = login7.OptionFlags2.INITIAL_LANGUAGE_MUST_SUCCEED | (
            login7.OptionFlags2.ODBC_CLIENT if o.odbc else login7.OptionFlags2(0))  # on by default (D-9)
        features = login7.feature_list(o.features, {login7.Feature.SESSION_RECOVERY: recovery} if recovery else None)
        for feature in features.keys() & login7.UNSUPPORTED.keys():
            warnings.warn(f"the login asks for {login7.UNSUPPORTED[feature]} ({feature.name}), which this driver does "
                          "not implement; the login fails if the server enables it", login7.UnsupportedFeatureWarning,
                          stacklevel=2)
        self._requested = set(features)
        if isinstance(login, logins.WindowsLogin):  # the first token goes in the login; the server may challenge it
            self._authenticating = True
            user = password = ""
            flags_2 |= login7.OptionFlags2.WINDOWS_AUTH
            exchange = yield from self._windows_call(login.provider.begin, o.host, o.port)
            windows_auth = yield from self._windows_step(exchange, None)
            if not windows_auth:
                raise ConnectError("log in", "the Windows provider supplied no initial token")
        elif federated:
            user = password = ""
            token = None
            if isinstance(login, logins.EntraToken):
                token = login.token if isinstance(login.token, str) else (
                    yield from self._obtain("the Entra ID token", login.token))
            features[login7.Feature.FEDERATED_AUTH] = logins.fed_auth_feature(login, token, fed_auth_echo, nonce)
        yield from self._send_login({
            "tds_version": login7.TDS_7_4,
            "packet_size": DEFAULT_SIZE,
            "client_library_version": 0x00010000,
            "client_process_id": os.getpid(),  # administrators see it as host_process_id (D-9)
            "connection_id": 0,
            "option_flags_1": login7.OptionFlags1.REPORT_DATABASE_CHANGES | login7.OptionFlags1.INITIAL_DATABASE_MUST_SUCCEED
            | login7.OptionFlags1.REPORT_LANGUAGE_CHANGES,
            "option_flags_2": flags_2,
            "type_flags": login7.TypeFlags.READ_ONLY_INTENT if o.read_only_intent else login7.TypeFlags(0),
            "option_flags_3": login7.OptionFlags3.CHANGE_PASSWORD if o.new_password else login7.OptionFlags3(0),
            # the feature list is added by login7.login (D-8)
            "time_zone": 0,
            "locale": 0x0409,
            "variable_part": {
                "host_name": o.host_name, "user_name": user, "password": password, "app_name": o.app_name,
                "server_name": o.login_server_name or o.host, "extension": b"", "library_name": "tds", "language": o.language,
                "database": o.database, "client_id": bytes(6), "windows_auth": windows_auth, "attach_file": "",
                "new_password": o.new_password, "large_windows_auth_length": 0},
        }, features)
        while True:  # the server's answer. For a Windows login, or a federated login that fetches its token mid-login,
            # it may first be an intermediate reply: a challenge (SSPI) or FEDAUTHINFO
            message = yield from self._next_message("log in")
            self.session_id = message.session_id
            reply = self._malformed_is_a_connect_error("log in", lambda m: self._tokens(m, "login reply", final=False),
                                                       message)
            done = any(r.token in ("LOGINACK", "ERROR") for r in reply)
            refused = any(r.token == "ERROR" for r in reply)
            challenges = [r.buffer for r in reply if r.token == "SSPI"]
            if len(challenges) > 1:
                raise ConnectError("log in", "multiple Windows authentication challenges in one reply")
            challenge = challenges[0] if challenges else None
            info = next((r for r in reply if r.token == "FEDAUTHINFO"), None)
            if exchange is not None and challenge is not None and not refused:
                answer = yield from self._windows_step(exchange, bytes(challenge))
                if done and answer:
                    raise ConnectError("log in", "the Windows provider produced another token after server acceptance")
                if answer:  # NTLM's challenge needs an answer. Kerberos's mutual authentication doesn't. The server
                    # sends its token, then its LOGINACK, without waiting. An empty answer would arrive after the
                    # login, as a request the server can't read, and the server would close the connection (observed)
                    yield from self._send_secret("Windows authentication: the answer to the server's token",
                                                 PacketType.WINDOWS_AUTH, bytes(answer))
                if not done:
                    continue
            if info is not None and isinstance(login, logins.EntraLogin):
                try:
                    where = _fed_auth_info(info)
                except ValueError as e:
                    raise ConnectError("log in", f"the server's FEDAUTHINFO is malformed: {e}") from None
                spn, sts_url = where.get(FedAuthInfoId.SPN, ""), where.get(FedAuthInfoId.STS_URL, "")
                self._step("log in", f"the server asks for a token for {spn} from {sts_url}")
                token = yield from self._obtain(f"a token for {spn} from {sts_url}", login.fetch, spn, sts_url)
                yield from self._send_secret("federated authentication token", PacketType.FEDERATED_AUTH_TOKEN,
                                             logins.fed_auth_token(token, nonce))
                continue
            break
        self._malformed_is_a_connect_error("log in", lambda m: self._final_done(reply, m, "login reply"), message)
        self._read_login_reply(reply)
        self._authenticating = False

        # CHANGE_PASSWORD is a one-time server operation. A completed final login
        # commits its result locally; routing/refused/incomplete logins never do.
        if o.new_password:
            self.options = dataclasses.replace(o, password=o.new_password, new_password="")

        self.link.packet_size = self.session.packet_size  # the announced size applies from the next message
        self.link.mars = o.mars  # MARS framing starts here, after login
        self._login = self.session.snapshot()
        if (ack := self.features.get(login7.Feature.SESSION_RECOVERY)) is not None:  # the session's initial states
            initial = {s.id: s.value for s in INITIAL_STATES.decode(ack, False).states} if ack else {}
            self.recovery = Recovery(self._login, initial)
        self._step("ready", f"session {self.session_id} · database {self.session.database} · packet size {self.session.packet_size}"
                            f"{' · MARS' if o.mars else ''}")

    def _secure_first(self) -> Generator[Action, Any, None]:
        """TDS 8.0: the TLS handshake runs directly on the TCP connection, before the hello. The certificate must be
        verified, because TLS that accepts any certificate can't stop a man-in-the-middle attack (D-10)."""
        o = self.options
        self._step("secure", "TDS 8.0: TLS first, ALPN tds/8.0")
        if o.ssl_context is not None and not verifies(o.ssl_context):
            raise ConnectError("secure", "TDS 8.0 requires verifying the server's certificate, and this ssl_context "
                                         "doesn't: TLS that accepts any certificate can't stop a man in the middle. "
                                         "To trust a private or self-signed authority, pass ssl_context="
                                         "ssl.create_default_context(cafile=…); for a certificate naming another host, "
                                         "server_hostname=…. tds_version='7.4' allows a context that doesn't verify")
        tls = Tls(o.server_hostname or o.host, o.ssl_context, ALPN_TDS_8)
        while not tls.handshake("secure"):
            if records := tls.take_output():
                yield Send(records)
                if self.observing:
                    self.observe(Event("send", f"→ TLS handshake · {len(records)} B"))
            data = yield Read()
            if not data:
                raise ConnectError("secure", "the server closed the connection during the TLS handshake. It may not "
                                             "support TDS 8.0, which needs SQL Server 2022 or later with a certificate "
                                             "configured; tds_version='7.4' agrees encryption in the hello instead")
            if self.observing:
                self.observe(Event("receive", f"← TLS handshake · {len(data)} B"))
            tls.feed(data)
        if records := tls.take_output():
            yield Send(records)
        self.link.tls = tls  # from here, every byte travels inside TLS, including the hello
        if self.observing:
            self.observe(Event("tls", f"secure · {tls.describe()}"))

    def _secure_in_hello(self) -> Generator[Action, Any, None]:
        """TDS 7.4: the TLS handshake travels inside hello packets, after the hello."""
        o = self.options
        self._step("secure", "the TLS handshake travels inside hello packets")
        tls = Tls(o.server_hostname or o.host, o.ssl_context)
        while True:
            done = tls.handshake("secure")
            if records := tls.take_output():
                yield from self._send_raw(PacketType.HELLO, records, "TLS handshake")
            if done:
                break
            try:
                message = yield from self._next_message("secure")
            except ConnectError as e:
                context = o.ssl_context
                if context is not None and context.minimum_version > ssl.TLSVersion.TLSv1_2:
                    raise ConnectError("secure", "the server closed the connection during the TLS handshake. Under "
                                                 "TDS 7.4 SQL Server negotiates TLS 1.2 at most, and this ssl_context "
                                                 f"requires {context.minimum_version.name}: tds_version='8.0' allows "
                                                 "TLS 1.3") from e
                raise ConnectError("secure", "the server closed the connection during the TLS handshake") from e
            if message.type != PacketType.HELLO:
                raise ConnectError("secure", f"expected TLS records in a hello packet, got a {message.type.name} packet")
            if self.observing:
                self.observe(Event("receive", f"← TLS handshake in hello packets · {len(message.body)} B"))
            tls.feed(message.body)
        self.link.tls = tls  # from here, whole packets travel inside TLS
        if self.observing:
            self.observe(Event("tls", f"secure · {tls.describe()}"))

    def _send_login(self, values: dict, features: dict) -> Generator[Action, Any, None]:
        body, node = login7.login(values, features, self.options.record)
        yield from self._send_body("log in", PacketType.LOGIN, body, node)

    def _read_login_reply(self, records: list[Record]) -> None:
        errors = [r for r in records if r.token == "ERROR"]
        ack = next((r for r in records if r.token == "LOGINACK"), None)  # success means LOGINACK is present
        routing = None
        for r in records:
            if r.token == "ENVCHANGE":
                if r.kind == EnvKind.ROUTING:
                    if r.old != 0:
                        raise ConnectError("log in", "the routing announcement has a nonempty old value")
                    routing = r.new
                else:
                    self._announce(r)
        for r in records:
            if r.token == "FEATUREEXTACK":
                self.features = dict(r.features)
        for feature in self.features.keys() & login7.UNSUPPORTED.keys():  # PY-AZ-06
            data = self.features[feature]
            if feature not in self._requested or len(data) != 1 or data[0] > 1:
                raise ConnectError("log in", f"the server's acknowledgement of {feature.name} is unrequested or "
                                             "malformed")
            if data == b"\x01":
                raise UnsupportedFeatureEnabled(feature)
        self.negotiated.update(login7.result_context(self.features))
        if ack is None:
            raise LoginRejected(errors)
        if ack.tds_version != login7.TDS_7_4:
            raise ConnectError("log in", f"the server speaks {login7.tds_version_name(ack.tds_version)}; "
                                         "TDS 7.4 or later is required (D-2)")
        if routing is not None:
            if routing.protocol != 0:
                raise ConnectError("log in", f"the routing protocol is {routing.protocol}, not TCP (0)")
            if routing.port == 0 or not routing.server or "\x00" in routing.server:
                raise ConnectError("log in", "the routing target has an invalid server name or port")
            raise Routed(routing.server, routing.port)
        self.server = ack

    # ----------------------------------------------------------------------- serial channels (D-17 to D-23)

    def open_channel(self, owner: Any) -> tuple[int, list[Send]]:
        """Without MARS a connection has exactly one serial channel; with MARS, as many as are opened."""
        if self.failure is not None:
            raise ConnectionError(self.why_broken()) from self.failure
        open_now = [c for c in self.link.channels.values() if not c.closed]
        if not self.link.mars and open_now:
            raise TooManySerialChannels()
        if not self.link.mars:
            # The previous lifetime was proven quiescent. Its stale handles are
            # rejected by identity; retaining its owner/state is unnecessary.
            self.link.channels.clear()
        channel_id = self._next_channel
        channel = self.link.open_channel(channel_id, owner)
        self._next_channel += 1
        if self.observing:
            self.observe(Event("channel", f"open serial channel {channel_id}"))
        if not self.link.mars:
            return channel_id, []
        return channel_id, [self.link.channel_frame(channel, MarsFlags.SYN)]

    def close_channel(self, channel_id: int) -> list[Send]:
        """Release a quiescent channel. Active close must cancel/drain first."""
        channel = self.link.channels.get(channel_id)
        if channel is None or channel.closed:
            return []
        if channel.busy:
            raise ExchangeInProgress(channel_id)
        if channel.open:
            raise RuntimeError("cannot release an unfinished bulk continuation")
        channel.closing = True
        channel.closed = True
        if self.observing:
            self.observe(Event("channel", f"close serial channel {channel_id}"))
        return [self.link.channel_frame(channel, MarsFlags.FIN)] if self.link.mars else []

    def revoke_channel(self, channel_id: int) -> None:
        """Revoke authority before any shell await or potentially failing I/O."""
        channel = self.link.channels.get(channel_id)
        if channel is None or channel.closed:
            return
        channel.closing = True

    def begin_channel_close(self, channel_id: int) -> list[Send]:
        """Only the private drainer may now advance the exchange."""
        self.revoke_channel(channel_id)
        channel = self.link.channels[channel_id]
        if channel.open and not channel.busy:
            # INSERT BULK's response ended, but the server still expects data.
            # Give its Attention acknowledgement the same sole reader/deadline
            # as active-response cleanup; FIN alone does not cancel this work.
            channel.open = None
            channel.busy, channel.writer = True, None
            channel.reader = ResponseReader(record=self.options.record, announce=self._announce,
                                            negotiated=self.negotiated)
        return self.cancel(channel_id)

    def drain_channel(self, channel_id: int) -> Generator[Action, Any, None]:
        """Cleanup's sole reader, after the shell has excluded the owner reader."""
        channel = self.link.channels[channel_id]
        if not channel.closing:
            raise RuntimeError("channel cleanup requires revoked authority")
        reader = channel.reader
        if reader is not None:
            reader.keep_new, reader.discard_new = False, True
            for result_set in reader.result_sets:
                result_set._drop_unread()
        while channel.busy:
            if reader is None:
                raise RuntimeError("busy channel has no response to drain")
            if reader.paused:
                reader.resume()  # an unclaimed large value may have paused decoding
            if reader.ended:
                self._ended(channel)
                break
            yield from self._read_channel(channel)

    def hand_over(self, channel_id: int, owner: Any, new_owner: Any) -> None:
        self._check_owner(channel_id, owner)
        self.link.channels[channel_id].owner = new_owner

    def _check_owner(self, channel_id: int, owner: Any) -> Channel:
        channel = self.link.channels.get(channel_id)
        if channel is None or channel.closing or channel.closed:
            raise ChannelClosed(channel_id)
        if channel.owner is not owner:
            raise NotTheOwner(channel_id)
        return channel

    # ------------------------------------------------------------------ an exchange: one request, its complete response
    # An exchange is one turn in the conversation on a serial channel. Every operation is built on it (D-33).
    # Constraint: neither this code nor the response reader branches on the kind of operation. The differences belong
    # in the request definitions and the outer layers.

    def exchange_channel(self, channel_id: int, owner: Any) -> Channel:
        """Check authority/failure/overlap before the shell waits on its reader lock.
        Recheck when starting the procedure, since an await can change the state."""
        channel = self._check_owner(channel_id, owner)
        if self.failure is not None:
            raise ConnectionError(self.why_broken()) from self.failure
        if channel.busy:
            raise ExchangeInProgress(channel_id)
        return channel

    def exchange(self, channel_id: int, owner: Any, request: Request,
                 decrypt: Callable | None = None,
                 on_complete: Callable | None = None) -> Generator[Action, Any, ResponseReader]:
        """Send one request. Returns the reader that `read` feeds the response to, packet by packet.

        A request is sent as it is produced: whole values at once, and each source's pieces as the source yields them
        (D-41). If something fails while the request is being sent (a source fails, a piece doesn't fit, or the task
        is canceled), the request is undone before the error reaches the caller, so the channel is free again (_undo).

        `decrypt` is Always Encrypted's hook (D-60). Given an encrypted value's type and ciphertext, it returns the
        value. Without it, encrypted values arrive as EncryptedValue: their ciphertext, as sent."""
        channel = self.exchange_channel(channel_id, owner)
        continues = getattr(request, "continues", None)  # requests that come in pairs say so (bulk load, D-50)
        if channel.open != continues:
            raise OutOfTurn(channel_id, channel.open, continues)
        channel.busy, channel.open, channel.opening = True, None, getattr(request, "opens", None)
        try:
            outstanding = sum(1 for c in self.link.channels.values() if c.busy)
            context = Context(self.session.transaction, outstanding, self.session.collation,
                              self.negotiated.get("column_encryption", 0))
            encoded = request.encode(context, self.options.record)  # a whole value that doesn't fit fails here, unsent
            reset, self.reset_pending = self.reset_pending, False
            channel.reader = ResponseReader(self.options.record, lambda change: self._announce(change, request),
                                            request.metadata, request, {**self.negotiated, "decrypt": decrypt}, on_complete)
            channel.writer = PacketWriter(request.kind, self.link.packet_size, self.options.record,
                                          Status.RESET_SESSION if reset else Status(0))
            yield from self._send_request(request.label, encoded, channel)
        except GeneratorExit:
            raise  # abandoned without cleanup: the channel stays busy, so the connection is never lent again
        except BaseException:
            if self.failure is None:  # failed recording already revoked the whole connection
                yield from self._undo(channel, continues)
            raise
        channel.writer = None
        return channel.reader

    def _send_request(self, what: str, encoded, channel: Channel) -> Generator[Action, Any, None]:
        writer, (body, node, streams) = channel.writer, encoded
        at, streamed = 0, []
        for stream in streams:  # each source's pieces go at its place in the body: PLP chunks, or a table's rows
            yield from self._put(writer, body[at : stream.offset], channel)
            at, pieces, size = stream.offset, 0, 0
            while (piece := (yield Produce(stream.source))) is not END:
                try:
                    data = stream.encode(piece)  # framed. A piece that doesn't fit is refused here (D-48)
                except Exception as e:
                    for place in reversed(stream.places):  # say where the source sits in the request (D-53)
                        if hasattr(e, "within"):
                            e.within(place)
                    raise
                if data:
                    pieces, size = pieces + 1, size + len(data)
                    yield from self._put(writer, data, channel)
            yield from self._put(writer, stream.end, channel)  # the chunk of length 0, or the end of the rows
            streamed.append(f"a source: {pieces} {stream.unit}, {size} bytes")
        yield from self._put(writer, body[at:], channel)
        yield from self._send_packets([writer.finish()], channel)
        channel.reader.timing.sent = time.perf_counter()  # the whole request has been handed to the connection
        if Status.RESET_SESSION in writer.first:
            what += " · resets the session"
        summary = " · ".join(filter(None, [node.shown if node is not None else "", *streamed]))
        self._show("send", "→", what, None, writer.headers, b"", channel, size=writer.size, shown=summary, count=writer.packets,
                   tree=node)

    def _put(self, writer: PacketWriter, data: bytes, channel: Channel) -> Generator[Action, Any, None]:
        if data:
            yield from self._send_packets(writer.add(data), channel)

    def _send_packets(self, packets: list[bytes], channel: Channel) -> Generator[Action, Any, None]:
        if not packets:
            return
        if not self.link.mars:
            yield self.link.plain(packets)
            return
        for packet in packets:
            while not self.link.can_send(channel):  # the server's credit is used up: wait for it to raise the window
                yield AwaitWindow(channel.id)
            yield self.link.data(channel, packet)

    def _undo(self, channel: Channel, continues: str | None = None) -> Generator[Action, Any, None]:
        """Undo a request that failed or was canceled while being sent, so the channel is free again (D-41).
          nothing sent yet         nothing to undo
          partly sent              the next packet carries IGNORE and LAST. The server runs nothing, and answers
                                   with a DONE marked error, which is read. SQL Server sends a message before it:
                                   error 4002 for a call, message 3621 for bulk rows
          all of it sent           Attention, as for any cancel. The response is read to the server's acknowledgement"""
        writer, reader = channel.writer, channel.reader
        if continues and (writer is None or not writer.started):
            # Preparation already succeeded on the server. No data was sent,
            # so the earlier obligation survives and awaited close must drain it.
            channel.open = continues
        channel.writer = None
        if writer is not None and writer.started and reader is not None:
            if writer.finished:
                yield from self._send_packets(self.cancel(channel.id), channel)
            else:
                yield from self._send_packets([writer.abandon()], channel)
                self._show("send", "→", "request abandoned · ignore + last", None, writer.headers[-1:], b"", channel,
                           count=1)
            while not reader.ended:
                packet = yield from self._receive_packet(channel)
                if packet is None:
                    break
                reader.feed(packet.body, packet.last, packet.header)
            self._show_response(channel, reader)
        channel.opening = None  # undone: nothing was opened
        self._ended(channel)

    def _ended(self, channel: Channel) -> None:
        """The response has ended, and the channel is free. What the request opened is open, if it succeeded."""
        reader = channel.reader
        if channel.opening and reader is not None and reader.ended and not reader.cancelled and not reader.errors \
                and not any(DoneStatus.ERROR in c.status for c in reader.completions):
            channel.open = channel.opening
        channel.busy, channel.reader, channel.opening = False, None, None

    def read(self, channel_id: int, owner: Any) -> Generator[Action, Any, None]:
        """Feed the channel's response one more packet. Once the response has ended, the channel is free."""
        channel = self._check_owner(channel_id, owner)
        yield from self._read_channel(channel)

    def _read_channel(self, channel: Channel) -> Generator[Action, Any, None]:
        channel_id = channel.id
        reader = channel.reader
        if reader is None or reader.ended:
            return
        if self.failure is not None:
            raise ConnectionError(self._in_flight(reader, self.failure)) from self.failure
        try:
            packet = yield from self._receive_packet(channel)
        except OSError as e:  # the connection broke while this request was in progress
            raise ConnectionError(self._in_flight(reader, e)) from e
        if packet is None:
            raise ConnectionError(f"the server closed serial channel {channel_id}")
        try:
            if packet.type != PacketType.SERVER_MESSAGE:
                raise MalformedMessage(f"expected a server message, got a {packet.type.name} packet", 0, packet.header)
            reader.feed(packet.body, packet.last, packet.header)
        except Exception as e:  # malformed, or a value that can't be decoded (such as an unknown collation)
            self.failure = e  # the token stream can't be followed further, so the connection can't continue
            self._on_failure(e)
            raise
        if reader.ended:
            self._ended(channel)
            self._show_response(channel, reader)

    @staticmethod
    def _in_flight(reader: ResponseReader, failure: BaseException) -> str:
        return (f"the connection broke while {reader.request} was in progress ({failure}). Whether it ran is unknown, "
                "so the driver never sends it again (D-57)")

    def why_broken(self) -> str:
        """Why the connection can't continue, and what that means for recovering its session (D-57)."""
        why = f"the connection can't continue: {self.failure}"
        if self.in_flight_when_broken and self.recovery is not None:
            why += (f". It broke while {', '.join(self.in_flight_when_broken)} was in progress, so it isn't recovered by "
                    "itself: whether that ran is unknown. connection.recover() recovers the session as the server "
                    "last reported it, without whatever that request did")
        return why

    def resume(self, channel_id: int) -> None:
        """Decode a paused response's bytes already received. Once the response has ended, the channel is free."""
        channel = self.link.channels.get(channel_id)
        if channel is None:
            raise ChannelClosed(channel_id)
        if channel.closing or channel.closed:
            raise ChannelClosed(channel_id)
        reader = channel.reader
        if reader is None or reader.ended:
            return
        try:
            reader.resume()
        except Exception as failure:
            self.failure = failure
            self._on_failure(failure)
            raise
        if reader.ended:
            self._ended(channel)
            self._show_response(channel, reader)

    def cancel(self, channel_id: int) -> list[Send]:
        """Send Attention for the channel's request in progress. Anyone may cancel (D-23). The owner's reading then
        discards everything up to the server's acknowledgement (Conversations #9). A partly sent request is undone
        by its own exchange instead (_undo)."""
        channel = self.link.channels.get(channel_id)
        reader = channel.reader if channel else None
        if reader is None or reader.ended or reader.cancelling or (channel.writer is not None and not channel.writer.finished):
            return []
        reader.cancelling = True
        packets, headers = self.link.packets(PacketType.CANCEL, b"")
        self._show("send", "→", "attention · cancel the request in progress", None, headers, b"", channel)
        if not self.link.mars:
            return [self.link.plain(packets)]
        if self.link.can_send(channel):
            return [self.link.data(channel, packets[0])]
        channel.waiting.append(packets[0])  # sent as soon as the server raises the window
        return []

    def _receive_packet(self, channel: Channel) -> Generator[Action, Any, Packet | None]:
        """Return one TDS packet; account credit per consumed SMP DATA frame."""
        while not channel.packets:
            incoming = yield Receive(channel.id)
            if incoming is None:
                return None
            if isinstance(incoming, MarsData):
                channel.packets.extend(channel.unpacker.feed(incoming.body))
                yield from self._return_credit(channel)
                if self.link.capture:
                    for packet in channel.packets:
                        self.link.capture("receive", channel.id, packet.raw)
            else:
                # Plain transport and core callers that supply a packet directly.
                if self.link.mars:
                    yield from self._return_credit(channel)
                return incoming
        return channel.packets.popleft()

    def _return_credit(self, channel: Channel) -> Generator[Action, Any, None]:
        """MARS: the owner consumed one more DATA frame. Return its credit in steps."""
        channel.consumed = (channel.consumed + 1) & MARS_MASK
        if ((channel.receive_window - channel.consumed) & MARS_MASK) < MARS_WINDOW // 2:
            channel.receive_window = (channel.consumed + MARS_WINDOW) & MARS_MASK
            yield self.link.channel_frame(channel, MarsFlags.ACK)

    def _show_response(self, channel: Channel, reader: ResponseReader) -> None:
        if not self.observing:
            return
        what = "cancel acknowledged" if reader.cancelled else "response"
        where = f" · channel {channel.id}" if self.link.mars else ""
        tally = " ".join(f"{name}×{n}" if n > 1 else name for name, n in reader.tally.items())
        packets = f"{reader.packets} packet{'s' if reader.packets != 1 else ''}"
        tree = Node(what, 0, reader.size, b"", children=reader.nodes) if self.options.record else None
        t = reader.timing
        took = " · ".join(f"{label} {milliseconds(v)}" for label, v in
                          (("first packet", t.until_first_packet), ("done", t.until_end)) if v is not None)
        if self.observing:
            self.observe(Event("receive", f"← {what}{where} · {reader.size} B · {packets} · {tally}", tree, took=took))

    # ----------------------------------------------------------------------- giving a connection back (D-36)

    def release(self) -> tuple[bool, list[Send]]:
        """Prepare this connection to be lent again. Returns False if it can't be, because with a request still in
        progress, its next borrower would read that request's response. Otherwise its channels close, and its session
        will be reset."""
        if any(c.busy or c.open or (c.closing and not c.closed) for c in self.link.channels.values()):
            if self.observing:
                self.observe(Event("pool", "can't be lent again: a request is still in progress, so it will be closed"))
            return False, []
        # Once a sequence number reaches FFFFFFFF, session recovery must stay off, and the client must not reset the
        # session: a reset would return it to a recoverable state (§2.2.7.21).
        if self.recovery is not None and self.recovery.exhausted:
            if self.observing:
                self.observe(Event("pool", "can't be lent again: its session can't be reset once its session state's "
                                           "sequence number has run out, so it will be closed"))
            return False, []
        sends = [s for c in list(self.link.channels) for s in self.close_channel(c)]
        self.reset_pending = True
        if self.observing:
            self.observe(Event("pool", "given back: its session will be reset by its next request"))
        return True, sends

    # ------------------------------------------------------------------ recovering a broken connection's session (D-57)

    def recovery_refusal(self) -> str | None:
        """Why this connection's session can't be recovered, or None if it can."""
        if any(c.open or c.opening for c in self.link.channels.values()):
            return "an unfinished bulk conversation must be completed or abandoned explicitly"
        if self._capture_failure is not None:
            return "the requested saved recording is incomplete; open a new connection explicitly"
        if self.recovery is None:
            if login7.Feature.SESSION_RECOVERY not in self.options.features:
                return "the login didn't ask for session recovery (it isn't among connect(features=…))"
            return "the server didn't agree to session recovery at login"
        return self.recovery.refusal()

    def recovery_data(self) -> bytes:
        """The recovery login's data: the session as login established it, and as the server last reported it."""
        data, _ = RECOVERY.encode(self.recovery.data(self.session, reset=self.reset_pending), False)
        return data

    def adopt(self, old: ConnectionCore) -> list[Send]:
        """After a recovery login, this connection continues the old connection's session (D-57). What recovery needs
        stays as the first login established it. The serial channels that were open on the old connection are opened
        here, with the same application ids and owners, and each is free. Under MARS each gets a fresh wire id
        and is opened with SYN, including the channels that the server closed when the session ended."""
        self.recovery = Recovery(old.recovery.initial, old.recovery.initial_states, dict(old.recovery.states))
        self._login = old._login
        self._next_channel = old._next_channel
        sends = []
        for c in old.link.channels.values():
            if c.closing or (c.closed and not c.closed_by_server):  # revoked by the application: it stays revoked
                continue
            channel = self.link.open_channel(c.id, c.owner)
            if self.link.mars:
                sends.append(self.link.channel_frame(channel, MarsFlags.SYN))
        return sends

    # ----------------------------------------------------------------------- closing

    def close(self) -> list[Send]:
        """Close every channel, then end TLS. TDS has no logout message: closing the connection ends the session."""
        self._step("close")
        # Connection destruction discards every outstanding conversation; unlike
        # channel release, it never promises that a busy channel became reusable.
        sends = []
        for channel in self.link.channels.values():
            channel.closing = channel.closed = True
        if self.link.tls:
            sends.append(Send(self.link.tls.close()))
        return sends

    def feed(self, raw: bytes) -> list[Send | tuple[int, Packet | MarsData | None]]:
        """Connected bytes: route packets/DATA frames to each channel's inbox."""
        return self.link.feed(raw)

    # ----------------------------------------------------------------------- helpers shared by the procedures

    def _step(self, name: str, detail: str = "") -> None:
        self.step = name  # the current connect step, for errors that say where connecting stopped
        if self.observing:
            began = getattr(self, "_began", None)
            took = f"at {milliseconds(time.perf_counter() - began)}" if began is not None and name != "close" else ""
            self.observe(Event("step", f"{name}{' · ' + detail if detail else ''}", took=took))

    def _send(self, what: str, kind: PacketType, definition: Struct, values: dict, channel: Channel | None = None,
              first: Status = Status(0)):
        body, node = definition.encode(values, self.options.record)
        yield from self._send_body(what, kind, body, node, channel, first)

    def _send_body(self, what: str, kind: PacketType, body: bytes, node: Node | None, channel: Channel | None = None,
                   first: Status = Status(0)):
        packets, headers = self.link.packets(kind, body, first)
        if Status.RESET_SESSION in first:
            what += " · resets the session"
        self._show("send", "→", what, node, headers, body, channel)
        if not self.link.mars:
            yield self.link.plain(packets)
            return
        for packet in packets:
            while not self.link.can_send(channel):  # the server's credit is used up: wait for it to raise the window
                yield AwaitWindow(channel.id)
            yield self.link.data(channel, packet)

    def _send_raw(self, kind: PacketType, payload: bytes, what: str):
        packets, _ = self.link.packets(kind, payload)
        if self.observing:
            self.observe(Event("send", f"→ {what} in hello packets · {len(payload)} B"))
        yield self.link.plain(packets)

    def _next_message(self, step: str) -> Generator[Read, bytes, Message]:
        """While connecting: read until a whole message has arrived."""
        while not self._pending:
            data = yield Read()
            if not data:
                why = (". SQL Server gives the reason only in its error log: for example, a dedicated administrator "
                       "connection already in use (one at a time), or a server shutting down") if step == "hello" else ""
                raise ConnectError(step, f"the server closed the connection{why}")
            for item in self.link.feed(data):
                if isinstance(item, tuple) and item[1] is not None:
                    packet = item[1]
                    if self._authenticating:
                        self._authentication_message_size += len(packet.body)
                        if self._authentication_message_size > logins.MAX_LOGIN_MESSAGE:
                            raise ConnectError(step, "Windows login message exceeds the driver size limit")
                        if packet.last:
                            self._authentication_message_size = 0
                    if (message := self._joiner.add(packet)) is not None:
                        self._pending.append(message)
        return self._pending.pop(0)

    def _malformed_is_a_connect_error(self, step: str, read: Callable[[Message], Any], message: Message) -> Any:
        """While connecting, a reply that can't be read fails the step, saying what arrived (D-53)."""
        try:
            return read(message)
        except MalformedMessage as e:
            if self._authenticating:
                raise ConnectError(step, f"the Windows login reply is malformed at byte {e.offset:#x}; "
                                         "authentication payload hidden") from None
            shown = message.body[:32].hex(" ").upper() + (" …" if len(message.body) > 32 else "")
            raise ConnectError(step, f"the server's reply can't be read: {e}. It arrived as {len(message.body)} "
                                     f"bytes: {shown}") from e

    def _decode(self, message: Message, definition: Struct, what: str) -> Record:
        if message.type != PacketType.SERVER_MESSAGE:
            raise ConnectError(what, f"expected a server message, got a {message.type.name} packet")
        record = definition.decode(message.body, self.options.record)
        self._show("receive", "←", what, record.node, message.headers, message.body)
        return record

    def _tokens(self, message: Message, what: str, channel: Channel | None = None, final: bool = True) -> list[Record]:
        """A whole message's tokens. `final`: it must end with a final DONE (a login's challenge doesn't)."""
        if message.type != PacketType.SERVER_MESSAGE:
            raise MalformedMessage(f"expected a server message, got a {message.type.name} packet", 0)
        records = TOKENS.decode(message.body, self.options.record)
        if final:
            self._final_done(records, message, what)
        node = Node(what, 0, len(message.body), message.body, children=[r.node for r in records if r.node])
        counts: dict[str, int] = {}
        for r in records:
            counts[r.token] = counts.get(r.token, 0) + 1
        node.shown = " ".join(f"{n}×{k}" if k > 1 else n for n, k in counts.items())
        safe_login_tokens = None
        if self._capture is not None and self._authenticating and what == "login reply":
            safe = bytearray(message.body)
            for record in records:
                if record.token == "SSPI":
                    start, end = record.node.start + 3, record.node.end
                    safe[start:end] = bytes(end - start)
            safe_login_tokens = bytes(safe)
        self._show("receive", "←", what, node, message.headers, message.body, channel,
                   safe_login_tokens=safe_login_tokens)
        return records

    @staticmethod
    def _final_done(records: list[Record], message: Message, what: str) -> None:
        last = records[-1] if records else None
        if last is None or last.token not in ("DONE", "DONEPROC", "DONEINPROC") or DoneStatus.MORE in last.status:
            raise MalformedMessage(f"the {what} didn't end with a final DONE", len(message.body))

    def _login_kind(self) -> str:
        login = self.options.login
        if isinstance(login, logins.WindowsLogin):
            return "Windows (Kerberos or NTLM, as the security library chooses)"
        if isinstance(login, logins.EntraToken):
            return "Entra ID, with a token"
        if isinstance(login, logins.EntraLogin):
            return "Entra ID, fetching a token when the server says where from"
        return f"SQL Server login {self.options.user}" + (", changing its password" if self.options.new_password else "")

    @staticmethod
    def _obtain(what: str, fn: Callable, *args: Any) -> Generator[Action, Any, Any]:
        """Call the application's token function (D-55). If it fails, the login fails, naming what was being made."""
        try:
            return (yield Obtain(fn, args))
        except Exception as e:
            raise ConnectError("log in", f"{what} couldn't be made: {type(e).__name__}: {e}") from e

    def _windows_step(self, exchange, challenge):
        if challenge is not None and len(challenge) > logins.MAX_TOKEN:
            raise ConnectError("log in", "Windows authentication challenge exceeds the driver token limit")
        if self._authentication_rounds >= logins.MAX_ROUNDS:
            raise ConnectError("log in", "Windows authentication exceeds the driver round limit")
        self._authentication_rounds += 1
        token = yield from self._windows_call(exchange.step, challenge)
        if token is None:
            token = b''
        if not isinstance(token, (bytes, bytearray, memoryview)):
            raise ConnectError("log in", "the Windows provider returned a non-byte token")
        if len(token) > logins.MAX_TOKEN:
            raise ConnectError("log in", "Windows authentication output exceeds the driver token limit")
        return bytes(token)

    @staticmethod
    def _windows_call(fn, *args):
        try:
            return (yield Obtain(fn, args))
        except Exception as failure:
            error = ConnectError("log in", "the Windows authentication provider refused or failed")
            error.provider_error = failure  # explicit inspection, excluded from ordinary diagnostics
            raise error from None

    def _send_secret(self, what: str, kind: PacketType, body: bytes) -> Generator[Action, Any, None]:
        """Send a message that is only a credential. It is shown by its length only, at every level, and captures zero
        its bytes too."""
        packets, headers = self.link.packets(kind, body)
        if self.observing:
            self.observe(Event("send", f"→ {what} · {len(body)} B · {len(packets)} packet{'s' if len(packets) != 1 else ''}"
                                       f" · •••• (hidden)"))
        yield self.link.plain(packets)

    def _announce(self, change: Record, request: Request | None = None) -> None:
        """A change the server announced: a session setting (ENVCHANGE), or the session's state (SESSIONSTATE)."""
        if change.token == "SESSIONSTATE":
            if self.recovery is not None:
                self.recovery.follow(change, str(request) if request is not None else "the login")
            if self.observing:
                recoverable = "recoverable" if change.status & 1 else "not recoverable"
                ids = ", ".join(str(s.id) for s in change.states)
                self.observe(Event("state", f"session state {change.sequence} · {recoverable} · states {ids}"))
            return
        if change.kind == EnvKind.RESET_COMPLETE and self._login is not None:
            self.session.restore(self._login)  # back to what login established
            if self.recovery is not None:
                self.recovery.reset()
        self.session.apply(change)
        self._on_session_change(change)
        if self.observing:
            self.observe(Event("state", f"session · {change.node.shown if change.node else change.kind.name.lower()}"))

    def _show(self, kind: str, arrow: str, what: str, node: Node | None, headers: list[Node], body: bytes,
              channel: Channel | None = None, size: int | None = None, shown: str | None = None,
              tree: Node | None = None, count: int | None = None,
              safe_login_tokens: bytes | None = None) -> None:
        if not self.observing:  # off: nothing is described
            return
        where = f" · channel {channel.id}" if channel is not None and self.link.mars else ""
        shown = shown if shown is not None else (node.shown if node is not None else "")
        summary = f" · {shown}" if shown else ""
        size = len(body) if size is None else size
        count = len(headers) if count is None else count  # a request's headers are kept only when recording
        packets = f"{count} packet{'s' if count != 1 else ''}"
        tree = tree or node
        whole = Node(what, 0, size, kept(body), children=[*headers, tree]) if tree is not None else None
        if what == "login reply":
            whole = logins._redact_authentication(whole)
        if self.observing:
            self.observe(Event(kind, f"{arrow} {what}{where} · {size} B · {packets}{summary}", whole,
                               safe_login_tokens=safe_login_tokens))
