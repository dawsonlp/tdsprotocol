"""Captures and replay (D-12): a conversation recorded as it happened, and replayed into the same view.

    connection = await tds.connect(…, capture=Capture("session.jsonl"))       # or: connection.capture = Capture(…)
    replay("session.jsonl", Printer(Level.FULL))                              # the identical view, offline

A capture is JSON lines, in the order that things happened. Each line has its time in seconds from the first line:
    {"t": 0, "start": wall-clock time, UTC, ISO 8601}                         first, to align it with server logs
    {"t": …, "event": kind, "text": the event's line, "took": durations}     every event the client shows
    {"t": …, "packet": "send" | "receive", "channel": id or null, "bytes": base64}
                                                                              every TDS packet as plaintext, after TLS
                                                                              for a received packet and before TLS for
                                                                              a sent packet

Packet channel ids identify application channel lifetimes. A recorded MARS
header carries the physical SMP wire id; after recovery these numbers can differ.
Each physical connection has its own recording, including each recovery login.

The password is removed from the login, unless keep_password=True. Its bytes are zeroed and its length is kept.
LOGIN7's scrambling is reversible, so otherwise a capture would hold the password. Query text and data stay, because
a capture exists to record them. Protect a capture as carefully as the data that it holds.

Replay decodes every message from its packets with the same definitions that the live client uses, so its fields
and bytes are what the server and client actually sent. Each event's line is the recorded one.
Saved table inputs decode their declaration, default columns, hints, placement and exact rows, separately from
result cells. The Rust development client can inspect the same physical recordings offline with --replay.
"""

import base64
import json
import time
from datetime import datetime, timezone
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Callable, TextIO

from . import login7, prelogin
from .connection.core import Event, Level, level_of
from .login7 import LOGIN7
from .packet import HEADER, HEADER_SIZE, PacketType, Status
from .requests import BULK_DATA, RPC, SQL_BATCH
from .response import ResponseReader
from .tokens import TOKENS
from .transactions import TRANSACTION_MANAGER
from .wire import Node

# Where LOGIN7's fixed part holds each credential's (offset u16, length u16). Lengths count characters or bytes
# (§2.2.6.4)
PASSWORD_AT, NEW_PASSWORD_AT, WINDOWS_AUTH_AT, EXTENSION_AT = 0x2C, 0x56, 0x4E, 0x38
LARGE_WINDOWS_AUTH_AT = 0x5A  # the u32 length, when the u16 one is FFFF
FEDERATED_AUTH = 0x02  # the feature whose data holds an Entra ID token
CREDENTIAL_MESSAGES = (PacketType.FEDERATED_AUTH_TOKEN, PacketType.WINDOWS_AUTH)  # messages that hold only a token


def _zero(body: bytearray, at: int, length: int) -> None:
    body[at : at + length] = bytes(len(body[at : at + length]))


def without_secrets(kind: int, body: bytes) -> bytes:
    """A message with every credential's bytes zeroed and their lengths kept, so the view doesn't change. In a login,
    these are the password, a new password, a Windows token and an Entra ID token. A token message is zeroed whole."""
    if kind in CREDENTIAL_MESSAGES:
        return bytes(len(body))
    if kind != PacketType.LOGIN:
        return body
    out = bytearray(body)
    u16 = lambda at: int.from_bytes(out[at : at + 2], "little")  # noqa: E731
    for at in (PASSWORD_AT, NEW_PASSWORD_AT):
        _zero(out, u16(at), 2 * u16(at + 2))
    windows = u16(WINDOWS_AUTH_AT + 2)
    if windows == 0xFFFF:
        windows = int.from_bytes(out[LARGE_WINDOWS_AUTH_AT : LARGE_WINDOWS_AUTH_AT + 4], "little")
    _zero(out, u16(WINDOWS_AUTH_AT), windows)
    if u16(EXTENSION_AT + 2) == 4:  # the feature list: search it for the federated authentication feature
        at = int.from_bytes(out[u16(EXTENSION_AT) : u16(EXTENSION_AT) + 4], "little")
        while at < len(out) and out[at] != 0xFF:
            feature, length = out[at], int.from_bytes(out[at + 1 : at + 5], "little")
            if feature == FEDERATED_AUTH and length > 1:
                _zero(out, at + 6, length - 1)  # everything after its options byte: the token, and the nonce
            at += 5 + length
    return bytes(out)


class Capture:
    """One physical connection's conversation, as JSON lines.

    A capture cannot move to another connection, even after detachment or close:
    this format has no connection identity. For pools, routing and recovery use
    capture_factory=… to create a new Capture with a distinct output each time.
    The application owns its captures and closes them when finished.
    """

    level = Level.OUTLINE  # a capture keeps every event's line. Replay rebuilds the trees from the packets

    def __init__(self, file: str | Path | TextIO, keep_password: bool = False):
        self._owned = not hasattr(file, "write")
        self._out: TextIO = open(file, "w") if self._owned else file
        self.keep_password = keep_password
        self._held: list[tuple[str, int | None, bytes]] = []  # a credential-bearing message's packets, until its last
        self._start: float | None = None
        self._owner: object | None = None

    def _claim(self, owner: object) -> None:
        if self._owner is not None and self._owner is not owner:
            raise ValueError("a Capture belongs to one physical connection; use capture_factory for new connections")
        self._owner = owner

    def _when(self, at: float) -> float:
        if self._start is None:
            self._start = at
            self._write({"t": 0, "start": datetime.now(timezone.utc).isoformat()})
        return round(at - self._start, 6)

    def _write(self, line: dict) -> None:
        text = json.dumps(line) + "\n"
        if self._out.write(text) != len(text):
            raise OSError("short saved-recording write")
        # Detect a buffered writer's failure while its connection can still be
        # stopped, rather than deferring it until an unrelated file close.
        self._out.flush()

    def __call__(self, event: Event) -> None:
        line = {"t": self._when(event.time), "event": event.kind, "text": event.text}
        if event.took:
            line["took"] = event.took
        if event.kind == "mars" and event.node is not None:  # a MARS frame's header: replay decodes it
            line["bytes"] = base64.b64encode(event.node.raw).decode()
        self._write(line)

    def packet(self, direction: str, channel: int | None, data: bytes) -> None:
        if direction == "send" and data[0] in (PacketType.LOGIN, *CREDENTIAL_MESSAGES) and not self.keep_password:
            self._held.append((direction, channel, data))  # a credential can span packets: redact the whole message
            if not data[1] & Status.LAST:
                return
            packets, self._held = self._held, []
            body = without_secrets(data[0], b"".join(p[HEADER_SIZE:] for _, _, p in packets))
            at = 0
            for direction, channel, packet in packets:  # the same packets, with their bodies redacted
                size = len(packet) - HEADER_SIZE
                self._write_packet(direction, channel, packet[:HEADER_SIZE] + body[at : at + size])
                at += size
            return
        self._write_packet(direction, channel, data)

    def _write_packet(self, direction: str, channel: int | None, data: bytes) -> None:
        self._write({"t": self._when(time.perf_counter()), "packet": direction, "channel": channel,
                     "bytes": base64.b64encode(data).decode()})

    def close(self) -> None:
        self._out.flush()
        if self._owned:
            self._out.close()


# --------------------------------------------------------------------------- replay


def _messages(lines: list[dict]) -> dict[tuple, deque]:
    """Every message, rebuilt from its packets, per direction and channel, in order. A message ends at a packet
    marked LAST."""
    messages: dict[tuple, deque] = defaultdict(deque)
    partial: dict[tuple, list[bytes]] = defaultdict(list)
    for line in lines:
        if "packet" in line:
            key, data = (line["packet"], line["channel"]), base64.b64decode(line["bytes"])
            partial[key].append(data)
            if Status.LAST in Status(data[1]):
                messages[key].append(partial.pop(key))
    return messages


def _headers(packets: list[bytes]) -> list[Node]:
    return [HEADER.decode(p[:HEADER_SIZE], True).node for p in packets]


def _body(packets: list[bytes]) -> bytes:
    return b"".join(p[HEADER_SIZE:] for p in packets)


def _decoded(what: str, packets: list[bytes], definition) -> Node:
    """A message as the live client shows it: its packets' headers, then its definition's fields."""
    body = _body(packets)
    try:
        node = definition(body)
    except Exception as e:  # say what failed, rather than show nothing
        node = Node(what, 0, len(body), body[:64], shown=f"can't be decoded on replay: {e}")
    return Node(what, 0, len(body), body[:8192], children=[*_headers(packets), node])


def _tokens(what: str, negotiated: dict):
    def decode(body: bytes) -> Node:
        records = TOKENS.decode(body, True)
        counts: dict[str, int] = {}
        for r in records:
            if r.token == "FEATUREEXTACK":
                negotiated.update(login7.result_context(dict(r.features)))
            counts[r.token] = counts.get(r.token, 0) + 1
        node = Node(what, 0, len(body), body, children=[r.node for r in records if r.node])
        node.shown = " ".join(f"{n}×{k}" if k > 1 else n for n, k in counts.items())
        return node
    return decode


REQUESTS: dict[str, Callable[[bytes], Node]] = {  # what the live client calls each message, and its definition
    "hello": lambda b: prelogin.PRELOGIN.decode(b, True).node,
    "hello reply": lambda b: prelogin.PRELOGIN.decode(b, True).node,
    "log in": lambda b: LOGIN7.decode(b, True).node,
    "SQL batch": lambda b: SQL_BATCH.decode(b, True).node,
    "INSERT BULK": lambda b: SQL_BATCH.decode(b, True).node,
    "RPC": lambda b: RPC.decode(b, True).node,
    "bulk data": lambda b: BULK_DATA.decode(b, True).node,
    "transaction manager": lambda b: TRANSACTION_MANAGER.decode(b, True).node,
}


def replay(file: str | Path | TextIO, observe: Callable[[Event], None]) -> None:
    """Decode a capture into the events the live client produced, for an observer such as a Printer (D-12)."""
    text = file.read() if hasattr(file, "read") else Path(file).read_text()
    lines = [json.loads(l) for l in text.splitlines() if l.strip()]
    messages = _messages(lines)
    full = level_of(observe) is Level.FULL
    cancelling: set = set()
    negotiated: dict = {}
    for line in lines:
        if "event" not in line:
            continue
        kind, shown, node = line["event"], line["text"], None
        if kind in ("send", "receive"):
            arrow, rest = shown[0], shown[2:]
            what, channel = rest.split(" · ")[0], None
            if " · channel " in rest:
                channel = int(rest.split(" · channel ")[1].split(" ")[0])
            queue = messages[(kind, channel)]
            if what.startswith("TLS handshake in hello packets"):
                queue.popleft()  # the handshake's records are carried in hello packets, which have no fields to show
            elif what.startswith("attention"):
                queue.popleft()
                cancelling.add(channel)
            elif what.startswith("request abandoned"):
                queue.popleft()
            elif what in ("response", "cancel acknowledged"):
                reader = ResponseReader(record=True, announce=lambda change: None, negotiated=negotiated)
                # Replay has no live caller to claim a row-reading mode. Inspect
                # every payload without retaining rows: otherwise a large row
                # pauses decoding and silently hides the remaining returns/DONE.
                reader.discard_new = True
                reader.cancelling = channel in cancelling
                cancelling.discard(channel)
                while not reader.ended and queue:
                    for packet in queue.popleft():
                        reader.feed(packet[HEADER_SIZE:], Status.LAST in Status(packet[1]),
                                    HEADER.decode(packet[:HEADER_SIZE], True).node)
                node = Node(what, 0, reader.size, b"", children=reader.nodes)
            elif what == "login reply":
                node = _decoded(what, queue.popleft(), _tokens(what, negotiated))
            elif what in REQUESTS:
                node = _decoded(what, queue.popleft(), REQUESTS[what])
        elif kind == "mars" and "bytes" in line:
            from .connection.core import MARS_HEADER
            node = MARS_HEADER.decode(base64.b64decode(line["bytes"]), True).node
        observe(Event(kind, shown, node if full else None, line["t"], line.get("took", "")))
