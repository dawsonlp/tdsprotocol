"""Packet: the unit written to the wire. It is an 8-byte header, then up to (packet size − 8) bytes of a message.

Reference: Packet. Checked against MS-TDS v20260617, §2.2.3.
"""

import enum
from dataclasses import dataclass

from .wire import Field, MalformedMessage, Node, Struct, U8, U16BE


class PacketType(enum.IntEnum):
    SQL_BATCH = 0x01
    RPC = 0x03
    SERVER_MESSAGE = 0x04  # every message the server sends
    CANCEL = 0x06
    BULK_LOAD = 0x07
    FEDERATED_AUTH_TOKEN = 0x08
    TRANSACTION_MANAGER = 0x0E
    LOGIN = 0x10
    WINDOWS_AUTH = 0x11
    HELLO = 0x12  # PRELOGIN. In 7.4 it also carries the TLS handshake


class Status(enum.IntFlag):
    LAST = 0x01  # the last packet of the message
    IGNORE = 0x02  # abandon a partly sent message
    RESET_SESSION = 0x08
    RESET_KEEP_TRANSACTION = 0x10


HEADER = Struct("packet header", [
    Field("type", U8, enum=PacketType),
    Field("status", U8, enum=Status),
    Field("length", U16BE, fmt=lambda v: f"{v} bytes"),  # the whole packet, header included
    Field("session_id", U16BE),
    Field("packet_number", U8),  # increases by 1 for each packet. Receivers ignore it
    Field("unused", U8),
], source="§2.2.3.1", summary=lambda h: f"{h.type.name.lower().replace('_', ' ')} · {h.length} bytes")

HEADER_SIZE = 8
DEFAULT_SIZE = 4096  # until the server announces another size
MAX_SIZE = 32767


@dataclass
class Message:
    """One complete thing that one side sends, rebuilt from its packets."""

    type: PacketType
    body: bytes
    headers: list[Node]  # the header of each packet that carried it
    session_id: int = 0  # the server's id for the session, from the packet header


def split(kind: PacketType, body: bytes, packet_size: int, record: bool = True,
          first: Status = Status(0)) -> tuple[list[bytes], list[Node]]:
    """Every packet except the last is exactly the packet size. The last packet is marked LAST.
    `first` adds flags to the first packet only, such as RESET_SESSION."""
    room = packet_size - HEADER_SIZE
    chunks = [body[i : i + room] for i in range(0, len(body), room)] or [b""]
    packets, headers = [], []
    for n, chunk in enumerate(chunks, start=1):
        header, node = HEADER.encode({
            "type": kind,
            "status": (Status.LAST if n == len(chunks) else Status(0)) | (first if n == 1 else Status(0)),
            "length": HEADER_SIZE + len(chunk),
            "session_id": 0,
            "packet_number": n % 256,
            "unused": 0,
        }, record)
        packets.append(header + chunk)
        headers.append(node)
    return packets, headers


class PacketWriter:
    """Splits one message into packets as its bytes are produced. Every packet except the last is exactly the packet
    size, and the last is marked LAST. A partly sent message that is abandoned instead ends with a header-only packet
    marked IGNORE and LAST. The server then runs nothing and answers with a DONE marked error (§2.2.1.7, §2.2.3.1.2),
    after a message of its own (Requests › Edge cases)."""

    def __init__(self, kind: PacketType, packet_size: int, record: bool = True, first: Status = Status(0)):
        self.kind, self.room, self.record, self.first = kind, packet_size - HEADER_SIZE, record, first
        self.pending = bytearray()
        self.packets = 0  # sent so far
        self.size = 0  # message bytes sent so far
        self.finished = False  # the LAST packet has been made
        self.headers: list[Node] = []

    @property
    def started(self) -> bool:
        return self.packets > 0

    def add(self, data: bytes) -> list[bytes]:
        """Adds more of the message. Returns the packets that are now full."""
        self.pending += data
        out = []
        while len(self.pending) > self.room:  # keep the remainder, because the last packet carries LAST
            out.append(self._packet(self.pending[: self.room], Status(0)))
            del self.pending[: self.room]
        return out

    def finish(self) -> bytes:
        self.finished = True
        packet = self._packet(self.pending, Status.LAST)
        self.pending.clear()
        return packet

    def abandon(self) -> bytes:
        self.finished = True
        self.pending.clear()
        return self._packet(b"", Status.IGNORE | Status.LAST)

    def _packet(self, chunk: bytes, status: Status) -> bytes:
        self.packets += 1
        if self.packets == 1:
            status |= self.first
        header, node = HEADER.encode({"type": self.kind, "status": status, "length": HEADER_SIZE + len(chunk),
                                      "session_id": 0, "packet_number": self.packets % 256, "unused": 0}, self.record)
        if self.record:
            self.headers.append(node)
        self.size += len(chunk)
        return header + bytes(chunk)


@dataclass
class Packet:
    """One packet as received. It holds its header's values and the part of a message that it carries."""

    type: PacketType
    status: Status
    body: bytes
    header: Node | None  # the inspection tree of its header, when recording
    session_id: int = 0
    raw: bytes = b""  # the whole packet as it arrived, header included. Used for captures (D-12)

    @property
    def last(self) -> bool:
        return Status.LAST in self.status


class Unpacker:
    """Splits a byte stream into packets. A packet is complete once its header's length has arrived."""

    def __init__(self, record: bool = True):
        self.record = record
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[Packet]:
        self._buffer += data
        packets = []
        while len(self._buffer) >= HEADER_SIZE:
            header = HEADER.decode(bytes(self._buffer[:HEADER_SIZE]), self.record)
            if not HEADER_SIZE <= header.length <= MAX_SIZE:
                raise MalformedMessage(f"packet length {header.length} is outside {HEADER_SIZE}–{MAX_SIZE}", 0, header.node)
            if len(self._buffer) < header.length:
                break  # the rest of this packet hasn't arrived yet
            packets.append(Packet(header.type, Status(header.status), bytes(self._buffer[HEADER_SIZE : header.length]),
                                  header.node, header.session_id, bytes(self._buffer[: header.length])))
            del self._buffer[: header.length]
        return packets


class Joiner:
    """Rebuilds messages from packets. A message is complete at the packet marked LAST."""

    def __init__(self, record: bool = True):
        self._unpacker = Unpacker(record)
        self._packets: list[Packet] = []

    def feed(self, data: bytes) -> list[Message]:
        """Takes bytes and returns the whole messages that they complete."""
        return [m for p in self._unpacker.feed(data) if (m := self.add(p)) is not None]

    def add(self, packet: Packet) -> Message | None:
        if self._packets and packet.type != self._packets[0].type:
            raise MalformedMessage(f"a {packet.type.name} packet arrived inside a {self._packets[0].type.name} message", 0,
                                   packet.header)
        self._packets.append(packet)
        if not packet.last:
            return None
        packets, self._packets = self._packets, []
        return Message(packets[0].type, b"".join(p.body for p in packets), [p.header for p in packets if p.header],
                       packets[-1].session_id)
