"""The SQL Server Browser (MC-SQLR): asking a machine, over UDP port 1434, where its SQL Server instances listen.

The Browser is not part of TDS. A named instance listens on a port of its own, which is often chosen again at each
start. The Browser is the service that knows which port. A client sends one datagram and receives one in reply. A
broadcast receives one from each machine that answers. Then the client connects with TDS as usual, to the port that
it received.

Reference: Browser. Checked against MC-SQLR v20251031 (docs/specification/mc-sqlr_v20251031.pdf), §2.2.

The four requests:
  - an instance's port: CLNT_UCAST_INST. The reply holds that instance's endpoints.
  - every instance on one machine: CLNT_UCAST_EX.
  - every instance on the network: CLNT_BCAST_EX, which is broadcast. Each machine that receives it answers.
  - an instance's dedicated administrator connection (DAC) port: CLNT_UCAST_DAC. The reply holds only the port.

A Browser doesn't answer when it can't. It ignores an unknown instance name or a request that it doesn't understand
(§3.1.5.2). The client therefore waits until a timer expires, and can't distinguish those cases from a missing
Browser. SQL Server on Linux has no Browser.

Text is in the code page that the client and server share, which is “assumed to be common” (§2.2). MC-SQLR doesn't
send which code page it is. The driver uses ASCII unless told otherwise. Instead of guessing, it refuses a name that
ASCII can't hold and reports a reply that it can't read. For another code page, pass the Windows machine's ANSI code
page as a Python codec name, such as encoding="cp1252" (Western European), "cp932" (Japanese) or "cp936" (Simplified
Chinese) (D-59).

Every call waits timeout_ms for its reply. The default is 1000 ms. A broadcast collects replies for that whole time.

Connecting to what the Browser names is the application's next step, not the driver's. connect() takes a host and a
port. A helper that combines the two belongs in a layer around the driver (D-39, D-59).

    instance = await browser.instance("db.example.com", "SALES")      # Instance(… tcp_port=50123 …)
    connection = await tds.connect("db.example.com", instance.tcp_port, …)
"""

import asyncio
import enum
import socket
from dataclasses import dataclass, replace

from .types import ValueRefused
from .wire import Field, MalformedMessage, Reader, Struct, Type, U8, U16, When, Writer

PORT = 1434
TIMEOUT_MS = 1000  # MC-SQLR's suggestion for an instance or DAC request (§3.2.2), the default for every request here
NAME_LIMIT = 32  # bytes, without the zero that ends it (§2.2.3, §2.2.4)
DAC_PROTOCOL_VERSION = 0x01


class Message(enum.IntEnum):
    BROADCAST = 0x02  # CLNT_BCAST_EX: every instance on the network
    MACHINE = 0x03  # CLNT_UCAST_EX: every instance on one machine
    INSTANCE = 0x04  # CLNT_UCAST_INST: one instance
    REPLY = 0x05  # SVR_RESP: the only reply
    DAC = 0x0F  # CLNT_UCAST_DAC: one instance's DAC port


SPEC_NAMES = {Message.BROADCAST: "CLNT_BCAST_EX", Message.MACHINE: "CLNT_UCAST_EX", Message.INSTANCE: "CLNT_UCAST_INST",
              Message.REPLY: "SVR_RESP", Message.DAC: "CLNT_UCAST_DAC"}


class Mbcs(Type):
    """Text in the shared code page, which the context's `encoding` names. The text either ends with a zero byte
    (`terminated`), or is as many bytes as an earlier field says (`size_field`)."""

    def __init__(self, terminated: bool = False, size_field: str | None = None):
        self.terminated, self.size_field = terminated, size_field

    def read(self, r: Reader) -> str:
        encoding = r.context.get("encoding", "ascii")
        if self.terminated:
            end = r.data.find(b"\x00", r.pos, r.end)
            if end < 0:
                raise MalformedMessage("no zero byte ends the text", r.pos, r.tree)
            data = r.take(end - r.pos, "text")
            r.take(1, "the zero that ends the text")
        else:
            data = r.take(r.values[-1][self.size_field], "text")
        try:
            return bytes(data).decode(encoding)
        except UnicodeDecodeError as e:
            raise MalformedMessage(f"the text isn't {encoding}: byte {data[e.start]:#04x}, {e.start} bytes in; if the "
                                   f"server's code page is another, name it with encoding=…", r.pos, r.tree) from None

    def write(self, w: Writer, value: str) -> None:
        encoding = w.context.get("encoding", "ascii")
        try:
            data = value.encode(encoding)
        except UnicodeEncodeError as e:
            raise ValueRefused(f"{value[e.start]!r} can't be written in {encoding}; MC-SQLR sends a name in the code "
                               f"page the client and server share: name it with encoding=…") from None
        if b"\x00" in data:
            raise ValueRefused(f"“{value}” holds a zero byte, which would end the name early")
        if len(data) > NAME_LIMIT:
            raise ValueRefused(f"“{value}” is {len(data)} bytes in {encoding}; an instance name is at most "
                               f"{NAME_LIMIT} (MC-SQLR §2.2.3)")
        w.put(data + b"\x00")

    def show(self, value: str) -> str:
        return f"“{value}”" if value else "(empty)"


def _is(*messages: Message):
    return lambda rw: rw.values[-1]["message"] in messages


REQUEST = Struct("Browser request", [
    Field("message", U8, enum=Message),
    Field("protocol_version", When(_is(Message.DAC), U8)),
    Field("instance", When(_is(Message.INSTANCE, Message.DAC), Mbcs(terminated=True))),
], source="MC-SQLR §2.2.1–§2.2.4", where=lambda rec: "the Browser request",
    summary=lambda r: SPEC_NAMES.get(r.message, "?") + (f" “{r.instance}”" if r.get("instance") else ""))

DAC_PORT = Struct("DAC port", [  # in a reply to CLNT_UCAST_DAC, instead of text (§2.2.6)
    Field("protocol_version", U8),
    Field("port", U16),
], summary=lambda d: f"port {d.port}")


class _Answer(Type):
    """What follows the size: a DAC port if the request asked for one, otherwise text. The bytes don't say which."""

    def resolve(self, rw) -> Type:
        return DAC_PORT if rw.context["asked"] == Message.DAC else Mbcs(size_field="size")


REPLY = Struct("SVR_RESP", [
    Field("message", U8, enum=Message),
    Field("size", U16),  # the text's length. In a DAC reply, it is the whole reply's length (always 6)
    Field("answer", _Answer()),
], source="MC-SQLR §2.2.5–§2.2.6")


def request(message: Message, instance: str | None = None, encoding: str = "ascii") -> bytes:
    """The bytes of one request. `instance` is used for INSTANCE and DAC only."""
    values = {"message": message, "protocol_version": DAC_PROTOCOL_VERSION if message == Message.DAC else None,
              "instance": instance}
    data, _ = REQUEST.encode(values, False, {"encoding": encoding})
    return data


def read_reply(data: bytes, asked: Message, encoding: str = "ascii"):
    """Reads one reply to the request `asked`. Returns its text, or the port for DAC. Raises MalformedMessage."""
    reply = REPLY.decode(data, False, {"asked": asked, "encoding": encoding})
    if reply.message != Message.REPLY:
        raise MalformedMessage(f"the reply starts {reply.message:#04x}, not SVR_RESP (0x05)", 0)
    if asked == Message.DAC:
        if reply.size != 6:
            raise MalformedMessage(f"a DAC reply's size is the whole reply's, 6; this one says {reply.size}", 1)
        if reply.answer.protocol_version != DAC_PROTOCOL_VERSION:
            raise MalformedMessage(f"protocol version {reply.answer.protocol_version}, not 1", 3)
        return reply.answer.port
    return reply.answer


# --------------------------------------------------------------------------- what the text says

PROTOCOLS = ("tcp", "np", "via", "rpc", "spx", "adsp", "bv")  # the endpoints an instance can name (§2.2.5)
HEADINGS = ("ServerName", "InstanceName", "IsClustered", "Version")


@dataclass(frozen=True)
class Instance:
    """One instance, as a Browser describes it. `protocols` maps each endpoint that the Browser named (“tcp”, “np”,
    …) to its text as sent, in the order sent. `address` is where the reply came from."""

    server_name: str
    instance_name: str
    is_clustered: bool
    version: str
    protocols: dict[str, str]
    address: str | None = None

    @property
    def tcp_port(self) -> int | None:
        """The TCP port to connect to, or None if the Browser named no TCP endpoint."""
        return int(self.protocols["tcp"]) if "tcp" in self.protocols else None


def instances(text: str) -> list[Instance]:
    """Read a reply's text: one or more instances, each ending in “;;”. Its words aren't case-sensitive (§2.2).
    Raises MalformedMessage."""
    if not text.endswith(";;"):
        raise MalformedMessage(f"the text doesn't end with “;;”: …{text[-20:]!r}", TEXT_STARTS + len(text))
    found, at = [], TEXT_STARTS
    for part in text[:-2].split(";;"):
        found.append(_instance(len(found) + 1, part, at))
        at += len(part) + 2
    return found


TEXT_STARTS = 3  # the text's offset in the reply, after SVR_RESP and its size. Errors in the text count from there


def _instance(n: int, text: str, at: int) -> Instance:
    parts = text.split(";")
    found = parts[0:8:2]
    if [p.lower() for p in found] != [h.lower() for h in HEADINGS] or len(parts) < 8:
        raise MalformedMessage(f"instance {n} doesn't begin {';'.join(h + ';…' for h in HEADINGS)}: {text[:80]!r}", at)
    clustered = parts[5].lower()
    if clustered not in ("yes", "no"):
        raise MalformedMessage(f"instance {n}: IsClustered is {parts[5]!r}, not Yes or No", at)
    protocols, rest = {}, parts[8:]
    while rest:
        name = rest.pop(0).lower()
        if name not in PROTOCOLS:
            raise MalformedMessage(f"instance {n}: {name!r} isn't an endpoint MC-SQLR names ({', '.join(PROTOCOLS)})", at)
        if name in protocols:
            raise MalformedMessage(f"instance {n} names {name} twice", at)
        taken = 1
        if name == "bv":  # Banyan VINES: several parts, up to the next endpoint's name
            while taken < len(rest) and rest[taken].lower() not in PROTOCOLS:
                taken += 1
        if taken > len(rest):
            raise MalformedMessage(f"instance {n}: {name} has no value", at)
        protocols[name], rest = ";".join(rest[:taken]), rest[taken:]
    return Instance(parts[1], parts[3], clustered == "yes", parts[7], protocols)


# --------------------------------------------------------------------------- asking (asyncio)


class BrowserError(Exception):
    """A request to a Browser failed because no reply arrived in time, the port was refused, or the reply can't be
    read. The error names the request and the machine that it was sent to. `reply` holds the bytes that arrived, if
    any."""

    def __init__(self, problem: str, reply: bytes | None = None):
        super().__init__(problem)
        self.reply = reply


async def instance(host: str, name: str, *, port: int = PORT, timeout_ms: int = TIMEOUT_MS,
                   encoding: str = "ascii") -> Instance:
    """Where one instance listens (CLNT_UCAST_INST). The default instance is named MSSQLSERVER."""
    found = await _ask(host, port, Message.INSTANCE, name, timeout_ms, encoding)
    if len(found) != 1:
        raise BrowserError(f"{_asked(Message.INSTANCE, name, host, port)}: the reply describes {len(found)} instances, "
                           f"not one")
    return found[0]


async def machine(host: str, *, port: int = PORT, timeout_ms: int = TIMEOUT_MS, encoding: str = "ascii") -> list[Instance]:
    """Every instance on one machine (CLNT_UCAST_EX)."""
    return await _ask(host, port, Message.MACHINE, None, timeout_ms, encoding)


async def dac_port(host: str, name: str, *, port: int = PORT, timeout_ms: int = TIMEOUT_MS, encoding: str = "ascii") -> int:
    """The port of an instance's dedicated administrator connection (CLNT_UCAST_DAC)."""
    return await _ask(host, port, Message.DAC, name, timeout_ms, encoding)


async def broadcast(address: str = "255.255.255.255", *, port: int = PORT, timeout_ms: int = TIMEOUT_MS,
                    encoding: str = "ascii") -> list[Instance]:
    """Every instance whose machine answers a broadcast (CLNT_BCAST_EX), from every reply that arrives within
    `timeout_ms`. As MC-SQLR requires (§3.2.5.3), a reply that can't be read is ignored. With no
    replies, the result is an empty list."""
    data = request(Message.BROADCAST, encoding=encoding)
    loop = asyncio.get_running_loop()
    transport, replies = await loop.create_datagram_endpoint(
        _Replies, local_addr=("0.0.0.0", 0), family=socket.AF_INET, allow_broadcast=True)
    found: list[Instance] = []
    try:
        transport.sendto(data, (address, port))
        deadline = loop.time() + timeout_ms / 1000
        while (left := deadline - loop.time()) > 0:
            try:
                reply, sender = await asyncio.wait_for(replies.queue.get(), left)
            except (TimeoutError, asyncio.TimeoutError):
                break
            if isinstance(reply, Exception):
                continue
            try:
                found += [replace(i, address=sender[0]) for i in instances(read_reply(reply, Message.BROADCAST, encoding))]
            except MalformedMessage:
                continue
    finally:
        transport.close()
    return found


class _Replies(asyncio.DatagramProtocol):
    def __init__(self):
        self.queue: asyncio.Queue = asyncio.Queue()

    def datagram_received(self, data: bytes, addr) -> None:
        self.queue.put_nowait((data, addr))

    def error_received(self, exc: Exception) -> None:
        self.queue.put_nowait((exc, None))


def _asked(message: Message, name: str | None, host: str, port: int) -> str:
    return f"{SPEC_NAMES[message]}{f' for “{name}”' if name is not None else ''} to {host}:{port}"


async def _ask(host: str, port: int, message: Message, name: str | None, timeout_ms: int, encoding: str):
    """Send one request to one machine and read its one reply."""
    data = request(message, name, encoding)
    asked = _asked(message, name, host, port)
    loop = asyncio.get_running_loop()
    try:
        transport, replies = await loop.create_datagram_endpoint(_Replies, remote_addr=(host, port))
    except OSError as e:
        raise BrowserError(f"{asked}: can't send ({e.strerror or e})") from e
    try:
        transport.sendto(data)
        try:
            reply, sender = await asyncio.wait_for(replies.queue.get(), timeout_ms / 1000)
        except (TimeoutError, asyncio.TimeoutError):
            unanswered = " (or no instance has that name: a Browser ignores a request it can't answer)" if name else ""
            raise BrowserError(f"{asked}: no reply within {timeout_ms:g} ms. No Browser answers there: it isn't running "
                               f"(SQL Server on Linux has none), or UDP {port} is blocked on the way{unanswered}. "
                               f"MC-SQLR has no reply that says no (§3.1.5.2).") from None
    finally:
        transport.close()
    if isinstance(reply, Exception):
        raise BrowserError(f"{asked}: refused ({reply.strerror or reply}): nothing listens on UDP {port} there, "
                           f"so no Browser is running") from reply
    try:
        answer = read_reply(reply, message, encoding)
        return answer if message == Message.DAC else [replace(i, address=sender[0]) for i in instances(answer)]
    except MalformedMessage as e:
        raise BrowserError(f"{asked}: the reply can't be read: {e}\nIt was: {reply[:200].hex(' ').upper()}"
                           f"{' …' if len(reply) > 200 else ''}", reply) from e
