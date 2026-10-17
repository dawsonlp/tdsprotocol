"""Transaction-manager requests: transactions controlled through the protocol rather than T-SQL.

Reference: Requests (Shape and Edge cases), and Request Response for the announcements that answer them. Checked
against MS-TDS v20260617, §2.2.6.9. Decision: D-51.

Each request is one exchange (D-33) and returns an ordinary response. What a request did is in that response, as the
server provides it:
  - the transaction state, in its announcements (ENVCHANGE). The session follows them, so every later request
    carries the new descriptor in its headers. Only the outermost transaction is announced. A nested Begin, an inner
    Commit, a Save and a Rollback to a savepoint announce nothing.
  - Promote's token, in its PROMOTE_TRANSACTION announcement.
  - the coordinator's address, as the response's one row.

The server checks the rules and reports what is wrong. The driver doesn't repeat the server's checks (D-51). Note
these results:
  - Save("") or a name of an odd byte count is refused, and the refusal rolls back the open transaction. The server
    announces the rollback.
  - Commit or Rollback with no transaction open is refused (errors 3902, 3903).
Only what can't be encoded is refused before sending. This is a name longer than 127 UTF-16 code units, whose byte
count doesn't fit its u8.

    async with await channel.exchange(transactions.Begin(Isolation.SERIALIZABLE, "prices")) as response: …
    … Save("before") … Rollback("before") … Commit(begin=Begin(Isolation.SERIALIZABLE)) …
"""

import enum
from dataclasses import dataclass
from typing import Any

from .packet import PacketType
from .requests import HEADERS, Context, Encoded, headers
from .types import ValueRefused
from .wire import Blob, Field, OneOf, Reader, Struct, Type, U8, U16, Writer


class RequestType(enum.IntEnum):
    COORDINATOR_ADDRESS = 0  # TM_GET_DTC_ADDRESS
    PROPAGATE = 1  # TM_PROPAGATE_XACT
    BEGIN = 5  # TM_BEGIN_XACT
    PROMOTE = 6  # TM_PROMOTE_XACT
    COMMIT = 7  # TM_COMMIT_XACT
    ROLLBACK = 8  # TM_ROLLBACK_XACT
    SAVE = 9  # TM_SAVE_XACT


class Isolation(enum.IntEnum):
    """The isolation level that a transaction begins with. On the wire, 0 means unchanged. The classes take None."""

    UNCHANGED = 0
    READ_UNCOMMITTED = 1
    READ_COMMITTED = 2
    REPEATABLE_READ = 3
    SERIALIZABLE = 4
    SNAPSHOT = 5


class TransactionFlags(enum.IntFlag):
    BEGIN_ANOTHER = 0x01  # fBeginXact: after the commit or rollback, begin a new transaction


class Name(Type):
    """A transaction or savepoint name: its length in bytes (u8), then UTF-16LE. MS-TDS says only "bytes". As
    observed, the server reads UTF-16LE and refuses an odd byte count (error 3976)."""

    def read(self, r: Reader) -> str:
        return bytes(r.take(U8.read(r), "name")).decode("utf-16-le", "surrogatepass")

    def write(self, w: Writer, value: str) -> None:
        data = value.encode("utf-16-le", "surrogatepass")
        if len(data) > 255:
            raise ValueRefused(f"a transaction name is at most 127 UTF-16 code units; {value[:20]!r}… is {len(data) // 2}")
        U8.write(w, len(data))
        w.put(data)

    def show(self, value: str) -> str:
        return f"“{value}”" if value else "(none)"


class Nothing(Type):
    """No bytes. It stands for a part that the request leaves out."""

    def read(self, r: Reader) -> None:
        return None

    def write(self, w: Writer, value: Any) -> None:
        pass

    def show(self, value: Any) -> str:
        return "none"


BEGIN_PAYLOAD = Struct("begin", [
    Field("isolation", U8, enum=Isolation),
    Field("name", Name()),
])

END_PAYLOAD = Struct("commit or roll back", [  # the same for both
    Field("name", Name()),  # empty: the current transaction. In a rollback, a savepoint's name rolls back to it
    Field("flags", U8, enum=TransactionFlags),
    Field("then", OneOf("flags", {TransactionFlags(0): Nothing(), TransactionFlags.BEGIN_ANOTHER: BEGIN_PAYLOAD})),
])

PAYLOADS = {
    RequestType.COORDINATOR_ADDRESS: Blob(U16),  # MS-TDS: should be empty
    RequestType.PROPAGATE: Blob(U16),  # the coordinator's cookie
    RequestType.BEGIN: BEGIN_PAYLOAD,
    RequestType.PROMOTE: Nothing(),
    RequestType.COMMIT: END_PAYLOAD,
    RequestType.ROLLBACK: END_PAYLOAD,
    RequestType.SAVE: Struct("save", [Field("name", Name())]),
}

TRANSACTION_MANAGER = Struct("transaction manager", [
    Field("headers", HEADERS),
    Field("request", U16, enum=RequestType),
    Field("payload", OneOf("request", PAYLOADS)),
], source="§2.2.6.9", summary=lambda t: t.request.name.lower().replace("_", " "),
   where=lambda t: f"the transaction-manager request {t['request'].name}")


def _begin(isolation: Isolation | None, name: str) -> dict:
    return {"isolation": isolation or Isolation.UNCHANGED, "name": name}


class _TransactionRequest:
    kind = PacketType.TRANSACTION_MANAGER
    label = "transaction manager"
    metadata = ()
    request: RequestType

    def payload(self) -> Any:
        raise NotImplementedError

    def encode(self, context: Context, record: bool) -> Encoded:
        values = {"headers": headers(context), "request": self.request, "payload": self.payload()}
        return Encoded(*TRANSACTION_MANAGER.encode(values, record))

    def __str__(self) -> str:
        name = getattr(self, "name", None)
        return f"the transaction-manager request {type(self).__name__}({f'“{name}”' if name is not None else ''})"


@dataclass(frozen=True)
class Begin(_TransactionRequest):
    """Begin a transaction, or nest one inside the open transaction. For the outermost transaction only, the server
    answers with a begin announcement that carries the new descriptor. `isolation` None leaves the session's level
    unchanged."""

    isolation: Isolation | None = None
    name: str = ""
    request = RequestType.BEGIN

    def payload(self) -> dict:
        return _begin(self.isolation, self.name)


@dataclass(frozen=True)
class _End(_TransactionRequest):
    name: str = ""
    begin: Begin | None = None  # begin another transaction immediately after, in the same request

    def payload(self) -> dict:
        then = None if self.begin is None else _begin(self.begin.isolation, self.begin.name)
        flags = TransactionFlags.BEGIN_ANOTHER if self.begin else TransactionFlags(0)
        return {"name": self.name, "flags": flags, "then": then}


@dataclass(frozen=True)
class Commit(_End):
    """Commit the open transaction, like T-SQL's COMMIT. Committing the outermost transaction is announced.
    Committing an inner one only lowers the nesting count. With `begin`, a new transaction begins immediately after,
    and an isolation level given in `begin` stays for the session after that transaction ends."""

    request = RequestType.COMMIT


@dataclass(frozen=True)
class Rollback(_End):
    """Roll back the open transaction. Given a savepoint's name, roll back to that savepoint instead, which announces
    nothing. With `begin`, a new transaction begins immediately after. According to MS-TDS, this does not apply to a
    rollback to a savepoint."""

    request = RequestType.ROLLBACK


@dataclass(frozen=True)
class Save(_TransactionRequest):
    """Set a savepoint in the open transaction. It announces nothing. The server refuses an empty name, and that
    refusal rolls back the open transaction (error 3977)."""

    name: str
    request = RequestType.SAVE

    def payload(self) -> dict:
        return {"name": self.name}


@dataclass(frozen=True)
class Promote(_TransactionRequest):
    """Promote the open transaction to a distributed one. The server answers with a PROMOTE_TRANSACTION
    announcement whose new value is the coordinator's token, for the application's coordinator client. As observed,
    SQL Server also promotes a transaction begun in T-SQL, although MS-TDS says that it refuses."""

    request = RequestType.PROMOTE

    def payload(self) -> None:
        return None


@dataclass(frozen=True)
class Propagate(_TransactionRequest):
    """Join a distributed transaction, given the coordinator's cookie for it. According to MS-TDS, the server answers
    with a result set that holds the new descriptor. This is untested because it needs a cookie from a coordinator
    client. Only the refusal of a bad cookie is tested (error 8509)."""

    cookie: bytes
    request = RequestType.PROPAGATE

    def payload(self) -> bytes:
        return bytes(self.cookie)


@dataclass(frozen=True)
class CoordinatorAddress(_TransactionRequest):
    """The distributed transaction coordinator's address, as the response's one row with one binary column."""

    request = RequestType.COORDINATOR_ADDRESS

    def payload(self) -> bytes:
        return b""
