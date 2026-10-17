"""Responses: the record of what the server did for one request, read forward as it arrives.

Reference: Request Response (the tokens, and where each structure starts and ends), and The Client §4–§5 (how a
response is read, and how outer layers read its structure). Decisions: D-34, D-42.

Two parts:
  ResponseReader   the state machine. It is fed the bodies of the response's packets and turns each token into an
                   item of the record, keeping the views up to date. It does no I/O and doesn't know what was
                   requested (D-33). Every view is one token rule. Rows with large values are read value by value
                   as their bytes arrive (RowDecoder, D-47).
  Response         how the application reads it: result sets, rows, fetch, finish, returns, cancel, close. A live
                   response reads more packets through its source (the connection's shell). A FetchedResponse
                   reads from memory.
"""

import enum
import time
import warnings
import weakref
from collections import Counter, deque
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Protocol

from .types import SqlType
from .wire import kept
from .tokens import TOKENS, Aggregate, ColumnFlags, ColumnInfoStatus, DoneStatus, EnvKind, ReturnValueStatus, SessionStateStatus
from .wire import Incomplete, MalformedMessage, Node, Reader, Record


# =========================================================================== the record's items (D-42)


class CompletionKind(enum.Enum):
    """Which DONE token ended something."""

    STATEMENT = "DONE"  # a statement in a batch
    STATEMENT_IN_PROCEDURE = "DONEINPROC"  # a statement inside a procedure
    CALL = "DONEPROC"  # an outermost procedure call


@dataclass(frozen=True)
class Completion:
    """A statement or call ended. `rows` is None when the server says the count isn't valid (for example,
    after SET NOCOUNT ON or an error). `statement` is the server's statement code, unchanged. MS-TDS leaves its values
    to the server."""

    kind: CompletionKind
    rows: int | None
    status: DoneStatus
    statement: int


@dataclass(frozen=True)
class Column:
    name: str  # may be empty, and may repeat: rows are positional
    type: SqlType
    nullable: bool
    flags: ColumnFlags
    user_type: int


@dataclass(frozen=True)
class _Report:
    number: int
    state: int
    severity: int  # as the server reported it
    text: str
    server: str
    procedure: str
    line: int


@dataclass(frozen=True)
class Message(_Report):
    """INFO: from PRINT, a low-severity RAISERROR, or a warning."""


@dataclass(frozen=True)
class Error(_Report):
    """ERROR: a statement failed."""


@dataclass(frozen=True)
class ReturnStatus:
    """RETURNSTATUS: a procedure call's RETURN value."""

    value: int


@dataclass(frozen=True)
class OutputValue:
    """RETURNVALUE: an output parameter's value, or the result of a function called as an RPC."""

    ordinal: int  # the parameter's position in the call, from 0
    name: str
    type: SqlType
    value: Any
    function_result: bool


@dataclass
class Timing:
    """When an exchange happened, on a monotonic clock (seconds, time.perf_counter). It is collected at every level of
    observability, with three clock reads per exchange (D-12)."""

    sent: float | None = None  # the request's last packet was handed to the connection
    first_packet: float | None = None  # the response's first packet arrived
    ended: float | None = None  # the response ended

    @property
    def until_first_packet(self) -> float | None:
        """Seconds from sending to the first packet. This is about how long the server took to start answering."""
        return None if self.sent is None or self.first_packet is None else self.first_packet - self.sent

    @property
    def until_end(self) -> float | None:
        """Seconds from sending to the response's end."""
        return None if self.sent is None or self.ended is None else self.ended - self.sent


@dataclass(frozen=True)
class ColumnInfo:
    """COLINFO, for one column (browse mode, and server cursors): where it came from."""

    column: int  # its number in the result set, from 1
    table: int  # its table in the result set's `tables`, from 1; 0 for an expression
    status: ColumnInfoStatus  # EXPRESSION, KEY, HIDDEN (added because it is part of a key), DIFFERENT_NAME
    base_name: str | None  # the base column's name, when the result names it differently


@dataclass(frozen=True)
class Sensitivity:
    """One sensitivity of a column: a label and an information type, each a (name, id) pair or None."""

    label: tuple[str, str] | None
    information_type: tuple[str, str] | None
    rank: int | None  # from data classification version 2


@dataclass(frozen=True)
class DataClassification:
    """DATACLASSIFICATION: the sensitivity of a result set's columns, as the server's classification records it."""

    labels: tuple[tuple[str, str], ...]  # (name, id)
    information_types: tuple[tuple[str, str], ...]
    rank: int | None
    columns: tuple[tuple[Sensitivity, ...], ...]  # one entry per column, or none if the server sent no detail


@dataclass(frozen=True)
class Totals:
    """ALTMETADATA: a COMPUTE clause's totals. They are deprecated in TDS 7.4, and SQL Server no longer sends them."""

    id: int
    by: tuple[int, ...]  # the grouping columns, from 1
    columns: tuple[tuple[Aggregate, int, SqlType, str], ...]  # aggregate, operand column, type, name


@dataclass(frozen=True)
class SessionState:
    """SESSIONSTATE: the session's state, for recovering it on a new connection (asked for at login)."""

    sequence: int
    recoverable: bool
    states: dict[int, bytes]


@dataclass(frozen=True)
class Announcement:
    """ENVCHANGE: a session setting changed. The session state is updated too."""

    kind: EnvKind
    new: Any
    old: Any


class Outputs:
    """A call's output values, by ordinal or by name: outputs[2], outputs["@total"]."""

    def __init__(self, items: list[OutputValue]):
        self.items = tuple(items)

    def __getitem__(self, key: int | str) -> OutputValue:
        for item in self.items:
            if item.ordinal == key or item.name == key:
                return item
        raise KeyError(key)

    def __iter__(self):
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def __repr__(self) -> str:
        return f"Outputs({', '.join(f'{o.name or o.ordinal}={o.value!r}' for o in self.items)})"


@dataclass(frozen=True)
class Return:
    """One outermost procedure call the server completed: what came before its DONEPROC."""

    status: int | None  # None if the call never reached RETURN
    outputs: Outputs
    function_result: OutputValue | None
    failed: bool  # its DONEPROC is marked as an error
    completion: Completion


Item = Any  # ResultSet | Completion | Message | Error | ReturnStatus | OutputValue | Announcement


# =========================================================================== errors


SEVERITY = {  # what each level means, as Microsoft's "Database Engine error severities" describes it
    **{level: "information" for level in range(0, 11)},  # the server sends severity 10 as 0
    11: "an error the user can correct: the object doesn't exist",
    12: "a query that takes no locks, because of its hints, may have read inconsistent data",
    13: "an error the user can correct: a deadlock",
    14: "an error the user can correct: security, such as permission denied",
    15: "an error the user can correct: syntax",
    16: "an error the user can correct",
    17: "for the administrator: the server ran out of resources, or reached a limit the administrator set",
    18: "for the administrator: a problem in the server's software; the statement completed",
    19: "for the administrator: a limit of the server's was exceeded, and the batch stopped",
    20: "fatal: a problem with the statement; the connection may close",
    21: "fatal: a problem affecting the whole database; the connection may close",
    22: "fatal: a table or index is damaged (DBCC CHECKDB); the connection may close",
    23: "fatal: the database's integrity is in question (DBCC CHECKDB); the connection may close",
    24: "fatal: a media failure; the connection may close",
    25: "fatal; the connection may close",
}


def report(e: Any) -> str:
    """A message from the server, with every field, in SQL Server's own format, followed by what its level means:

        Msg 547, Level 16, State 0, Procedure shop.place_order, Line 3 · server lpdtest1 · an error the user can correct
        The INSERT statement conflicted with the CHECK constraint …"""
    text = getattr(e, "text", None) or getattr(e, "message", "")
    server = getattr(e, "server", None) or getattr(e, "server_name", "")
    where = [f"Procedure {e.procedure}" if e.procedure else "", f"Line {e.line}" if e.line else ""]
    head = ", ".join([f"Msg {e.number}", f"Level {e.severity}", f"State {e.state}", *filter(None, where)])
    meaning = SEVERITY.get(e.severity, f"level {e.severity} isn't one Microsoft describes")
    return f"{head}{f' · server {server}' if server else ''} · {meaning}\n{text}"


def _indent(text: str) -> str:
    return "\n".join("  " + line for line in text.splitlines())


def _what(request: Any) -> str:
    return str(request) if request is not None else "the request"


class ServerError(Exception):
    """The server reported errors. It is raised at the end of the response, and carries the whole record (`response`)
    and the errors (`errors`). Its message is literate. It gives every error and message from the first error on, in
    full. It names the call that each error belongs to, when the request had calls. Last, it says what the server did
    afterward."""

    def __init__(self, errors: tuple[Error, ...], response: FetchedResponse):
        super().__init__(self._describe(errors, response))
        self.errors, self.response = errors, response

    @staticmethod
    def _describe(errors: tuple[Error, ...], response: FetchedResponse) -> str:
        request = getattr(response, "request", None)
        calls = getattr(request, "calls", None) or ((request,) if hasattr(request, "target") else None)
        items = list(response.sequence)
        first = next((i for i, item in enumerate(items) if isinstance(item, Error)), len(items))
        lines = [f"SQL Server reported {len(errors)} error{'' if len(errors) == 1 else 's'} for {_what(request)}:"]
        done_calls = sum(1 for item in items[:first] if isinstance(item, Completion) and item.kind is CompletionKind.CALL)
        for item in items[first:]:
            if isinstance(item, Completion) and item.kind is CompletionKind.CALL:
                done_calls += 1
            elif isinstance(item, (Error, Message)):
                lines.append("")
                lines.append(_indent(("Error · " if isinstance(item, Error) else "Message · ") + report(item)))
                if isinstance(item, Error) and calls and done_calls < len(calls):
                    target = calls[done_calls].target
                    name = target.name.lower() if hasattr(target, "name") else target
                    lines.append(f"  (in call {done_calls + 1} of {len(calls)}: {name})")
        last = max(i for i, item in enumerate(items) if isinstance(item, Error)) if errors else len(items)
        after = items[last + 1:]
        own = next((i for i, item in enumerate(after) if isinstance(item, Completion)), None)
        later = [item for item in after[own + 1:] if isinstance(item, Completion)] if own is not None else []
        followed = [f"the server announced {item.kind.name.lower().replace('_', ' ')}" for item in after
                    if isinstance(item, Announcement)]
        followed.append(f"the server went on, with {len(later)} more completion{'' if len(later) == 1 else 's'}"
                        if later else "the response ended")
        lines += ["", "Then: " + "; ".join(followed) + "."]
        return "\n".join(lines)


class Cancelled(Exception):
    """The request was canceled and the server acknowledged it. It carries the record up to that point."""

    def __init__(self, response: FetchedResponse):
        sets, done = len(response.result_sets), len(response.completions)
        super().__init__(f"{_what(getattr(response, 'request', None))} was canceled, and the server acknowledged it. "
                         f"Before that: {sets} result set{'' if sets == 1 else 's'} and {done} completion"
                         f"{'' if done == 1 else 's'} (e.response holds them).")
        self.response = response


class NotYetRead(Exception):
    """An end-of-response item was asked for, with Unread.REFUSE, before the response was read that far."""


class RowsNotAvailable(Exception):
    """A result set's rows can't be read here: they streamed past, or the set was passed."""


class Unread(enum.Enum):
    """What happens to items not yet read when something later in the response is asked for (D-34)."""

    REFUSE = "refuse"  # raise NotYetRead, naming the options
    KEEP = "keep"  # read ahead, keeping everything, as fetch() does
    DISCARD = "discard"  # read ahead, skipping rows, as finish() does


# =========================================================================== result sets


class ResultSet:
    """Columns, then rows (plain tuples). COLMETADATA opens it, and the next completion (`completion`) closes it.

    In a live response, a result set is read forward once, while it is the response's current set. Rows that
    streamed past are counted (`rows_read`), not kept. `rows` exists only where every row was kept: on a
    FetchedResponse."""

    def __init__(self, columns: tuple[Column, ...], owner: weakref.ref[Response] | None):
        self.columns = columns
        self.order: tuple[int, ...] | None = None  # sort columns, numbered from 1, if the server sent ORDER
        self.tables: tuple[tuple[str, ...], ...] | None = None  # TABNAME: the base tables, in parts (browse mode)
        self.column_info: tuple[ColumnInfo, ...] | None = None  # COLINFO: where each column came from
        self.classification: DataClassification | None = None  # DATACLASSIFICATION, if the login asked for it
        self.totals: dict[int, Totals] = {}  # ALTMETADATA, by id
        self.total_rows: list[tuple[int, tuple]] = []  # ALTROW: (id, values)
        self.completion: Completion | None = None
        self.rows_read = 0
        self._owner = owner  # the live response, held weakly so that a dropped response can be garbage-collected
        self._large = any(c.type.large for c in columns)  # its rows are read value by value as they arrive
        self._streamed = False  # streamed(): rows from now on arrive as StreamedRows
        self._claimed = False  # the application has chosen how to read it. Until then, rows with large values wait
        self._queue: deque = deque()  # arrived (or arriving, when streamed), not yet handed out
        self._kept: list[tuple] | None = None  # every row, when rows are kept from the start
        self._discard = False

    @property
    def rows(self) -> tuple[tuple, ...]:
        if self.completion is None:
            raise RowsNotAvailable("this result set is still arriving: iterate it, or fetch() the response first")
        if self._kept is None or len(self._kept) != self.rows_read:
            raise RowsNotAvailable(f"{self.rows_read} rows arrived and streamed past without being kept; "
                                   "fetch() keeps them for reading again")
        return tuple(self._kept)

    def __aiter__(self) -> AsyncIterator[tuple]:
        return self._iterate()

    def streamed(self) -> AsyncIterator[StreamedRow]:
        """Rows read value by value, in column order (D-47). Each large value arrives as a ValueStream, readable while
        its row is current. Moving to the next value or row discards what is unread. Use it for values too large to
        hold in memory."""
        return self._stream_rows()

    async def _stream_rows(self) -> AsyncIterator[StreamedRow]:
        owner = self._owner() if self._owner is not None else None
        if owner is None:  # in memory: every row was kept whole
            for row in self.rows:
                yield StreamedRow.whole(self.columns, row)
            return
        if not owner._is_current(self):
            raise RowsNotAvailable("a live response reads one result set at a time, forward only; this one isn't the "
                                   "current set")
        self._streamed = self._claimed = True
        row = None
        while True:
            if row is not None:
                row._move_on()  # moving to the next row discards what is unread of this one
            if self._queue:
                item = self._queue.popleft()
                row = item if isinstance(item, StreamedRow) else StreamedRow.whole(self.columns, item)
                yield row
                continue
            if self.completion is not None:
                return
            await owner._pull()

    async def _iterate(self) -> AsyncIterator[tuple]:
        owner = self._owner() if self._owner is not None else None
        if owner is None:  # in memory: it can be read any number of times, if every row was kept
            for row in self.rows:
                yield row
            return
        if self._streamed:
            raise RowsNotAvailable("this result set is being read value by value, with streamed()")
        self._claimed = True
        if not owner._is_current(self):
            raise RowsNotAvailable("a live response reads one result set at a time, forward only; this one isn't the "
                                   "current set. fetch() keeps result sets for reading again")
        while True:
            if self._queue:
                yield self._queue.popleft()
                continue
            if self.completion is not None:
                return
            await owner._pull()

    def __repr__(self) -> str:
        names = ", ".join(c.name or "(no name)" for c in self.columns)
        return f"ResultSet([{names}], rows_read={self.rows_read}, completion={self.completion})"

    # ----------------------------------------------------------------------- used by the reader and the response

    def _arrive(self, row: tuple) -> None:
        self.rows_read += 1
        if self._discard:
            return
        self._queue.append(row)
        if self._kept is not None:
            self._kept.append(row)

    def _drop_unread(self) -> None:
        self._discard = self._claimed = True
        for item in self._queue:
            if isinstance(item, StreamedRow):
                item._move_on()
        self._queue.clear()

    def _keep_from_now(self) -> None:
        """Keep every row from here on. The kept rows are complete only if none was handed out or dropped before."""
        self._claimed = True
        if self._kept is None and not self._discard and len(self._queue) == self.rows_read:
            self._kept = list(self._queue)

    def _snapshot(self) -> ResultSet:
        copy = ResultSet(self.columns, None)
        copy._streamed = self._streamed
        copy.order, copy.completion, copy.rows_read = self.order, self.completion, self.rows_read
        copy.tables, copy.column_info, copy.classification = self.tables, self.column_info, self.classification
        copy.totals, copy.total_rows = dict(self.totals), list(self.total_rows)
        copy._kept = list(self._kept) if self._kept is not None else None
        return copy


# =========================================================================== large values, value by value (D-47)


class ValueStream:
    """One large value as it arrives: an async iterator of bytes (binary types) or str (text and xml), in the order its
    bytes arrive. Text is never split inside a character. It can be read once, while its row is current. Moving to
    the next value, or the next row, discards what is unread."""

    def __init__(self, column: Column, owner: weakref.ref[Response] | None):
        self.column = column
        self._owner = owner  # weakly, as for result sets
        self._pieces: deque = deque()
        self._complete = False
        self._discarded = False
        self._iterated = False

    @classmethod
    def whole(cls, column: Column, value: Any) -> ValueStream:
        stream = cls(column, None)
        if value:
            stream._pieces.append(value)
        stream._complete = True
        return stream

    def __aiter__(self) -> AsyncIterator[bytes | str]:
        if self._iterated:
            raise RowsNotAvailable("a ValueStream is read once")
        self._iterated = True
        return self._iterate()

    async def _iterate(self) -> AsyncIterator[bytes | str]:
        while True:
            if self._discarded:
                raise RowsNotAvailable(f"the rest of {self.column.name or 'this value'} was discarded: its row moved on")
            if self._pieces:
                yield self._pieces.popleft()
                continue
            if self._complete:
                return
            await _live(self._owner)._pull()

    def __repr__(self) -> str:
        return f"ValueStream({self.column.name or '(no name)'} {self.column.type})"

    # used by the reader
    def _add(self, piece: bytes | str) -> None:
        if piece and not self._discarded:
            self._pieces.append(piece)

    def _move_on(self) -> None:
        self._discarded = True
        self._pieces.clear()


class StreamedRow:
    """One row, read value by value in column order: `async for value in row`. A short value comes whole. A large one
    (D-47) comes as a ValueStream, or as None for NULL. It can be read once. Moving to the next row discards what is
    unread."""

    def __init__(self, columns: tuple[Column, ...], owner: weakref.ref[Response] | None):
        self.columns = columns
        self._owner = owner  # weakly, as for result sets
        self._values: deque = deque()
        self._complete = False
        self._discarded = False
        self._iterated = False

    @classmethod
    def whole(cls, columns: tuple[Column, ...], values: tuple) -> StreamedRow:
        """A row already read whole. Its large values still arrive as ValueStreams, so code reads both kinds of row the
        same way."""
        row = cls(columns, None)
        for column, value in zip(columns, values):
            row._values.append(ValueStream.whole(column, value) if column.type.large and value is not None else value)
        row._complete = True
        return row

    def __aiter__(self) -> AsyncIterator[Any]:
        if self._iterated:
            raise RowsNotAvailable("a streamed row is read once")
        self._iterated = True
        return self._iterate()

    async def _iterate(self) -> AsyncIterator[Any]:
        current = None
        while True:
            if current is not None:
                current._move_on()  # moving to the next value discards what is unread of a large one
                current = None
            if self._discarded:
                return
            if self._values:
                value = self._values.popleft()
                if isinstance(value, ValueStream):
                    current = value
                yield value
                continue
            if self._complete:
                return
            await _live(self._owner)._pull()

    # used by the reader and the result set
    def _move_on(self) -> None:
        self._discarded = True
        for value in self._values:
            if isinstance(value, ValueStream):
                value._move_on()
        self._values.clear()


def _live(owner: weakref.ref[Response] | None) -> Response:
    response = owner() if owner is not None else None
    if response is None:
        raise RowsNotAvailable("the response this came from is gone")
    return response


ROW_TAG, NBCROW_TAG = 0xD1, 0xD2


class RowDecoder:
    """One ROW or NBCROW of a result set with large values, read value by value as its bytes arrive (D-47). Values go
    where the result set is being read: into a tuple (large values assembled whole), into a StreamedRow (large values
    as ValueStreams, piece by piece), or nowhere (rows being discarded are counted, not kept)."""

    def __init__(self, result_set: ResultSet, null_bitmap: bool, record: bool, owner: weakref.ref[Response] | None):
        self.rs, self.columns, self.record = result_set, result_set.columns, record
        self.nulls: bytes | None = None if null_bitmap else b""
        self.index = 0
        self.values: list = []
        self.large = None  # the large value being read
        self.decoder = None  # its incremental text decoder, when streamed
        self.pieces: list = []  # its pieces, when held whole
        self.stream: ValueStream | None = None
        self.nodes: list[Node] = []
        self.done = False
        self.row = None
        if not result_set._discard and result_set._streamed:
            self.row = StreamedRow(self.columns, owner)
            result_set._queue.append(self.row)  # handed out as it arrives

    @property
    def _dropping(self) -> bool:
        return self.rs._discard or (self.row is not None and self.row._discarded)

    def read(self, data: memoryview, at: int, complete: bool) -> int:
        """Read what has arrived from data[at:], and return where it stopped. `done` is set once the row is complete."""
        if self.nulls is None:
            size = (len(self.columns) + 7) // 8
            if len(data) - at < size:
                return at
            self.nulls, at = bytes(data[at : at + size]), at + size
        while self.index < len(self.columns):
            column = self.columns[self.index]
            if self.nulls and self.nulls[self.index // 8] >> (self.index % 8) & 1:
                self._value(column, None, b"")
                continue
            if column.type.large:
                at = self._large(column, data, at)
                if self.large is not None:
                    return at
                continue
            value_reader = Reader(bytes(data[at:]), False, complete=complete)
            try:
                value = column.type.read_value(value_reader)
            except Incomplete:
                return at
            self._value(column, value, bytes(data[at : at + value_reader.pos]))
            at += value_reader.pos
        self.done = True
        return at

    def _large(self, column: Column, data: memoryview, at: int) -> int:
        if self.large is None:
            self.large = column.type.large_value()
            if self.row is not None:
                self.decoder = column.type.text_decoder()
        at, pieces = self.large.read(data, at)
        if self.large.null and self.large.done:
            self.large = self.decoder = None
            self._value(column, None, b"")
            return at
        if self.row is not None and self.stream is None and not self._dropping:
            self.stream = ValueStream(column, self.row._owner)
            self.row._values.append(self.stream)
        for piece in pieces:
            if self._dropping:
                continue
            if self.stream is not None:
                self.stream._add(self.decoder.decode(piece) if self.decoder else piece)
            else:
                self.pieces.append(piece)
        if self.large.done:
            large, self.large = self.large, None
            if self.stream is not None:
                if self.decoder:
                    self.stream._add(self.decoder.decode(b"", final=True))
                self.stream._complete = True
                self.values.append(self.stream)
            else:
                self.values.append(None if self._dropping else column.type.assemble(b"".join(self.pieces)))
            self.stream, self.decoder, self.pieces = None, None, []
            if self.record:
                self.nodes.append(Node(column.name or f"column {self.index + 1}", 0, 0, kept(large.first),
                                       f"{column.type} · {large.size} bytes in {large.chunks} chunks"))
            self.index += 1
        return at

    def _value(self, column: Column, value: Any, raw: bytes) -> None:
        self.values.append(value)
        if self.row is not None and not self._dropping:
            self.row._values.append(value)
        if self.record:
            self.nodes.append(Node(column.name or f"column {self.index + 1}", 0, len(raw), kept(raw),
                                   column.type.show(value)))
        self.index += 1

    def finish(self) -> Node | None:
        """The row is complete. Count it, and keep it where rows are being kept."""
        if self.row is not None:
            self.rs.rows_read += 1
            self.row._complete = True
        else:
            self.rs._arrive(tuple(self.values))
        if not self.record:
            return None
        return Node("ROW", 0, 0, b"", "a row read value by value", children=self.nodes)


# =========================================================================== the state machine


KINDS = {"DONE": CompletionKind.STATEMENT, "DONEINPROC": CompletionKind.STATEMENT_IN_PROCEDURE,
         "DONEPROC": CompletionKind.CALL}


class ResponseReader:
    """Turns a response's tokens into the record, as its packets arrive. Every view is one token rule:

      result sets    COLMETADATA opens one; the next completion closes it
      completions    every DONE, DONEINPROC and DONEPROC
      messages       every INFO          errors    every ERROR
      returns        one Return per DONEPROC: the RETURNSTATUS and RETURNVALUEs since the previous one

    The response ends at the completion whose MORE bit is clear. Once a cancel has been sent, it ends instead at the
    completion that acknowledges the cancel, which may come in a later message."""

    def __init__(self, record: bool, announce: Callable[[Record], None], metadata: tuple = (), request: Any = None,
                 negotiated: dict | None = None):
        self.record = record
        self.request = request  # the request this response answers, for errors that name it
        self.timing = Timing()
        self._announce = announce
        self._metadata = list(metadata)  # columns the request supplied, for result sets sent without metadata
        self._buffer = bytearray()  # bytes not yet decoded: the start of a token split by a packet boundary
        self._context: dict[str, Any] = {}  # what later tokens depend on: the current columns
        self._context.update(negotiated or {})  # what the login agreed, such as the data classification version
        self.owner: weakref.ref[Response] | None = None  # weakly: the connection holds the reader, not the response

        self.sequence: list[Item] = []
        self.result_sets: list[ResultSet] = []
        self.completions: list[Completion] = []
        self.messages: list[Message] = []
        self.errors: list[Error] = []
        self.returns: list[Return] = []
        self._open: ResultSet | None = None
        self._status: int | None = None
        self._outputs: list[OutputValue] = []
        self._function_result: OutputValue | None = None

        self._row: RowDecoder | None = None  # a row with large values, being read value by value
        self._last = False  # the message's last packet has arrived
        self.paused = False  # at a row with large values, waiting for the application to choose how to read it
        self._wait_for = 0  # a token split by a packet boundary is tried again once the buffer has grown this much
        self.ended = False
        self.cancelling = False  # Attention has been sent
        self.cancelled = False  # and acknowledged
        self.discard_new = False  # finish() or close(): rows of later result sets are dropped
        self.keep_new = False  # fetch() or Unread.KEEP: rows of later result sets are kept

        # for observability
        self.size = 0
        self.packets = 0
        self.tally: Counter[str] = Counter()
        self.nodes: list[Node] = []  # packet headers and tokens, in arrival order, when recording

    def feed(self, body: bytes, last: bool, header: Node | None = None) -> None:
        """Take one packet's body. `last` says that the packet ends its message."""
        if self.ended:
            raise MalformedMessage("bytes arrived after the end of the response", 0)
        if self.timing.first_packet is None:
            self.timing.first_packet = time.perf_counter()
        self.packets += 1
        self.size += len(body)
        if self.record and header is not None:
            self.nodes.append(header)
        self._buffer += body
        self._last = last
        self._decode()
        self._timed()

    def resume(self) -> None:
        """Decode the bytes already received, once the application has chosen how to read a paused result set."""
        self._decode()
        self._timed()

    def _timed(self) -> None:
        if self.ended and self.timing.ended is None:
            self.timing.ended = time.perf_counter()

    def _decode(self) -> None:
        last = self._last
        if len(self._buffer) < self._wait_for and not last:
            return  # a long token is still arriving. Trying again on every packet would read it repeatedly
        self._wait_for = 0
        self.paused = False
        data = bytes(self._buffer)
        view = memoryview(data)
        r = Reader(data, self.record, complete=last)
        r.context = self._context
        while r.pos < len(data) and not self.ended:
            if self._row is not None:  # a row with large values, value by value
                r.pos = self._row.read(view, r.pos, last)
                if not self._row.done:
                    break
                node, self._row = self._row.finish(), None
                if node is not None:
                    r.tree.children.append(node)
                continue
            tag = data[r.pos]
            if tag in (ROW_TAG, NBCROW_TAG) and self._open is not None and self._open._large:
                if not self._open._claimed:  # wait: the application chooses to hold large values whole or stream them
                    self.paused = True
                    break
                self.tally["ROW" if tag == ROW_TAG else "NBCROW"] += 1
                self._row = RowDecoder(self._open, tag == NBCROW_TAG, self.record, self.owner)
                r.pos += 1
                continue
            mark, recorded = r.pos, len(r.tree.children)
            try:
                record = TOKENS.read_one(r)
            except Incomplete:  # the rest of this token is in a packet that hasn't arrived yet
                r.pos = mark
                del r.tree.children[recorded:]
                self._wait_for = 2 * (len(data) - mark)
                break
            self._take(record)
        if self.ended and r.pos < len(data):
            raise MalformedMessage(f"{len(data) - r.pos} bytes after the response's final DONE", r.pos, r.tree)
        del self._buffer[: r.pos]
        if self.record:
            self.nodes.extend(r.tree.children)
        if self.paused:
            return
        if last and self._row is not None:
            raise MalformedMessage("the response's message ended inside a row", r.pos, r.tree)
        if last and not self.ended and not self.cancelling:
            raise MalformedMessage("the response's message ended without a final DONE", r.pos, r.tree)

    def _take(self, rec: Record) -> None:
        self.tally[rec.token] += 1
        match rec.token:
            case "COLMETADATA":
                if rec.count == 0xFFFF:  # no metadata: the request supplied these columns (CallOptions.NO_METADATA)
                    if not self._metadata:
                        raise MalformedMessage("a result set arrived without metadata, and the request supplied none", 0,
                                               rec.node)
                    columns = tuple(self._metadata.pop(0))
                    self._context["columns"] = columns
                else:
                    columns = tuple(Column(c.name, c.type, ColumnFlags.NULLABLE in c.flags, c.flags, c.user_type)
                                    for c in rec.columns)
                rs = ResultSet(columns, self.owner)
                if self.discard_new:
                    rs._discard = rs._claimed = True
                elif self.keep_new:
                    rs._kept, rs._claimed = [], True
                self.result_sets.append(rs)
                self.sequence.append(rs)
                self._open = rs
            case "ORDER":
                if self._open is None:
                    raise MalformedMessage("an ORDER arrived outside a result set", 0, rec.node)
                self._open.order = tuple(rec.columns)
            case "TABNAME" | "COLINFO" | "DATACLASSIFICATION" | "ALTMETADATA" | "ALTROW":
                if self._open is None:
                    raise MalformedMessage(f"a {rec.token} arrived outside a result set", 0, rec.node)
                self._describe(self._open, rec)
            case "SESSIONSTATE":
                self.sequence.append(SessionState(rec.sequence, SessionStateStatus.RECOVERABLE in rec.status,
                                                  {s.id: s.value for s in rec.states}))
                self._announce(rec)  # the connection keeps the latest state, for recovering the session (D-57)
            case "ROW" | "NBCROW":
                if self._open is None:
                    raise MalformedMessage(f"a {rec.token} arrived outside a result set", 0, rec.node)
                self._open._arrive(tuple(rec["values"]))
            case "DONE" | "DONEINPROC" | "DONEPROC":
                done = Completion(KINDS[rec.token], rec.row_count if DoneStatus.COUNT in rec.status else None,
                                  rec.status, rec.current_command)
                self.completions.append(done)
                self.sequence.append(done)
                if self._open is not None:
                    self._open.completion, self._open = done, None
                if rec.token == "DONEPROC":
                    self.returns.append(Return(self._status, Outputs(self._outputs), self._function_result,
                                               bool(done.status & (DoneStatus.ERROR | DoneStatus.SERVER_ERROR)), done))
                    self._status, self._outputs, self._function_result = None, [], None
                if self.cancelling:
                    if DoneStatus.ATTENTION in done.status:
                        self.ended = self.cancelled = True
                elif DoneStatus.MORE not in done.status:
                    self.ended = True
            case "INFO" | "ERROR":
                report = (Message if rec.token == "INFO" else Error)(
                    rec.number, rec.state, rec.severity, rec.message, rec.server_name, rec.procedure, rec.line)
                (self.messages if rec.token == "INFO" else self.errors).append(report)
                self.sequence.append(report)
            case "RETURNSTATUS":
                self.sequence.append(ReturnStatus(rec.value))
                self._status = rec.value
            case "RETURNVALUE":
                output = OutputValue(rec.ordinal, rec.name, rec.type, rec.value,
                                     rec.status == ReturnValueStatus.FUNCTION_RESULT)
                self.sequence.append(output)
                if output.function_result:
                    self._function_result = output
                else:
                    self._outputs.append(output)
            case "ENVCHANGE":
                self.sequence.append(Announcement(rec.kind, rec.new, rec.old))
                self._announce(rec)
            case _:  # SSPI and FEDAUTHINFO belong to a login's reply
                raise MalformedMessage(f"{rec.token} doesn't belong in a request's response", 0, rec.node)

    def _describe(self, rs: ResultSet, rec: Record) -> None:
        """Tokens that say more about the open result set: where its columns came from, their classification, and
        COMPUTE totals."""
        match rec.token:
            case "TABNAME":
                rs.tables = tuple(tuple(t.names) for t in rec.tables)
            case "COLINFO":
                rs.column_info = tuple(ColumnInfo(c.column, c.table, ColumnInfoStatus(c.status), c.base_name)
                                       for c in rec.columns)
            case "DATACLASSIFICATION":
                labels = tuple((l.name, l.id) for l in rec.labels)
                kinds = tuple((t.name, t.id) for t in rec.information_types)
                pick = lambda items, i: None if i == 0xFFFF else items[i]
                rs.classification = DataClassification(labels, kinds, rec.rank, tuple(
                    tuple(Sensitivity(pick(labels, p.label), pick(kinds, p.information_type), p.rank) for p in c.sensitivities)
                    for c in rec.columns))
            case "ALTMETADATA":
                rs.totals[rec.id] = Totals(rec.id, tuple(rec.by), tuple(
                    (c.aggregate, c.operand, c.type, c.name) for c in rec.columns))
                self._context.setdefault("computed", {})[rec.id] = rec.columns  # how ALTROWs with this id are laid out
            case "ALTROW":
                rs.total_rows.append((rec.id, tuple(rec["values"])))


# =========================================================================== reading a response


class Source(Protocol):
    """Where a live response's packets come from: the connection's shell."""

    async def read_more(self) -> None:
        """Feed the response's reader at least one more packet."""

    def cancel(self) -> None:
        """Send Attention now. It is safe to call from any task."""

    def resume(self) -> None:
        """Decode bytes already received. The reader paused there, at a result set that the application hadn't chosen
        how to read."""

    def describe(self) -> str: ...


class Response:
    """A live response: the record of what the server did, read forward as it arrives (D-34, D-42).

        async with await channel.exchange(request) as response:
            async for result_set in response:       # each result set as it starts arriving
                async for row in result_set:        # its rows: plain tuples
                    ...
            returns = await response.returns(unread=Unread.KEEP)

    An open response holds its serial channel. Errors are raised at the end, by whichever call reaches the end, as
    a ServerError carrying the whole record. Leaving the `async with` block early cancels the request."""

    def __init__(self, reader: ResponseReader, source: Source | None):
        self._reader = reader
        self.request = reader.request  # the request this response answers
        self.timing = reader.timing  # when it was sent, first answered and ended (D-12)
        self._source = source
        reader.owner = weakref.ref(self)
        self._current: ResultSet | None = None
        self._next = 0  # index of the next result set to hand out
        self._reported = False  # the error or cancellation has been raised
        self._closed = False

    # ----------------------------------------------------------------------- views, as far as the response was read

    @property
    def sequence(self) -> tuple[Item, ...]:
        return tuple(self._reader.sequence)

    @property
    def completions(self) -> tuple[Completion, ...]:
        return tuple(self._reader.completions)

    @property
    def messages(self) -> tuple[Message, ...]:
        return tuple(self._reader.messages)

    @property
    def errors(self) -> tuple[Error, ...]:
        return tuple(self._reader.errors)

    @property
    def ended(self) -> bool:
        return self._reader.ended

    # ----------------------------------------------------------------------- moving forward

    async def peek(self) -> Item | None:
        """Read until the record's first item has arrived, and return it without consuming anything. Every way of
        reading the response still starts at its beginning. Returns None if the response ended with nothing in it.
        tds.encryption uses it to see whether the server refused a call before running it (D-60)."""
        while not self._reader.sequence and not self.ended:
            await self._pull()
        return self._reader.sequence[0] if self._reader.sequence else None

    def __aiter__(self) -> AsyncIterator[ResultSet]:
        return self._result_sets()

    async def _result_sets(self) -> AsyncIterator[ResultSet]:
        while True:
            if self._current is not None:
                self._current._drop_unread()  # moving to the next result set discards the current one's unread rows
            sets = self._reader.result_sets
            if self._next < len(sets):
                self._current = sets[self._next]
                self._next += 1
                yield self._current
                continue
            if self.ended:
                self._at_end()
                return
            await self._pull()

    async def fetch(self) -> FetchedResponse:
        """Read to the end, keeping everything. Return the response, backed by memory. The serial channel is then
        free."""
        self._keep_everything()
        while not self.ended:
            await self._pull()
        fetched = self._snapshot()
        self._at_end(fetched)
        return fetched

    async def finish(self) -> None:
        """Read to the end, skipping rows. Completions, messages, errors and returns are kept."""
        self._discard_everything()
        while not self.ended:
            await self._pull()
        self._at_end()

    async def returns(self, unread: Unread = Unread.REFUSE) -> tuple[Return, ...]:
        """One Return per outermost procedure call the server completed. They come at the end of the response."""
        if not self.ended:
            if unread is Unread.REFUSE:
                raise NotYetRead("returns() comes at the end of the response, which hasn't been read that far. "
                                 "Pass unread=Unread.KEEP to read ahead keeping everything, or Unread.DISCARD to "
                                 "skip rows; or call fetch() or finish() first.")
            if unread is Unread.KEEP:
                self._keep_everything()
                while not self.ended:
                    await self._pull()
            else:
                self._discard_everything()
                while not self.ended:
                    await self._pull()
        self._at_end()
        return tuple(self._reader.returns)

    # ----------------------------------------------------------------------- stopping

    def cancel(self) -> None:
        """Cancel the request: send Attention and return immediately. It is safe to call from any task (D-23). The
        owner's next read raises Cancelled once the server has acknowledged the cancel. The serial channel is then
        free."""
        if self._source is not None and not self.ended and not self._reader.cancelling:
            self._source.cancel()

    async def close(self) -> None:
        """The owner stops reading. A response that hasn't ended is canceled, and read up to the server's
        acknowledgement."""
        if self._closed or self._source is None:
            return
        if not self.ended:
            self.cancel()
            self._discard_everything()
            try:
                while not self.ended:
                    await self._pull()
            except Cancelled:
                pass  # closing early is the owner's own choice
        self._closed = True

    async def __aenter__(self) -> Response:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None:
            try:
                await self.close()
            except Exception:
                pass  # the error already being raised is the one that matters, so closing must not hide it
            return
        ended_before = self.ended
        await self.close()
        if ended_before:
            self._at_end()  # the block finished a response that had already ended: report its errors

    def __del__(self) -> None:
        if getattr(self, "_source", None) is not None and not self._reader.ended and not self._closed:
            warnings.warn(f"a response on {self._source.describe()} was dropped while still open; its serial channel "
                          "stays busy. Read it to the end, or use `async with`.", ResourceWarning, source=self)

    # ----------------------------------------------------------------------- internals

    def _is_current(self, result_set: ResultSet) -> bool:
        return result_set is self._current

    async def _pull(self) -> None:
        """Read one more packet. A cancellation is raised by whichever read gets the acknowledgement. Errors wait until
        the application's own reading reaches the end (_at_end), so that every result set is handed out first."""
        if self.ended:
            return
        if self._reader.paused:
            self._source.resume()  # the bytes are here. Decode them, now that the application has chosen how to read
            if not self._reader.paused:
                return
        await self._source.read_more()
        if self._reader.cancelled and not self._reported:
            self._reported = True
            raise Cancelled(self._snapshot())

    def _at_end(self, fetched: FetchedResponse | None = None) -> None:
        """The response has ended: raise its cancellation or its errors, once."""
        if self._reported:
            return
        if self._reader.cancelled:
            self._reported = True
            raise Cancelled(fetched or self._snapshot())
        if self._reader.errors:
            self._reported = True
            raise ServerError(tuple(self._reader.errors), fetched or self._snapshot())

    def _keep_everything(self) -> None:
        """From the current result set on, keep every row (fetch, Unread.KEEP). Earlier result sets have been passed."""
        reader = self._reader
        reader.keep_new, reader.discard_new = True, False
        for rs in reader.result_sets[max(self._next - 1, 0):]:
            rs._keep_from_now()

    def _discard_everything(self) -> None:
        """From the current result set on, drop rows not yet read (finish, Unread.DISCARD, close)."""
        reader = self._reader
        reader.discard_new, reader.keep_new = True, False
        for rs in reader.result_sets[max(self._next - 1, 0):]:
            rs._drop_unread()

    def _snapshot(self) -> FetchedResponse:
        return FetchedResponse(self._reader)


class FetchedResponse(Response):
    """A response backed by memory. It was read to its end, and its serial channel is already free (D-34). It is read
    exactly as a live response is, and adds what memory makes possible: reading again, and indexing
    (`result_sets[1].rows[9]`)."""

    def __init__(self, reader: ResponseReader):
        snapshots = {id(rs): rs._snapshot() for rs in reader.result_sets}
        self._sets = tuple(snapshots[id(rs)] for rs in reader.result_sets)
        self._items = tuple(snapshots.get(id(item), item) for item in reader.sequence)
        self._frozen = (tuple(reader.completions), tuple(reader.messages), tuple(reader.errors), tuple(reader.returns))
        self._cancelled = reader.cancelled
        self.request = reader.request
        self.timing = reader.timing
        self._source = None
        self._closed = True

    @property
    def result_sets(self) -> tuple[ResultSet, ...]:
        return self._sets

    @property
    def sequence(self) -> tuple[Item, ...]:
        return self._items

    @property
    def completions(self) -> tuple[Completion, ...]:
        return self._frozen[0]

    @property
    def messages(self) -> tuple[Message, ...]:
        return self._frozen[1]

    @property
    def errors(self) -> tuple[Error, ...]:
        return self._frozen[2]

    @property
    def ended(self) -> bool:
        return True

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    async def _result_sets(self) -> AsyncIterator[ResultSet]:
        for rs in self._sets:
            yield rs

    async def fetch(self) -> FetchedResponse:
        return self

    async def finish(self) -> None:
        return None

    async def returns(self, unread: Unread = Unread.REFUSE) -> tuple[Return, ...]:
        return self._frozen[3]

    def cancel(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    def __del__(self) -> None:
        return None

    def __repr__(self) -> str:
        return (f"FetchedResponse({len(self._sets)} result sets, {len(self._frozen[0])} completions, "
                f"{len(self._frozen[1])} messages, {len(self._frozen[2])} errors, {len(self._frozen[3])} returns)")
