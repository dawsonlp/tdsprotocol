"""Requests: what a client can ask the server, each sent as one message on a serial channel.

Reference: Requests, and Conversations for where each one fits. Checked against MS-TDS v20260617, §2.2.5.3 (the
headers every request carries), §2.2.6.7 (SQL batch), §2.2.6.6 (RPC) and §2.2.6.1 (bulk load). Decisions: D-33,
D-40, D-50. Transaction-manager requests are in transactions.py (D-51).

A request knows its packet type and encodes its own body from a small context. That is all that the connection needs
from it, so the connection never needs to know what kind of request it is sending (D-33).
"""

import enum
from dataclasses import dataclass
from typing import Any, NamedTuple, Protocol

from .packet import PacketType
from .tokens import CRYPTO_METADATA, KEY_TABLE, ColumnFlags
from .types import (FIXED_CODES, PLP_NULL, PLP_UNKNOWN, Collation, Encrypted, EncryptionType, SqlType, Stream, Table, TypeInfo,
                    ValueOf, ValueRefused, _check, _numbered, is_source)
from .wire import Blob, Field, Node, Raw, Repeat, Separated, Struct, Text, Type, U8, U16, U32, U64, When, Writer

# --------------------------------------------------------------------------- the headers every request carries

TRANSACTION_DESCRIPTOR = 2  # header type. This header is required on every request

TRANSACTION_HEADER = Struct("transaction descriptor", [
    Field("length", U32, total=True, fmt=lambda v: f"{v} bytes"),
    Field("type", U16, fmt=lambda v: "transaction descriptor" if v == TRANSACTION_DESCRIPTOR else f"{v}"),
    Field("transaction", U64, fmt=lambda v: f"{v:#x}" if v else "0 (none)"),  # from the latest BEGIN TRANSACTION announcement
    Field("outstanding_requests", U32),  # requests active on the connection, this one included
])

HEADERS = Struct("headers", [
    Field("total_length", U32, total=True, fmt=lambda v: f"{v} bytes"),
    Field("transaction_descriptor", TRANSACTION_HEADER),
], source="§2.2.5.3")


@dataclass(frozen=True)
class Context:
    """What a request needs from the connection to encode itself."""

    transaction: int  # the current transaction descriptor, or 0 when none is open
    outstanding_requests: int  # requests active on the connection, this one included
    collation: bytes  # the session's collation, for text without a collation of its own
    column_encryption: int = 0  # the Always Encrypted version that the login agreed (D-60). From 1,
    # bulk data's columns carry a key table. From 2 (enclaves), every batch and call carries an enclave package,
    # which is empty when there is none


def headers(context: Context) -> dict:
    return {"transaction_descriptor": {"type": TRANSACTION_DESCRIPTOR, "transaction": context.transaction,
                                       "outstanding_requests": context.outstanding_requests}}


class Encoded(NamedTuple):
    """A request, encoded: its body, the body's inspection tree, and the sources whose chunks go into the body, each
    at its offset, as it is sent (D-41)."""

    body: bytes
    node: Node | None
    streams: tuple = ()


class Request(Protocol):
    """Anything the connection can send as a request."""

    kind: PacketType  # the packet type that carries its message
    label: str  # the name that the client shows for it
    metadata: tuple  # columns for result sets the server will send without metadata, in order (CallOptions.NO_METADATA)

    def encode(self, context: Context, record: bool) -> Encoded: ...


# --------------------------------------------------------------------------- SQL batch: T-SQL text

def _enclaves(rw) -> bool:
    return rw.context.get("column_encryption", 0) >= 2


ENCLAVE_PACKAGE = When(_enclaves, Blob(U16))  # Always Encrypted with enclaves: bytes for the server's enclave, which the
# server passes on without reading them. Once the login agreed enclaves, every batch and call has one, which is empty
# when there is none. MS-TDS says a u32 length (L_VARBYTE). SqlClient writes a u16, which is what SQL Server reads
# (Always Encrypted › Edge cases)

SQL_BATCH = Struct("SQL batch", [
    Field("headers", HEADERS),
    Field("enclave_package", ENCLAVE_PACKAGE),
    Field("text", Text()),  # UTF-16LE, to the end of the message
], source="§2.2.6.7", summary=lambda b: f"“{b.text}”")


@dataclass(frozen=True)
class Batch:
    """T-SQL text, run as written: one or more statements."""

    sql: str
    enclave_package: bytes | None = None  # Always Encrypted with enclaves only (D-60)
    kind = PacketType.SQL_BATCH
    label = "SQL batch"
    metadata = ()

    def encode(self, context: Context, record: bool) -> Encoded:
        enclave = self.enclave_package or b"" if context.column_encryption >= 2 else None
        return Encoded(*SQL_BATCH.encode({"headers": headers(context), "enclave_package": enclave, "text": self.sql},
                                         record, {"column_encryption": context.column_encryption}))

    def __str__(self) -> str:
        text = " ".join(self.sql.split())
        return f"the {self.label} “{text[:100]}{'…' if len(text) > 100 else ''}”"


# --------------------------------------------------------------------------- RPC: procedure calls, with typed parameters (D-40)


class Builtin(enum.IntEnum):
    """The procedures an RPC can call by number instead of by name."""

    SP_CURSOR = 1
    SP_CURSOROPEN = 2
    SP_CURSORPREPARE = 3
    SP_CURSOREXECUTE = 4
    SP_CURSORPREPEXEC = 5
    SP_CURSORUNPREPARE = 6
    SP_CURSORFETCH = 7
    SP_CURSOROPTION = 8
    SP_CURSORCLOSE = 9
    SP_EXECUTESQL = 10
    SP_PREPARE = 11
    SP_EXECUTE = 12
    SP_PREPEXEC = 13
    SP_PREPEXECRPC = 14
    SP_UNPREPARE = 15


class CallOptions(enum.IntFlag):
    RECOMPILE = 0x01  # compile a new plan for this call
    NO_METADATA = 0x02  # the server sends no column metadata, so the call supplies the columns (see Call)
    REUSE_METADATA = 0x04  # the server reuses its cached metadata (it still sends it)


class ParamStatus(enum.IntFlag):
    BY_REFERENCE = 0x01  # an output parameter. Its value is returned in a RETURNVALUE
    DEFAULT_VALUE = 0x02  # use the procedure's default. The value sent is NULL
    ENCRYPTED = 0x08  # Always Encrypted: the value is ciphertext, and its cipher info follows it (D-60)


@dataclass(frozen=True)
class CipherInfo:
    """What an encrypted parameter's ciphertext holds (ParamCipherInfo, §2.2.6.6): the plaintext's type, how it was
    encrypted, and with which column key. tds.encryption fills it from sp_describe_parameter_encryption (D-60)."""

    base: SqlType
    encryption_type: EncryptionType
    database_id: int
    key_id: int
    key_version: int
    key_metadata_version: bytes  # 8 bytes, as the server gave them
    algorithm: int = 2  # AEAD_AES_256_CBC_HMAC_SHA256
    algorithm_name: str | None = None  # only for algorithm 0
    normalization: int = 1

    def wire(self) -> dict:
        return {"base": self.base, "algorithm": self.algorithm, "algorithm_name": self.algorithm_name,
                "encryption_type": self.encryption_type, "database_id": self.database_id, "key_id": self.key_id,
                "key_version": self.key_version, "key_metadata_version": self.key_metadata_version,
                "normalization": self.normalization}


class _Default:
    def __repr__(self) -> str:
        return "DEFAULT"


DEFAULT = _Default()  # as a parameter's value, it selects the procedure's default


@dataclass(frozen=True)
class Param:
    """One parameter, as the wire carries it: a name (empty means positional), a declared type, a value, and whether
    it is passed by reference. Passing by reference is TDS's only output mechanism. With output=True, the parameter's
    value is returned, and the procedure receives the value sent. None is sent as NULL."""

    name: str
    type: SqlType
    value: Any = None
    output: bool = False
    cipher: CipherInfo | None = None  # Always Encrypted: `type` is varbinary, and `value` is its ciphertext (D-60)

    def check(self, collation: Any) -> None:
        """Refuse a value that doesn't fit its declared type, before anything is sent (D-48)."""
        if self.value is DEFAULT:
            return
        _check(self.type, self.value, collation)

    def wire(self) -> dict:
        default = self.value is DEFAULT
        status = (ParamStatus.BY_REFERENCE if self.output else ParamStatus(0)) | (
            ParamStatus.DEFAULT_VALUE if default else ParamStatus(0)) | (  # a table's default also sends "no table"
            ParamStatus.ENCRYPTED if self.cipher else ParamStatus(0))
        return {"name": self.name, "status": status, "type": self.type, "value": None if default else self.value,
                "cipher": self.cipher.wire() if self.cipher else None}


class Procedure(Type):
    """The procedure an RPC calls: a name (its length, then UTF-16LE), or FFFF and a built-in procedure's number."""

    def write(self, w: Writer, target: str | Builtin) -> None:
        if isinstance(target, Builtin):
            w.put(b"\xff\xff" + target.to_bytes(2, "little"))
        else:
            Text(U16).write(w, target)

    def read(self, r) -> str | Builtin:  # for replaying a capture (D-12)
        n = U16.read(r)
        if n == 0xFFFF:
            number = U16.read(r)
            return Builtin(number) if number in Builtin._value2member_map_ else number
        return bytes(r.take(2 * n, "procedure name")).decode("utf-16-le", "surrogatepass")

    def show(self, target: str | Builtin) -> str:
        return target.name.lower() if isinstance(target, Builtin) else str(target)


def _named(rw) -> bool:
    return rw.values[-1]["algorithm"] == 0


PARAM_CIPHER_INFO = Struct("cipher info", [  # ParamCipherInfo (§2.2.6.6)
    Field("base", TypeInfo()),  # the plaintext's type
    Field("algorithm", U8),
    Field("algorithm_name", When(_named, Text(U8))),
    Field("encryption_type", U8, enum=EncryptionType),
    Field("database_id", U32),
    Field("key_id", U32),
    Field("key_version", U32),
    Field("key_metadata_version", Raw(8)),
    Field("normalization", U8),
], summary=lambda c: f"{c.base} · {getattr(c.encryption_type, 'name', c.encryption_type)}".lower() + f" · key {c.key_id}")


def _encrypted_parameter(rw) -> bool:
    return ParamStatus.ENCRYPTED in ParamStatus(rw.values[-1]["status"])


PARAMETER = Struct("parameter", [
    Field("name", Text(U8)),  # empty means positional
    Field("status", U8, enum=ParamStatus),
    Field("type", TypeInfo()),  # for an encrypted parameter, the ciphertext's type (varbinary)
    Field("value", ValueOf("type")),
    Field("cipher", When(_encrypted_parameter, PARAM_CIPHER_INFO)),
], summary=lambda p: f"{p.name or '(positional)'} {p.type} = {p.type.show(p.value)}"
                     f"{' · encrypted ' + PARAM_CIPHER_INFO.show(p.cipher) if p.get('cipher') else ''}"
                     f"{' · output' if ParamStatus.BY_REFERENCE in p.status else ''}"
                     f"{' · default' if ParamStatus.DEFAULT_VALUE in p.status else ''}",
   where=lambda p: f"parameter {p['name'] or '(positional)'} ({p['type']})")

CALL = Struct("call", [
    Field("procedure", Procedure()),
    Field("options", U16, enum=CallOptions),
    Field("enclave_package", ENCLAVE_PACKAGE),
    Field("parameters", Repeat(None, PARAMETER, stop_at=b"\xff\xfe")),  # up to the next call's separator
], summary=lambda c: f"{Procedure().show(c.procedure)}({len(c.parameters)} parameter{'' if len(c.parameters) == 1 else 's'})",
   where=lambda c: f"the call to {Procedure().show(c['procedure'])}")

RPC = Struct("RPC", [
    Field("headers", HEADERS),
    Field("calls", Separated(CALL, 0xFF, "call")),  # the BATCH separator between calls (D-40: never NO-EXEC)
], source="§2.2.6.6", summary=lambda r: " · ".join(CALL.show(c) for c in r.calls))


@dataclass(frozen=True, init=False)
class Call:
    """One RPC: a procedure by name or built-in number, with explicitly typed parameters, in order (D-40).

        Call("shop.place_order", Param("@customer", types.int, 42), Param("@order", types.int, None, output=True))
        Call(Builtin.SP_EXECUTESQL, Param("@stmt", types.nvarchar(4000), "SELECT …"), …)

    A NO_METADATA call must supply the columns of each result set that it will return without metadata. The columns
    come from an earlier response. Rows can't be read without them."""

    target: str | Builtin
    params: tuple[Param, ...]
    options: CallOptions
    columns: tuple[tuple, ...]
    enclave_package: bytes | None  # Always Encrypted with enclaves only (D-60)

    kind = PacketType.RPC
    label = "RPC"

    def __init__(self, target: str | Builtin, *params: Param, options: CallOptions = CallOptions(0),
                 columns: tuple[tuple, ...] = (), enclave_package: bytes | None = None):
        if CallOptions.NO_METADATA in options and not columns:
            raise ValueError("a NO_METADATA call must supply the columns of the result sets it returns without them")
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "params", tuple(params))
        object.__setattr__(self, "options", options)
        object.__setattr__(self, "columns", tuple(tuple(c) for c in columns))
        object.__setattr__(self, "enclave_package", enclave_package)

    @property
    def metadata(self) -> tuple:
        return self.columns

    def encode(self, context: Context, record: bool) -> Encoded:
        return Calls(self).encode(context, record)

    def __str__(self) -> str:
        return f"the call to {Procedure().show(self.target)}"

    def wire(self, collation: Any) -> dict:
        for i, param in enumerate(self.params):
            try:
                param.check(collation)
            except ValueRefused as e:
                e.within(f"parameter {param.name or f'{i + 1} (positional)'} ({param.type})")
                e.within(str(self))
                raise
        return {"procedure": self.target, "options": self.options, "enclave_package": self.enclave_package,
                "parameters": [p.wire() for p in self.params]}


@dataclass(frozen=True, init=False)
class Calls:
    """Several calls in one request, separated by BATCH. The server completes or refuses each call in turn. An
    error that ends the batch ends the request (D-40, D-42)."""

    calls: tuple[Call, ...]

    kind = PacketType.RPC
    label = "RPC"

    def __init__(self, *calls: Call):
        if not calls:
            raise ValueError("Calls needs at least one call")
        object.__setattr__(self, "calls", tuple(calls))

    @property
    def metadata(self) -> tuple:
        return tuple(columns for call in self.calls for columns in call.columns)

    def __str__(self) -> str:
        names = [Procedure().show(c.target) for c in self.calls]
        return f"the {len(names)} calls ({', '.join(names[:5])}{', …' if len(names) > 5 else ''})"

    def encode(self, context: Context, record: bool) -> Encoded:
        collation = Collation(context.collation) if context.collation else None  # for text without its own (D-40)
        calls = [call.wire(collation) for call in self.calls]
        for call in calls:  # once enclaves are agreed, every call carries a package, empty when there is none
            call["enclave_package"] = call["enclave_package"] or b"" if context.column_encryption >= 2 else None
        values = {"headers": headers(context), "calls": calls}
        streams: list = []  # filled as sources are found. Their chunks are sent when the body reaches them (D-41)
        body, node = RPC.encode(values, record, {"collation": collation, "streams": streams,
                                                 "column_encryption": context.column_encryption})
        return Encoded(body, node, tuple(streams))


# --------------------------------------------------------------------------- bulk load: rows into a table (D-50)


@dataclass(frozen=True)
class BulkInsert(Batch):
    """The first half of a bulk load: the application's own `INSERT BULK` statement, sent as a SQL batch.

        BulkInsert("INSERT BULK shop.orders (id int NOT NULL, placed datetimeoffset(7), total money) WITH (TABLOCK)")

    The statement names the table, the columns that the rows will fill (in order, with their SQL types and
    nullability), and the options (CHECK_CONSTRAINTS, FIRE_TRIGGERS, KEEP_NULLS, TABLOCK, ORDER (…), ROWS_PER_BATCH = n,
    KILOBYTES_PER_BATCH = n). The server answers with a DONE.

    Once it succeeds, a bulk load is open on the serial channel, and the channel's next request must be the
    `BulkRows` that continues it. Bulk data sent at any other time makes the server close the connection, so the
    channel refuses it (OutOfTurn). If the statement fails, nothing is open.

    The driver sends the statement as written and checks nothing in it (D-50). A convenience layer that writes the
    statement should write it and the BulkRows columns from the same column descriptions. See BulkRows."""

    label = "INSERT BULK"
    opens = "bulk load"


class _ColumnType(TypeInfo):
    """A column's type as the server itself describes it. A NOT NULL column of a fixed-size type keeps its
    fixed-size code. Every other type is described as for a parameter. It is read as TYPE_INFO is read."""

    def write(self, w: Writer, sql_type: SqlType) -> None:
        if isinstance(sql_type, Encrypted):  # its ciphertext's type. Its crypto metadata follows (D-60)
            return super().write(w, sql_type.cipher)
        if sql_type.code not in FIXED_CODES:
            return super().write(w, sql_type)
        start = w.pos
        w.put(bytes([sql_type.code]))
        if w.record and w._stack[-1].start == start:  # name its field as the reader names it
            from .wire import Reader
            r = Reader(bytes(w.buf[start:]), True)
            self.read(r)
            w._stack[-1].children.extend(r.tree.children)

    def show(self, sql_type: SqlType) -> str:
        return f"{sql_type}{' (fixed size: NOT NULL)' if sql_type.code in FIXED_CODES else ''}"


BULK_DONE = bytes.fromhex("FD 00 00 00 00 00 00 00 00 00 00 00 00")  # the end of the rows. The server ignores its count


def _bulk_value(w: Writer, sql_type: SqlType, value: Any, collation: Any) -> None:
    """One value in a bulk row, encoded for its column as the server describes the column."""
    if isinstance(sql_type, Encrypted):  # its ciphertext, which tds.encryption made from the row's value (D-60)
        if value is not None and not isinstance(value, (bytes, bytearray)):
            raise ValueRefused(f"the column is encrypted: its value is sent as ciphertext, which tds.encryption makes "
                               f"from {type(value).__name__} values; this connection sends values as given")
        return _bulk_value(w, sql_type.cipher, value, collation)
    if is_source(value):
        raise ValueRefused(f"a value in a bulk row is sent whole: rows can come from a source, not one value")
    _check(sql_type, value, collation)  # values that can't be encoded exactly are refused (D-48)
    if sql_type.code in FIXED_CODES:  # the value without the one-byte length that starts its nullable form
        if value is None:
            raise ValueRefused(f"a fixed-size {sql_type} column is NOT NULL: its layout has no NULL")
        inner = Writer(False)
        inner.context.update(w.context)
        sql_type.write_value(inner, value)
        w.put(bytes(inner.buf[1:]))
    elif sql_type.large and hasattr(sql_type, "encode_piece"):
        # As observed, and contrary to MS-TDS, in bulk data a known length must be followed by the bytes alone, not
        # chunks. The unknown-length form, with chunks, is accepted as MS-TDS defines it, so it is used for every value.
        if value is None:
            w.put(PLP_NULL.to_bytes(8, "little"))
        else:
            data = sql_type.encode_piece(value, collation)
            w.put(PLP_UNKNOWN.to_bytes(8, "little") + (len(data).to_bytes(4, "little") + data if data else b"") + bytes(4))
    else:
        sql_type.write_value(w, value)


def _bulk_row(columns: tuple, row: Any, context: dict) -> bytes:
    """ROW: each column's value, in order."""
    if not isinstance(row, (tuple, list)) or len(row) != len(columns):
        raise ValueRefused(f"a bulk row is a tuple of {len(columns)} values, one per column, not {row!r:.80}")
    w = Writer(False)
    w.context.update(context)
    w.put(b"\xd1")
    for i, (column, value) in enumerate(zip(columns, row), 1):
        try:
            _bulk_value(w, column.type, value, context.get("collation"))
        except ValueRefused as e:
            e.within(f"column {column.name or i} ({column.type})")
            raise
    return bytes(w.buf)


class _Rows(Type):
    """The rows, then the DONE that ends them. For a source, the place where the rows go as the source produces them."""

    composite = False

    def write(self, w: Writer, rows: Any) -> None:
        columns, context = tuple(w.values[-1]["described"]), {"collation": w.context.get("collation")}
        encode = _numbered(lambda row: _bulk_row(columns, row, context))
        if is_source(rows):
            w.context.setdefault("streams", []).append(Stream(w.pos, rows, encode, BULK_DONE, "rows", tuple(w.places)))
            return
        for row in rows:
            w.put(encode(row))
        w.put(BULK_DONE)

    def read(self, r) -> list:
        """For replaying a capture (D-12): the rows, decoded by the columns before them, up to the DONE. They are
        read as one field, as they are written."""
        from .tokens import RowValues
        from .wire import Reader

        inner = Reader(bytes(r.take(r.end - r.pos, "bulk rows")), False)
        inner.context["columns"] = r.values[-1]["columns"]
        rows = []
        while inner.peek() == 0xD1:
            inner.take(1, "ROW")
            rows.append(tuple(RowValues().read(inner)))
        inner.take(len(BULK_DONE), "DONE")
        return rows

    def show(self, rows: Any) -> str:
        return "rows from a source" if is_source(rows) else f"{len(rows)} rows" if hasattr(rows, "__len__") else "rows"


def _encrypted_column(rw) -> bool:
    return bool(rw.values[-1]["flags"] & ColumnFlags.ENCRYPTED)


BULK_COLUMN = Struct("column", [
    Field("user_type", U32),
    Field("flags", U16, enum=ColumnFlags),
    Field("type", _ColumnType()),
    Field("crypto", When(_encrypted_column, CRYPTO_METADATA)),  # for an encrypted column, as a result set describes it
    Field("name", Text(U8)),  # the server matches columns by position and ignores it, but refuses an empty name
], summary=lambda c: f"{c.name} {_ColumnType().show(c.type)}")

BULK_DATA = Struct("bulk data", [  # no headers
    Field("tag", U8, fmt=lambda v: "COLMETADATA"),
    Field("count", U16),
    Field("key_table", When(lambda rw: rw.context.get("column_encryption"), KEY_TABLE)),  # once column encryption
    # is agreed, every COLMETADATA has one, including the client's. It is empty when no column is encrypted (D-60)
    Field("columns", Repeat("count", BULK_COLUMN)),
    Field("rows", _Rows()),
], source="§2.2.6.1", summary=lambda b: f"{b.count} columns", where=lambda b: "the bulk data")


@dataclass(frozen=True, init=False)
class BulkRows:
    """The second half of a bulk load: the bulk data. It is the columns (COLMETADATA, its header), then the rows,
    then a DONE, in the layout that the server would use to send the same rows. The server answers with one DONE
    whose count is the number of rows loaded.

        columns = (await fetch(channel, "SELECT TOP 0 id, placed, total FROM shop.orders")).result_sets[0].columns
        BulkRows(columns, [(1, placed, Decimal("9.99")), …])        # or rows from an async source of tuples

    It must be the next request after a successful BulkInsert on the same serial channel. Otherwise the channel
    refuses it (OutOfTurn).

    The columns must describe exactly the columns BulkInsert's statement names: the same columns, in the same order,
    with the same types and nullability. The server matches them by position and refuses a mismatch, and the
    connection stays usable (errors 4804, 4815, 4816). The recommended way is to take them from `SELECT TOP 0 …` of
    the same columns, which gives them exactly as the server describes them, and to write the statement from the
    same columns. Some columns are sent as another type, which the application states in the column that it passes
    here (observed; Requests › Edge cases):
      - xml as nvarchar(max), and CLR types as varbinary(max). The statement may declare either type.
      - text, ntext and image as varchar(max), nvarchar(max) and varbinary(max), and json as nvarchar(max). The
        statement must declare that type too.
    A column is anything with name, type, flags and user_type, such as a result set's Column.

    An encrypted column (Always Encrypted, D-60) is named in the statement by its ciphertext's type
    (column.type.cipher, such as varbinary(81)), and its values are ciphertext, which tds.encryption makes.

    The rows are an iterable of tuples, or an async source of tuples sent as it produces them (D-41). Each value is
    checked against its column's type, as for a parameter (D-48). A row's values are sent whole. If a source fails
    while the bulk data is partly sent, the driver abandons it with the ignore flag, and the server loads nothing."""

    columns: tuple
    rows: Any

    kind = PacketType.BULK_LOAD
    label = "bulk data"
    metadata = ()
    continues = "bulk load"

    def __init__(self, columns: Any, rows: Any):
        object.__setattr__(self, "columns", tuple(columns))
        object.__setattr__(self, "rows", rows)

    def __str__(self) -> str:
        return f"the bulk data ({', '.join(f'{c.name} {c.type}' for c in self.columns)}; {_Rows().show(self.rows)})"

    def encode(self, context: Context, record: bool) -> Encoded:
        collation = Collation(context.collation) if context.collation else None
        keys: list = []  # the column keys the encrypted columns use: their ids, not their values (as SqlClient sends them)
        described = []
        for c in self.columns:
            column = {"user_type": c.user_type, "flags": c.flags, "type": c.type, "name": c.name, "crypto": None}
            if isinstance(c.type, Encrypted):
                if not context.column_encryption:
                    raise ValueRefused(f"{self}: column {c.name} is encrypted, but this connection's login didn't agree "
                                       "column encryption, so its bulk data can't describe it")
                key = c.type.key
                if key not in keys:
                    keys.append(key)
                column["flags"] = ColumnFlags(c.flags) | ColumnFlags.ENCRYPTED
                column["crypto"] = {"ordinal": keys.index(key), "user_type": c.type.base_user_type, "base": c.type.base,
                                    "algorithm": c.type.algorithm, "algorithm_name": c.type.algorithm_name,
                                    "encryption_type": c.type.encryption_type, "normalization": c.type.normalization}
            described.append(column)
        table = {"count": len(keys), "keys": [{"database_id": k.database_id, "key_id": k.key_id, "version": k.version,
                                               "metadata_version": k.metadata_version, "count": 0, "values": []}
                                              for k in keys]}
        values = {"tag": 0x81, "count": len(described), "columns": described, "described": self.columns,
                  "rows": self.rows, "key_table": table if context.column_encryption else None}
        streams: list = []
        body, node = BULK_DATA.encode(values, record, {"collation": collation, "streams": streams,
                                                       "column_encryption": context.column_encryption})
        return Encoded(body, node, tuple(streams))
