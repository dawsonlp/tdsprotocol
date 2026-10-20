"""Token stream: tokens one after another, each a 1-byte tag and a body. Each tag's definition says where it ends.

Reference: Token Stream; Login Response for the login tokens; Request Response for the rest. Checked against
MS-TDS v20260617, §2.2.4, §2.2.5.8, §2.2.7. It covers the tokens that a login reply and a request's response
carry. An unknown tag ends the connection, because without its length rule the rest can't be read.
"""

import enum

from .types import ColumnKey, Encrypted, EncryptionType, MasterKeyValue, SqlType, TypeInfo, Value, ValueOf
from .login7 import FeatureList, tds_version_name
from .wire import (Blob, Field, I32, MalformedMessage, OneOf, Prefixed, Raw, Reader, Record, Repeat, Struct, Text, Token,
                   TokenStream, Type, U8, U16, U16BE, U32, U32BE, U64, When)

SHORT_TEXT = Text(U8)  # a u8 character count, then UTF-16LE
LONG_TEXT = Text(U16)  # a u16 character count, then UTF-16LE
SHORT_BYTES = Blob(U8)  # a u8 byte count, then bytes


# --------------------------------------------------------------------------- ENVCHANGE: a session setting changed


class EnvKind(enum.IntEnum):
    DATABASE = 1
    LANGUAGE = 2
    PACKET_SIZE = 4  # the new size, written as decimal text
    COLLATION = 7
    BEGIN_TRANSACTION = 8
    COMMIT_TRANSACTION = 9
    ROLLBACK_TRANSACTION = 10
    ENLIST_DTC_TRANSACTION = 11  # the session joined a distributed transaction
    DEFECT_TRANSACTION = 12
    MIRRORING_PARTNER = 13
    PROMOTE_TRANSACTION = 15  # the answer to a promote request: the coordinator's token for the transaction
    TRANSACTION_MANAGER_ADDRESS = 16  # MS-TDS: not used
    TRANSACTION_ENDED = 17
    RESET_COMPLETE = 18
    USER_INSTANCE = 19  # the user instance a login started
    ROUTING = 20  # connect to another server instead


ROUTING = Prefixed(U16, Struct("routing", [
    Field("protocol", U8, fmt=lambda v: "TCP" if v == 0 else f"{v}"),
    Field("port", U16),
    Field("server", LONG_TEXT),
], summary=lambda r: f"{r.server}:{r.port}"))

TEXT_KINDS = (EnvKind.DATABASE, EnvKind.LANGUAGE, EnvKind.PACKET_SIZE, EnvKind.MIRRORING_PARTNER, EnvKind.USER_INSTANCE)
TRANSACTION_KINDS = (EnvKind.BEGIN_TRANSACTION, EnvKind.COMMIT_TRANSACTION, EnvKind.ROLLBACK_TRANSACTION,
                     EnvKind.ENLIST_DTC_TRANSACTION, EnvKind.DEFECT_TRANSACTION, EnvKind.TRANSACTION_ENDED)
BYTE_KINDS = (EnvKind.COLLATION, *TRANSACTION_KINDS, EnvKind.TRANSACTION_MANAGER_ADDRESS, EnvKind.RESET_COMPLETE)
NEW_VALUE = {**{k: SHORT_TEXT for k in TEXT_KINDS}, **{k: SHORT_BYTES for k in BYTE_KINDS}, EnvKind.ROUTING: ROUTING,
             EnvKind.PROMOTE_TRANSACTION: Blob(U32)}  # the token is opaque, and may be long
OLD_VALUE = {**{k: SHORT_TEXT for k in TEXT_KINDS}, **{k: SHORT_BYTES for k in BYTE_KINDS}, EnvKind.ROUTING: U16,
             EnvKind.PROMOTE_TRANSACTION: SHORT_BYTES}


def _show_change(e: Record) -> str:
    kind = e.kind.name.lower().replace("_", " ")
    if e.kind == EnvKind.ROUTING:
        return f"{kind} → {e.new.server}:{e.new.port}"
    if e.kind == EnvKind.RESET_COMPLETE:
        return "reset complete: back to the session login established"
    show = (lambda v: v) if e.kind in TEXT_KINDS else (lambda v: v.hex(" ").upper())
    return f"{kind} {show(e.old)} → {show(e.new)}" if e.old else f"{kind} → {show(e.new)}"


ENVCHANGE = Token(0xE3, "ENVCHANGE", length=U16, source="§2.2.7.9", body=Struct("ENVCHANGE", [
    Field("kind", U8, enum=EnvKind),
    Field("new", OneOf("kind", NEW_VALUE)),
    Field("old", OneOf("kind", OLD_VALUE)),
], summary=_show_change),
    # Observed: for a promoted transaction the length is 1, covering only the kind. The token (u32 length, then its
    # bytes) and the empty old value follow outside it. MS-TDS doesn't say so.
    beyond_length=lambda kind: kind == EnvKind.PROMOTE_TRANSACTION)


# --------------------------------------------------------------------------- INFO and ERROR: a message from the server


def _message(name: str) -> Struct:
    return Struct(name, [
        Field("number", I32),
        Field("state", U8),
        Field("severity", U8),  # MS-TDS: Class. Below 10 is informational.
        Field("message", LONG_TEXT),
        Field("server_name", SHORT_TEXT),
        Field("procedure", SHORT_TEXT),
        Field("line", I32),
    ], summary=lambda m: f"{m.number} · {m.message}")


INFO = Token(0xAB, "INFO", length=U16, source="§2.2.7.13", body=_message("INFO"))
ERROR = Token(0xAA, "ERROR", length=U16, source="§2.2.7.10", body=_message("ERROR"))


# --------------------------------------------------------------------------- LOGINACK: the login is accepted


class Interface(enum.IntEnum):
    DEFAULT = 0
    TSQL = 1


LOGINACK = Token(0xAD, "LOGINACK", length=U16, source="§2.2.7.14", body=Struct("LOGINACK", [
    Field("interface", U8, enum=Interface),
    Field("tds_version", U32BE, fmt=tds_version_name),
    Field("server_program", SHORT_TEXT),
    Field("server_version", Struct("server version", [
        Field("major", U8), Field("minor", U8), Field("build", U16BE),
    ], summary=lambda v: f"{v.major}.{v.minor}.{v.build}")),
], summary=lambda a: f"login accepted · {a.server_program.rstrip(chr(0))} · {tds_version_name(a.tds_version)}"))


FEATUREEXTACK = Token(0xAE, "FEATUREEXTACK", source="§2.2.7.11", body=Struct("FEATUREEXTACK", [  # walked: ends at FF
    Field("features", FeatureList()),
], summary=lambda a: "features accepted: " + (FeatureList().show(a.features) or "none")))


# --------------------------------------------------------------------------- DONE: the end of a result, or of the reply


class DoneStatus(enum.IntFlag):
    MORE = 0x01  # another DONE follows. When this bit is clear, the reply is complete
    ERROR = 0x02
    IN_TRANSACTION = 0x04
    COUNT = 0x10  # the row count is valid
    ATTENTION = 0x20  # acknowledges a cancel
    RPC_IN_BATCH = 0x80  # DONEPROC: this call is one of several in the request
    SERVER_ERROR = 0x100


def _done(tag: int, name: str, source: str) -> Token:
    return Token(tag, name, source=source, body=Struct(name, [  # fixed size: no length field
        Field("status", U16, enum=DoneStatus, fmt=lambda s: " · ".join(
            m.name.lower().replace("_", " ") for m in DoneStatus if m in s) or "final"),
        Field("current_command", U16),
        Field("row_count", U64),
    ], summary=lambda d: f"{'more follows' if DoneStatus.MORE in d.status else 'final'}"
                         f"{f' · {d.row_count} rows' if DoneStatus.COUNT in d.status else ''}"))


DONE = _done(0xFD, "DONE", "§2.2.7.6")
DONEPROC = _done(0xFE, "DONEPROC", "§2.2.7.8")
DONEINPROC = _done(0xFF, "DONEINPROC", "§2.2.7.7")


# --------------------------------------------------------------------------- COLMETADATA and ROW: a result's columns, then its rows


class ColumnFlags(enum.IntFlag):
    NULLABLE = 0x0001
    CASE_SENSITIVE = 0x0002
    IDENTITY = 0x0010
    COMPUTED = 0x0020
    FIXED_LENGTH_CLR_TYPE = 0x0100  # a CLR type whose values are all one size (.NET's Native format)
    ENCRYPTED = 0x0800  # Always Encrypted: crypto metadata follows the type, and values are ciphertext (D-60)


# --------------------------------------------------------------------------- Always Encrypted: the key table, and crypto metadata (D-60)
# These are present only once the login has agreed the column encryption feature (the context's column_encryption).

MASTER_KEY_VALUE = Struct("master key value", [  # EncryptionKeyValue (§2.2.5.7)
    Field("encrypted", Blob(U16)),
    Field("key_store", SHORT_TEXT),
    Field("key_path", LONG_TEXT),
    Field("algorithm", SHORT_TEXT),
], summary=lambda v: f"{v.key_store} “{v.key_path}” · {v.algorithm}")

COLUMN_KEY = Struct("column key", [  # EK_INFO (§2.2.5.7)
    Field("database_id", U32),
    Field("key_id", U32),
    Field("version", U32),
    Field("metadata_version", Raw(8)),
    Field("count", U8),
    Field("values", Repeat("count", MASTER_KEY_VALUE)),
], summary=lambda k: f"key {k.key_id} v{k.version} in database {k.database_id}")

KEY_TABLE = Struct("key table", [  # CekTable: the column keys this result's encrypted columns use
    Field("count", U16),
    Field("keys", Repeat("count", COLUMN_KEY)),
], summary=lambda t: f"{t.count} column key{'' if t.count == 1 else 's'}")


def _named_algorithm(rw) -> bool:
    return rw.values[-1]["algorithm"] == 0  # a custom algorithm: its name is sent


def _crypto(ordinal: bool) -> Struct:
    return Struct("crypto metadata", [  # CryptoMetaData (§2.2.7.4; RETURNVALUE's has no ordinal, §2.2.7.19)
        *([Field("ordinal", U16)] if ordinal else []),  # which column key in the key table, from 0
        Field("user_type", U32),
        Field("base", TypeInfo()),  # the plaintext's type
        Field("algorithm", U8, fmt=lambda v: {2: "AEAD_AES_256_CBC_HMAC_SHA256", 0: "named"}.get(v, f"algorithm {v}")),
        Field("algorithm_name", When(_named_algorithm, SHORT_TEXT)),
        Field("encryption_type", U8, enum=EncryptionType),
        Field("normalization", U8),
    ], summary=lambda c: f"{c.base} · {getattr(c.encryption_type, 'name', c.encryption_type)}".lower())


CRYPTO_METADATA, RETURN_CRYPTO_METADATA = _crypto(True), _crypto(False)


def _is_encrypted(rw) -> bool:
    return bool(rw.values[-1]["flags"] & ColumnFlags.ENCRYPTED)


def column_key(record: Record) -> ColumnKey:
    return ColumnKey(record.database_id, record.key_id, record.version, record.metadata_version,
                     tuple(MasterKeyValue(v.encrypted, v.key_store, v.key_path, v.algorithm) for v in record["values"]))


def encrypted(cipher: SqlType, crypto: Record, key: ColumnKey | None, decrypt=None,
              parameter: str | int | None = None) -> Encrypted:
    """The type of an encrypted column or output parameter, from its ciphertext's type and its crypto metadata."""
    return Encrypted(cipher, crypto.base, crypto.encryption_type, crypto.algorithm, crypto.algorithm_name,
                     crypto.normalization, crypto.user_type, key, parameter, decrypt)


class _Column(Struct):
    """A column. An encrypted column's type becomes Encrypted, which holds its ciphertext's type, its crypto metadata,
    its column key from the key table, and the exchange's decrypt hook, if the exchange was given one (D-60)."""

    def read(self, r: Reader) -> Record:
        rec = super().read(r)
        if rec.get("crypto") is not None:
            table = r.values[-1].get("key_table")
            keys = table["keys"] if table else []
            if rec.crypto.ordinal >= len(keys):
                raise MalformedMessage(f"column {rec.name} uses column key {rec.crypto.ordinal}, but the key table "
                                       f"holds {len(keys)}", r.pos, r.tree)
            rec["type"] = encrypted(rec.type, rec.crypto, column_key(keys[rec.crypto.ordinal]), r.context.get("decrypt"))
        return rec


COLUMN = _Column("column", [
    Field("user_type", U32),
    Field("flags", U16, enum=ColumnFlags),
    Field("type", TypeInfo()),  # for an encrypted column, its ciphertext's type, varbinary
    Field("crypto", When(_is_encrypted, CRYPTO_METADATA)),
    Field("name", SHORT_TEXT),
], summary=lambda c: f"{c.name or '(no name)'} {c.type}")


def _key_table(rw) -> bool:
    return bool(rw.context.get("column_encryption"))


COLMETADATA = Token(0x81, "COLMETADATA", remember="columns", source="§2.2.7.4", body=Struct("COLMETADATA", [
    Field("count", U16),
    Field("key_table", When(_key_table, KEY_TABLE)),  # always sent once column encryption is agreed, even if empty
    Field("columns", Repeat("count", COLUMN, none=0xFFFF)),  # 0xFFFF: no columns follow
], summary=lambda m: ", ".join(f"{c.name or '(no name)'} {c.type}" for c in m.columns)))


class RowValues(Type):
    """A row has no length of its own: its layout is the most recent COLMETADATA's columns, in order."""

    composite = True

    def read(self, r: Reader) -> list:
        columns = r.context.get("columns")
        if columns is None:
            raise MalformedMessage("a ROW arrived before any COLMETADATA described its columns", r.pos, r.tree)
        return [r.read(Field(c.name or f"column {i + 1}", Value(c.type))) for i, c in enumerate(columns)]

    def show(self, values: list) -> str:
        return " · ".join(Value(None).show(v) for v in values)


ROW = Token(0xD1, "ROW", source="§2.2.7.20", body=Struct("ROW", [Field("values", RowValues())],
                                                        summary=lambda r: RowValues().show(r["values"])))


class NullBitmapRowValues(Type):
    """NBCROW: first a bitmap with one bit per column (1 = NULL), then the values of the columns that aren't NULL.
    The server chooses it over ROW when it is shorter."""

    composite = True

    def read(self, r: Reader) -> list:
        columns = r.context.get("columns")
        if columns is None:
            raise MalformedMessage("an NBCROW arrived before any COLMETADATA described its columns", r.pos, r.tree)
        bitmap = r.read(Field("null bitmap", Raw((len(columns) + 7) // 8)))
        return [None if bitmap[i // 8] >> (i % 8) & 1 else r.read(Field(c.name or f"column {i + 1}", Value(c.type)))
                for i, c in enumerate(columns)]

    def show(self, values: list) -> str:
        return RowValues().show(values)


NBCROW = Token(0xD2, "NBCROW", source="§2.2.7.15", body=Struct("NBCROW", [Field("values", NullBitmapRowValues())],
                                                              summary=lambda r: RowValues().show(r["values"])))

ORDER = Token(0xA9, "ORDER", length=U16, source="§2.2.7.17", body=Struct("ORDER", [
    Field("columns", Repeat(None, U16)),  # the result set's sort columns, numbered from 1
], summary=lambda o: "sorted on column" + ("s " if len(o.columns) != 1 else " ") + ", ".join(map(str, o.columns))))


# --------------------------------------------------------------------------- RETURNSTATUS and RETURNVALUE: what a procedure call returns


RETURNSTATUS = Token(0x79, "RETURNSTATUS", source="§2.2.7.18", body=Struct("RETURNSTATUS", [  # fixed size: 4 bytes
    Field("value", I32),
], summary=lambda s: f"return status {s.value}"))


class ReturnValueStatus(enum.IntEnum):
    OUTPUT = 0x01  # an output parameter's value
    FUNCTION_RESULT = 0x02  # the result of a user-defined function called as an RPC


class _ReturnedValue(Type):
    """An output parameter's value, read by its type. An encrypted one is read by an Encrypted type made from its
    crypto metadata. That type has no column key, because the call's own parameters say which key it is (D-60)."""

    def resolve(self, rw) -> Type:
        rec = rw.values[-1]
        if rec.get("crypto") is not None:
            rec["type"] = encrypted(rec["type"], rec["crypto"], None, rw.context.get("decrypt"),
                                    rec["name"] or rec["ordinal"])  # a positional parameter has no name
        return Value(rec["type"])


RETURNVALUE = Token(0xAC, "RETURNVALUE", source="§2.2.7.19", body=Struct("RETURNVALUE", [  # walked: no length field
    Field("ordinal", U16),  # the parameter's position in the call, from 0
    Field("name", SHORT_TEXT),
    Field("status", U8, enum=ReturnValueStatus),
    Field("user_type", U32),
    Field("flags", U16, enum=ColumnFlags),
    Field("type", TypeInfo()),
    Field("crypto", When(_is_encrypted, RETURN_CRYPTO_METADATA)),
    Field("value", _ReturnedValue()),
], summary=lambda v: f"{v.name or f'parameter {v.ordinal}'} = {Value(None).show(v.value)}"))


# --------------------------------------------------------------------------- browse mode: where each column came from


TABLE_NAME = Struct("table", [
    Field("parts", U8),
    Field("names", Repeat("parts", LONG_TEXT)),  # for example, "shop", "orders"
], summary=lambda t: ".".join(t.names))

TABNAME = Token(0xA4, "TABNAME", length=U16, source="§2.2.7.23", body=Struct("TABNAME", [
    Field("tables", Repeat(None, TABLE_NAME)),  # the base tables, numbered from 1 by COLINFO
], summary=lambda t: ", ".join(TABLE_NAME.show(x) for x in t.tables)))


class ColumnInfoStatus(enum.IntFlag):
    EXPRESSION = 0x04  # computed by an expression: no base table
    KEY = 0x08  # part of a key of its table
    HIDDEN = 0x10  # not asked for: added because it is part of a key
    DIFFERENT_NAME = 0x20  # an alias: the base column's name follows


COLUMN_INFO = Struct("column", [
    Field("column", U8),  # its number in the result set, from 1
    Field("table", U8),  # its table in TABNAME, from 1; 0 for an expression
    Field("status", U8, enum=ColumnInfoStatus),
    Field("base_name", When(lambda r: ColumnInfoStatus.DIFFERENT_NAME in ColumnInfoStatus(r.values[-1]["status"]),
                            SHORT_TEXT)),
], summary=lambda c: f"column {c.column}: table {c.table}" + (f", base column {c.base_name}" if c.base_name else ""))

COLINFO = Token(0xA5, "COLINFO", length=U16, source="§2.2.7.3", body=Struct("COLINFO", [
    Field("columns", Repeat(None, COLUMN_INFO)),
], summary=lambda c: f"{len(c.columns)} columns"))


# --------------------------------------------------------------------------- data classification (asked for at login)


def _ranked(r) -> bool:
    """Sensitivity ranks are sent from data classification version 2, as the login acknowledged it."""
    return r.context.get("data_classification_version", 1) >= 2


LABEL = Struct("label", [Field("name", SHORT_TEXT), Field("id", SHORT_TEXT)], summary=lambda l: l.name)
SENSITIVITY = Struct("sensitivity", [
    Field("label", U16),  # index into the labels, or FFFF for none
    Field("information_type", U16),  # index into the information types, or FFFF for none
    Field("rank", When(_ranked, I32)),
])
COLUMN_SENSITIVITY = Struct("column", [
    Field("count", U16),
    Field("sensitivities", Repeat("count", SENSITIVITY)),
])

DATACLASSIFICATION = Token(0xA3, "DATACLASSIFICATION", source="§2.2.7.5", body=Struct("DATACLASSIFICATION", [  # walked
    Field("label_count", U16),
    Field("labels", Repeat("label_count", LABEL)),
    Field("type_count", U16),
    Field("information_types", Repeat("type_count", LABEL)),
    Field("rank", When(_ranked, I32)),  # the result set's own
    Field("column_count", U16),  # 0: no detail per column
    Field("columns", Repeat("column_count", COLUMN_SENSITIVITY)),
], summary=lambda d: f"{len(d.labels)} labels, {len(d.information_types)} information types"))


# --------------------------------------------------------------------------- COMPUTE totals (deprecated in 7.4)


class Aggregate(enum.IntEnum):
    STDEV = 0x30
    STDEVP = 0x31
    VAR = 0x32
    VARP = 0x33
    COUNT = 0x4B
    SUM = 0x4D
    AVG = 0x4F
    MIN = 0x51
    MAX = 0x52


COMPUTED_COLUMN = Struct("computed column", [
    Field("aggregate", U8, enum=Aggregate),
    Field("operand", U16),  # the result-set column it totals, from 1
    Field("user_type", U32),
    Field("flags", U16, enum=ColumnFlags),
    Field("type", TypeInfo()),  # for text, ntext and image, this includes the table name
    Field("name", SHORT_TEXT),
], summary=lambda c: f"{c.aggregate.name if isinstance(c.aggregate, Aggregate) else c.aggregate}(column {c.operand})")

ALTMETADATA = Token(0x88, "ALTMETADATA", source="§2.2.7.1", body=Struct("ALTMETADATA", [  # walked
    Field("count", U16),
    Field("id", U16),  # which COMPUTE clause. ALTROW names it by this id
    Field("by_count", U8),
    Field("by", Repeat("by_count", U16)),  # the grouping columns, from 1
    Field("columns", Repeat("count", COMPUTED_COLUMN)),
], summary=lambda m: f"totals {m.id}: " + ", ".join(COMPUTED_COLUMN.show(c) for c in m.columns)))


class AltRowValues(Type):
    """An ALTROW's values, laid out as the ALTMETADATA with its id describes them."""

    composite = True

    def read(self, r: Reader) -> list:
        computed = r.context.get("computed", {}).get(r.values[-1]["id"])
        if computed is None:
            raise MalformedMessage(f"an ALTROW for totals {r.values[-1]['id']} arrived before its ALTMETADATA", r.pos, r.tree)
        return [r.read(Field(c.name or f"total {i + 1}", Value(c.type))) for i, c in enumerate(computed)]

    def show(self, values: list) -> str:
        return RowValues().show(values)


ALTROW = Token(0xD3, "ALTROW", source="§2.2.7.2", body=Struct("ALTROW", [
    Field("id", U16),
    Field("values", AltRowValues()),
], summary=lambda r: f"totals {r.id}: {AltRowValues().show(r['values'])}"))


# --------------------------------------------------------------------------- session state (asked for at login)


class StateLength(Type):
    """A session state's value: its length in one byte, or FF and four more bytes, then the value."""

    def read(self, r: Reader) -> bytes:
        n = U8.read(r)
        if n == 0xFF:
            n = U32.read(r)
        return bytes(r.take(n, "state value"))

    def write(self, w, value: bytes) -> None:
        w.put((bytes([len(value)]) if len(value) < 0xFF else b"\xff" + len(value).to_bytes(4, "little")) + value)

    def show(self, value: bytes) -> str:
        return f"{len(value)} bytes"


class SessionStateStatus(enum.IntFlag):
    RECOVERABLE = 0x01  # every state in this token can be recovered


SESSION_STATE = Struct("state", [Field("id", U8), Field("value", StateLength())], summary=lambda s: f"state {s.id}")

SESSIONSTATE = Token(0xE4, "SESSIONSTATE", length=U32, source="§2.2.7.21", body=Struct("SESSIONSTATE", [
    Field("sequence", U32),  # from 0, increased by one each time
    Field("status", U8, enum=SessionStateStatus),
    Field("states", Repeat(None, SESSION_STATE)),
], summary=lambda s: f"session state {s.sequence}: {len(s.states)} states"))


# --------------------------------------------------------------------------- login tokens for other logins (M17)


SSPI = Token(0xED, "SSPI", length=U16, source="§2.2.7.22", body=Struct("SSPI", [
    Field("buffer", Raw()),  # the server's next security token, for the client's security library
], summary=lambda s: f"{len(s.buffer)} bytes"))


class FedAuthInfoId(enum.IntEnum):
    STS_URL = 0x01  # where to get a token
    SPN = 0x02  # the resource to ask for


FEDAUTHINFO_OPTION = Struct("option", [
    Field("id", U8, enum=FedAuthInfoId),
    Field("length", U32),
    Field("offset", U32),  # from the start of the option count
])


def _fed_auth_info(f) -> dict:
    """Each option's data, as UTF-16 text. The offsets count from the option count, which comes before the options.

    Strict (PY-AZ-01, owner decision 2026-10-20): each option lies inside the token, has an even length and valid
    UTF-16, and appears once, and the SPN is present. Azure's real FEDAUTHINFO meets all of these (observed
    2026-10-20); a token that doesn't raises ValueError, naming the problem."""
    start = 4 + 9 * len(f.options)
    out = {}
    for o in f.options:
        begin = o.offset - start
        if o.id in out:
            raise ValueError(f"option {o.id} appears twice")
        if begin < 0 or begin + o.length > len(f.data):
            raise ValueError(f"option {o.id} lies outside the token")
        if o.length % 2:
            raise ValueError(f"option {o.id} has an odd length, not UTF-16")
        try:
            out[o.id] = f.data[begin:begin + o.length].decode("utf-16-le")
        except UnicodeDecodeError:
            raise ValueError(f"option {o.id} is not valid UTF-16") from None
    if FedAuthInfoId.SPN not in out:
        raise ValueError("it names no SPN (option 2)")
    return out


def _fed_auth_info_summary(f) -> str:
    try:
        return ", ".join(f"{k.name.lower() if hasattr(k, 'name') else k}: {v}" for k, v in _fed_auth_info(f).items())
    except ValueError as e:
        return f"malformed: {e}"


FEDAUTHINFO = Token(0xEE, "FEDAUTHINFO", length=U32, source="§2.2.7.12", body=Struct("FEDAUTHINFO", [
    Field("count", U32),
    Field("options", Repeat("count", FEDAUTHINFO_OPTION)),
    Field("data", Raw()),
], summary=_fed_auth_info_summary))


TOKENS = TokenStream([ENVCHANGE, INFO, ERROR, LOGINACK, FEATUREEXTACK, DONE, DONEPROC, DONEINPROC, COLMETADATA, ORDER,
                      ROW, NBCROW, RETURNSTATUS, RETURNVALUE, TABNAME, COLINFO, DATACLASSIFICATION, ALTMETADATA, ALTROW,
                      SESSIONSTATE, SSPI, FEDAUTHINFO])
