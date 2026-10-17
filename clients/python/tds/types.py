"""Data types: the vocabulary of SQL Server types (`tds.types`), how each is described on the wire (TYPE_INFO), how its
values are laid out, and how a value is checked before it is sent.

Reference: Data Types. Checked against MS-TDS v20260617, §2.2.5.4–§2.2.5.6. Decisions: D-40 (one vocabulary, for
parameters and columns alike), D-43 (every type, in milestones), D-44 (collations), D-48 (every value round-trips
exactly, a Python type is used only where it holds every value, and a value is refused rather than rounded).

    types.int · types.decimal(10, 2) · types.nvarchar(50) · types.varchar(20, collation=…) · types.datetime2(7)

A column's type arrives as the same objects, so a value read from a column can be sent back with `column.type`. This
module covers every type: the short types (M2), large values (M4), sql_variant (M5), json and vector (M6), CLR types
(M7) and table-valued parameters (M8). Large values are the (max) types, xml, text, ntext and image. They are read whole
or as they arrive (D-47), and sent whole or from a source (D-41).
"""

import builtins
import codecs
import datetime as dt
import enum
import math
import struct
import uuid
from dataclasses import dataclass, field
from decimal import Decimal as PyDecimal
from typing import Any, Callable

from . import collations
from .wire import Field, MalformedMessage, Raw, Reader, Type, U8, U16, U32, Writer
from .wire import Text as WireText


class ValueRefused(ValueError):
    """A value doesn't fit its declared type exactly. Nothing is rounded, truncated or replaced (D-48).

    Its message says where the value was, because each layer that the error passes through adds its place (D-53).
    For example:
    "the call to shop.update_prices › parameter @changes › row 3 › column 2: 123456789.5 doesn't fit decimal(10, 2)"."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason, self.path = reason, []

    def within(self, place: str) -> None:
        """Records that the value was in `place`, which contains the places already known."""
        self.path.insert(0, place)
        self.args = (f"{' › '.join(self.path)}: {self.reason}",)


# =========================================================================== the type codes (MS-TDS §2.2.5.4)


class TypeCode(enum.IntEnum):
    # fixed size: the code alone says how many bytes a value takes. These are used for NOT NULL columns
    TINYINT = 0x30
    BIT = 0x32
    SMALLINT = 0x34
    INT = 0x38
    SMALLDATETIME = 0x3A
    REAL = 0x3B
    MONEY = 0x3C
    DATETIME = 0x3D
    FLOAT = 0x3E
    SMALLMONEY = 0x7A
    BIGINT = 0x7F
    # with a length: the nullable forms. Every parameter uses these
    INTN = 0x26
    BITN = 0x68
    DECIMALN = 0x6A
    NUMERICN = 0x6C
    FLTN = 0x6D
    MONEYN = 0x6E
    DATETIMN = 0x6F
    GUID = 0x24
    DATE = 0x28
    TIME = 0x29
    DATETIME2 = 0x2A
    DATETIMEOFFSET = 0x2B
    BIGVARBINARY = 0xA5
    BIGVARCHAR = 0xA7
    BIGBINARY = 0xAD
    BIGCHAR = 0xAF
    NVARCHAR = 0xE7
    NCHAR = 0xEF
    # added in later milestones (D-46)
    XML = 0xF1
    UDT = 0xF0
    TEXT = 0x23
    IMAGE = 0x22
    NTEXT = 0x63
    SQL_VARIANT = 0x62
    JSON = 0xF4
    VECTOR = 0xF5
    TVP = 0xF3  # parameters only
    # legacy: MS-TDS keeps these for old clients. SQL Server sends the modern codes (D-43)
    LEGACY_DECIMAL = 0x37
    LEGACY_NUMERIC = 0x3F
    LEGACY_CHAR = 0x2F
    LEGACY_VARCHAR = 0x27
    LEGACY_BINARY = 0x2D
    LEGACY_VARBINARY = 0x25
    NULL = 0x1F


MAX_LENGTH = 0xFFFF  # a max length that means (max). Values then come as PLP, in chunks
NULL_LENGTH = 0xFFFF  # a u16 value length meaning NULL
PLP_NULL = 0xFFFF_FFFF_FFFF_FFFF  # a PLP total length meaning NULL
PLP_UNKNOWN = 0xFFFF_FFFF_FFFF_FFFE  # a PLP total length that means "not known yet". The chunks give the length
LARGEST = 2**31 - 1  # the most bytes a large value can hold


class _Max:
    """types.MAX: the (max) in varbinary(max), nvarchar(max), varchar(max)."""

    def __repr__(self) -> str:
        return "types.MAX"

    def __str__(self) -> str:
        return "max"


MAX = _Max()


def is_source(value: Any) -> bool:
    """True if `value` is a source: an async iterator that the driver sends from while it produces (D-41)."""
    return hasattr(value, "__anext__")


# =========================================================================== collations (D-44)


class CollationFlags(enum.IntFlag):
    IGNORE_CASE = 0x01
    IGNORE_ACCENT = 0x02
    IGNORE_WIDTH = 0x04
    IGNORE_KANA = 0x08
    BINARY = 0x10
    BINARY2 = 0x20
    UTF8 = 0x40


class UnknownCollation(ValueError):
    """A collation that is missing from tds/collations.py. To add its row, regenerate the file (D-44)."""


@dataclass(frozen=True)
class Collation:
    """Five bytes: a locale id (20 bits), flags (8), a version (4), then a sort id (8). They decide the code page of a
    varchar's bytes. The code page is UTF-8 if the UTF-8 flag is set. Otherwise a SQL collation (sort id not 0) uses
    its sort id's code page, and any other collation uses its locale's."""

    raw: bytes

    @property
    def _bits(self) -> int:
        return builtins.int.from_bytes(self.raw[:4], "little")

    @property
    def locale(self) -> int:
        return self._bits & 0xFFFFF

    @property
    def flags(self) -> CollationFlags:
        return CollationFlags((self._bits >> 20) & 0xFF)

    @property
    def version(self) -> int:
        return self._bits >> 28

    @property
    def sort_id(self) -> int:
        return self.raw[4]

    @property
    def code_page(self) -> int:
        if CollationFlags.UTF8 in self.flags:
            return 65001
        table, key = ((collations.SORT_CODE_PAGES, self.sort_id) if self.sort_id
                      else (collations.LOCALE_CODE_PAGES, self.locale))
        if key not in table:
            raise UnknownCollation(f"collation {self.raw.hex(' ')} (locale id {self.locale:#06x}, sort id {self.sort_id}) "
                                   f"isn't in tds/collations.py, generated from SQL Server {collations.SERVER}. "
                                   "Regenerate it with tools/generate_collations.py against a server that knows it.")
        return table[key]

    def decode(self, data: bytes) -> str:
        """The characters SQL Server reads in these bytes (D-44). Some bytes SQL Server holds but reads as no character,
        and would write back the same. Those bytes are carried as escapes (U+DC80–U+DCFF), so they are sent back
        unchanged (D-48)."""
        if self.code_page == 0:
            raise MalformedMessage(f"a varchar value under a Unicode-only collation ({self})", 0)
        return code_page(self.code_page).decode(data)

    def decoder(self):
        """An incremental decoder, for text that arrives in pieces (D-47)."""
        if self.code_page == 0:
            raise MalformedMessage(f"a varchar value under a Unicode-only collation ({self})", 0)
        return code_page(self.code_page).decoder()

    def encode(self, text: str) -> bytes:
        """The bytes SQL Server writes for these characters. A character the code page can't hold is refused (D-48)."""
        if self.code_page == 0:
            raise ValueRefused(f"collation {self} is Unicode only: it holds no varchar text")
        return code_page(self.code_page).encode(text)

    def __str__(self) -> str:
        return self.raw.hex(" ")


def _escape(byte: int) -> str:
    return chr(0xDC00 + byte)


def _escaped(char: str) -> int | None:
    return ord(char) - 0xDC00 if 0xDC00 <= ord(char) <= 0xDCFF else None


class CodePage:
    """One code page as SQL Server reads and writes it. It is Python's codec for the same number, corrected by the
    tables generated from the server (collations.py)."""

    def __init__(self, page: builtins.int):
        self.page, self.python = page, f"cp{page}"
        self.leads = {b for first, last in collations.LEAD_BYTES.get(page, []) for b in range(first, last + 1)}
        self.reads: dict[bytes, str] = {}
        for first, count, first_char in collations.SERVER_CHARACTERS.get(page, []):
            start, size = builtins.int(first, 16), len(first) // 2
            for i in range(count):
                self.reads[(start + i).to_bytes(size, "big")] = chr(first_char + i)
        self.escaped = {bytes.fromhex(h) for line in collations.ESCAPED.get(page, []) for h in line.split()}
        self.writes = {char: data for data, char in self.reads.items()}
        for first_char, count, first in collations.SERVER_BYTES.get(page, []):
            start, size = builtins.int(first, 16), len(first) // 2
            for i in range(count):
                self.writes[chr(first_char + i)] = (start + i).to_bytes(size, "big")
        if not self.leads:  # one byte per character: a 256-character table, and Python's fast charmap codec
            self.table = "".join(self._single(bytes([b])) for b in range(256))
            self.map = codecs.charmap_build(self.table)

    def _single(self, data: bytes) -> str:
        if data in self.reads:
            return self.reads[data]
        if data in self.escaped:
            return _escape(data[0])
        try:
            return data.decode(self.python)
        except UnicodeDecodeError:
            return _escape(data[0])

    def decode(self, data: bytes) -> str:
        return self.decode_part(data, final=True)[0]

    def decode_part(self, data: bytes, final: bool) -> tuple[str, builtins.int]:
        """Decodes what can be decoded. Unless `final` is true, a lead byte at the very end waits for its second byte.
        Returns the text and how many bytes it used."""
        if not self.leads:
            return codecs.charmap_decode(data, "strict", self.table)[0], len(data)
        out, i, n = [], 0, len(data)
        while i < n:
            if data[i] in self.leads and i + 1 == n and not final:
                break
            if data[i] in self.leads and i + 1 < n:
                pair = bytes(data[i : i + 2])
                if pair in self.reads:
                    out.append(self.reads[pair])
                    i += 2
                    continue
                if pair in self.escaped:
                    out += [_escape(pair[0]), _escape(pair[1])]
                    i += 2
                    continue
                try:
                    char = pair.decode(self.python)
                except UnicodeDecodeError:
                    char = ""
                if len(char) == 1:
                    out.append(char)
                    i += 2
                    continue
            out.append(_escape(data[i]) if data[i] in self.leads else self._single(bytes(data[i : i + 1])))
            i += 1
        return "".join(out), i

    def decoder(self) -> _HoldingDecoder:
        return _HoldingDecoder(self)

    def encode(self, text: str) -> bytes:
        if not self.leads:
            try:
                return codecs.charmap_encode(text, "strict", self.map)[0]
            except UnicodeEncodeError as e:
                raise ValueRefused(self._refusal(text[e.start])) from None
        out = bytearray()
        for char in text:
            if char in self.writes:
                out += self.writes[char]
            elif (byte := _escaped(char)) is not None:
                out.append(byte)
            else:
                try:
                    data = char.encode(self.python)
                except UnicodeEncodeError:
                    raise ValueRefused(self._refusal(char)) from None
                if self.decode(data) != char:  # SQL Server would read those bytes as something else
                    raise ValueRefused(self._refusal(char))
                out += data
        return bytes(out)

    def _refusal(self, char: str) -> str:
        return f"code page {self.page} can't hold {char!r} (U+{ord(char):04X}) as SQL Server reads it"


class Utf8:
    """UTF-8 collations. SQL Server refuses some invalid UTF-8, but stores some (0xFF, encoded surrogates, code points
    past U+10FFFF). It sends those with U+FFFD in their place (observed without the UTF-8 login feature), so such values
    can't come back exactly. Bytes that Python refuses are still carried as escapes, in case a server sends them."""

    page = 65001

    def decode(self, data: bytes) -> str:
        return data.decode("utf-8", "surrogateescape")

    def decoder(self):
        return codecs.getincrementaldecoder("utf-8")("surrogateescape")

    def encode(self, text: str) -> bytes:
        try:
            return text.encode("utf-8", "surrogateescape")
        except UnicodeEncodeError as e:
            raise ValueRefused(f"UTF-8 can't hold {text[e.start]!r} (U+{ord(text[e.start]):04X})") from None


class _HoldingDecoder:
    """Decodes text that arrives in pieces, and never splits a character. A lead byte at the end of a piece waits."""

    def __init__(self, page: CodePage):
        self.page, self.held = page, b""

    def decode(self, data: bytes, final: bool = False) -> str:
        data, self.held = self.held + bytes(data), b""
        text, used = self.page.decode_part(data, final)
        self.held = data[used:]
        return text


_CODE_PAGES: dict[builtins.int, CodePage | Utf8] = {}


def code_page(page: builtins.int) -> CodePage | Utf8:
    if page not in _CODE_PAGES:
        _CODE_PAGES[page] = Utf8() if page == 65001 else CodePage(page)
    return _CODE_PAGES[page]


# =========================================================================== times Python can't hold exactly (D-48)


TICKS = 10_000_000  # 100-nanosecond ticks per second, the finest precision SQL Server keeps
DAY = 86_400 * TICKS


def _clock(ticks: int, digits: int = 7) -> str:
    seconds, fraction = divmod(ticks, TICKS)
    h, rest = divmod(seconds, 3600)
    return f"{h:02}:{rest // 60:02}:{rest % 60:02}" + (f".{fraction:07}"[: digits + 1] if digits else "")


def _python_time(ticks: int, round_to_microseconds: bool) -> dt.time:
    if ticks % 10 and not round_to_microseconds:
        raise ValueRefused(f"{_clock(ticks)} is finer than Python's microseconds; pass round_to_microseconds=True to round")
    micro = min(round(ticks / 10), DAY // 10 - 1)
    return (dt.datetime.min + dt.timedelta(microseconds=micro)).time()


def _ticks_of(t: dt.time) -> int:
    if t.tzinfo is not None:
        raise ValueRefused("a time of day with a time zone: SQL Server's time has none")
    return ((t.hour * 60 + t.minute) * 60 + t.second) * TICKS + t.microsecond * 10


@dataclass(frozen=True, order=True)
class SqlTime:
    """A time of day exactly as SQL Server holds it: 100-nanosecond ticks since midnight."""

    ticks: int

    @classmethod
    def from_python(cls, t: dt.time) -> SqlTime:
        return cls(_ticks_of(t))

    def to_python(self, round_to_microseconds: bool = False) -> dt.time:
        return _python_time(self.ticks, round_to_microseconds)

    def __str__(self) -> str:
        return _clock(self.ticks)


@dataclass(frozen=True, order=True)
class SqlDateTime2:
    """A date and time exactly as SQL Server holds it: a date, and 100-nanosecond ticks since its midnight."""

    date: dt.date
    ticks: int

    @classmethod
    def from_python(cls, value: dt.datetime) -> SqlDateTime2:
        if value.tzinfo is not None:
            raise ValueRefused("a datetime with a time zone: datetime2 has none (datetimeoffset does)")
        return cls(value.date(), _ticks_of(value.time()))

    def to_python(self, round_to_microseconds: bool = False) -> dt.datetime:
        return dt.datetime.combine(self.date, _python_time(self.ticks, round_to_microseconds))

    def __str__(self) -> str:
        return f"{self.date.isoformat()} {_clock(self.ticks)}"


@dataclass(frozen=True)
class SqlDateTimeOffset:
    """An instant exactly as SQL Server holds it: the UTC date and 100-nanosecond ticks, and the offset in minutes that
    the value was given in. Two values are equal only if all three are equal. SQL Server compares the instant, but
    keeps the offset."""

    utc_date: dt.date
    utc_ticks: int
    offset_minutes: int

    @classmethod
    def from_python(cls, value: dt.datetime) -> SqlDateTimeOffset:
        offset = value.utcoffset()
        if offset is None:
            raise ValueRefused("a datetime without a time zone: datetimeoffset needs its offset")
        minutes, rest = divmod(offset, dt.timedelta(minutes=1))
        if rest or not -840 <= minutes <= 840:
            raise ValueRefused(f"offset {offset}: datetimeoffset holds whole minutes, from -14:00 to +14:00")
        utc = value.replace(tzinfo=None) - offset
        return cls(utc.date(), _ticks_of(utc.time()), minutes)

    @property
    def local(self) -> SqlDateTime2:
        days, ticks = divmod(self.utc_ticks + self.offset_minutes * 60 * TICKS, DAY)
        return SqlDateTime2(self.utc_date + dt.timedelta(days=days), ticks)

    def to_python(self, round_to_microseconds: bool = False) -> dt.datetime:
        zone = dt.timezone(dt.timedelta(minutes=self.offset_minutes))
        return self.local.to_python(round_to_microseconds).replace(tzinfo=zone)

    def __str__(self) -> str:
        sign, minutes = ("-" if self.offset_minutes < 0 else "+"), abs(self.offset_minutes)
        return f"{self.local} {sign}{minutes // 60:02}:{minutes % 60:02}"


DATETIME_EPOCH = dt.date(1900, 1, 1)


@dataclass(frozen=True, order=True)
class SqlDateTime:
    """A datetime exactly as SQL Server holds it: days since 1900-01-01 (negative for dates back to 1753), and
    1/300-second ticks since midnight, which microseconds can't represent exactly."""

    days: int
    ticks: int  # 300 per second

    @classmethod
    def from_python(cls, value: dt.datetime) -> SqlDateTime:
        if value.tzinfo is not None:
            raise ValueRefused("a datetime with a time zone: datetime has none")
        micro = (value - dt.datetime.combine(value.date(), dt.time())) // dt.timedelta(microseconds=1)
        if micro * 3 % 10_000:
            raise ValueRefused(f"{value.time()} isn't a whole number of 1/300 seconds; use SqlDateTime to give exact ticks")
        return cls((value.date() - DATETIME_EPOCH).days, micro * 3 // 10_000)

    def to_python(self, round_to_microseconds: bool = False) -> dt.datetime:
        if self.ticks % 3 and not round_to_microseconds:
            raise ValueRefused(f"{self} is a third of a millisecond Python can't hold; pass round_to_microseconds=True")
        return (dt.datetime.combine(DATETIME_EPOCH, dt.time()) + dt.timedelta(days=self.days)
                + dt.timedelta(microseconds=round(self.ticks * 10_000 / 3)))

    def __str__(self) -> str:
        date = DATETIME_EPOCH + dt.timedelta(days=self.days)
        seconds, part = divmod(self.ticks, 300)
        return f"{date.isoformat()} {_clock(seconds * TICKS, 0)} + {part}/300 s"


# =========================================================================== large values, as they arrive (D-47)


class PlpValue:
    """A PLP value (partially length-prefixed), read as it arrives. It is an 8-byte total length, then chunks until a
    chunk of length 0. Each chunk is a 4-byte length and its bytes. A total length of all ones means NULL, and all ones
    minus one means unknown. MS-TDS §2.2.5.2.3."""

    def __init__(self):
        self.stage, self.total, self.null, self.done = "total", None, False, False
        self.chunks = self.size = self.left = 0
        self.first = b""  # the first bytes, for observability

    def read(self, data: memoryview, at: builtins.int) -> tuple[builtins.int, list[bytes]]:
        """Reads what has arrived in data[at:]. Returns where it stopped, and the value's bytes that it found."""
        pieces = []
        while not self.done:
            room = len(data) - at
            if self.stage == "total":
                if room < 8:
                    break
                total, at = builtins.int.from_bytes(data[at : at + 8], "little"), at + 8
                if total == PLP_NULL:
                    self.null = self.done = True
                    break
                self.total, self.stage = (None if total == PLP_UNKNOWN else total), "length"
            elif self.stage == "length":
                if room < 4:
                    break
                n, at = builtins.int.from_bytes(data[at : at + 4], "little"), at + 4
                if n == 0:
                    self.done = True
                    break
                self.chunks, self.left, self.stage = self.chunks + 1, n, "data"
            else:
                take = min(self.left, room)
                if take == 0:
                    break
                piece = bytes(data[at : at + take])
                pieces.append(piece)
                if len(self.first) < 16:
                    self.first += piece[: 16 - len(self.first)]
                at, self.left, self.size = at + take, self.left - take, self.size + take
                if self.left == 0:
                    self.stage = "length"
        return at, pieces


class TextPointerValue:
    """A text, ntext or image value, read as it arrives. It is a text pointer with a 1-byte length, an 8-byte
    timestamp, then the value's 4-byte length and its bytes. A pointer length of 0 means NULL, and nothing follows it.
    MS-TDS §2.2.4.2.1.3."""

    def __init__(self):
        self.stage, self.null, self.done = "pointer", False, False
        self.need, self.left, self.size, self.chunks = 0, 0, 0, 1
        self.first = b""

    def read(self, data: memoryview, at: builtins.int) -> tuple[builtins.int, list[bytes]]:
        pieces = []
        while not self.done:
            room = len(data) - at
            if self.stage == "pointer":
                if room < 1:
                    break
                n, at = data[at], at + 1
                if n == 0:
                    self.null = self.done = True
                    break
                self.need, self.stage = n + 8, "skip"  # the pointer, then the timestamp
            elif self.stage == "skip":
                take = min(self.need, room)
                at, self.need = at + take, self.need - take
                if self.need:
                    break
                self.stage = "length"
            elif self.stage == "length":
                if room < 4:
                    break
                self.left, at, self.stage = builtins.int.from_bytes(data[at : at + 4], "little"), at + 4, "data"
                if self.left == 0:
                    self.done = True
            else:
                take = min(self.left, room)
                if take == 0:
                    break
                piece = bytes(data[at : at + take])
                pieces.append(piece)
                if len(self.first) < 16:
                    self.first += piece[: 16 - len(self.first)]
                at, self.left, self.size = at + take, self.left - take, self.size + take
                if self.left == 0:
                    self.done = True
        return at, pieces


def _read_whole(reader: PlpValue | TextPointerValue, r: Reader) -> bytes | None:
    """Reads a large value whole from a Reader that holds all of it (RETURNVALUE)."""
    pieces = []
    while not reader.done:
        at, found = reader.read(memoryview(r.data)[: r.end], r.pos)
        if at == r.pos and not found and not reader.done:
            raise r._short("a large value")
        r.pos = at
        pieces += found
    return None if reader.null else b"".join(pieces)


def _plp(data: bytes | None) -> bytes:
    """A whole value as PLP: its total length, one chunk, and the chunk of length 0 that ends it."""
    if data is None:
        return PLP_NULL.to_bytes(8, "little")
    chunk = len(data).to_bytes(4, "little") + data if data else b""
    return len(data).to_bytes(8, "little") + chunk + bytes(4)


@dataclass(frozen=True)
class Stream:
    """A source in a request's body (D-41). What it produces goes at `offset`, each piece framed as the wire carries
    it, followed by `end`. A large value's pieces are PLP chunks, ended by the chunk of length 0. A table's pieces are
    rows, ended by TVP_END."""

    offset: builtins.int
    source: Any
    encode: Callable[[Any], bytes]  # frames one piece. b"" sends nothing. A piece that doesn't fit is refused here
    end: bytes
    unit: str  # what a piece is, for observability: "chunks" or "rows"
    places: tuple = ()  # where in the request the source sits, for a refusal while it produces (D-53)


def _stream(w: Writer, sql_type: Any, value: Any, collation: Any) -> None:
    def chunk(piece: Any) -> bytes:
        data = sql_type.encode_piece(piece, collation)
        return len(data).to_bytes(4, "little") + data if data else b""

    w.put(PLP_UNKNOWN.to_bytes(8, "little"))
    w.context.setdefault("streams", []).append(Stream(w.pos, value, chunk, bytes(4), "chunks", tuple(w.places)))


# =========================================================================== the types


def _integral(value: Any) -> bool:
    return isinstance(value, builtins.int) and not isinstance(value, bool)


@dataclass(frozen=True)
class SqlType:
    """One SQL Server type, as declared. Two types are equal whatever wire code (`code`) they arrived in."""

    large = False  # a large value: (max), xml, text, ntext, image (D-47)

    def large_value(self) -> PlpValue | TextPointerValue:
        """A reader for one of this type's values, as it arrives."""
        return PlpValue()

    def text_decoder(self):
        """An incremental decoder for a text type's value bytes. Binary types return None."""
        return None

    def assemble(self, data: bytes | None) -> Any:
        """A large value from its whole bytes."""
        return data

    def check(self, value: Any) -> None:
        """Refuses a value that doesn't fit exactly (D-48). None (NULL) always fits."""

    # reading
    def read_value(self, r: Reader) -> Any:
        raise NotImplementedError

    # writing: parameters always use the nullable code, with a length
    def write_info(self, w: Writer) -> None:
        raise NotImplementedError

    def write_value(self, w: Writer, value: Any) -> None:
        raise NotImplementedError

    def show(self, value: Any) -> str:
        return "NULL" if value is None else str(value)


def _length(r: Reader, what: str, allowed: tuple[int, ...]) -> int | None:
    """A value's 1-byte length, where 0 means NULL."""
    n = U8.read(r)
    if n == 0:
        return None
    if n not in allowed:
        raise MalformedMessage(f"a {what} value {n} bytes long (expected {' or '.join(map(str, allowed))})", r.pos)
    return n


@dataclass(frozen=True)
class Integer(SqlType):
    size: int  # 1 tinyint (unsigned), 2 smallint, 4 int, 8 bigint
    code: TypeCode = field(default=TypeCode.INTN, compare=False)

    @property
    def name(self) -> str:
        return {1: "tinyint", 2: "smallint", 4: "int", 8: "bigint"}[self.size]

    def __str__(self) -> str:
        return self.name

    def _range(self) -> range:
        return range(256) if self.size == 1 else range(-(1 << (self.size * 8 - 1)), 1 << (self.size * 8 - 1))

    def check(self, value: Any) -> None:
        if value is None:
            return
        if not _integral(value):
            raise ValueRefused(f"{self} takes an int, not {type(value).__name__}")
        if value not in self._range():
            raise ValueRefused(f"{value} is outside {self}'s range, {self._range().start} to {self._range().stop - 1}")

    def read_value(self, r: Reader) -> int | None:
        n = self.size if self.code != TypeCode.INTN else _length(r, self.name, (self.size,))
        return None if n is None else builtins.int.from_bytes(r.take(n, self.name), "little", signed=self.size > 1)

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.INTN, self.size]))

    def write_value(self, w: Writer, value: int | None) -> None:
        w.put(b"\x00" if value is None else bytes([self.size]) + value.to_bytes(self.size, "little", signed=self.size > 1))


@dataclass(frozen=True)
class Bit(SqlType):
    code: TypeCode = field(default=TypeCode.BITN, compare=False)

    def __str__(self) -> str:
        return "bit"

    def check(self, value: Any) -> None:
        if value is not None and not isinstance(value, bool):
            raise ValueRefused(f"bit takes a bool, not {type(value).__name__}")

    def read_value(self, r: Reader) -> bool | None:
        n = 1 if self.code == TypeCode.BIT else _length(r, "bit", (1,))
        return None if n is None else r.take(1, "bit")[0] != 0

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.BITN, 1]))

    def write_value(self, w: Writer, value: bool | None) -> None:
        w.put(b"\x00" if value is None else bytes([1, 1 if value else 0]))


def _decimal_digits(value: PyDecimal | int, scale: int, what: str) -> int:
    """The value × 10^scale as an integer, exactly, without decimal arithmetic (which rounds at 28 digits)."""
    if _integral(value):
        return value * 10 ** scale
    if not isinstance(value, PyDecimal) or not value.is_finite():
        raise ValueRefused(f"{what} takes a Decimal or an int, not {value!r}")
    sign, digits, exponent = value.as_tuple()
    n = builtins.int("".join(map(str, digits)) or "0")
    shift = exponent + scale
    if shift >= 0:
        n *= 10 ** shift
    else:
        n, rest = divmod(n, 10 ** -shift)
        if rest:
            raise ValueRefused(f"{value} has more than {scale} decimal places, so {what} would round it")
    return -n if sign else n


def _decimal_from(n: int, scale: int, negative: bool) -> PyDecimal:
    return PyDecimal((1 if negative else 0, tuple(map(builtins.int, str(abs(n)))), -scale))


@dataclass(frozen=True)
class Decimal(SqlType):
    precision: int
    scale: int
    numeric: bool = False  # declared numeric rather than decimal. The two are the same in every other way
    code: TypeCode = field(default=TypeCode.DECIMALN, compare=False)

    def __str__(self) -> str:
        return f"{'numeric' if self.numeric else 'decimal'}({self.precision}, {self.scale})"

    @property
    def _size(self) -> int:
        return 4 if self.precision <= 9 else 8 if self.precision <= 19 else 12 if self.precision <= 28 else 16

    def check(self, value: Any) -> None:
        if value is None:
            return
        n = _decimal_digits(value, self.scale, str(self))
        if abs(n) >= 10 ** self.precision:
            raise ValueRefused(f"{value} has more than {self.precision} digits, so it doesn't fit {self}")

    def read_value(self, r: Reader) -> PyDecimal | None:
        n = _length(r, str(self), (5, 9, 13, 17))
        if n is None:
            return None
        positive = r.take(1, "sign")[0] == 1
        return _decimal_from(builtins.int.from_bytes(r.take(n - 1, "digits"), "little"), self.scale, not positive)

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.NUMERICN if self.numeric else TypeCode.DECIMALN, self._size + 1, self.precision, self.scale]))

    def write_value(self, w: Writer, value: PyDecimal | int | None) -> None:
        if value is None:
            w.put(b"\x00")
            return
        n = _decimal_digits(value, self.scale, str(self))
        negative = n < 0 or (isinstance(value, PyDecimal) and value.is_signed())
        # the smallest of 4, 8, 12 or 16 bytes that holds it, as the server itself writes values (MS-TDS §2.2.5.5.1.6)
        size = next(size for size in (4, 8, 12, 16) if abs(n) < 1 << (8 * size) or size == self._size)
        w.put(bytes([size + 1, 0 if negative else 1]) + abs(n).to_bytes(size, "little"))


@dataclass(frozen=True)
class Float(SqlType):
    size: int  # 4 real, 8 float
    code: TypeCode = field(default=TypeCode.FLTN, compare=False)

    def __str__(self) -> str:
        return "real" if self.size == 4 else "float"

    def _format(self) -> str:
        return "<f" if self.size == 4 else "<d"

    def check(self, value: Any) -> None:
        if value is None:
            return
        if not (isinstance(value, builtins.float) or _integral(value)):
            raise ValueRefused(f"{self} takes a float, not {type(value).__name__}")
        number = builtins.float(value)
        if _integral(value) and builtins.int(number) != value:
            raise ValueRefused(f"{value} has no exact {self} value")
        if not math.isfinite(number):
            raise ValueRefused(f"{value}: SQL Server holds no infinities or NaNs")
        if self.size == 4:
            try:
                exact = struct.unpack("<f", struct.pack("<f", number))[0] == number
            except OverflowError:
                exact = False
            if not exact:
                raise ValueRefused(f"{value!r} has no exact real (32-bit) value; declare float, or give one that has")

    def read_value(self, r: Reader) -> builtins.float | None:
        fixed = self.code in (TypeCode.REAL, TypeCode.FLOAT)
        n = self.size if fixed else _length(r, str(self), (self.size,))
        return None if n is None else struct.unpack(self._format(), r.take(n, str(self)))[0]

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.FLTN, self.size]))

    def write_value(self, w: Writer, value: builtins.float | None) -> None:
        w.put(b"\x00" if value is None else bytes([self.size]) + struct.pack(self._format(), builtins.float(value)))


@dataclass(frozen=True)
class Money(SqlType):
    size: int  # 8 money, 4 smallmoney
    code: TypeCode = field(default=TypeCode.MONEYN, compare=False)

    def __str__(self) -> str:
        return "money" if self.size == 8 else "smallmoney"

    def check(self, value: Any) -> None:
        if value is None:
            return
        n = _decimal_digits(value, 4, str(self))
        bits = self.size * 8
        if not -(1 << (bits - 1)) <= n < 1 << (bits - 1):
            raise ValueRefused(f"{value} is outside {self}'s range")

    def read_value(self, r: Reader) -> PyDecimal | None:
        fixed = self.code in (TypeCode.MONEY, TypeCode.SMALLMONEY)
        n = self.size if fixed else _length(r, str(self), (self.size,))
        if n is None:
            return None
        if n == 4:
            units = builtins.int.from_bytes(r.take(4, "smallmoney"), "little", signed=True)
        else:  # the more significant half first, then the less significant
            high = builtins.int.from_bytes(r.take(4, "money high"), "little", signed=True)
            units = (high << 32) | builtins.int.from_bytes(r.take(4, "money low"), "little")
        return _decimal_from(units, 4, units < 0)

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.MONEYN, self.size]))

    def write_value(self, w: Writer, value: PyDecimal | int | None) -> None:
        if value is None:
            w.put(b"\x00")
            return
        n = _decimal_digits(value, 4, str(self))
        if self.size == 4:
            w.put(b"\x04" + n.to_bytes(4, "little", signed=True))
        else:
            w.put(b"\x08" + (n >> 32).to_bytes(4, "little", signed=True) + (n & 0xFFFFFFFF).to_bytes(4, "little"))


DATE_EPOCH = dt.date(1, 1, 1)


def _date_from(days: int) -> dt.date:
    return DATE_EPOCH + dt.timedelta(days=days)


def _time_size(scale: int) -> int:
    return 3 if scale <= 2 else 4 if scale <= 4 else 5


def _check_scale(ticks: int, scale: int, what: str) -> None:
    if ticks % 10 ** (7 - scale):
        raise ValueRefused(f"{_clock(ticks)} has more than {scale} fractional digits, so {what} would round it")


@dataclass(frozen=True)
class Date(SqlType):
    code: TypeCode = field(default=TypeCode.DATE, compare=False)

    def __str__(self) -> str:
        return "date"

    def check(self, value: Any) -> None:
        if value is not None and (not isinstance(value, dt.date) or isinstance(value, dt.datetime)):
            raise ValueRefused(f"date takes a datetime.date, not {type(value).__name__}")

    def read_value(self, r: Reader) -> dt.date | None:
        n = _length(r, "date", (3,))
        return None if n is None else _date_from(builtins.int.from_bytes(r.take(3, "date"), "little"))

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.DATE]))

    def write_value(self, w: Writer, value: dt.date | None) -> None:
        w.put(b"\x00" if value is None else b"\x03" + (value - DATE_EPOCH).days.to_bytes(3, "little"))


@dataclass(frozen=True)
class Time(SqlType):
    scale: int = 7
    code: TypeCode = field(default=TypeCode.TIME, compare=False)

    def __str__(self) -> str:
        return f"time({self.scale})"

    def _ticks(self, value: Any) -> int:
        if isinstance(value, SqlTime):
            return value.ticks
        if isinstance(value, dt.time):
            return _ticks_of(value)
        raise ValueRefused(f"{self} takes a SqlTime or a datetime.time, not {type(value).__name__}")

    def check(self, value: Any) -> None:
        if value is not None:
            _check_scale(self._ticks(value), self.scale, str(self))

    def read_value(self, r: Reader) -> SqlTime | None:
        size = _time_size(self.scale)
        if _length(r, str(self), (size,)) is None:
            return None
        return SqlTime(builtins.int.from_bytes(r.take(size, "time"), "little") * 10 ** (7 - self.scale))

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.TIME, self.scale]))

    def write_value(self, w: Writer, value: Any) -> None:
        if value is None:
            w.put(b"\x00")
            return
        size = _time_size(self.scale)
        w.put(bytes([size]) + (self._ticks(value) // 10 ** (7 - self.scale)).to_bytes(size, "little"))


@dataclass(frozen=True)
class DateTime2(SqlType):
    scale: int = 7
    code: TypeCode = field(default=TypeCode.DATETIME2, compare=False)

    def __str__(self) -> str:
        return f"datetime2({self.scale})"

    def _exact(self, value: Any) -> SqlDateTime2:
        if isinstance(value, SqlDateTime2):
            return value
        if isinstance(value, dt.datetime):
            return SqlDateTime2.from_python(value)
        raise ValueRefused(f"{self} takes a SqlDateTime2 or a datetime.datetime, not {type(value).__name__}")

    def check(self, value: Any) -> None:
        if value is not None:
            _check_scale(self._exact(value).ticks, self.scale, str(self))

    def read_value(self, r: Reader) -> SqlDateTime2 | None:
        size = _time_size(self.scale)
        if _length(r, str(self), (size + 3,)) is None:
            return None
        ticks = builtins.int.from_bytes(r.take(size, "time"), "little") * 10 ** (7 - self.scale)
        return SqlDateTime2(_date_from(builtins.int.from_bytes(r.take(3, "date"), "little")), ticks)

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.DATETIME2, self.scale]))

    def write_value(self, w: Writer, value: Any) -> None:
        if value is None:
            w.put(b"\x00")
            return
        exact, size = self._exact(value), _time_size(self.scale)
        w.put(bytes([size + 3]) + (exact.ticks // 10 ** (7 - self.scale)).to_bytes(size, "little")
              + (exact.date - DATE_EPOCH).days.to_bytes(3, "little"))


@dataclass(frozen=True)
class DateTimeOffset(SqlType):
    scale: int = 7
    code: TypeCode = field(default=TypeCode.DATETIMEOFFSET, compare=False)

    def __str__(self) -> str:
        return f"datetimeoffset({self.scale})"

    def _exact(self, value: Any) -> SqlDateTimeOffset:
        if isinstance(value, SqlDateTimeOffset):
            return value
        if isinstance(value, dt.datetime):
            return SqlDateTimeOffset.from_python(value)
        raise ValueRefused(f"{self} takes a SqlDateTimeOffset or an aware datetime.datetime, not {type(value).__name__}")

    def check(self, value: Any) -> None:
        if value is not None:
            _check_scale(self._exact(value).utc_ticks, self.scale, str(self))

    def read_value(self, r: Reader) -> SqlDateTimeOffset | None:
        size = _time_size(self.scale)
        if _length(r, str(self), (size + 5,)) is None:
            return None
        ticks = builtins.int.from_bytes(r.take(size, "time"), "little") * 10 ** (7 - self.scale)
        date = _date_from(builtins.int.from_bytes(r.take(3, "date"), "little"))
        return SqlDateTimeOffset(date, ticks, builtins.int.from_bytes(r.take(2, "offset"), "little", signed=True))

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.DATETIMEOFFSET, self.scale]))

    def write_value(self, w: Writer, value: Any) -> None:
        if value is None:
            w.put(b"\x00")
            return
        exact, size = self._exact(value), _time_size(self.scale)
        w.put(bytes([size + 5]) + (exact.utc_ticks // 10 ** (7 - self.scale)).to_bytes(size, "little")
              + (exact.utc_date - DATE_EPOCH).days.to_bytes(3, "little")
              + exact.offset_minutes.to_bytes(2, "little", signed=True))


@dataclass(frozen=True)
class DateTime(SqlType):
    """datetime: 1/300-second ticks, from 1753. Its values are SqlDateTime (D-48)."""

    code: TypeCode = field(default=TypeCode.DATETIMN, compare=False)

    def __str__(self) -> str:
        return "datetime"

    def _exact(self, value: Any) -> SqlDateTime:
        if isinstance(value, SqlDateTime):
            exact = value
        elif isinstance(value, dt.datetime):
            exact = SqlDateTime.from_python(value)
        else:
            raise ValueRefused(f"datetime takes a SqlDateTime or a datetime.datetime, not {type(value).__name__}")
        if not -53_690 <= exact.days <= 2_958_463 or not 0 <= exact.ticks < 300 * 86_400:
            raise ValueRefused(f"{exact} is outside datetime's range, 1753-01-01 to 9999-12-31")
        return exact

    def check(self, value: Any) -> None:
        if value is not None:
            self._exact(value)

    def read_value(self, r: Reader) -> SqlDateTime | None:
        if self.code != TypeCode.DATETIME and _length(r, "datetime", (8,)) is None:
            return None
        days = builtins.int.from_bytes(r.take(4, "days"), "little", signed=True)
        return SqlDateTime(days, builtins.int.from_bytes(r.take(4, "ticks"), "little"))

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.DATETIMN, 8]))

    def write_value(self, w: Writer, value: Any) -> None:
        if value is None:
            w.put(b"\x00")
            return
        exact = self._exact(value)
        w.put(b"\x08" + exact.days.to_bytes(4, "little", signed=True) + exact.ticks.to_bytes(4, "little"))


SMALLDATETIME_LAST = dt.datetime(2079, 6, 6, 23, 59)


@dataclass(frozen=True)
class SmallDateTime(SqlType):
    """smalldatetime: whole minutes, 1900-01-01 to 2079-06-06. Python's datetime holds every value exactly."""

    code: TypeCode = field(default=TypeCode.DATETIMN, compare=False)

    def __str__(self) -> str:
        return "smalldatetime"

    def check(self, value: Any) -> None:
        if value is None:
            return
        if not isinstance(value, dt.datetime) or value.tzinfo is not None:
            raise ValueRefused("smalldatetime takes a datetime.datetime without a time zone")
        if value.second or value.microsecond:
            raise ValueRefused(f"{value} isn't a whole minute, so smalldatetime would round it")
        if not dt.datetime(1900, 1, 1) <= value <= SMALLDATETIME_LAST:
            raise ValueRefused(f"{value} is outside smalldatetime's range, 1900-01-01 to 2079-06-06 23:59")

    def read_value(self, r: Reader) -> dt.datetime | None:
        if self.code != TypeCode.SMALLDATETIME and _length(r, "smalldatetime", (4,)) is None:
            return None
        days = builtins.int.from_bytes(r.take(2, "days"), "little")
        minutes = builtins.int.from_bytes(r.take(2, "minutes"), "little")
        return dt.datetime(1900, 1, 1) + dt.timedelta(days=days, minutes=minutes)

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.DATETIMN, 4]))

    def write_value(self, w: Writer, value: dt.datetime | None) -> None:
        if value is None:
            w.put(b"\x00")
            return
        since = value - dt.datetime(1900, 1, 1)
        w.put(b"\x04" + since.days.to_bytes(2, "little") + (since.seconds // 60).to_bytes(2, "little"))


@dataclass(frozen=True)
class Character(SqlType):
    """char, varchar, nchar, nvarchar. `length` is as declared: bytes for char and varchar, UTF-16 code units for nchar
    and nvarchar. Without a collation, a parameter uses the session's (D-40)."""

    length: int
    varying: bool
    unicode: bool
    collation: Collation | None = None
    code: TypeCode = field(default=TypeCode.NVARCHAR, compare=False)

    def __str__(self) -> str:
        return f"{'n' if self.unicode else ''}{'var' if self.varying else ''}char({self.length})"

    @property
    def large(self) -> bool:
        return self.length is MAX

    @property
    def max_bytes(self) -> int:
        if self.large:
            return LARGEST
        return self.length * 2 if self.unicode else self.length

    def text_decoder(self):
        if self.unicode:
            return codecs.getincrementaldecoder("utf-16-le")("surrogatepass")
        if self.collation is None:
            raise MalformedMessage(f"a {self} value without a collation", 0)
        return self.collation.decoder()

    def assemble(self, data: bytes | None) -> str | None:
        return None if data is None else self.decode(data)

    def encode_piece(self, piece: Any, collation: Collation | None) -> bytes:
        if not isinstance(piece, str):
            raise ValueRefused(f"a source for {self} yields str, not {type(piece).__name__}")
        return self.encode(piece, collation)

    def encode(self, text: str, collation: Collation | None = None) -> bytes:
        if self.unicode:
            try:
                return text.encode("utf-16-le", "surrogatepass")  # nvarchar holds unpaired surrogates (D-48)
            except UnicodeEncodeError as e:
                raise ValueRefused(str(e)) from None
        chosen = self.collation or collation
        if chosen is None:
            raise ValueRefused(f"{self} needs a collation to encode its text")
        return chosen.encode(text)

    def decode(self, data: bytes) -> str:
        if self.unicode:
            return data.decode("utf-16-le", "surrogatepass")
        if self.collation is None:
            raise MalformedMessage(f"a {self} value without a collation", 0)
        return self.collation.decode(data)

    def check(self, value: Any, collation: Collation | None = None) -> None:
        if value is None:
            return
        if self.large and is_source(value):
            return  # each piece is checked as it is encoded
        if not isinstance(value, str):
            raise ValueRefused(f"{self} takes a str, not {type(value).__name__}")
        size = len(self.encode(value, collation))
        if size > self.max_bytes:
            raise ValueRefused(f"{size} bytes don't fit {self} ({self.max_bytes} bytes)")

    def read_value(self, r: Reader) -> str | None:
        if self.large:
            return self.assemble(_read_whole(PlpValue(), r))
        n = U16.read(r)
        return None if n == NULL_LENGTH else self.decode(bytes(r.take(n, str(self))))

    def write_info(self, w: Writer) -> None:
        code = {(False, False): TypeCode.BIGCHAR, (True, False): TypeCode.BIGVARCHAR,
                (False, True): TypeCode.NCHAR, (True, True): TypeCode.NVARCHAR}[(self.varying, self.unicode)]
        collation = self.collation or w.context.get("collation")
        length = MAX_LENGTH if self.large else self.max_bytes
        w.put(bytes([code]) + length.to_bytes(2, "little") + (collation.raw if collation else bytes(5)))

    def write_value(self, w: Writer, value: Any) -> None:
        collation = self.collation or w.context.get("collation")
        if self.large:
            if is_source(value):
                _stream(w, self, value, collation)
            else:
                w.put(_plp(None if value is None else self.encode(value, collation)))
            return
        if value is None:
            w.put(NULL_LENGTH.to_bytes(2, "little"))
            return
        data = self.encode(value, collation)
        w.put(len(data).to_bytes(2, "little") + data)

    def show(self, value: Any) -> str:
        if value is None:
            return "NULL"
        if is_source(value):
            return "a source"
        return f"“{value}”" if len(value) <= 200 else f"“{value[:200]}…” ({len(value)} characters)"


@dataclass(frozen=True)
class Binary(SqlType):
    length: int
    varying: bool
    code: TypeCode = field(default=TypeCode.BIGVARBINARY, compare=False)

    def __str__(self) -> str:
        return f"{'var' if self.varying else ''}binary({self.length})"

    @property
    def large(self) -> bool:
        return self.length is MAX

    def encode_piece(self, piece: Any, collation: Any) -> bytes:
        if not isinstance(piece, (bytes, bytearray, memoryview)):
            raise ValueRefused(f"a source for {self} yields bytes, not {type(piece).__name__}")
        return bytes(piece)

    def check(self, value: Any) -> None:
        if value is None:
            return
        if self.large and is_source(value):
            return  # each piece is checked as it is encoded
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise ValueRefused(f"{self} takes bytes, not {type(value).__name__}")
        if len(value) > (LARGEST if self.large else self.length):
            raise ValueRefused(f"{len(value)} bytes don't fit {self}")

    def read_value(self, r: Reader) -> bytes | None:
        if self.large:
            return _read_whole(PlpValue(), r)
        n = U16.read(r)
        return None if n == NULL_LENGTH else bytes(r.take(n, str(self)))

    def write_info(self, w: Writer) -> None:
        length = MAX_LENGTH if self.large else self.length
        w.put(bytes([TypeCode.BIGVARBINARY if self.varying else TypeCode.BIGBINARY]) + length.to_bytes(2, "little"))

    def write_value(self, w: Writer, value: Any) -> None:
        if self.large:
            if is_source(value):
                _stream(w, self, value, None)
            else:
                w.put(_plp(None if value is None else bytes(value)))
            return
        w.put(NULL_LENGTH.to_bytes(2, "little") if value is None else len(value).to_bytes(2, "little") + bytes(value))

    def show(self, value: Any) -> str:
        if value is None:
            return "NULL"
        if is_source(value):
            return "a source"
        return "0x" + value[:64].hex().upper() + ("…" if len(value) > 64 else "")


@dataclass(frozen=True)
class Xml(SqlType):
    """xml: UTF-16LE text, sent as PLP. A typed xml column names its schema collection."""

    schema: tuple[str, str, str] | None = None  # database, owning schema, schema collection
    code: TypeCode = field(default=TypeCode.XML, compare=False)
    large = True

    def __str__(self) -> str:
        return "xml" if self.schema is None else f"xml({'.'.join(self.schema)})"

    def text_decoder(self):
        return codecs.getincrementaldecoder("utf-16-le")("surrogatepass")

    def assemble(self, data: bytes | None) -> str | None:
        return None if data is None else data.decode("utf-16-le", "surrogatepass")

    def encode_piece(self, piece: Any, collation: Any) -> bytes:
        if not isinstance(piece, str):
            raise ValueRefused(f"a source for xml yields str, not {type(piece).__name__}")
        return piece.encode("utf-16-le", "surrogatepass")

    def check(self, value: Any) -> None:
        if value is not None and not is_source(value) and not isinstance(value, str):
            raise ValueRefused(f"xml takes a str, not {type(value).__name__}")

    def read_value(self, r: Reader) -> str | None:
        return self.assemble(_read_whole(PlpValue(), r))

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.XML, 0]))  # no schema collection

    def write_value(self, w: Writer, value: Any) -> None:
        if is_source(value):
            _stream(w, self, value, None)
        else:
            w.put(_plp(None if value is None else self.encode_piece(value, None)))

    def show(self, value: Any) -> str:
        return Character.show(self, value)


@dataclass(frozen=True)
class LegacyText(SqlType):
    """text and ntext: deprecated, but still found in old schemas. Their length goes first, so they can't be sent from a
    source. In a result, each value carries a text pointer and a timestamp before its bytes."""

    unicode: bool
    collation: Collation | None = None
    table: tuple[str, ...] = field(default=(), compare=False)  # the table the column comes from, in a result
    code: TypeCode = field(default=TypeCode.TEXT, compare=False)
    large = True

    def __str__(self) -> str:
        return "ntext" if self.unicode else "text"

    def large_value(self) -> TextPointerValue:
        return TextPointerValue()

    def text_decoder(self):
        return Character.text_decoder(self)

    def decode(self, data: bytes) -> str:
        return Character.decode(self, data)

    def encode(self, text: str, collation: Collation | None = None) -> bytes:
        return Character.encode(self, text, collation)

    def assemble(self, data: bytes | None) -> str | None:
        return None if data is None else self.decode(data)

    def check(self, value: Any, collation: Collation | None = None) -> None:
        if value is None:
            return
        if not isinstance(value, str):
            raise ValueRefused(f"{self} takes a whole str: its length goes first, so it can't come from a source")
        if len(self.encode(value, collation)) > LARGEST:
            raise ValueRefused(f"the value is longer than {self} can hold")

    def read_value(self, r: Reader) -> str | None:
        return self.assemble(_read_whole(TextPointerValue(), r))

    def write_info(self, w: Writer) -> None:
        collation = self.collation or w.context.get("collation")
        w.put(bytes([TypeCode.NTEXT if self.unicode else TypeCode.TEXT]) + LARGEST.to_bytes(4, "little")
              + (collation.raw if collation else bytes(5)))

    def write_value(self, w: Writer, value: str | None) -> None:
        if value is None:
            w.put(b"\xff\xff\xff\xff")
            return
        data = self.encode(value, self.collation or w.context.get("collation"))
        w.put(len(data).to_bytes(4, "little") + data)

    def show(self, value: Any) -> str:
        return Character.show(self, value)


@dataclass(frozen=True)
class Image(SqlType):
    """image: the deprecated binary type, as text is the deprecated form of varchar."""

    table: tuple[str, ...] = field(default=(), compare=False)
    code: TypeCode = field(default=TypeCode.IMAGE, compare=False)
    large = True

    def __str__(self) -> str:
        return "image"

    def large_value(self) -> TextPointerValue:
        return TextPointerValue()

    def check(self, value: Any) -> None:
        if value is not None and not isinstance(value, (bytes, bytearray, memoryview)):
            raise ValueRefused("image takes whole bytes: its length goes first, so it can't come from a source")

    def read_value(self, r: Reader) -> bytes | None:
        return _read_whole(TextPointerValue(), r)

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.IMAGE]) + LARGEST.to_bytes(4, "little"))

    def write_value(self, w: Writer, value: bytes | None) -> None:
        w.put(b"\xff\xff\xff\xff" if value is None else len(value).to_bytes(4, "little") + bytes(value))

    def show(self, value: Any) -> str:
        return Binary.show(self, value)


@dataclass(frozen=True)
class UniqueIdentifier(SqlType):
    code: TypeCode = field(default=TypeCode.GUID, compare=False)

    def __str__(self) -> str:
        return "uniqueidentifier"

    def check(self, value: Any) -> None:
        if value is not None and not isinstance(value, uuid.UUID):
            raise ValueRefused(f"uniqueidentifier takes a uuid.UUID, not {type(value).__name__}")

    def read_value(self, r: Reader) -> uuid.UUID | None:
        n = _length(r, "uniqueidentifier", (16,))
        # mixed-endian on the wire: the first three groups little-endian, the last two as written
        return None if n is None else uuid.UUID(bytes_le=bytes(r.take(16, "uniqueidentifier")))

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.GUID, 16]))

    def write_value(self, w: Writer, value: uuid.UUID | None) -> None:
        w.put(b"\x00" if value is None else b"\x10" + value.bytes_le)


# =========================================================================== json and vector (M6)
# The login asks for them (D-8).


@dataclass(frozen=True)
class Json(SqlType):
    """json: text sent as PLP, like nvarchar(max). It arrives as json only when the login asked for JSON support
    (D-8). Otherwise the server sends nvarchar(max). Observed: the server sends json as UTF-8 when the login also asked
    for UTF-8 support (the driver's default), and as UTF-16LE when it didn't. It reads parameters as UTF-8 in both
    cases. `utf8` says which encoding a column's values arrive in, as the login agreed it."""

    code: TypeCode = field(default=TypeCode.JSON, compare=False)
    utf8: bool = field(default=True, compare=False)
    large = True

    def __str__(self) -> str:
        return "json"

    def text_decoder(self):
        return codecs.getincrementaldecoder("utf-8" if self.utf8 else "utf-16-le")("surrogatepass")

    def assemble(self, data: bytes | None) -> str | None:
        return None if data is None else data.decode("utf-8" if self.utf8 else "utf-16-le", "surrogatepass")

    def encode_piece(self, piece: Any, collation: Any) -> bytes:
        if not isinstance(piece, str):
            raise ValueRefused(f"a source for json yields str, not {type(piece).__name__}")
        try:
            return piece.encode("utf-8")  # observed: the server reads json parameters as UTF-8 (RFC 8259)
        except UnicodeEncodeError:
            raise ValueRefused("json text can't hold an unpaired surrogate (UTF-8)") from None

    def check(self, value: Any) -> None:
        if value is not None and not is_source(value) and not isinstance(value, str):
            raise ValueRefused(f"json takes a str, not {type(value).__name__}")

    def read_value(self, r: Reader) -> str | None:
        return self.assemble(_read_whole(PlpValue(), r))

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.JSON]))

    def write_value(self, w: Writer, value: Any) -> None:
        if is_source(value):
            _stream(w, self, value, None)
        else:
            w.put(_plp(None if value is None else self.encode_piece(value, None)))

    def show(self, value: Any) -> str:
        return Character.show(self, value)


class VectorElement(enum.IntEnum):
    """The type of each of a vector's values (MS-TDS §2.2.5.5.7.4)."""

    FLOAT32 = 0x00
    FLOAT16 = 0x01


ELEMENT = {VectorElement.FLOAT32: ("<f", 4), VectorElement.FLOAT16: ("<e", 2)}
VECTOR_LAYOUT, VECTOR_LAYOUT_VERSION, VECTOR_HEADER = 0xA9, 0x01, 8


@dataclass(frozen=True)
class SqlVector:
    """A vector value: its element type and its values. Each value is exactly what the server holds (D-48)."""

    element: VectorElement
    values: tuple

    def __str__(self) -> str:
        return f"[{', '.join(repr(v) for v in self.values)}]"


@dataclass(frozen=True)
class Vector(SqlType):
    """vector(n) and vector(n, float16): n values of one element type, after an 8-byte header (layout A9, version 01,
    the count, the element type, 3 reserved bytes). It arrives as vector only when the login asked for vector support
    (D-8). Otherwise the server sends nvarchar text."""

    dimensions: builtins.int
    element: VectorElement = VectorElement.FLOAT32
    code: TypeCode = field(default=TypeCode.VECTOR, compare=False)

    def __str__(self) -> str:
        return f"vector({self.dimensions})" if self.element == VectorElement.FLOAT32 else \
            f"vector({self.dimensions}, {self.element.name.lower()})"

    @property
    def _size(self) -> builtins.int:
        return VECTOR_HEADER + self.dimensions * ELEMENT[self.element][1]

    def check(self, value: Any) -> None:
        if value is None:
            return
        if not isinstance(value, SqlVector):
            raise ValueRefused(f"{self} takes a SqlVector(element, values), not {type(value).__name__}")
        if value.element != self.element or len(value.values) != self.dimensions:
            raise ValueRefused(f"a {len(value.values)}-value {value.element.name.lower()} vector doesn't fit {self}")
        layout = ELEMENT[self.element][0]
        for v in value.values:
            number = builtins.float(v)
            try:
                exact = math.isfinite(number) and struct.unpack(layout, struct.pack(layout, number))[0] == number
            except (OverflowError, struct.error):
                exact = False
            if not exact:
                raise ValueRefused(f"{v!r} has no exact {self.element.name.lower()} value")

    def read_value(self, r: Reader) -> SqlVector | None:
        n = U16.read(r)
        if n == NULL_LENGTH:
            return None
        data = bytes(r.take(n, str(self)))
        if data[0] != VECTOR_LAYOUT or data[1] != VECTOR_LAYOUT_VERSION:
            raise MalformedMessage(f"a vector in layout {data[0]:#04x}, version {data[1]}", r.pos)
        count, element = builtins.int.from_bytes(data[2:4], "little"), VectorElement(data[4])
        layout, size = ELEMENT[element]
        values = tuple(struct.unpack(layout, data[VECTOR_HEADER + i * size : VECTOR_HEADER + (i + 1) * size])[0]
                       for i in range(count))
        return SqlVector(element, values)

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.VECTOR]) + self._size.to_bytes(2, "little") + bytes([self.element]))

    def write_value(self, w: Writer, value: SqlVector | None) -> None:
        if value is None:
            w.put(NULL_LENGTH.to_bytes(2, "little"))
            return
        layout = ELEMENT[self.element][0]
        data = (bytes([VECTOR_LAYOUT, VECTOR_LAYOUT_VERSION]) + len(value.values).to_bytes(2, "little")
                + bytes([self.element]) + bytes(3) + b"".join(struct.pack(layout, builtins.float(v)) for v in value.values))
        w.put(len(data).to_bytes(2, "little") + data)


# =========================================================================== CLR types (M7)


@dataclass(frozen=True)
class Clr(SqlType):
    """A CLR type: hierarchyid, geometry, geography, or a user-defined type. Its values are bytes in the type's own
    serialization, sent as PLP together with the type's full name (D-43). Turning them into paths or shapes is left to
    an outer layer (D-39). A column also carries the assembly that implements the type."""

    database: str
    schema: str
    name: str
    assembly: str = field(default="", compare=False)  # the assembly-qualified name, in a result
    max_size: Any = field(default=None, compare=False)  # in a result: bytes, or MAX
    code: TypeCode = field(default=TypeCode.UDT, compare=False)
    large = True

    def __str__(self) -> str:
        return ".".join(part for part in (self.database, self.schema, self.name) if part)

    def encode_piece(self, piece: Any, collation: Any) -> bytes:
        return Binary.encode_piece(self, piece, collation)

    def check(self, value: Any) -> None:
        if value is not None and not is_source(value) and not isinstance(value, (bytes, bytearray, memoryview)):
            raise ValueRefused(f"{self} takes its serialized bytes, not {type(value).__name__}")

    def read_value(self, r: Reader) -> bytes | None:
        return _read_whole(PlpValue(), r)

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.UDT]))
        for part in (self.database, self.schema, self.name):  # a request carries only the names
            WireText(U8).write(w, part)

    def write_value(self, w: Writer, value: Any) -> None:
        if is_source(value):
            _stream(w, self, value, None)
        else:
            w.put(_plp(None if value is None else bytes(value)))

    def show(self, value: Any) -> str:
        return Binary.show(self, value)


def clr(name: str) -> Clr:
    """A CLR type by its name: "schema.type", or "database.schema.type"."""
    parts = name.split(".")
    if len(parts) not in (2, 3) or not all(parts):
        raise ValueError(f"a CLR type is named schema.type or database.schema.type, not {name!r}")
    return Clr(*([""] * (3 - len(parts)) + parts))


# =========================================================================== sql_variant (M5)
# A sql_variant value carries its own base type.


@dataclass(frozen=True)
class SqlVariant:
    """A sql_variant value: the value together with its base type (D-48). It is sent back with the same base type."""

    type: SqlType
    value: Any

    def __str__(self) -> str:
        return f"{self.type}: {self.type.show(self.value)}"


def _variant_layout(base: SqlType) -> tuple[builtins.int, bytes, builtins.int]:
    """A base type's code inside a sql_variant, its properties, and how many length bytes its usual value layout
    starts with. Those length bytes are left out inside a sql_variant, because the sql_variant's own length covers the
    value."""
    match base:
        case Integer():
            return {1: TypeCode.TINYINT, 2: TypeCode.SMALLINT, 4: TypeCode.INT, 8: TypeCode.BIGINT}[base.size], b"", 1
        case Bit():
            return TypeCode.BIT, b"", 1
        case Float():
            return (TypeCode.REAL if base.size == 4 else TypeCode.FLOAT), b"", 1
        case Money():
            return (TypeCode.SMALLMONEY if base.size == 4 else TypeCode.MONEY), b"", 1
        case DateTime():
            return TypeCode.DATETIME, b"", 1
        case SmallDateTime():
            return TypeCode.SMALLDATETIME, b"", 1
        case UniqueIdentifier():
            return TypeCode.GUID, b"", 1
        case Date():
            return TypeCode.DATE, b"", 1
        case Time() | DateTime2() | DateTimeOffset():
            return {Time: TypeCode.TIME, DateTime2: TypeCode.DATETIME2, DateTimeOffset: TypeCode.DATETIMEOFFSET}[type(base)], \
                bytes([base.scale]), 1
        case Decimal():
            return (TypeCode.NUMERICN if base.numeric else TypeCode.DECIMALN), bytes([base.precision, base.scale]), 1
        case Binary() if not base.large:
            return (TypeCode.BIGVARBINARY if base.varying else TypeCode.BIGBINARY), base.length.to_bytes(2, "little"), 2
        case Character() if not base.large:
            code = {(False, False): TypeCode.BIGCHAR, (True, False): TypeCode.BIGVARCHAR,
                    (False, True): TypeCode.NCHAR, (True, True): TypeCode.NVARCHAR}[(base.varying, base.unicode)]
            return code, None, 2  # its properties need the collation that applies (see Variant.write_value)
    raise ValueRefused(f"a sql_variant can't hold {base}")


def _variant_base(code: builtins.int, props: bytes) -> SqlType:
    """The base type a sql_variant names, from its code and properties."""
    match code:
        case TypeCode.TINYINT | TypeCode.SMALLINT | TypeCode.INT | TypeCode.BIGINT:
            return Integer({0x30: 1, 0x34: 2, 0x38: 4, 0x7F: 8}[code], TypeCode(code))
        case TypeCode.BIT:
            return Bit(TypeCode.BIT)
        case TypeCode.REAL | TypeCode.FLOAT:
            return Float(4 if code == TypeCode.REAL else 8, TypeCode(code))
        case TypeCode.MONEY | TypeCode.SMALLMONEY:
            return Money(8 if code == TypeCode.MONEY else 4, TypeCode(code))
        case TypeCode.DATETIME:
            return DateTime(TypeCode.DATETIME)
        case TypeCode.SMALLDATETIME:
            return SmallDateTime(TypeCode.SMALLDATETIME)
        case TypeCode.GUID:
            return UniqueIdentifier()
        case TypeCode.DATE:
            return Date()
        case TypeCode.TIME | TypeCode.DATETIME2 | TypeCode.DATETIMEOFFSET:
            return {TypeCode.TIME: Time, TypeCode.DATETIME2: DateTime2, TypeCode.DATETIMEOFFSET: DateTimeOffset}[code](props[0])
        case TypeCode.DECIMALN | TypeCode.NUMERICN:
            return Decimal(props[0], props[1], code == TypeCode.NUMERICN, TypeCode(code))
        case TypeCode.BIGVARBINARY | TypeCode.BIGBINARY:
            return Binary(builtins.int.from_bytes(props[:2], "little"), code == TypeCode.BIGVARBINARY, TypeCode(code))
        case TypeCode.BIGVARCHAR | TypeCode.BIGCHAR | TypeCode.NVARCHAR | TypeCode.NCHAR:
            unicode = code in (TypeCode.NVARCHAR, TypeCode.NCHAR)
            length = builtins.int.from_bytes(props[5:7], "little")
            return Character(length // 2 if unicode else length, code in (TypeCode.BIGVARCHAR, TypeCode.NVARCHAR),
                             unicode, Collation(bytes(props[:5])), TypeCode(code))
    raise MalformedMessage(f"a sql_variant with base type {code:#04x}", 0)


VARIANT_LIMIT = 8016  # the most bytes a sql_variant value takes


@dataclass(frozen=True)
class Variant(SqlType):
    """sql_variant: each value is a SqlVariant, which carries its own base type. The value inside a sql_variant can't
    be NULL, and a large type can't be the base type (MS-TDS §2.2.5.5.4)."""

    code: TypeCode = field(default=TypeCode.SQL_VARIANT, compare=False)

    def __str__(self) -> str:
        return "sql_variant"

    def check(self, value: Any, collation: Collation | None = None) -> None:
        if value is None:
            return
        if not isinstance(value, SqlVariant):
            raise ValueRefused(f"sql_variant takes a SqlVariant(type, value), not {type(value).__name__}")
        if value.value is None:
            raise ValueRefused("a sql_variant can't hold NULL inside: the sql_variant itself is NULL (None)")
        _variant_layout(value.type)
        if isinstance(value.type, Character):
            value.type.check(value.value, collation)
        else:
            value.type.check(value.value)

    def read_value(self, r: Reader) -> SqlVariant | None:
        total = builtins.int.from_bytes(r.take(4, "sql_variant length"), "little")
        if total == 0:
            return None
        code, count = r.take(1, "base type")[0], r.take(1, "property bytes")[0]
        props = bytes(r.take(count, "properties"))
        base = _variant_base(code, props)
        data = bytes(r.take(total - 2 - count, "value"))
        _, _, prefix = _variant_layout(base)
        length = len(data).to_bytes(prefix, "little") if base.code not in FIXED_CODES else b""
        return SqlVariant(base, base.read_value(Reader(length + data, False)))

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.SQL_VARIANT]) + VARIANT_LIMIT.to_bytes(4, "little"))

    def write_value(self, w: Writer, value: SqlVariant | None) -> None:
        if value is None:
            w.put(bytes(4))
            return
        base = value.type
        code, props, prefix = _variant_layout(base)
        if props is None:  # text: its collation, then its max length in bytes
            collation = base.collation or w.context.get("collation")
            props = collation.raw + base.max_bytes.to_bytes(2, "little")
        inner = Writer(False)
        inner.context.update(w.context)
        base.write_value(inner, value.value)
        data = bytes(inner.buf[prefix:])
        w.put((2 + len(props) + len(data)).to_bytes(4, "little") + bytes([code, len(props)]) + props + data)

    def show(self, value: Any) -> str:
        return "NULL" if value is None else str(value)


FIXED_CODES = {TypeCode.TINYINT, TypeCode.SMALLINT, TypeCode.INT, TypeCode.BIGINT, TypeCode.BIT, TypeCode.REAL,
               TypeCode.FLOAT, TypeCode.MONEY, TypeCode.SMALLMONEY, TypeCode.DATETIME, TypeCode.SMALLDATETIME}


# =========================================================================== table-valued parameters (M8, D-49)


class Order(enum.IntFlag):
    """A table column's entry in TVP_ORDER_UNIQUE: its sort direction, and whether it is in the unique set
    (§2.2.5.5.5.2)."""

    ASCENDING = 0x01
    DESCENDING = 0x02
    UNIQUE = 0x04


TVP_NULL = 0xFFFF  # in place of the column count: no table. SQL Server accepts it only with the default status bit
TVP_ROW, TVP_END = b"\x01", b"\x00"
TVP_ORDER_UNIQUE, TVP_COLUMN_ORDERING = 0x10, 0x11
TVP_DEFAULT_COLUMN = 0x0200  # fDefault: the server fills the column, and rows leave out its values
TVP_NULLABLE = 0x0001


@dataclass(frozen=True)
class DefaultColumn:
    """A table column the server fills: an identity column, a computed column, or a column with a default. It is
    described with MS-TDS's default flag, and rows leave out its values."""

    type: SqlType

    def __str__(self) -> str:
        return f"default {self.type}"


def default(sql_type: SqlType) -> DefaultColumn:
    """Marks a table column the server fills, for example:
    types.table("shop.order_line", types.default(types.int), …)."""
    return DefaultColumn(sql_type)


def _numbered(encode: Callable[[Any], bytes]) -> Callable[[Any], bytes]:
    """Encodes rows one after another, and names the row that a refused value was in (D-53)."""
    count = [0]

    def encode_row(row: Any) -> bytes:
        count[0] += 1
        try:
            return encode(row)
        except ValueRefused as e:
            e.within(f"row {count[0]}")
            raise

    return encode_row


def _check(sql_type: SqlType, value: Any, collation: Any) -> None:
    """Refuses a value that doesn't fit its type (D-48). Text types need a collation to encode."""
    if isinstance(sql_type, (Character, LegacyText, Variant, Table)):
        sql_type.check(value, collation)
    else:
        sql_type.check(value)


@dataclass(frozen=True)
class Table(SqlType):
    """A table-valued parameter: a user-defined table type, its columns' types in order, and rows (D-49). TDS sends
    no column names. Rows are tuples of the values for every column the server doesn't fill, in the type's order.

    `order` and `unique` become TVP_ORDER_UNIQUE, a hint that the rows are sorted and which columns are unique.
    `send_order` becomes TVP_COLUMN_ORDERING, the order in which the values are sent, with every column listed. Columns
    are numbered from 1, as MS-TDS numbers them. Tables are only parameters, so they never come back."""

    schema: str
    name: str
    columns: tuple
    order: tuple = ()  # (column, Order.ASCENDING or Order.DESCENDING), the primary sort first
    unique: tuple = ()  # columns in the unique set
    send_order: tuple = ()  # every column, in the order its values are sent
    code: TypeCode = field(default=TypeCode.TVP, compare=False)

    def __post_init__(self):
        """Checks only what the encoding needs. The server checks the rest and says what is wrong: how many columns a
        table may have, whether tables nest, and which columns the hint may name."""
        n = len(self.columns)
        for c in self.columns:
            if not isinstance(c.type if isinstance(c, DefaultColumn) else c, SqlType):
                raise ValueError(f"a table's column is a type from tds.types, or types.default(type), not {c!r}")
        for c, sort in self.order:
            if sort not in (Order.ASCENDING, Order.DESCENDING):
                raise ValueError(f"order: column {c} is sorted Order.ASCENDING or Order.DESCENDING, not {sort!r}")
        if self.send_order and sorted(self.send_order) != list(range(1, n + 1)):  # otherwise values can't be placed
            raise ValueError(f"send_order lists every column, 1 to {n}, once: it places each row's values")

    def __str__(self) -> str:
        return ".".join(part for part in (self.schema, self.name) if part) or "(a table)"

    @property
    def given(self) -> list[builtins.int]:
        """The columns rows give values for, numbered from 1."""
        return [i for i, c in enumerate(self.columns, 1) if not isinstance(c, DefaultColumn)]

    def check(self, value: Any, collation: Any = None) -> None:
        if value is None or is_source(value):  # None means no table. The server refuses it unless it is the DEFAULT
            return  # a source's rows are checked as each is encoded
        if isinstance(value, (str, bytes, bytearray, memoryview)) or not hasattr(value, "__iter__"):
            raise ValueRefused(f"table {self} takes an iterable of rows, or a source of rows, not {type(value).__name__}")
        # rows from a plain iterable are checked as they are encoded, before anything is sent

    def write_info(self, w: Writer) -> None:
        w.put(bytes([TypeCode.TVP]))
        for part in ("", self.schema, self.name):  # the database must be empty (§2.2.5.5.5.1)
            WireText(U8).write(w, part)

    def write_value(self, w: Writer, value: Any) -> None:
        if value is None:  # no table. Sent for DEFAULT, with the default status bit, it gives the procedure an empty
            # table. Sent for None, without the bit, SQL Server refuses it (error 8060). This is against MS-TDS, which
            # says the bit must be zero for a table
            w.put(TVP_NULL.to_bytes(2, "little") + TVP_END + TVP_END)
            return
        w.put(len(self.columns).to_bytes(2, "little"))
        for c in self.columns:
            filled = isinstance(c, DefaultColumn)
            w.put(bytes(4) + (TVP_NULLABLE | (TVP_DEFAULT_COLUMN if filled else 0)).to_bytes(2, "little"))
            (c.type if filled else c).write_info(w)
            WireText(U8).write(w, "")  # no column names in a table parameter
        ordered = [c for c, _ in self.order]  # sent as given, each entry once. The server checks them
        entries = [(c, sort | (Order.UNIQUE if c in self.unique else Order(0))) for c, sort in self.order]
        entries += [(c, Order.UNIQUE) for c in self.unique if c not in ordered]
        if entries:
            w.put(bytes([TVP_ORDER_UNIQUE]) + len(entries).to_bytes(2, "little")
                  + b"".join(c.to_bytes(2, "little") + bytes([f]) for c, f in entries))
        if self.send_order:
            w.put(bytes([TVP_COLUMN_ORDERING]) + len(self.send_order).to_bytes(2, "little")
                  + b"".join(c.to_bytes(2, "little") for c in self.send_order))
        w.put(TVP_END)
        context = {"collation": w.context.get("collation")}
        if is_source(value):
            w.context.setdefault("streams", []).append(
                Stream(w.pos, value, _numbered(lambda row: self.encode_row(row, context)), TVP_END, "rows", tuple(w.places)))
            return
        encode = _numbered(lambda row: self.encode_row(row, context))
        for row in value:
            w.put(encode(row))
        w.put(TVP_END)

    def encode_row(self, row: Any, context: dict) -> bytes:
        """Encodes one row: TVP_ROW, then each given column's value, in the order the values are sent."""
        given = self.given
        if not isinstance(row, (tuple, list)) or len(row) != len(given):
            raise ValueRefused(f"a row of {self} is a tuple of {len(given)} values (the columns the server doesn't "
                               f"fill), not {row!r:.80}")
        values = dict(zip(given, row))
        w = Writer(False)
        w.context.update(context)
        w.put(TVP_ROW)
        for c in self.send_order or range(1, len(self.columns) + 1):
            if c in values:
                sql_type, value = self.columns[c - 1], values[c]
                try:
                    if is_source(value):
                        raise ValueRefused(f"a table's values are sent whole, not from a source")
                    _check(sql_type, value, context.get("collation"))
                    sql_type.write_value(w, value)
                except ValueRefused as e:
                    e.within(f"column {c} ({sql_type})")
                    raise
        return bytes(w.buf)

    def show(self, value: Any) -> str:
        if value is None:
            return "no table"
        if is_source(value):
            return "rows from a source"
        return f"{len(value)} rows" if hasattr(value, "__len__") else "rows"


# =========================================================================== Always Encrypted, as TDS carries it (D-60)
# Once the login's column encryption feature is agreed, an encrypted column or output parameter arrives as varbinary
# ciphertext, described by its crypto metadata: the plaintext's type, the algorithm, and which column key. The core
# reads and writes all of it, but has no keys. tds.encryption decrypts, through the hook that an exchange is given.


class EncryptionType(enum.IntEnum):
    DETERMINISTIC = 1  # the same plaintext gives the same ciphertext, so the server can test equality on it
    RANDOMIZED = 2


ENCRYPTION_ALGORITHMS = {2: "AEAD_AES_256_CBC_HMAC_SHA256"}  # by EncryptionAlgo. 0 means the name is sent instead


@dataclass(frozen=True)
class MasterKeyValue:
    """A column key, encrypted by one master key, and where that master key is (EK_INFO's EncryptionKeyValue)."""

    encrypted: bytes
    key_store: str  # as the database names it, such as AZURE_KEY_VAULT
    key_path: str
    algorithm: str  # how the master key encrypted it: RSA_OAEP

    def __repr__(self) -> str:
        return f"MasterKeyValue({self.key_store}, “{self.key_path}”, {self.algorithm}, {len(self.encrypted)} bytes)"


@dataclass(frozen=True)
class ColumnKey:
    """One column key, as the key table holds it (EK_INFO): its ids, and its value under each master key."""

    database_id: int
    key_id: int
    version: int
    metadata_version: bytes  # 8 bytes, kept as sent
    values: tuple[MasterKeyValue, ...]


@dataclass(frozen=True)
class EncryptedValue:
    """A value that arrived encrypted, with no tds.encryption to decrypt it: its ciphertext, as sent."""

    ciphertext: bytes

    def __repr__(self) -> str:
        return f"EncryptedValue({len(self.ciphertext)} bytes)"


@dataclass(frozen=True)
class NotDecrypted:
    """A value tds.encryption couldn't decrypt: its ciphertext, and why."""

    ciphertext: bytes
    reason: str

    def __repr__(self) -> str:
        return f"NotDecrypted({len(self.ciphertext)} bytes: {self.reason})"


@dataclass(frozen=True)
class Encrypted(SqlType):
    """An encrypted column or output parameter. Its values travel as `cipher` (varbinary) and hold a `base` value."""

    cipher: SqlType
    base: SqlType
    encryption_type: EncryptionType
    algorithm: builtins.int
    algorithm_name: str | None  # sent only for algorithm 0
    normalization: builtins.int
    base_user_type: builtins.int = 0
    key: ColumnKey | None = None  # a column's key comes from the key table, and an output parameter's from its call
    parameter: str | builtins.int | None = None  # an output parameter's name, or a positional one's ordinal from 0
    decrypt: Callable[[Encrypted, bytes], Any] | None = field(default=None, compare=False, repr=False)

    large = False  # read whole: no plaintext is released before the value's authentication is checked

    @property
    def code(self) -> TypeCode:
        return self.cipher.code  # on the wire, an encrypted column's type is its ciphertext's

    @property
    def algorithm_label(self) -> str:
        return self.algorithm_name or ENCRYPTION_ALGORITHMS.get(self.algorithm, f"algorithm {self.algorithm}")

    def __str__(self) -> str:
        return f"{self.base} encrypted {self.encryption_type.name.lower()}"

    def read_value(self, r: Reader) -> Any:
        ciphertext = self.cipher.read_value(r)
        if ciphertext is None:
            return None
        if self.decrypt is None:
            return EncryptedValue(ciphertext)
        try:
            return self.decrypt(self, ciphertext)
        except ValueError as e:  # a key or a value that can't be decrypted. The value says why. The stream continues
            return NotDecrypted(ciphertext, str(e))

    def show(self, value: Any) -> str:
        if isinstance(value, (EncryptedValue, NotDecrypted)) or value is None:
            return repr(value) if value is not None else "NULL"
        return self.base.show(value)


# =========================================================================== TYPE_INFO and values, for the wire engine


class TypeInfo(Type):
    """TYPE_INFO: a type code, then whatever that code needs (a size, or a precision and a scale, or a scale, or a max
    length and a collation). It is read as the vocabulary's objects."""

    composite = True

    def read(self, r: Reader) -> SqlType:
        code = r.read(Field("type", U8, enum=TypeCode))
        size = lambda: r.read(Field("size", U8))  # noqa: E731
        match code:
            case TypeCode.TINYINT | TypeCode.SMALLINT | TypeCode.INT | TypeCode.BIGINT:
                return Integer({0x30: 1, 0x34: 2, 0x38: 4, 0x7F: 8}[code], code)
            case TypeCode.INTN:
                return Integer(self._one_of(size(), (1, 2, 4, 8), "int", r), code)
            case TypeCode.BIT:
                return Bit(code)
            case TypeCode.BITN:
                self._one_of(size(), (1,), "bit", r)
                return Bit(code)
            case TypeCode.DECIMALN | TypeCode.NUMERICN:
                size()
                precision, scale = r.read(Field("precision", U8)), r.read(Field("scale", U8))
                return Decimal(precision, scale, code == TypeCode.NUMERICN, code)
            case TypeCode.REAL | TypeCode.FLOAT:
                return Float(4 if code == TypeCode.REAL else 8, code)
            case TypeCode.FLTN:
                return Float(self._one_of(size(), (4, 8), "float", r), code)
            case TypeCode.MONEY | TypeCode.SMALLMONEY:
                return Money(8 if code == TypeCode.MONEY else 4, code)
            case TypeCode.MONEYN:
                return Money(self._one_of(size(), (4, 8), "money", r), code)
            case TypeCode.DATETIME:
                return DateTime(code)
            case TypeCode.SMALLDATETIME:
                return SmallDateTime(code)
            case TypeCode.DATETIMN:
                return DateTime(code) if self._one_of(size(), (4, 8), "datetime", r) == 8 else SmallDateTime(code)
            case TypeCode.DATE:
                return Date(code)
            case TypeCode.TIME | TypeCode.DATETIME2 | TypeCode.DATETIMEOFFSET:
                scale = r.read(Field("scale", U8))
                if scale > 7:
                    raise MalformedMessage(f"a time scale of {scale} (0 to 7)", r.pos, r.tree)
                return {TypeCode.TIME: Time, TypeCode.DATETIME2: DateTime2, TypeCode.DATETIMEOFFSET: DateTimeOffset}[code](scale, code)
            case TypeCode.GUID:
                self._one_of(size(), (16,), "uniqueidentifier", r)
                return UniqueIdentifier(code)
            case TypeCode.BIGBINARY | TypeCode.BIGVARBINARY:
                length = self._max_length(r, code)
                return Binary(length, code == TypeCode.BIGVARBINARY, code)
            case TypeCode.BIGCHAR | TypeCode.BIGVARCHAR | TypeCode.NCHAR | TypeCode.NVARCHAR:
                length = self._max_length(r, code)
                collation = Collation(bytes(r.read(Field("collation", Raw(5), fmt=lambda v: v.hex(" ").upper()))))
                unicode = code in (TypeCode.NCHAR, TypeCode.NVARCHAR)
                if unicode and length is not MAX:
                    length //= 2
                return Character(length, code in (TypeCode.BIGVARCHAR, TypeCode.NVARCHAR), unicode, collation, code)
            case TypeCode.SQL_VARIANT:
                r.read(Field("max_length", U32, fmt=lambda v: f"{v} bytes"))
                return Variant(code)
            case TypeCode.JSON:  # its encoding follows the login's UTF-8 support (D-8)
                return Json(code, r.context.get("utf8_support", False))
            case TypeCode.UDT:
                size = r.read(Field("max_size", U16, fmt=lambda v: "max" if v == MAX_LENGTH else f"{v} bytes"))
                names = [r.read(Field(f, WireText(U8))) for f in ("database", "schema", "type_name")]
                assembly = r.read(Field("assembly", WireText(U16)))
                return Clr(*names, assembly, MAX if size == MAX_LENGTH else size, code)
            case TypeCode.VECTOR:
                size = r.read(Field("max_length", U16, fmt=lambda v: f"{v} bytes"))
                element = r.read(Field("element", U8, enum=VectorElement))
                if element not in ELEMENT:
                    raise MalformedMessage(f"a vector of element type {element:#04x}", r.pos, r.tree)
                return Vector((size - VECTOR_HEADER) // ELEMENT[element][1], element, code)
            case TypeCode.XML:
                if r.read(Field("schema_present", U8)):
                    schema = (r.read(Field("database", WireText(U8))), r.read(Field("owning_schema", WireText(U8))),
                              r.read(Field("schema_collection", WireText(U16))))
                    return Xml(schema, code)
                return Xml(None, code)
            case TypeCode.TEXT | TypeCode.NTEXT | TypeCode.IMAGE:
                r.read(Field("max_length", U32, fmt=lambda v: f"{v} bytes"))
                collation = None
                if code != TypeCode.IMAGE:
                    collation = Collation(bytes(r.read(Field("collation", Raw(5), fmt=lambda v: v.hex(" ").upper()))))
                parts = r.read(Field("table_parts", U8))  # in a result: the table the column comes from
                table = tuple(r.read(Field(f"table part {i + 1}", WireText(U16))) for i in range(parts))
                if code == TypeCode.IMAGE:
                    return Image(table, code)
                return LegacyText(code == TypeCode.NTEXT, collation, table, code)
        if isinstance(code, TypeCode):
            raise MalformedMessage(f"type code {code:#04x} ({code.name.lower()}) is kept by MS-TDS for older clients; "
                                   "SQL Server sends the modern code", r.pos, r.tree)
        raise MalformedMessage(f"unknown data type {code:#04x}", r.pos, r.tree)

    @staticmethod
    def _one_of(n: int, allowed: tuple[int, ...], what: str, r: Reader) -> int:
        if n not in allowed:
            raise MalformedMessage(f"a {what} type with size {n}", r.pos, r.tree)
        return n

    @staticmethod
    def _max_length(r: Reader, code: TypeCode) -> int | _Max:
        n = r.read(Field("max_length", U16, fmt=lambda v: "max" if v == MAX_LENGTH else f"{v} bytes"))
        return MAX if n == MAX_LENGTH else n

    def write(self, w: Writer, value: SqlType) -> None:
        start = w.pos
        value.write_info(w)
        if w.record and w._stack[-1].start == start:  # to name its fields as reading names them, read the bytes back
            r = Reader(bytes(w.buf[start:]), True)
            r.context.update(w.context)
            self.read(r)
            for node in r.tree.children:
                _shift(node, start)
                w._stack[-1].children.append(node)

    def show(self, value: SqlType) -> str:
        return str(value)


def _shift(node, by: int) -> None:
    node.start, node.end = node.start + by, node.end + by
    for child in node.children:
        _shift(child, by)


class Value(Type):
    """One value, laid out as its type says."""

    def __init__(self, sql_type: SqlType | None):
        self.sql_type = sql_type

    def read(self, r: Reader) -> Any:
        return self.sql_type.read_value(r)

    def write(self, w: Writer, value: Any) -> None:
        self.sql_type.write_value(w, value)

    def show(self, value: Any) -> str:
        if self.sql_type is not None:
            return self.sql_type.show(value)
        return "NULL" if value is None else f"“{value}”" if isinstance(value, str) else str(value)


class ValueOf(Type):
    """A value laid out by a type given in an earlier field of the same structure (RETURNVALUE's `type`)."""

    def __init__(self, type_field: str):
        self.type_field = type_field

    def resolve(self, rw) -> Type:
        return Value(rw.values[-1][self.type_field])


# =========================================================================== the vocabulary: tds.types


tinyint, smallint, int, bigint = Integer(1), Integer(2), Integer(4), Integer(8)
bit = Bit()
real, float = Float(4), Float(8)
money, smallmoney = Money(8), Money(4)
date = Date()
datetime = DateTime()
smalldatetime = SmallDateTime()
uniqueidentifier = UniqueIdentifier()


def decimal(precision: builtins.int = 18, scale: builtins.int = 0) -> Decimal:
    if not 1 <= precision <= 38 or not 0 <= scale <= precision:
        raise ValueError(f"decimal({precision}, {scale}): precision 1 to 38, scale 0 to the precision")
    return Decimal(precision, scale)


def numeric(precision: builtins.int = 18, scale: builtins.int = 0) -> Decimal:
    return Decimal(decimal(precision, scale).precision, scale, numeric=True, code=TypeCode.NUMERICN)


def time(scale: builtins.int = 7) -> Time:
    return Time(_scale(scale))


def datetime2(scale: builtins.int = 7) -> DateTime2:
    return DateTime2(_scale(scale))


def datetimeoffset(scale: builtins.int = 7) -> DateTimeOffset:
    return DateTimeOffset(_scale(scale))


def _scale(scale: builtins.int) -> builtins.int:
    if not 0 <= scale <= 7:
        raise ValueError(f"a fractional-second scale of {scale}: 0 to 7")
    return scale


def _length_of(length: builtins.int | _Max, limit: builtins.int, name: str, can_be_max: bool = True) -> builtins.int | _Max:
    if length is MAX and can_be_max:
        return MAX
    if not isinstance(length, builtins.int) or not 1 <= length <= limit:
        raise ValueError(f"{name}({length}): 1 to {limit}" + (", or types.MAX" if can_be_max else ""))
    return length


def char(length: builtins.int = 1, collation: Collation | None = None) -> Character:
    return Character(_length_of(length, 8000, "char", can_be_max=False), False, False, collation, TypeCode.BIGCHAR)


def varchar(length: builtins.int = 1, collation: Collation | None = None) -> Character:
    return Character(_length_of(length, 8000, "varchar"), True, False, collation, TypeCode.BIGVARCHAR)


def nchar(length: builtins.int = 1) -> Character:
    return Character(_length_of(length, 4000, "nchar", can_be_max=False), False, True, None, TypeCode.NCHAR)


def nvarchar(length: builtins.int = 1) -> Character:
    return Character(_length_of(length, 4000, "nvarchar"), True, True, None, TypeCode.NVARCHAR)


def binary(length: builtins.int = 1) -> Binary:
    return Binary(_length_of(length, 8000, "binary", can_be_max=False), False, TypeCode.BIGBINARY)


def varbinary(length: builtins.int = 1) -> Binary:
    return Binary(_length_of(length, 8000, "varbinary"), True, TypeCode.BIGVARBINARY)


xml = Xml()
text = LegacyText(False)
ntext = LegacyText(True)
image = Image()
sql_variant = Variant()
json = Json()


def vector(dimensions: builtins.int, element: VectorElement = VectorElement.FLOAT32) -> Vector:
    limit = (8000 - VECTOR_HEADER) // ELEMENT[element][1]
    if not 1 <= dimensions <= limit:
        raise ValueError(f"vector({dimensions}): 1 to {limit} {element.name.lower()} values")
    return Vector(dimensions, element)
hierarchyid, geometry, geography = Clr("", "sys", "hierarchyid"), Clr("", "sys", "geometry"), Clr("", "sys", "geography")


def table(name: str, *columns: SqlType | DefaultColumn, order: tuple = (), unique: tuple = (),
          send_order: tuple = ()) -> Table:
    """A table type for a table-valued parameter (D-49), by its name, "schema.type" or "type", and its columns'
    types, in order:

        types.table("shop.order_line", types.default(types.int), types.int, types.int, types.default(types.int))

    Its value is an iterable of rows, or a source of rows. Each row holds values for the columns the server doesn't
    fill."""
    parts = name.split(".") if name else []
    if len(parts) > 2 or not all(parts):
        raise ValueError(f"a table type is named schema.type or type (the database is never sent), not {name!r}")
    return Table(*([""] * (2 - len(parts)) + parts), tuple(columns), tuple(order), tuple(unique), tuple(send_order))
