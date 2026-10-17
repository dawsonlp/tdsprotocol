"""A value's plaintext before it is encrypted: normalization version 1 (D-60).

MS-TDS names the normalization version but not its rules. Source: SqlClient (TdsParser's SerializeUnencryptedValue
and DeserializeUnencryptedValue). Checked against a running SqlClient (D-61).

Each type's plaintext is its value as TDS lays it out, without its length, in the type's widest form:
  bit, tinyint, smallint, int, bigint   8 bytes, as a bigint (bit: 0 or 1)
  real, float                            4 or 8 bytes, as sent
  smallmoney, money                      8 bytes, as money
  decimal(p, s), numeric(p, s)           17 bytes: sign (1 positive, 0 negative), then 16 bytes of digits, as (38, s)
  date                                   3 bytes
  time(n), datetime2(n), datetimeoffset(n)  at scale 7 for any n: 5, 8 and 10 bytes
  smalldatetime, datetime, uniqueidentifier  as sent
  char, varchar, nchar, nvarchar         the text's bytes in the column's encoding, unpadded
  binary, varbinary                      the bytes, unpadded
When read back, char(n), nchar(n) and binary(n) values are padded to their length, as in unencrypted columns.
Other types can't be encrypted.
"""

from typing import Any

from ..types import (MAX, Binary, Bit, Character, Collation, Date, DateTime, DateTime2, DateTimeOffset, Decimal, Float,
                     Integer, Money, SmallDateTime, SqlType, Time, UniqueIdentifier, ValueRefused)
from ..wire import MalformedMessage, Reader, Writer

VERSION = 1


def _widest(base: SqlType) -> SqlType | None:
    """The type whose TDS value, without its length, is the plaintext. None for text and bytes, which are used
    unchanged."""
    match base:
        case Integer() | Bit():
            return Integer(8)
        case Money():
            return Money(8)
        case Decimal():
            return Decimal(38, base.scale)
        case Time():
            return Time(7)
        case DateTime2():
            return DateTime2(7)
        case DateTimeOffset():
            return DateTimeOffset(7)
        case Float() | Date() | DateTime() | SmallDateTime() | UniqueIdentifier():
            return base
    return None


def _supported(base: SqlType) -> None:
    if not isinstance(base, (Integer, Bit, Money, Decimal, Time, DateTime2, DateTimeOffset, Float, Date, DateTime,
                             SmallDateTime, UniqueIdentifier, Character, Binary)):
        raise ValueRefused(f"Always Encrypted can't encrypt {base}")


def normalize(base: SqlType, value: Any, collation: Collation | None = None) -> bytes:
    """The plaintext of a value of type `base`. The value is checked against `base` first (D-48)."""
    _supported(base)
    base.check(value, collation) if isinstance(base, Character) else base.check(value)
    if isinstance(base, Character):
        return base.encode(value, collation)
    if isinstance(base, Binary):
        return bytes(value)
    if isinstance(base, Bit):
        value = int(bool(value))
    w = Writer(False)
    _widest(base).write_value(w, value)
    plaintext = bytes(w.buf[1:])  # without its length
    if isinstance(base, Decimal):  # TDS sends only the digit bytes the value needs. The plaintext always has 16.
        plaintext = plaintext[:1] + plaintext[1:].ljust(16, b"\x00")
    return plaintext


def denormalize(base: SqlType, plaintext: bytes) -> Any:
    """The value a plaintext holds, as a column of type `base` gives it."""
    _supported(base)
    if isinstance(base, Character):
        text = base.decode(plaintext)
        if not base.varying and base.length is not MAX:  # char(n), nchar(n): padded, as their columns are
            if base.unicode:
                text += " " * (base.length - len(plaintext) // 2)
            else:
                text += " " * (base.length - len(plaintext))
        return text
    if isinstance(base, Binary):
        if not base.varying and base.length is not MAX:
            return plaintext + bytes(base.length - len(plaintext))
        return plaintext
    widest = _widest(base)
    r = Reader(bytes([len(plaintext)]) + plaintext, False)
    try:
        value = widest.read_value(r)
    except MalformedMessage as e:
        raise ValueRefused(f"{len(plaintext)} bytes of {base} plaintext don't match normalization version {VERSION}: "
                           f"{e.what}") from None
    if r.pos != r.end:
        raise ValueRefused(f"{len(plaintext)} bytes of {base} plaintext: normalization version {VERSION} lays it out "
                           f"in {r.pos - 1}")
    if isinstance(base, Bit):
        return value != 0
    base.check(value)  # an integer that doesn't fit its column, written by a broken client, is refused (D-48)
    return value
