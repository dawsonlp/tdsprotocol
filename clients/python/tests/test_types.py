"""Tests of the type vocabulary (M2) against the core alone.

Every short type round-trips through its wire form at its limits. Values that don't fit are refused, not rounded (D-48).
Collations decode as the server decodes them (D-44).
"""

import datetime as dt
import math
import struct
import uuid
from decimal import Decimal

import pytest

from tds import types
from tds.types import (Collation, SqlDateTime, SqlDateTime2, SqlDateTimeOffset, SqlTime, TypeInfo, UnknownCollation,
                       ValueRefused)
from tds.wire import Field, Reader, Writer

LATIN1 = Collation(bytes.fromhex("09 04 D0 00 34"))  # SQL_Latin1_General_CP1_CI_AS, the test server's default
JAPANESE = Collation(bytes.fromhex("11 04 D0 30 00"))  # Japanese_XJIS_140_CI_AS: cp932
UTF8 = Collation(bytes.fromhex("09 04 D0 24 00"))  # Latin1_General_100_CI_AS_SC_UTF8


def round_trip(sql_type, value, collation=LATIN1):
    """Write the type's description and the value as a parameter would, then read both back as a column would."""
    w = Writer(record=False)
    w.context["collation"] = collation
    sql_type.check(value) if not isinstance(sql_type, types.Character) else sql_type.check(value, collation)
    sql_type.write_info(w)
    sql_type.write_value(w, value)
    r = Reader(bytes(w.buf), record=False)
    read_type = r.read(Field("type", TypeInfo()))
    assert read_type == sql_type or isinstance(sql_type, types.Character)
    got = read_type.read_value(r)
    assert r.pos == r.end
    return got


@pytest.mark.parametrize("value", [
    SqlDateTimeOffset(dt.date(1, 1, 1), 0, -840),
    SqlDateTimeOffset(dt.date(9999, 12, 31), 86_400 * 10**7 - 1, 840),
    SqlDateTimeOffset(dt.date(2026, 1, 1), -1, 0),
    SqlDateTimeOffset(dt.date(2026, 1, 1), 86_400 * 10**7, 0),
    SqlDateTimeOffset(dt.date(2026, 1, 1), 0, 841),
    SqlDateTimeOffset(dt.date(2026, 1, 1), 0, -841),
    SqlDateTimeOffset(dt.date(2026, 1, 1), 0, 0.5),
    dt.datetime(1, 1, 1, tzinfo=dt.timezone(dt.timedelta(hours=14))),
    dt.datetime(9999, 12, 31, 23, 59, tzinfo=dt.timezone(dt.timedelta(hours=-14))),
])
def test_direct_datetimeoffset_parameters_refuse_invalid_utc_local_ticks_and_offsets(value):
    with pytest.raises(ValueRefused):
        types.datetimeoffset(7).check(value)


EXACT = [
    (types.tinyint, [0, 255]),
    (types.smallint, [-32768, 32767]),
    (types.int, [-(2**31), 2**31 - 1, 0]),
    (types.bigint, [-(2**63), 2**63 - 1]),
    (types.bit, [True, False]),
    (types.decimal(38, 0), [Decimal(10**38 - 1), Decimal(-(10**38 - 1)), Decimal(0)]),
    (types.decimal(38, 38), [Decimal("0." + "9" * 38), Decimal("-0." + "0" * 37 + "1")]),
    (types.decimal(10, 2), [Decimal("1.50"), Decimal("-12345678.90")]),
    (types.numeric(5, 1), [Decimal("1234.5")]),
    (types.money, [Decimal("-922337203685477.5808"), Decimal("922337203685477.5807"), Decimal("0.0001")]),
    (types.smallmoney, [Decimal("-214748.3648"), Decimal("214748.3647")]),
    (types.float, [1.0 / 3, -2.2250738585072014e-308, 5e-324, 1.7976931348623157e308, -0.0]),
    (types.real, [struct.unpack("<f", struct.pack("<f", 1 / 3))[0], 3.4028234663852886e38]),
    (types.date, [dt.date(1, 1, 1), dt.date(9999, 12, 31)]),
    (types.time(7), [SqlTime(0), SqlTime(86_400 * 10**7 - 1)]),
    (types.time(0), [SqlTime(86_399 * 10**7)]),
    (types.datetime2(7), [SqlDateTime2(dt.date(1, 1, 1), 0), SqlDateTime2(dt.date(9999, 12, 31), 86_400 * 10**7 - 1)]),
    (types.datetime2(3), [SqlDateTime2(dt.date(2026, 10, 16), 123_4560_000)]),
    (types.datetimeoffset(7), [SqlDateTimeOffset(dt.date(2026, 10, 16), 1, 840), SqlDateTimeOffset(dt.date(1, 1, 1), 840 * 60 * 10**7, -840)]),
    (types.datetime, [SqlDateTime(-53_690, 0), SqlDateTime(2_958_463, 300 * 86_400 - 1), SqlDateTime(0, 1)]),
    (types.smalldatetime, [dt.datetime(1900, 1, 1), dt.datetime(2079, 6, 6, 23, 59)]),
    (types.char(4), ["ab  "]),
    (types.varchar(10), ["", "€\x81ÿ"]),
    (types.nchar(2), ["\ud800x"]),  # an unpaired surrogate, which SQL Server stores
    (types.nvarchar(4000), ["😀" * 2000]),
    (types.binary(3), [b"\x00\x01\x02"]),
    (types.varbinary(8000), [b"", bytes(range(256)) * 31]),
    (types.uniqueidentifier, [uuid.UUID("01234567-89ab-cdef-0123-456789abcdef")]),
]


@pytest.mark.parametrize("sql_type, values", EXACT, ids=[str(t) for t, _ in EXACT])
def test_every_value_comes_back_exactly(sql_type, values):
    for value in [*values, None]:
        got = round_trip(sql_type, value)
        assert got == value and type(got) is type(value), (sql_type, value, got)
        if isinstance(value, Decimal):
            assert got.as_tuple() == value.as_tuple() or got.as_tuple().exponent == -sql_type.scale


def test_negative_zero_survives_as_a_float():
    assert math.copysign(1, round_trip(types.float, -0.0)) == -1


REFUSED = [
    (types.tinyint, -1), (types.int, 2**31), (types.int, 1.0), (types.int, True), (types.bit, 1),
    (types.decimal(10, 2), Decimal("1.234")), (types.decimal(3, 0), Decimal(1000)), (types.decimal(10, 2), 1.5),
    (types.money, Decimal("0.00001")), (types.smallmoney, Decimal("214748.3648")),
    (types.real, 0.1), (types.float, math.inf), (types.float, 2**53 + 1),
    (types.date, dt.datetime(2026, 1, 1)), (types.time(3), SqlTime(1)), (types.datetime2(0), dt.datetime(2026, 1, 1, 0, 0, 0, 1)),
    (types.datetimeoffset(7), dt.datetime(2026, 1, 1)), (types.datetime, dt.datetime(2026, 1, 1, 0, 0, 0, 1000)),
    (types.datetime, dt.datetime(1752, 12, 31)), (types.smalldatetime, dt.datetime(2026, 1, 1, 0, 0, 30)),
    (types.varchar(2), "abc"), (types.varchar(5), "Ā"), (types.nvarchar(1), "ab"), (types.binary(1), b"ab"),
    (types.uniqueidentifier, "01234567-89ab-cdef-0123-456789abcdef"),
]


@pytest.mark.parametrize("sql_type, value", REFUSED, ids=[f"{t}={v!r}"[:40] for t, v in REFUSED])
def test_a_value_that_doesnt_fit_is_refused_not_rounded(sql_type, value):
    with pytest.raises(ValueRefused):
        if isinstance(sql_type, types.Character):
            sql_type.check(value, LATIN1)
        else:
            sql_type.check(value)


def test_python_values_are_accepted_where_exact():
    assert round_trip(types.time(6), dt.time(12, 34, 56, 789012)) == SqlTime.from_python(dt.time(12, 34, 56, 789012))
    assert round_trip(types.datetime, dt.datetime(2026, 10, 16, 12, 0, 0, 10_000)) == SqlDateTime(46_309, 12 * 3600 * 300 + 3)
    zone = dt.timezone(dt.timedelta(hours=-5, minutes=-30))
    got = round_trip(types.datetimeoffset(7), dt.datetime(2026, 10, 16, 1, 2, 3, tzinfo=zone))
    assert got.to_python() == dt.datetime(2026, 10, 16, 1, 2, 3, tzinfo=zone) and str(got).endswith("-05:30")


def test_fixed_size_codes_read_as_the_same_types():
    def column(data: bytes):
        r = Reader(data, record=False)
        t = r.read(Field("type", TypeInfo()))
        return t, t.read_value(r)

    assert column(b"\x38" + (-5).to_bytes(4, "little", signed=True)) == (types.int, -5)
    assert column(b"\x30\xff") == (types.tinyint, 255)
    assert column(b"\x32\x01") == (types.bit, True)
    assert column(b"\x3e" + struct.pack("<d", 2.5)) == (types.float, 2.5)
    assert column(b"\x7a" + (12345).to_bytes(4, "little", signed=True)) == (types.smallmoney, Decimal("1.2345"))
    assert column(b"\x3d" + (1).to_bytes(4, "little") + (2).to_bytes(4, "little")) == (types.datetime, SqlDateTime(1, 2))
    assert column(b"\x3a" + (1).to_bytes(2, "little") + (61).to_bytes(2, "little")) == (types.smalldatetime, dt.datetime(1900, 1, 2, 1, 1))


def test_a_decimal_value_may_be_shorter_than_its_precisions_maximum():  # MS-TDS §2.2.5.5.1.6
    r = Reader(b"\x6a\x11\x26\x02" + b"\x05\x01" + (150).to_bytes(4, "little"), record=False)
    t = r.read(Field("type", TypeInfo()))
    assert t == types.decimal(38, 2) and t.read_value(r) == Decimal("1.50")


def test_legacy_codes_are_refused_by_name():
    for code in (b"\x27", b"\x3f"):
        with pytest.raises(Exception, match="older clients"):
            Reader(code + bytes(8), record=False).read(Field("type", TypeInfo()))


# --------------------------------------------------------------------------- collations


def test_a_collations_bytes_name_its_code_page():
    assert (LATIN1.locale, LATIN1.sort_id, LATIN1.code_page) == (0x0409, 52, 1252)
    assert JAPANESE.code_page == 932 and UTF8.code_page == 65001


def test_an_unknown_collation_fails_clearly():
    unknown = Collation(bytes.fromhex("99 99 0F 00 00"))
    with pytest.raises(UnknownCollation, match=r"99 99 0f 00 00 \(locale id 0xf9999, sort id 0\).*generate_collations"):
        unknown.code_page


def test_every_single_byte_goes_back_exactly_in_every_single_byte_code_page():
    for page in (437, 850, 874, 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258):
        codec = types.code_page(page)
        text = codec.decode(bytes(range(256)))
        assert len(text) == 256 and codec.encode(text) == bytes(range(256)), page


def test_sql_servers_own_characters_where_python_has_none():
    assert LATIN1.decode(b"\x81\x8d\x8f\x90\x9d") == "\x81\x8d\x8f\x90\x9d"  # C1 controls
    assert types.code_page(874).decode(b"\xdb") == ""  # a private-use character


def test_a_duplicate_encoding_is_carried_as_escapes_so_its_bytes_come_back():
    # U+7E8A has two cp932 encodings. SQL Server writes it as FA5C, so ED40 is carried as escapes.
    assert JAPANESE.decode(b"\xfa\x5c") == "纊" and JAPANESE.encode("纊") == b"\xfa\x5c"
    assert JAPANESE.decode(b"\xed\x40") == "\udced\udc40" and JAPANESE.encode("\udced\udc40") == b"\xed\x40"


def test_utf8_bytes_sql_server_stores_but_python_refuses_come_back():
    for stored in (b"\xffA", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", "é😀".encode()):
        assert UTF8.encode(UTF8.decode(stored)) == stored


def test_a_character_the_code_page_cant_hold_is_refused():
    with pytest.raises(ValueRefused, match="1252"):
        LATIN1.encode("Ā")
    with pytest.raises(ValueRefused):
        types.varchar(10).check("日本", LATIN1)
    types.varchar(10).check("日本", JAPANESE)


# --------------------------------------------------------------------------- exact time values


def test_time_values_convert_to_python_exactly_or_refuse():
    assert SqlTime(10).to_python() == dt.time(0, 0, 0, 1)
    with pytest.raises(ValueRefused, match="round_to_microseconds"):
        SqlTime(1).to_python()
    assert SqlTime(5).to_python(round_to_microseconds=True) == dt.time(0, 0, 0, 0)
    assert SqlDateTime(0, 3).to_python() == dt.datetime(1900, 1, 1, 0, 0, 0, 10_000)
    with pytest.raises(ValueRefused):
        SqlDateTime(0, 1).to_python()
    assert str(SqlDateTime2(dt.date(2026, 10, 16), 1)) == "2026-10-16 00:00:00.0000001"
    assert str(SqlDateTimeOffset(dt.date(2026, 10, 16), 0, -330)) == "2026-10-15 18:30:00.0000000 -05:30"


# --------------------------------------------------------------------------- sql_variant (M5)


VARIANTS = [
    (types.tinyint, 255), (types.bigint, -(2**63)), (types.bit, True), (types.real, 1.5), (types.float, -1e300),
    (types.money, Decimal("-922337203685477.5808")), (types.smallmoney, Decimal("1.2345")),
    (types.decimal(38, 10), Decimal("-1234567890123456789012345678.0123456789")), (types.numeric(10, 2), Decimal("1.50")),
    (types.datetime, SqlDateTime(1, 2)), (types.smalldatetime, dt.datetime(2026, 10, 16, 12, 34)),
    (types.date, dt.date(9999, 12, 31)), (types.time(7), SqlTime(1)), (types.datetime2(3), SqlDateTime2(dt.date(1, 1, 1), 10_000)),
    (types.datetimeoffset(7), SqlDateTimeOffset(dt.date(2026, 10, 16), 1, -330)),
    (types.uniqueidentifier, uuid.UUID(int=1)), (types.binary(4), b"\x00\x01\x02\x03"), (types.varbinary(10), b"\xff"),
    (types.char(3, LATIN1), "ab "), (types.varchar(10, LATIN1), "€\x81"), (types.nchar(2), "\ud800x"), (types.nvarchar(10), "😀"),
]


@pytest.mark.parametrize("base, value", VARIANTS, ids=[str(b) for b, _ in VARIANTS])
def test_a_sql_variant_comes_back_with_its_base_type_and_value(base, value):
    got = round_trip(types.sql_variant, types.SqlVariant(base, value))
    assert type(got.type) is type(base) and got.value == value and type(got.value) is type(value)
    assert str(got.type) == str(base)


def test_a_sql_variant_refuses_what_it_cant_hold():
    for bad in (types.SqlVariant(types.int, None), types.SqlVariant(types.nvarchar(types.MAX), "x"),
                types.SqlVariant(types.xml, "<a/>"), 5):
        with pytest.raises(ValueRefused):
            types.sql_variant.check(bad, LATIN1)
