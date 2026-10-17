"""Tests of the short types against the live SQL Server 2025 (M2).

Values that the server generates are read exactly, as the server itself renders them. Every byte under every code page
decodes as the server reads it and encodes back unchanged.
"""

import asyncio
import datetime as dt
import struct
import uuid
from decimal import Decimal

import pytest

import tds
from conftest import fetch
from tds import types
from tds.types import SqlDateTime, SqlDateTime2, SqlDateTimeOffset, SqlTime

pytestmark = pytest.mark.live

COLUMNS = {  # name: (declaration, the value the server generates for each row)
    "ti": ("tinyint", "ABS(CHECKSUM(NEWID())) % 256"),
    "si": ("smallint", "CHECKSUM(NEWID()) % 32768"),
    "i": ("int", "CHECKSUM(NEWID())"),
    "bi": ("bigint", "CAST(CHECKSUM(NEWID()) AS bigint) * CHECKSUM(NEWID())"),
    "b": ("bit", "ABS(CHECKSUM(NEWID())) % 2"),
    "d": ("decimal(38, 10)", "CAST((RAND(CHECKSUM(NEWID())) - 0.5) * 1e20 AS decimal(38, 10))"),
    "n": ("numeric(10, 2)", "CAST((RAND(CHECKSUM(NEWID())) - 0.5) * 1e7 AS numeric(10, 2))"),
    "f": ("float", "(RAND(CHECKSUM(NEWID())) - 0.5) * POWER(CAST(10 AS float), ABS(CHECKSUM(NEWID())) % 600 - 300)"),
    "r": ("real", "CAST((RAND(CHECKSUM(NEWID())) - 0.5) * 1e6 AS real)"),
    "m": ("money", "CAST((RAND(CHECKSUM(NEWID())) - 0.5) * 1e12 AS money)"),
    "sm": ("smallmoney", "CAST((RAND(CHECKSUM(NEWID())) - 0.5) * 1e5 AS smallmoney)"),
    "dt": ("date", "DATEADD(day, CHECKSUM(NEWID()) % 700000, CAST(SYSDATETIME() AS date))"),
    "t": ("time(7)", "CAST(DATEADD(nanosecond, ABS(CHECKSUM(NEWID())) % 1000000000, SYSDATETIME()) AS time(7))"),
    "t3": ("time(3)", "CAST(SYSDATETIME() AS time(3))"),
    "d2": ("datetime2(7)", "DATEADD(nanosecond, ABS(CHECKSUM(NEWID())) % 1000000000, SYSDATETIME())"),
    "dto": ("datetimeoffset(7)", "SWITCHOFFSET(SYSDATETIMEOFFSET(), CHECKSUM(NEWID()) % 841)"),
    "dtm": ("datetime", "DATEADD(millisecond, ABS(CHECKSUM(NEWID())) % 1000, GETDATE())"),
    "sdt": ("smalldatetime", "CAST(SYSDATETIME() AS smalldatetime)"),
    "c": ("char(10)", "CONVERT(char(10), CRYPT_GEN_RANDOM(10))"),
    "vc": ("varchar(50)", "CONVERT(varchar(50), CRYPT_GEN_RANDOM(1 + ABS(CHECKSUM(NEWID())) % 50))"),
    "nc": ("nchar(10)", "CONVERT(nchar(10), CRYPT_GEN_RANDOM(20))"),
    "nvc": ("nvarchar(50)", "CONVERT(nvarchar(50), CRYPT_GEN_RANDOM(2 * (1 + ABS(CHECKSUM(NEWID())) % 50)))"),
    "sn": ("sysname", "CONVERT(nvarchar(64), CRYPT_GEN_RANDOM(128))"),
    "bn": ("binary(8)", "CRYPT_GEN_RANDOM(8)"),
    "vb": ("varbinary(50)", "CRYPT_GEN_RANDOM(1 + ABS(CHECKSUM(NEWID())) % 50)"),  # CRYPT_GEN_RANDOM(0) gives NULL
    "g": ("uniqueidentifier", "NEWID()"),
}
LIMITS = {  # each type's minimum and maximum, as literals the server parses
    "ti": ("0", "255"), "si": ("-32768", "32767"), "i": ("-2147483648", "2147483647"),
    "bi": ("-9223372036854775808", "9223372036854775807"), "b": ("0", "1"),
    "d": ("-9999999999999999999999999999.9999999999", "9999999999999999999999999999.9999999999"),
    "n": ("-99999999.99", "99999999.99"), "f": ("-1.79E+308", "2.23E-308"), "r": ("-3.40E+38", "1.18E-38"),
    "m": ("-922337203685477.5808", "922337203685477.5807"), "sm": ("-214748.3648", "214748.3647"),
    "dt": ("'0001-01-01'", "'9999-12-31'"), "t": ("'00:00:00'", "'23:59:59.9999999'"), "t3": ("'00:00:00'", "'23:59:59.999'"),
    "d2": ("'0001-01-01'", "'9999-12-31 23:59:59.9999999'"),
    "dto": ("'0001-01-01 14:00:00 +14:00'", "'9999-12-31 09:59:59.9999999 -14:00'"),
    "dtm": ("'1753-01-01'", "'9999-12-31 23:59:59.997'"), "sdt": ("'1900-01-01'", "'2079-06-06 23:59'"),
    "c": ("''", "REPLICATE(CHAR(255), 10)"), "vc": ("''", "REPLICATE(CHAR(255), 50)"), "nc": ("N''", "REPLICATE(NCHAR(65535), 10)"),
    "nvc": ("N''", "REPLICATE(NCHAR(65535), 50)"), "sn": ("N''", "REPLICATE(NCHAR(65535), 128)"),
    "bn": ("0x0000000000000000", "0xFFFFFFFFFFFFFFFF"), "vb": ("0x", "CAST(REPLICATE(CHAR(255), 50) AS varbinary(50))"),
    "g": ("'00000000-0000-0000-0000-000000000000'", "'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF'"),
}
RENDERED = {  # how the server itself renders each column exactly, to compare with what the driver read
    "ti": "CAST(ti AS nvarchar(40))", "si": "CAST(si AS nvarchar(40))", "i": "CAST(i AS nvarchar(40))",
    "bi": "CAST(bi AS nvarchar(40))", "b": "CAST(b AS nvarchar(1))", "d": "CAST(d AS nvarchar(60))",
    "n": "CAST(n AS nvarchar(60))", "f": "CONVERT(nvarchar(40), f, 3)", "r": "CONVERT(nvarchar(40), r, 3)",
    "m": "CONVERT(nvarchar(40), m, 2)", "sm": "CONVERT(nvarchar(40), sm, 2)", "dt": "CONVERT(nvarchar(10), dt, 23)",
    "t": "CAST(DATEDIFF_BIG(nanosecond, CAST('00:00' AS time(7)), t) / 100 AS nvarchar(40))",
    "t3": "CAST(DATEDIFF_BIG(nanosecond, CAST('00:00' AS time(7)), t3) / 100 AS nvarchar(40))",
    "d2": "CONVERT(nvarchar(40), d2, 121)", "dto": "CONVERT(nvarchar(50), dto, 121)",
    # dtm: in the driver's sessions, NULL + ' ' is ' '
    "dtm": "CASE WHEN dtm IS NOT NULL THEN CAST(DATEDIFF(day, '19000101', dtm) AS nvarchar(20)) + N' ' "
           "+ CAST(CAST(SUBSTRING(CAST(dtm AS binary(8)), 5, 4) AS int) AS nvarchar(20)) END",
    "sdt": "CONVERT(nvarchar(20), sdt, 120)",
    # the exact bytes, through binary(n) and DATALENGTH, because converting to varbinary drops trailing zero bytes
    "c": "LEFT(CONVERT(nvarchar(600), CAST(c AS binary(10)), 2), 2 * DATALENGTH(c))", "vc": "LEFT(CONVERT(nvarchar(600), CAST(vc AS binary(50)), 2), 2 * DATALENGTH(vc))", "nc": "LEFT(CONVERT(nvarchar(600), CAST(nc AS binary(20)), 2), 2 * DATALENGTH(nc))", "nvc": "LEFT(CONVERT(nvarchar(600), CAST(nvc AS binary(100)), 2), 2 * DATALENGTH(nvc))",
    "sn": "LEFT(CONVERT(nvarchar(600), CAST(sn AS binary(256)), 2), 2 * DATALENGTH(sn))", "bn": "CONVERT(nvarchar(40), bn, 2)", "vb": "LEFT(CONVERT(nvarchar(600), CAST(vb AS binary(50)), 2), 2 * DATALENGTH(vb))", "g": "CAST(g AS nvarchar(36))",
}


def rendered(name: str, column, value) -> str:
    """The driver's value, rendered as the server's expression in RENDERED renders it."""
    match value:
        case bool():
            return str(int(value))
        case float() if name == "r":
            return value  # compared numerically below
        case float():
            return value
        case SqlTime():
            return str(value.ticks)
        case SqlDateTime2() | SqlDateTimeOffset():
            return str(value)
        case SqlDateTime():
            return f"{value.days} {value.ticks}"
        case dt.datetime():
            return value.strftime("%Y-%m-%d %H:%M:%S")
        case dt.date():
            return value.isoformat()
        case uuid.UUID():
            return str(value).upper()
        case bytes():
            return value.hex().upper()
        case str() if column.type.unicode:
            return value.encode("utf-16-le", "surrogatepass").hex().upper()
        case str():
            return column.type.collation.encode(value).hex().upper()
        case _:
            return str(value)


def run(coroutine):
    return asyncio.run(coroutine)


async def shop(channel) -> None:
    await fetch(channel, "IF DB_ID('tds_test') IS NULL CREATE DATABASE tds_test")
    await fetch(channel, "USE tds_test; IF SCHEMA_ID('shop') IS NULL EXEC('CREATE SCHEMA shop')")
    for table, null in (("short_types_not_null", "NOT NULL"), ("short_types_nullable", "NULL")):
        columns = ", ".join(f"{name} {declared} {null}" for name, (declared, _) in COLUMNS.items())
        await fetch(channel, f"DROP TABLE IF EXISTS shop.{table}; CREATE TABLE shop.{table} (id int IDENTITY, {columns}, rv rowversion)")
        names = ", ".join(COLUMNS)
        generated = ", ".join(expr for _, expr in COLUMNS.values())
        await fetch(channel, f"INSERT shop.{table} ({names}) SELECT TOP 200 {generated} FROM sys.all_objects")
        for side in (0, 1):
            await fetch(channel, f"INSERT shop.{table} ({names}) VALUES ({', '.join(LIMITS[n][side] for n in COLUMNS)})")
    await fetch(channel, f"INSERT shop.short_types_nullable ({', '.join(COLUMNS)}) VALUES ({', '.join('NULL' for _ in COLUMNS)})")


@pytest.mark.parametrize("table", ["short_types_not_null", "short_types_nullable"])
def test_every_short_type_is_read_exactly(server, table):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await shop(channel)
                values = ", ".join(COLUMNS)
                checks = ", ".join(f"{RENDERED[n]} AS [{n}?]" for n in COLUMNS)
                return await fetch(channel, f"SELECT {values}, rv, {checks} FROM shop.{table}")

    fetched = run(go())
    rs = fetched.result_sets[0]
    count = len(COLUMNS)
    by_name = {c.name: c for c in rs.columns}
    expected = {"ti": types.tinyint, "si": types.smallint, "i": types.int, "bi": types.bigint, "b": types.bit,
                "d": types.decimal(38, 10), "n": types.numeric(10, 2), "f": types.float, "r": types.real,
                "m": types.money, "sm": types.smallmoney, "dt": types.date, "t": types.time(7), "t3": types.time(3),
                "d2": types.datetime2(7), "dto": types.datetimeoffset(7), "dtm": types.datetime,
                "sdt": types.smalldatetime, "bn": types.binary(8), "vb": types.varbinary(50), "g": types.uniqueidentifier}
    for name, sql_type in expected.items():
        assert by_name[name].type == sql_type, name
        assert by_name[name].nullable == (table == "short_types_nullable"), name
    assert str(by_name["vc"].type) == "varchar(50)" and by_name["vc"].type.collation.code_page == 1252
    assert by_name["sn"].user_type == 256 and str(by_name["sn"].type) == "nvarchar(128)"  # sysname
    assert by_name["rv"].user_type == 80 and by_name["rv"].type == types.binary(8)  # rowversion
    if table == "short_types_not_null":
        assert by_name["i"].type.code == types.TypeCode.INT and by_name["dtm"].type.code == types.TypeCode.DATETIME

    assert len(rs.rows) == 202 + (table == "short_types_nullable")
    for row in rs.rows:
        values, checks = row[:count], row[count + 1:]
        if all(v is None for v in values):
            assert {n: c for n, c in zip(COLUMNS, checks) if c is not None} == {}
            continue
        for (name, value), check in zip(zip(COLUMNS, values), checks):
            mine = rendered(name, by_name[name], value)
            if name == "f":
                assert value == float(check), (name, value, check)
            elif name == "r":
                assert value == struct.unpack("<f", struct.pack("<f", float(check)))[0], (name, value, check)
            else:
                assert mine == check, (name, value, mine, check)


CODE_PAGES = {437: "SQL_Latin1_General_CP437_BIN", 850: "SQL_1xCompat_CP850_CI_AS", 874: "Thai_BIN",
              932: "Japanese_BIN", 936: "Chinese_PRC_BIN", 949: "Korean_90_BIN", 950: "Chinese_Hong_Kong_Stroke_90_BIN",
              1250: "Albanian_BIN", 1251: "Cyrillic_General_CI_AS", 1252: "Latin1_General_CI_AS", 1253: "Greek_BIN",
              1254: "Turkish_CI_AS", 1255: "Hebrew_BIN", 1256: "Arabic_BIN", 1257: "Estonian_BIN", 1258: "Vietnamese_BIN"}
NUMBERS = "SELECT TOP 256 ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1 AS n FROM sys.all_objects"
SEQUENCES = (f"SELECT CAST(CAST(n AS tinyint) AS varbinary(1)) FROM ({NUMBERS}) AS d UNION ALL "  # varbinary: no padding
             f"SELECT CAST(CAST(a.n AS tinyint) AS binary(1)) + CAST(CAST(b.n AS tinyint) AS binary(1)) "
             f"FROM ({NUMBERS}) AS a CROSS JOIN ({NUMBERS}) AS b WHERE a.n >= 0x81 AND b.n >= 0x40")


@pytest.mark.parametrize("page", sorted(CODE_PAGES))
def test_every_byte_sequence_decodes_as_the_server_reads_it_and_goes_back_unchanged(server, page):
    collation = CODE_PAGES[page]

    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                return await fetch(channel, f"""
                    SET NOCOUNT ON;
                    DECLARE @t TABLE (b varbinary(2), v varchar(2) COLLATE {collation});
                    INSERT @t SELECT b, b FROM ({SEQUENCES}) AS s(b) WHERE {'1 = 1' if page in (932, 936, 949, 950) else 'DATALENGTH(b) = 1'};
                    DELETE @t WHERE CAST(v AS varbinary(2)) <> b OR DATALENGTH(v) <> DATALENGTH(b);  -- binary = pads with zeros
                    DECLARE @u TABLE (b varbinary(2), back varchar(2) COLLATE {collation});
                    INSERT @u SELECT b, CAST(v AS nvarchar(2)) FROM @t;
                    SELECT t.v, t.b, CAST(t.v AS nvarchar(2)), CAST(u.back AS varbinary(2))
                    FROM @t AS t JOIN @u AS u ON u.b = t.b AND DATALENGTH(u.b) = DATALENGTH(t.b)""")

    fetched = run(go())
    column = fetched.result_sets[0].columns[0]
    assert column.type.collation.code_page == page
    rows = fetched.result_sets[0].rows
    assert len(rows) >= 128
    for text, stored, server_reads, server_writes in rows:
        assert column.type.collation.encode(text) == stored, (stored.hex(), text)  # goes back unchanged
        if server_writes == stored and len(server_reads) == 1:
            assert text == server_reads, (stored.hex(), text, server_reads)  # the server's own character


@pytest.mark.parametrize("utf8_support", [True, False], ids=["with UTF-8 support", "without"])
def test_utf8_values_and_invalid_bytes(server, utf8_support):
    """Valid UTF-8 round-trips exactly.

    SQL Server also stores some bytes that aren't valid UTF-8 (0xFF, an encoded surrogate, a code point past U+10FFFF).
    With the UTF-8 login feature (a default, D-8), it sends them as stored, and the driver carries them as escapes, so
    they encode back to the same bytes (D-48). Without the feature, it sends them with U+FFFD in their place. Those
    values can't come back exactly, and the driver shows what arrived.
    """
    valid = ["0x41", "0xC3A9", "0xF09F9880"]
    invalid = ["0xFF41", "0xEDA080", "0xF4908080"]
    features = [f for f in tds.DEFAULT_FEATURES if utf8_support or f is not tds.Feature.UTF8_SUPPORT]

    async def go():
        async with await tds.connect(**server, features=features) as connection:
            async with connection.serial_channel() as channel:
                values = ", ".join(f"({b})" for b in valid + invalid)
                return await fetch(channel, f"""
                    DECLARE @t TABLE (v varchar(8) COLLATE Latin1_General_100_CI_AS_SC_UTF8);
                    INSERT @t VALUES {values};
                    SELECT v, CAST(v AS varbinary(8)) FROM @t""")

    fetched = run(go())
    utf8 = fetched.result_sets[0].columns[0].type.collation
    assert utf8.code_page == 65001
    rows = fetched.result_sets[0].rows
    for text, raw in rows[: len(valid)]:
        assert utf8.encode(text) == raw
    for text, raw in rows[len(valid):]:
        if utf8_support:
            assert "\ufffd" not in text and utf8.encode(text) == raw  # as stored, so the same bytes go back
        else:
            assert "\ufffd" in text and utf8.encode(text) != raw  # stored as given, sent replaced


def test_nvarchar_keeps_unpaired_surrogates(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                return await fetch(channel, "SELECT NCHAR(0xD800) + N'x' AS v, NCHAR(0xDFFF) AS w")

    assert run(go()).result_sets[0].rows == (("\ud800x", "\udfff"),)
