"""Bulk load against the live SQL Server 2025 (M9, D-50).

Every type loads exactly, from a list or from a source. 1 GB loads in bounded memory. A failing source is abandoned.
The options behave as documented. Every bulk-load behavior on Requests › Edge cases holds, including the deviations
from MS-TDS.
"""

import asyncio
import hashlib
import io
import resource
import sys

import pytest

import tds
from conftest import fetch
from tds import types
from tds.observe import Level, Printer
from tds.packet import PacketType
from tds.requests import BULK_DONE, HEADERS, Encoded, headers
from tds.response import Column
from tds.tokens import ColumnFlags, DoneStatus
from test_calls_live import projection
from test_large_live import LARGE, exact as large_exact
from test_types_live import COLUMNS, LIMITS

pytestmark = pytest.mark.live
MAX = types.MAX


def run(coroutine):
    return asyncio.run(coroutine)


async def load(channel, statement: str, columns, rows) -> int:
    """A bulk load (the statement, then the rows). Returns the number of rows the server says it loaded."""
    await fetch(channel, tds.BulkInsert(statement))
    [done] = (await fetch(channel, tds.BulkRows(columns, rows))).completions
    return done.rows


async def columns_of(channel, sql: str) -> tuple:
    return (await fetch(channel, sql)).result_sets[0].columns


async def refused(channel, request) -> list[int]:
    with pytest.raises(tds.ServerError) as e:
        await fetch(channel, request)
    return [x.number for x in e.value.errors]


def as_(column: Column, sql_type) -> Column:
    """The same column, traveling as another type (Requests › Edge cases)."""
    return Column(column.name, sql_type, True, column.flags, 0)


# --------------------------------------------------------------------------- every type, exactly


@pytest.mark.parametrize("null", ["NULL", "NOT NULL"])
@pytest.mark.parametrize("given_as", ["list", "source"])
def test_every_short_type_loads_exactly(server, null, given_as):
    names = list(COLUMNS)
    declared = ", ".join(f"{n} {d} {null}" for n, (d, _) in COLUMNS.items())

    async def go():
        async with await tds.connect(**server, database="tds_test") as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "IF SCHEMA_ID('shop') IS NULL EXEC('CREATE SCHEMA shop')")
                await fetch(channel, "DROP TABLE IF EXISTS shop.bulk_source, shop.bulk_copy")
                await fetch(channel, f"CREATE TABLE shop.bulk_source (id int IDENTITY, {declared}); "
                                     f"CREATE TABLE shop.bulk_copy (id int NOT NULL, {declared})")
                generated = ", ".join(e for _, e in COLUMNS.values())
                await fetch(channel, f"INSERT shop.bulk_source ({', '.join(names)}) SELECT TOP 200 {generated} FROM sys.all_objects")
                for side in (0, 1):
                    await fetch(channel, f"INSERT shop.bulk_source ({', '.join(names)}) VALUES ({', '.join(LIMITS[n][side] for n in names)})")
                if null == "NULL":
                    await fetch(channel, f"INSERT shop.bulk_source ({', '.join(names)}) VALUES ({', '.join('NULL' for _ in names)})")
                rows = (await fetch(channel, f"SELECT id, {', '.join(names)} FROM shop.bulk_source ORDER BY id")).result_sets[0].rows
                columns = await columns_of(channel, f"SELECT TOP 0 id, {', '.join(names)} FROM shop.bulk_copy")

                async def produce():
                    for row in rows:
                        yield row

                count = await load(channel, f"INSERT BULK shop.bulk_copy (id int NOT NULL, {declared})", columns,
                                   rows if given_as == "list" else produce())
                exact = ", ".join(projection(n, COLUMNS[n][0]) for n in names)
                differences = await fetch(channel, f"""
                    SELECT COUNT(*) FROM (SELECT id, {exact} FROM shop.bulk_source EXCEPT SELECT id, {exact} FROM shop.bulk_copy) AS a;
                    SELECT COUNT(*) FROM (SELECT id, {exact} FROM shop.bulk_copy EXCEPT SELECT id, {exact} FROM shop.bulk_source) AS b""")
                copy = (await fetch(channel, f"SELECT id, {', '.join(names)} FROM shop.bulk_copy ORDER BY id")).result_sets[0].rows
                fixed = [str(c.type) for c in columns[1:] if c.type.code in types.FIXED_CODES]  # id is always NOT NULL
                return rows, copy, count, [rs.rows[0][0] for rs in differences.result_sets], fixed

    rows, copy, count, differences, fixed = run(go())
    assert count == len(rows) == (203 if null == "NULL" else 202) and differences == [0, 0] and copy == rows
    assert bool(fixed) == (null == "NOT NULL")  # NOT NULL columns were described with their fixed-size codes


SPECIAL = {  # name: (declared in the table, declared in INSERT BULK, a value the server generates)
    **{n: (d, {"xml": "xml", "text": "varchar(max)", "ntext": "nvarchar(max)", "image": "varbinary(max)"}.get(d, d), e)
       for n, (d, e) in LARGE.items()},
    "v": ("sql_variant", "sql_variant", "CAST(CHECKSUM(NEWID()) AS sql_variant)"),
    "j": ("json", "nvarchar(max)", "JSON_OBJECT('id': CAST(NEWID() AS nvarchar(36)), 'note': N'é😀')"),
    "vec": ("vector(3)", "vector(3)", "CAST(JSON_ARRAY(RAND(CHECKSUM(NEWID())), -RAND(CHECKSUM(NEWID())) * 1e30, 0.5) AS vector(3))"),
    "g": ("geography", "geography", "geography::Point(RAND(CHECKSUM(NEWID())) * 170 - 85, RAND(CHECKSUM(NEWID())) * 360 - 180, 4326)"),
    "h": ("hierarchyid", "varbinary(max)", "CAST('/' + CAST(ABS(CHECKSUM(NEWID())) % 100 AS varchar(10)) + '/' AS hierarchyid)"),
}
TRAVELS_AS = {"xml": types.nvarchar(MAX), "ntext": types.nvarchar(MAX), "image": types.varbinary(MAX),
              "json": types.nvarchar(MAX), "geography": types.varbinary(MAX), "hierarchyid": types.varbinary(MAX)}


def special_exact(name: str, declared: str) -> str:
    if declared in ("json", "vector(3)"):
        return f"CAST(CAST({name} AS nvarchar(max)) AS varbinary(max)) AS {name}_bytes"
    if declared == "sql_variant":
        return f"CAST(SQL_VARIANT_PROPERTY({name}, 'BaseType') AS nvarchar(20)) AS {name}_base, CONVERT(varbinary(8000), {name}) AS {name}_bytes"
    if declared in ("geography", "hierarchyid"):
        return f"CAST({name} AS varbinary(max)) AS {name}_bytes"
    return large_exact(name, declared)


def test_large_and_special_types_load_exactly(server):
    names = list(SPECIAL)

    async def go():
        async with await tds.connect(**server, database="tds_test") as connection:
            async with connection.serial_channel() as channel:
                table = ", ".join(f"{n} {d}" for n, (d, _, _) in SPECIAL.items())
                await fetch(channel, f"CREATE TABLE #source (id int IDENTITY, {table}); CREATE TABLE #copy (id int NOT NULL, {table})")
                await fetch(channel, f"INSERT #source ({', '.join(names)}) SELECT TOP 20 {', '.join(e for _, _, e in SPECIAL.values())} FROM sys.all_objects")
                await fetch(channel, f"INSERT #source ({', '.join(names)}) VALUES ({', '.join('NULL' for _ in names)})")
                rows = (await fetch(channel, f"SELECT id, {', '.join(names)} FROM #source ORDER BY id")).result_sets[0].rows
                columns = await columns_of(channel, f"SELECT TOP 0 id, {', '.join(names)} FROM #copy")
                travelling = [columns[0]] + [
                    as_(c, types.varchar(MAX, collation=c.type.collation) if d == "text" else TRAVELS_AS[d]) if d in TRAVELS_AS or d == "text" else c
                    for c, (d, _, _) in zip(columns[1:], SPECIAL.values())]
                statement = f"INSERT BULK #copy (id int NOT NULL, {', '.join(f'{n} {b}' for n, (_, b, _) in SPECIAL.items())})"
                count = await load(channel, statement, travelling, rows)
                exact = ", ".join(["id"] + [special_exact(n, d) for n, (d, _, _) in SPECIAL.items()])
                differences = await fetch(channel, f"""
                    SELECT COUNT(*) FROM (SELECT {exact} FROM #source EXCEPT SELECT {exact} FROM #copy) AS a;
                    SELECT COUNT(*) FROM (SELECT {exact} FROM #copy EXCEPT SELECT {exact} FROM #source) AS b""")
                copy = (await fetch(channel, f"SELECT id, {', '.join(names)} FROM #copy ORDER BY id")).result_sets[0].rows
                return rows, copy, count, [rs.rows[0][0] for rs in differences.result_sets]

    rows, copy, count, differences = run(go())
    assert count == len(rows) == 21 and differences == [0, 0] and copy == rows


# --------------------------------------------------------------------------- streaming and abandoning


def test_a_gigabyte_loads_from_a_source_in_bounded_memory(server):  # Done When M9 item 2
    def peak() -> int:  # bytes on macOS, kilobytes on Linux
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return rss if sys.platform == "darwin" else rss * 1024

    block = bytes(range(256)) * 4096  # 1 MB
    count = 1024

    async def rows():
        for n in range(count):
            yield (n, block)

    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE #big (n int NOT NULL, b varbinary(max))")
                columns = await columns_of(channel, "SELECT TOP 0 n, b FROM #big")
                before = peak()
                loaded = await load(channel, "INSERT BULK #big (n int NOT NULL, b varbinary(max)) WITH (TABLOCK)", columns, rows())
                grew = peak() - before
                check = (await fetch(channel, "SELECT COUNT(*), SUM(CAST(DATALENGTH(b) AS bigint)), COUNT(DISTINCT HASHBYTES('SHA2_256', b)), "
                                              "MIN(HASHBYTES('SHA2_256', b)) FROM #big")).result_sets[0].rows[0]
                return loaded, check, grew

    loaded, (rows_, size, distinct, digest), grew = run(go())
    assert loaded == rows_ == count and size == count * len(block) == 1024 ** 3
    assert distinct == 1 and digest == hashlib.sha256(block).digest()
    assert grew < 200 * 1024 * 1024, f"memory grew by {grew:,} bytes"


def test_a_failing_source_is_abandoned_and_nothing_loads(server):
    async def failing():
        for n in range(5000):  # more rows than one packet holds, before it fails
            yield (n,)
        raise OSError("disk failed")

    shown = io.StringIO()

    async def go():
        async with await tds.connect(**server, observe=Printer(Level.OUTLINE, shown)) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE #b (n int NOT NULL)")
                columns = await columns_of(channel, "SELECT TOP 0 n FROM #b")
                await fetch(channel, tds.BulkInsert("INSERT BULK #b (n int NOT NULL)"))
                with pytest.raises(OSError, match="disk failed"):
                    await channel.exchange(tds.BulkRows(columns, failing()))
                after = (await fetch(channel, "SELECT COUNT(*) FROM #b")).result_sets[0].rows  # the channel is free
                again = await load(channel, "INSERT BULK #b (n int NOT NULL)", columns, [(1,), (2,)])  # and works
                return after, again

    after, again = run(go())
    assert after == ((0,),) and again == 2
    out = shown.getvalue()
    answer = out[out.index("request abandoned · ignore + last"):].splitlines()[1]
    assert "← response" in answer and answer.split(" · ")[3] == "INFO DONE"  # MS-TDS says a DONE alone, but SQL Server
    # also sends message 3621, "The statement has been terminated"


# --------------------------------------------------------------------------- the options


def test_the_options(server):
    async def go():
        async with await tds.connect(**server, database="tds_test") as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "IF SCHEMA_ID('shop') IS NULL EXEC('CREATE SCHEMA shop')")
                await fetch(channel, "DROP TABLE IF EXISTS shop.bulk_checked, shop.bulk_triggered, shop.bulk_log, shop.bulk_ordered")
                await fetch(channel, "CREATE TABLE shop.bulk_checked (a int CONSTRAINT bulk_positive CHECK (a > 0), d int DEFAULT 5); "
                                     "CREATE TABLE shop.bulk_triggered (a int); CREATE TABLE shop.bulk_log (n int); "
                                     "CREATE TABLE shop.bulk_ordered (id int NOT NULL PRIMARY KEY CLUSTERED)")
                await fetch(channel, "CREATE TRIGGER shop.bulk_logger ON shop.bulk_triggered AFTER INSERT AS "
                                     "INSERT shop.bulk_log SELECT COUNT(*) FROM inserted")
                checked = await columns_of(channel, "SELECT TOP 0 a, d FROM shop.bulk_checked")
                out = {}
                await fetch(channel, tds.BulkInsert("INSERT BULK shop.bulk_checked (a int, d int) WITH (CHECK_CONSTRAINTS)"))
                out["CHECK_CONSTRAINTS"] = await refused(channel, tds.BulkRows(checked, [(1, 1), (-1, 1)]))
                out["without CHECK_CONSTRAINTS"] = await load(channel, "INSERT BULK shop.bulk_checked (a int, d int)", checked, [(-1, 1)])
                out["constraint not trusted afterwards"] = (await fetch(channel, "SELECT is_not_trusted FROM sys.check_constraints "
                                                                             "WHERE name = 'bulk_positive'")).result_sets[0].rows[0][0]
                await fetch(channel, "TRUNCATE TABLE shop.bulk_checked")
                await load(channel, "INSERT BULK shop.bulk_checked (a int, d int) WITH (KEEP_NULLS)", checked, [(1, None)])
                await load(channel, "INSERT BULK shop.bulk_checked (a int, d int)", checked, [(2, None)])
                out["KEEP_NULLS"] = (await fetch(channel, "SELECT a, d FROM shop.bulk_checked ORDER BY a")).result_sets[0].rows
                triggered = await columns_of(channel, "SELECT TOP 0 a FROM shop.bulk_triggered")
                await load(channel, "INSERT BULK shop.bulk_triggered (a int)", triggered, [(1,), (2,)])
                await load(channel, "INSERT BULK shop.bulk_triggered (a int) WITH (FIRE_TRIGGERS)", triggered, [(3,), (4,), (5,)])
                out["FIRE_TRIGGERS"] = (await fetch(channel, "SELECT n FROM shop.bulk_log")).result_sets[0].rows
                ordered = await columns_of(channel, "SELECT TOP 0 id FROM shop.bulk_ordered")
                out["ORDER, in order"] = await load(channel, "INSERT BULK shop.bulk_ordered (id int NOT NULL) WITH (ORDER (id ASC))",
                                                    ordered, [(1,), (2,), (3,)])
                await fetch(channel, tds.BulkInsert("INSERT BULK shop.bulk_ordered (id int NOT NULL) WITH (ORDER (id ASC))"))
                out["ORDER, out of order"] = await refused(channel, tds.BulkRows(ordered, [(5,), (4,)]))
                out["TABLOCK, ROWS_PER_BATCH, KILOBYTES_PER_BATCH"] = await load(
                    channel, "INSERT BULK shop.bulk_triggered (a int) WITH (TABLOCK, ROWS_PER_BATCH = 2, KILOBYTES_PER_BATCH = 1)",
                    triggered, [(6,), (7,)])
                await fetch(channel, "DROP TABLE shop.bulk_checked, shop.bulk_triggered, shop.bulk_log, shop.bulk_ordered")
                return out

    out = run(go())
    assert out["CHECK_CONSTRAINTS"] == [547]  # checked, so the load fails and loads nothing
    assert out["without CHECK_CONSTRAINTS"] == 1 and out["constraint not trusted afterwards"] is True  # loaded unchecked
    assert out["KEEP_NULLS"] == ((1, None), (2, 5))  # without it, NULL becomes the column's default
    assert out["FIRE_TRIGGERS"] == ((3,),)  # triggers fire only when asked, once per load
    assert out["ORDER, in order"] == 3 and 4819 in out["ORDER, out of order"]
    assert out["TABLOCK, ROWS_PER_BATCH, KILOBYTES_PER_BATCH"] == 2


# --------------------------------------------------------------------------- the server's rules (Requests › Edge cases)


class Raw:
    """A request built by hand, to show what the server does with a request the driver itself would refuse."""

    metadata = ()

    def __init__(self, kind, body: bytes, continues=None, with_headers=False):
        self.kind, self.label, self.body, self.continues, self.with_headers = kind, "by hand", body, continues, with_headers

    def encode(self, context, record):
        return Encoded((HEADERS.encode(headers(context), False)[0] if self.with_headers else b"") + self.body, None)


INT = Column("a", types.int, True, ColumnFlags.NULLABLE, 0)  # nullable: the code with a length
COLMETA_INT = bytes.fromhex("81 01 00 00 00 00 00 01 00 26 04 01 61 00")


def test_bulk_data_out_of_turn_closes_the_connection(server):
    async def go():
        out = {}
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE #b (a int)")
                fetched = await fetch(channel, Raw(PacketType.BULK_LOAD, COLMETA_INT + BULK_DONE))  # no INSERT BULK
                out["alone"] = [DoneStatus.ERROR in c.status for c in fetched.completions]
                with pytest.raises(ConnectionError):
                    await fetch(channel, "SELECT 1")
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE #b (a int)")
                await fetch(channel, tds.BulkInsert("INSERT BULK #b (a int)"))
                between = Raw(PacketType.SQL_BATCH, "SELECT 2".encode("utf-16-le"), continues="bulk load", with_headers=True)
                out["between"] = await refused(channel, between)
                await fetch(channel, Raw(PacketType.BULK_LOAD, COLMETA_INT + BULK_DONE))
                with pytest.raises(ConnectionError):
                    await fetch(channel, "SELECT 1")
        return out

    out = run(go())
    assert out["alone"] == [True]  # a DONE marked error, then the server closes the connection
    assert out["between"] == [4022]  # "bulk load data was expected but not sent", and the bulk load ends


def test_the_columns_must_match_the_statement(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                out = {}
                await fetch(channel, "CREATE TABLE #b (a int, b int); CREATE TABLE #n (a int NOT NULL)")
                for label, statement, columns, rows in (
                        ("a different type", "INSERT BULK #b (a int, b int)", [as_(INT, types.bigint), INT], [(1, 2)]),
                        ("the wrong code for its nullability", "INSERT BULK #n (a int NOT NULL)", [INT], [(1,)]),
                        ("a column missing", "INSERT BULK #b (a int, b int)", [INT], [(1,)]),
                        ("an empty name", "INSERT BULK #b (a int, b int)", [INT, Column("", types.int, True, ColumnFlags.NULLABLE, 0)], [(1, 2)])):
                    await fetch(channel, tds.BulkInsert(statement))
                    out[label] = await refused(channel, tds.BulkRows(columns, rows))
                other_names = [Column("x", types.int, True, ColumnFlags.NULLABLE, 0), Column("y", types.int, True, ColumnFlags.NULLABLE, 0)]
                out["other names"] = await load(channel, "INSERT BULK #b (a int, b int)", other_names, [(1, 2)])
                out["stored"] = (await fetch(channel, "SELECT a, b FROM #b")).result_sets[0].rows
                return out

    out = run(go())
    assert out["a different type"] == [4815] and out["the wrong code for its nullability"] == [4816]
    assert out["a column missing"] == [4804] and out["an empty name"] == [4804]
    assert out["other names"] == 1 and out["stored"] == ((1, 2),)  # names are ignored, and columns match by position


def test_types_that_travel_as_another(server):
    def text(name, sql_type):
        return Column(name, sql_type, True, ColumnFlags.NULLABLE, 0)

    cases = [  # column, statement's declaration, data's type, expected
        ("xml", "xml", types.nvarchar(MAX), "loads"), ("xml", "nvarchar(max)", types.nvarchar(MAX), "loads"), ("xml", "xml", types.xml, 4816),
        ("text", "varchar(max)", types.varchar(MAX), "loads"), ("text", "text", types.varchar(MAX), 4816),
        ("ntext", "nvarchar(max)", types.nvarchar(MAX), "loads"), ("ntext", "ntext", types.nvarchar(MAX), 4816),
        ("image", "varbinary(max)", types.varbinary(MAX), "loads"), ("image", "image", types.varbinary(MAX), 4816),
        ("json", "nvarchar(max)", types.nvarchar(MAX), "loads"), ("json", "json", types.nvarchar(MAX), 4816), ("json", "json", types.json, 4816),
        ("geography", "geography", types.varbinary(MAX), "loads"), ("geography", "varbinary(max)", types.varbinary(MAX), "loads"),
    ]
    values = {"xml": "<a>é</a>", "text": "t" * 9000, "ntext": "é" * 5000, "image": b"\x01" * 9000, "json": '{"a":"é"}'}

    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                coll = types.Collation(connection.session.collation)
                point = (await fetch(channel, "SELECT CAST(geography::Point(47.6, -122.3, 4326) AS varbinary(max))")).result_sets[0].rows[0][0]
                out = []
                for column, declared, data, _ in cases:
                    await fetch(channel, f"DROP TABLE IF EXISTS #b; CREATE TABLE #b (c {column})")
                    sql_type = types.varchar(MAX, collation=coll) if data == types.varchar(MAX) else data
                    value = point if column == "geography" else values[column]
                    await fetch(channel, tds.BulkInsert(f"INSERT BULK #b (c {declared})"))
                    try:
                        await fetch(channel, tds.BulkRows([text("c", sql_type)], [(value,)]))
                        out.append("loads")
                    except tds.ServerError as e:
                        out.append(e.errors[0].number)
                return out

    assert run(go()) == [expected for *_, expected in cases]


def test_identity_one_statement_and_transactions(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE #i (id int IDENTITY, a int); INSERT #i (a) VALUES (0)")
                columns = await columns_of(channel, "SELECT TOP 0 id, a FROM #i")
                await load(channel, "INSERT BULK #i (id int NOT NULL, a int)", columns, [(100, 1)])
                await fetch(channel, "INSERT #i (a) VALUES (2)")
                identity = (await fetch(channel, "SELECT id, a FROM #i ORDER BY a")).result_sets[0].rows
                await fetch(channel, "CREATE TABLE #c (a int CHECK (a > 0))")
                await fetch(channel, tds.BulkInsert("INSERT BULK #c (a int) WITH (CHECK_CONSTRAINTS)"))
                check = await refused(channel, tds.BulkRows([INT], [(1,), (2,), (-1,)]))
                await fetch(channel, tds.transactions.Begin())
                await load(channel, "INSERT BULK #c (a int)", [INT], [(1,), (2,)])
                await fetch(channel, tds.transactions.Rollback())
                counts = (await fetch(channel, "SELECT COUNT(*) FROM #c")).result_sets[0].rows
                return identity, check, counts

    identity, check, counts = run(go())
    assert identity == ((1, 0), (100, 1), (101, 2))  # kept without IDENTITY_INSERT, and the identity continues from it
    assert check == [547] and counts == ((0,),)  # a failed check loads nothing, and a rolled-back load is gone


def test_large_values_of_known_length_and_the_done_count(server):  # deviations from MS-TDS
    colmeta = bytes.fromhex("81 01 00 00 00 00 00 01 00 A5 FF FF 01 6D 00")  # one varbinary(max) column, m
    known_chunks = (3).to_bytes(8, "little") + (3).to_bytes(4, "little") + b"abc" + bytes(4)  # as MS-TDS defines
    known_bytes = (3).to_bytes(8, "little") + b"abc"  # as the server accepts
    done_99 = bytes.fromhex("FD 10 00 00 00") + (99).to_bytes(8, "little")

    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE #b (m varbinary(max))")
                out = {}
                for label, data, done in (("chunks", known_chunks, BULK_DONE), ("bytes", known_bytes, done_99)):
                    await fetch(channel, tds.BulkInsert("INSERT BULK #b (m varbinary(max))"))
                    try:
                        fetched = await fetch(channel, Raw(PacketType.BULK_LOAD, colmeta + b"\xd1" + data + done, continues="bulk load"))
                        out[label] = fetched.completions[0].rows
                    except tds.ServerError as e:
                        out[label] = [x.number for x in e.errors]
                out["stored"] = (await fetch(channel, "SELECT m FROM #b")).result_sets[0].rows
                return out

    out = run(go())
    assert out["chunks"] == [4804]  # a known length with chunks, as MS-TDS defines PLP, is refused
    assert out["bytes"] == 1 and out["stored"] == ((b"abc",),)  # the bytes alone load; the DONE's count of 99 is ignored
