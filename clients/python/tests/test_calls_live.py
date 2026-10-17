"""Calls against the live SQL Server 2025 (M3).

The RPC facts on Request Response still hold when the driver's own Call sends the requests. Every short type
round-trips exactly: select → insert through a Call → select compares equal (D-48).
"""

import asyncio

import pytest

import response_samples as samples
import tds
from conftest import fetch
from test_response import at_server, outline, reader
from test_responses_live import record_of
from test_types_live import CODE_PAGES, COLUMNS, LIMITS, SEQUENCES
from tds import types

pytestmark = pytest.mark.live

PROCEDURES = [
    "CREATE PROCEDURE #bump @a int OUTPUT AS BEGIN SELECT @a AS seen_on_entry; SET @a = ISNULL(@a, 0) + 1; RETURN 7 END",
    "CREATE PROCEDURE #plain @a int AS BEGIN SELECT @a AS seen_on_entry END",
    "CREATE PROCEDURE #outer @o int OUTPUT AS BEGIN DECLARE @x int = 100; EXEC #bump @x OUTPUT; SET @o = @x; "
    "SELECT N'outer done' AS step; RETURN 3 END",
    "CREATE PROCEDURE #fails AS BEGIN SELECT 1 AS before_error; SELECT CAST(N'x' AS int) AS b; SELECT 2 AS after_error; "
    "RETURN 4 END",
]
CALLS = {  # the RPC fixtures, sent by the driver's own Calls
    "TWO_CALLS": tds.Calls(tds.Call("#bump", tds.Param("@a", types.int, 41, output=True)),
                           tds.Call("#outer", tds.Param("@o", types.int, None, output=True))),
    "REFUSED_THEN_RUNS": tds.Calls(tds.Call("#plain", tds.Param("@a", types.int, 1, output=True)),
                                   tds.Call("#bump", tds.Param("@a", types.int, 5, output=True))),
    "CALL_ENDS_REQUEST": tds.Calls(tds.Call("#fails"), tds.Call("#bump", tds.Param("@a", types.int, 5, output=True))),
}
TEXT = types.nvarchar(4000)


def run(coroutine):
    return asyncio.run(coroutine)


async def call(channel, request):
    async with await channel.exchange(request) as response:
        try:
            return await response.fetch()
        except tds.ServerError as e:
            return e.response


@pytest.mark.parametrize("name", CALLS)
def test_every_rpc_fact_on_request_response_still_holds(server, name):
    """Check the captured RPC record against this server, with explicit message language and session defaults."""
    async def go():  # the fixtures were captured without the ODBC flag
        async with await tds.connect(**server, odbc=False, language="us_english") as connection:
            async with connection.serial_channel() as channel:
                server_name = (await fetch(channel, "SELECT @@SERVERNAME")).result_sets[0].rows[0][0]
                for sql in PROCEDURES:
                    await fetch(channel, sql)
                fetched = await call(channel, CALLS[name])
                return server_name, [("set", [c.name for c in i.columns], i.order, i.rows, i.completion)
                                     if isinstance(i, tds.ResultSet) else i for i in fetched.sequence]

    server_name, live = run(go())
    assert live == at_server(outline(reader(getattr(samples, name))), server_name)


def test_outputs_are_matched_by_their_position_in_the_call(server):  # Request Response › Rules
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, PROCEDURES[0])
                fetched = await call(channel, tds.Call(
                    tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, "EXEC #bump @p OUTPUT"),
                    tds.Param("@params", TEXT, "@p int OUTPUT"), tds.Param("@p", types.int, 41, output=True)))
                return await fetched.returns()

    [returned] = run(go())
    output = returned.outputs["@p"]
    assert output.ordinal == 2 and output.value == 42  # counting @stmt and @params
    assert returned.status == 0 and not returned.failed


def test_a_function_called_as_an_rpc_returns_its_result(server):
    async def go():
        async with await tds.connect(**server, odbc=True, database="tempdb") as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE OR ALTER FUNCTION dbo.tds_double(@x int) RETURNS int AS BEGIN RETURN @x * 2 END")
                fetched = await call(channel, tds.Call("dbo.tds_double", tds.Param("@x", types.int, 21)))
                await fetch(channel, "DROP FUNCTION dbo.tds_double")
                return await fetched.returns()

    [returned] = run(go())
    assert returned.function_result.value == 42 and returned.function_result.function_result
    assert returned.status is None and len(returned.outputs) == 0  # a function sends no return status


def test_default_uses_the_procedures_default(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE PROCEDURE #d @a int = 5 AS SELECT @a AS a")
                return await call(channel, tds.Call("#d", tds.Param("@a", types.int, tds.DEFAULT)))

    assert run(go()).result_sets[0].rows == ((5,),)


def test_observed_sp_execute_by_number_refuses_a_named_handle(server):  # Requests › Edge cases
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                prepared = await call(channel, tds.Call(
                    tds.Builtin.SP_PREPARE, tds.Param("@handle", types.int, None, output=True),
                    tds.Param("@params", TEXT, ""), tds.Param("@stmt", TEXT, "SELECT 1 AS a")))
                handle = (await prepared.returns())[0].outputs["@handle"].value
                named = await call(channel, tds.Call(tds.Builtin.SP_EXECUTE, tds.Param("@handle", types.int, handle)))
                positional = await call(channel, tds.Call(tds.Builtin.SP_EXECUTE, tds.Param("", types.int, handle)))
                return named, positional

    named, positional = run(go())
    assert [e.number for e in named.errors] == [4002]
    assert positional.result_sets[0].rows == ((1,),)


def test_observed_no_metadata_still_gets_metadata(server):  # Requests › Edge cases
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                statement = tds.Param("@stmt", TEXT, "SELECT 1 AS a")
                first = await call(channel, tds.Call(tds.Builtin.SP_EXECUTESQL, statement))
                columns = first.result_sets[0].columns
                again = await call(channel, tds.Call(tds.Builtin.SP_EXECUTESQL, statement,
                                                     options=tds.CallOptions.NO_METADATA, columns=[columns]))
                return again

    again = run(go())
    assert again.result_sets[0].rows == ((1,),) and again.result_sets[0].columns[0].name == "a"


# --------------------------------------------------------------------------- D-48: every short type round-trips exactly


def projection(name: str, declared: str) -> str:
    """A column as exact bytes and values, for EXCEPT.

    Text goes through binary(n) and DATALENGTH, because converting to varbinary drops trailing zeros and collations
    compare case-insensitively. A datetimeoffset is text that includes its offset.
    """
    if declared.startswith(("char", "varchar", "nchar", "nvarchar", "sysname", "binary", "varbinary")):
        size = {"nchar(10)": 20, "nvarchar(50)": 100, "sysname": 256}.get(declared, int(declared.split("(")[1][:-1]) if "(" in declared else 256)
        return f"CAST({name} AS binary({size})) AS {name}_bytes, DATALENGTH({name}) AS {name}_length"
    if declared.startswith("datetimeoffset"):
        return f"CONVERT(nvarchar(50), {name}, 121) AS {name}_text"
    return name


def test_every_short_type_round_trips_exactly(server):
    names = list(COLUMNS)
    columns = ", ".join(f"{n} {declared} NULL" for n, (declared, _) in COLUMNS.items())

    async def go():
        async with await tds.connect(**server, odbc=True, database="tds_test") as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "IF SCHEMA_ID('shop') IS NULL EXEC('CREATE SCHEMA shop')")
                await fetch(channel, f"DROP TABLE IF EXISTS shop.round_source, shop.round_copy; "
                                     f"CREATE TABLE shop.round_source (id int IDENTITY, {columns}); "
                                     f"CREATE TABLE shop.round_copy (id int, {columns})")
                generated = ", ".join(expr for _, expr in COLUMNS.values())
                await fetch(channel, f"INSERT shop.round_source ({', '.join(names)}) SELECT TOP 200 {generated} FROM sys.all_objects")
                for side in (0, 1):
                    await fetch(channel, f"INSERT shop.round_source ({', '.join(names)}) "
                                         f"VALUES ({', '.join(LIMITS[n][side] for n in names)})")
                await fetch(channel, f"INSERT shop.round_source ({', '.join(names)}) VALUES ({', '.join('NULL' for _ in names)})")

                source = (await fetch(channel, f"SELECT id, {', '.join(names)} FROM shop.round_source ORDER BY id")).result_sets[0]
                types_of = [c.type for c in source.columns]
                statement = (f"INSERT shop.round_copy (id, {', '.join(names)}) "
                             f"VALUES (@id, {', '.join(f'@{n}' for n in names)})")
                declared = ", ".join([f"@id int"] + [f"@{n} {t}" for n, t in zip(names, types_of[1:])])
                rows = list(source.rows)
                for start in range(0, len(rows), 25):  # 25 calls in each request
                    calls = [tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, statement),
                                      tds.Param("@params", TEXT, declared),
                                      *[tds.Param(f"@{c.name}", t, v) for c, t, v in zip(source.columns, types_of, row)])
                             for row in rows[start : start + 25]]
                    async with await channel.exchange(tds.Calls(*calls)) as response:
                        returns = await response.returns(unread=tds.Unread.DISCARD)
                    assert len(returns) == len(calls) and not any(r.failed for r in returns)

                exact = ", ".join(projection(n, COLUMNS[n][0]) for n in names)
                differences = await fetch(channel, f"""
                    SELECT COUNT(*) FROM (SELECT id, {exact} FROM shop.round_source
                                          EXCEPT SELECT id, {exact} FROM shop.round_copy) AS missing;
                    SELECT COUNT(*) FROM (SELECT id, {exact} FROM shop.round_copy
                                          EXCEPT SELECT id, {exact} FROM shop.round_source) AS extra""")
                copy = (await fetch(channel, f"SELECT id, {', '.join(names)} FROM shop.round_copy ORDER BY id")).result_sets[0]
                return rows, copy.rows, [rs.rows[0][0] for rs in differences.result_sets]

    source, copy, (missing, extra) = run(go())
    assert len(source) == 203
    assert (missing, extra) == (0, 0)  # equal on the server, byte for byte
    assert list(copy) == source  # and equal in Python


async def round_trip_bytes(channel, collation: str, which: str, declared_as: str) -> tuple[int, int, int]:
    """Store every sequence under the collation, read the sequences as text, and send them back through Calls with each
    column's type. Returns three counts: the sequences, those that came back different, and those the server itself
    writes back differently."""
    await fetch(channel, f"""
        CREATE TABLE #source (b varbinary(2), v varchar(2) COLLATE {collation});
        CREATE TABLE #copy (b varbinary(2), v varchar(2) COLLATE {collation});
        INSERT #source SELECT b, b FROM ({SEQUENCES}) AS s(b) WHERE {which};
        DELETE #source WHERE CAST(v AS varbinary(2)) <> b OR DATALENGTH(v) <> DATALENGTH(b)""")
    source = (await fetch(channel, "SELECT b, v FROM #source")).result_sets[0]
    binary, text = source.columns[0].type, source.columns[1].type
    rows = list(source.rows)
    calls = []
    for start in range(0, len(rows), 100):  # 100 rows in each call, because its text must fit nvarchar(4000) until M4
        chunk = rows[start : start + 100]
        values = ", ".join(f"(@b{i}, @v{i})" for i in range(len(chunk)))
        declared = ", ".join(f"@b{i} {binary}, @v{i} {declared_as}" for i in range(len(chunk)))
        params = [p for i, (b, v) in enumerate(chunk) for p in (tds.Param(f"@b{i}", binary, b), tds.Param(f"@v{i}", text, v))]
        calls.append(tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, f"INSERT #copy (b, v) VALUES {values}"),
                              tds.Param("@params", TEXT, declared), *params))
    for start in range(0, len(calls), 20):  # 20 calls in each request
        async with await channel.exchange(tds.Calls(*calls[start : start + 20])) as response:
            assert not any(r.failed for r in await response.returns(unread=tds.Unread.DISCARD))
    different = await fetch(channel, """
        SELECT COUNT(*) FROM #source AS s LEFT JOIN #copy AS c ON c.b = s.b AND DATALENGTH(c.b) = DATALENGTH(s.b)
        WHERE c.b IS NULL OR CAST(c.v AS binary(2)) <> CAST(s.v AS binary(2)) OR DATALENGTH(c.v) <> DATALENGTH(s.v)""")
    server_limit = await fetch(channel, f"""
        DECLARE @u TABLE (b varbinary(2), back varchar(2) COLLATE {collation});
        INSERT @u SELECT b, CAST(v AS nvarchar(2)) FROM #source;
        SELECT COUNT(*) FROM @u AS u JOIN #source AS s ON s.b = u.b AND DATALENGTH(s.b) = DATALENGTH(u.b)
        WHERE CAST(u.back AS binary(2)) <> CAST(s.v AS binary(2)) OR DATALENGTH(u.back) <> DATALENGTH(s.v)""")
    return len(rows), different.result_sets[0].rows[0][0], server_limit.result_sets[0].rows[0][0]


@pytest.mark.parametrize("page", sorted(CODE_PAGES))
def test_every_byte_sequence_round_trips_through_a_call(server, page):
    """Every sequence SQL Server holds under the code page goes back exactly when the statement declares its parameter
    nvarchar. The exceptions are the sequences the server itself writes back differently (duplicate encodings, default
    characters). A varchar parameter would be in the database's collation and would be converted (see the next test)."""
    which = "1 = 1" if page in (932, 936, 949, 950) else "DATALENGTH(b) = 1"

    async def go():
        async with await tds.connect(**server, odbc=True) as connection:
            async with connection.serial_channel() as channel:
                return await round_trip_bytes(channel, CODE_PAGES[page], which, "nvarchar(2)")

    count, different, server_limit = run(go())
    assert count >= 128 and different == server_limit  # exactly what the server itself can't write back
    if page not in (932, 936, 949, 950):
        assert different == 0  # single-byte code pages: everything


def test_observed_a_varchar_parameter_is_in_the_databases_collation(server):  # Requests › Edge cases
    """SQL Server puts a declared varchar parameter in the database's default collation (here cp1252), whatever
    collation the value arrives in. A Greek value is converted to cp1252 when it arrives."""
    async def go():
        async with await tds.connect(**server, odbc=True) as connection:
            async with connection.serial_channel() as channel:
                same = await round_trip_bytes(channel, CODE_PAGES[1252], "DATALENGTH(b) = 1", "varchar(2)")
                await fetch(channel, "DROP TABLE #source, #copy")
                greek = await round_trip_bytes(channel, CODE_PAGES[1253], "DATALENGTH(b) = 1", "varchar(2)")
                return same, greek

    (_, same, _), (_, greek, _) = run(go())
    assert same == 0 and greek > 0
