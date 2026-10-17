"""Tests of responses against the live SQL Server 2025 (M1).

The record matches what Request Response says. Errors arrive at the end with the record. Cancel works from any task.
Responses stream in bounded memory.
"""

import asyncio
import gc
import io
import time
import tracemalloc

import pytest

import response_samples as samples
import tds
from conftest import fetch
from test_response import at_server, outline, reader
from tds.observe import Level, Printer
from tds.tokens import DoneStatus

pytestmark = pytest.mark.live

PROCEDURES = [
    "CREATE PROCEDURE #work AS BEGIN DECLARE @t TABLE (i int); INSERT @t VALUES (1),(2); SELECT i FROM @t; RETURN 5 END",
]
BATCH_SAMPLES = {  # fixtures sent as SQL batches. Each one's SQL is the comment above it in response_samples.py
    "TWO_RESULT_SETS": "SELECT 1 AS a UNION ALL SELECT 2; SELECT N'x' AS b WHERE 1 = 0",
    "COUNTS": "DECLARE @t TABLE (i int); INSERT @t VALUES (1),(2),(3); UPDATE @t SET i = i + 1 WHERE i > 1; SELECT i FROM @t; DELETE @t",
    "NOCOUNT": "SET NOCOUNT ON; DECLARE @t TABLE (i int); INSERT @t VALUES (1),(2),(3); SELECT i FROM @t; SET NOCOUNT OFF",
    "STATEMENT_FAILS": "SET ANSI_WARNINGS ON; SELECT 1 AS a; SELECT 1 / 0 AS b; SELECT 2 AS c; SET ANSI_WARNINGS OFF",
    "BATCH_ENDS": "SELECT 1 AS a; SELECT CAST(N'x' AS int) AS b; SELECT 2 AS c",
    "EXEC_IN_BATCH": "EXEC #work; SELECT 9 AS after",
    "ORDERED": "SELECT name, n FROM (VALUES (N'b', 2), (N'a', 1)) AS v(name, n) ORDER BY name",
    "NULL_BITMAP": "SELECT CAST(NULL AS int) AS c1, CAST(NULL AS int) AS c2, CAST(NULL AS int) AS c3, CAST(NULL AS int) AS c4, "
                   "CAST(NULL AS int) AS c5, CAST(NULL AS int) AS c6, CAST(NULL AS int) AS c7, CAST(NULL AS int) AS c8, 42 AS c9",
    "MESSAGES": "PRINT N'hello'; RAISERROR(N'just so you know', 10, 1); SELECT 1 AS a",
    "ASSIGNMENTS": "DECLARE @x int = 41; SET @x = @x + 1; SELECT @x AS x",
    "DIVIDE_BY_ZERO_DEFAULTS": "SELECT 1 / 0 AS b",
    "USE_DATABASE": "USE tempdb; USE master",
}
# The RPC fixtures (TWO_CALLS, REFUSED_THEN_RUNS, CALL_ENDS_REQUEST) are checked live in test_calls_live.py.


def run(coroutine):
    return asyncio.run(coroutine)


async def record_of(channel, sql: str) -> list:
    """The live record, as test_response.outline shows it, with every row kept."""
    async with await channel.exchange(tds.Batch(sql)) as response:
        try:
            fetched = await response.fetch()
        except tds.ServerError as e:
            fetched = e.response
    out = []
    for item in fetched.sequence:
        if isinstance(item, tds.ResultSet):
            out.append(("set", [c.name for c in item.columns], item.order, item.rows, item.completion))
        else:
            out.append(item)
    return out


@pytest.mark.parametrize("name", BATCH_SAMPLES)
def test_every_batch_fact_on_request_response_still_holds(server, name):
    """Check each scenario's record, binding only captured report identities to the current server.

    Keep the capture's session defaults and select its message language explicitly. Every other asserted field,
    row and item position must match the capture; the offline tests still decode its original bytes exactly.
    """
    async def go():
        async with await tds.connect(**server, odbc=False, language="us_english") as connection:
            async with connection.serial_channel() as channel:
                server_name = (await fetch(channel, "SELECT @@SERVERNAME")).result_sets[0].rows[0][0]
                for sql in PROCEDURES:
                    await fetch(channel, sql)
                return server_name, await record_of(channel, BATCH_SAMPLES[name])

    server_name, live = run(go())
    assert live == at_server(outline(reader(getattr(samples, name))), server_name)


def test_without_the_odbc_flag_sessions_start_with_ansi_warnings_and_arithabort_off(server):  # D-9
    async def go():
        async with await tds.connect(**server, odbc=False) as connection:
            async with connection.serial_channel() as channel:
                return await fetch(channel, "SELECT CAST(SESSIONPROPERTY('ANSI_WARNINGS') AS int), "
                                            "CAST(SESSIONPROPERTY('ARITHABORT') AS int)")

    assert run(go()).result_sets[0].rows == ((0, 0),)


def test_an_error_arrives_at_the_end_with_the_record_and_the_channel_is_free(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                with pytest.raises(tds.ServerError) as failed:
                    await fetch(channel, "SELECT 1 AS a; SELECT * FROM no_such_table; SELECT 2 AS c")
                after = await fetch(channel, "SELECT 3")  # the channel is free
                return failed.value, after

    error, after = run(go())
    assert [e.number for e in error.errors] == [208]
    assert error.response.result_sets[0].rows == ((1,),)
    assert after.result_sets[0].rows == ((3,),)


@pytest.mark.parametrize("mars", [False, True], ids=["plain", "mars"])
def test_another_task_cancels_and_the_owner_gets_cancelled(server, mars):  # D-23, D-34
    async def go():
        async with await tds.connect(**server, mars=mars) as connection:
            async with connection.serial_channel() as channel:
                async with await channel.exchange(tds.Batch("WAITFOR DELAY '00:00:10'; SELECT 1")) as response:
                    watchdog = asyncio.get_running_loop().call_later(0.3, response.cancel)  # as if from another task
                    started = time.monotonic()
                    with pytest.raises(tds.Cancelled) as cancelled:
                        await response.fetch()
                    took = time.monotonic() - started
                    watchdog.cancel()
                after = await fetch(channel, "SELECT 2")  # the channel works again
                return cancelled.value, took, after

    cancelled, took, after = run(go())
    assert took < 5  # the server stopped waiting
    assert DoneStatus.ATTENTION in cancelled.response.completions[-1].status
    assert after.result_sets[0].rows == ((2,),)


ROWS = 2000  # × 8,000 bytes each, about 16 MB in the response
BIG = f"SELECT TOP {ROWS} REPLICATE(N'y', 4000) AS v FROM sys.all_objects a CROSS JOIN sys.all_objects b"


@pytest.mark.parametrize("mars", [False, True], ids=["plain", "mars"])
def test_a_large_response_streams_in_bounded_memory(server, mars):
    async def go():
        async with await tds.connect(**server, mars=mars) as connection:
            async with connection.serial_channel() as channel:
                tracemalloc.start()
                read = 0
                async with await channel.exchange(tds.Batch(BIG)) as response:
                    async for rs in response:
                        async for row in rs:
                            read += len(row[0])
                peak = tracemalloc.get_traced_memory()[1]
                tracemalloc.stop()
                return read, peak

    read, peak = run(go())
    assert read == ROWS * 4000
    assert peak < 4_000_000, f"peak {peak:,} bytes while streaming {ROWS * 8000:,}"


def test_under_mars_a_channel_nobody_reads_doesnt_stall_another(server):
    async def go():
        async with await tds.connect(**server, mars=True) as connection:
            async with connection.serial_channel() as big, connection.serial_channel() as small:
                response = await big.exchange(tds.Batch(BIG))  # not read yet, so the server soon has no window left
                await asyncio.sleep(0.3)
                quick = await asyncio.wait_for(fetch(small, "SELECT 1"), timeout=5)
                rows = 0
                async with response:
                    async for rs in response:
                        async for _ in rs:
                            rows += 1
                return quick, rows

    quick, rows = run(go())
    assert quick.result_sets[0].rows == ((1,),) and rows == ROWS


def test_a_dropped_response_warns(server):
    async def go():
        connection = await tds.connect(**server)
        channel = connection.serial_channel()
        response = await channel.exchange(tds.Batch("SELECT 1"))
        with pytest.warns(ResourceWarning, match="dropped while still open"):
            del response
            gc.collect()
        await connection.close()

    run(go())


def test_outline_shows_each_response_and_the_cancel(server):
    shown = io.StringIO()

    async def go():
        async with await tds.connect(**server, observe=Printer(Level.OUTLINE, shown)) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, BATCH_SAMPLES["ORDERED"])  # a real sort: ORDER BY on one constant row sends no ORDER
                async with await channel.exchange(tds.Batch("WAITFOR DELAY '00:00:10'")) as response:
                    asyncio.get_running_loop().call_later(0.2, response.cancel)
                    with pytest.raises(tds.Cancelled):
                        await response.finish()

    run(go())
    out = shown.getvalue()
    assert "← response · " in out and "COLMETADATA ORDER ROW×2 DONE" in out
    assert "→ attention · cancel the request in progress" in out and "← cancel acknowledged" in out


def test_full_shows_every_token(server):
    shown = io.StringIO()

    async def go():
        async with await tds.connect(**server, observe=Printer(Level.FULL, shown)) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "SELECT 1 AS a; PRINT N'hi'")

    run(go())
    out = shown.getvalue()
    for token in ("COLMETADATA", "ROW", "INFO", "DONE"):
        assert f"\n        {token}" in out, token


def test_statement_codes_seen(server):  # Request Response › Edge cases
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                created = await fetch(channel, "CREATE PROCEDURE #inner AS SELECT 1 AS x")
                nested = await fetch(channel, "CREATE PROCEDURE #around AS EXEC #inner")
                ran = await fetch(channel, "EXEC #around")
                empty = await fetch(channel, "")
                return created, nested, ran, empty

    created, _, ran, empty = run(go())
    assert [c.statement for c in created.completions] == [222]  # CREATE PROCEDURE
    assert 224 in [c.statement for c in ran.completions if c.kind.name == "STATEMENT_IN_PROCEDURE"]  # the nested EXEC
    assert [(c.statement, c.rows) for c in empty.completions] == [(253, None)]  # an empty batch


def test_sql_text_alone_is_refused_clearly(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                with pytest.raises(TypeError, match="tds.Batch"):
                    await channel.exchange("SELECT 1")
                return await fetch(channel, "SELECT 1")  # nothing was sent, so the channel is free

    assert run(go()).result_sets[0].rows == ((1,),)
