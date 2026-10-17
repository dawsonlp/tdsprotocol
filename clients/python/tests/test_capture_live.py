"""Captures and replay (M13, D-12) against the live SQL Server 2025.

A capture replays into the identical full view, under TDS 7.4 and 8.0, with and without MARS. It holds the password
only when asked to. Its times start at 0. A capture can start on a live connection.
"""

import asyncio
import base64
import io
import json

import pytest

import tds
from conftest import fetch
from tds import login7, transactions, types
from tds.capture import Capture, replay
from tds.observe import Level, Printer

pytestmark = pytest.mark.live


async def conversation(channel) -> None:
    """One example of each kind of exchange: results and a message, an output parameter, an error, transactions, a
    bulk load, and a cancel."""
    await fetch(channel, "SELECT 1 AS a, N'é' AS b; PRINT 'hi'")
    await fetch(channel, tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", types.nvarchar(100), "SELECT @x = 41 + 1"),
                                  tds.Param("@params", types.nvarchar(100), "@x int OUTPUT"),
                                  tds.Param("@x", types.int, None, output=True)))
    with pytest.raises(tds.ServerError):
        await fetch(channel, "SELECT 1/0")
    await fetch(channel, transactions.Begin())
    await fetch(channel, transactions.Commit())
    await fetch(channel, "CREATE TABLE #b (n int NOT NULL, s nvarchar(10))")
    columns = (await fetch(channel, "SELECT TOP 0 n, s FROM #b")).result_sets[0].columns
    await fetch(channel, tds.BulkInsert("INSERT BULK #b (n int NOT NULL, s nvarchar(10))"))
    await fetch(channel, tds.BulkRows(columns, [(1, "x"), (2, None)]))
    async with await channel.exchange(tds.Batch("WAITFOR DELAY '00:00:05'")) as response:
        response.cancel()
        with pytest.raises(tds.Cancelled):
            await response.fetch()


def session(server, **options) -> tuple[str, str]:
    """The live full view, and the capture made at the same time."""
    live, captured = io.StringIO(), io.StringIO()

    async def go():
        async with await tds.connect(**server, **options, observe=Printer(Level.FULL, live),
                                     capture=Capture(captured)) as connection:
            async with connection.serial_channel() as channel:
                await conversation(channel)

    asyncio.run(go())
    return live.getvalue(), captured.getvalue()


@pytest.mark.parametrize("version", ["7.4", "8.0"])
@pytest.mark.parametrize("mars", [False, True])
def test_a_capture_replays_into_the_identical_view(server, version, mars):
    live, captured = session(server, tds_version=version, mars=mars)
    replayed = io.StringIO()
    replay(io.StringIO(captured), Printer(Level.FULL, replayed))
    assert replayed.getvalue() == live  # every line, every field, every byte
    assert "cancel acknowledged" in live and "bulk data" in live and "can't be decoded" not in live


def packets(captured: str) -> list[bytes]:
    return [base64.b64decode(l["bytes"]) for l in map(json.loads, captured.splitlines()) if "packet" in l]


def test_the_password_stays_out_unless_kept(server):
    scrambled = login7.scramble(server["password"].encode("utf-16-le"))  # as LOGIN7 carries it

    def holds_password(keep: bool) -> bool:
        captured = io.StringIO()

        async def go():
            async with await tds.connect(**server, capture=Capture(captured, keep_password=keep)):
                pass

        asyncio.run(go())
        return any(scrambled in p for p in packets(captured.getvalue()))

    assert not holds_password(False) and holds_password(True)


def test_times_and_a_capture_started_on_a_live_connection(server):
    captured = io.StringIO()

    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "SELECT 1")
                connection.capture = Capture(captured)  # capture a live connection from this point
                await fetch(channel, "SELECT 2")
                connection.capture = None
                await fetch(channel, "SELECT 3")

    asyncio.run(go())
    lines = [json.loads(l) for l in captured.getvalue().splitlines()]
    times = [l["t"] for l in lines]
    assert times[0] == 0 and times == sorted(times)
    events = [l["text"] for l in lines if "event" in l]
    assert any("SELECT 2" in t for t in events) and not any("SELECT 1" in t or "SELECT 3" in t for t in events)
    out = io.StringIO()
    replay(io.StringIO(captured.getvalue()), Printer(Level.FULL, out))
    assert "“SELECT 2”" in out.getvalue() and "can't be decoded" not in out.getvalue()
