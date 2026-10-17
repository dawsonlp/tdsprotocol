"""Tests of observability levels (M13, D-12) against the live SQL Server 2025.

Off builds nothing. Outline builds one line per step and message. Full opens every message to its fields and bytes. The
level can change between exchanges on a live connection, but not while a request is in progress.
"""

import asyncio

import pytest

import tds
from conftest import fetch
from tds.connection.core import Level, SerialChannelMisuse

pytestmark = pytest.mark.live


class Collect:
    """An observer that keeps every event. Its `level` says which level it observes."""

    def __init__(self, level: Level):
        self.level, self.events = level, []

    def __call__(self, event):
        self.events.append(event)


def leaves(node) -> int:
    return 0 if node is None else (1 if not node.children else sum(leaves(c) for c in node.children))


def run(coroutine):
    return asyncio.run(coroutine)


def test_each_level_builds_what_it_shows(server):
    async def go(level):
        observer = Collect(level)
        async with await tds.connect(**server, observe=observer) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "SELECT 1")
        return observer.events

    off, outline, full = (run(go(level)) for level in (Level.OFF, Level.OUTLINE, Level.FULL))
    assert off == []  # no event is built
    assert [e.text for e in outline] == [e.text for e in full]  # the same lines
    pairs = [(o, f) for o, f in zip(outline, full) if f.node is not None and f.kind in ("send", "receive")]
    assert pairs and all(leaves(f.node) > leaves(o.node) for o, f in pairs)  # full opens every message to its fields


def test_the_level_changes_between_exchanges(server):
    async def go():
        observer = Collect(Level.FULL)
        async with await tds.connect(**server) as connection:  # off
            async with connection.serial_channel() as channel:
                await fetch(channel, "SELECT 1")
                assert connection.observe is None
                connection.observe = observer  # observe a live connection
                await fetch(channel, "SELECT 2")
                seen = len(observer.events)
                connection.observe = None
                await fetch(channel, "SELECT 3")
                async with await channel.exchange(tds.Batch("SELECT 4")) as response:  # a request in progress
                    with pytest.raises(SerialChannelMisuse, match="between exchanges"):
                        connection.observe = observer
                    await response.fetch()
                return seen, len(observer.events), [e.text for e in observer.events]

    seen, total, texts = run(go())
    assert seen == total and seen >= 2  # SELECT 2's request and response, and nothing after
    assert any("SELECT 2" in t for t in texts) and not any("SELECT 3" in t or "SELECT 1" in t for t in texts)


def test_timing_is_kept_for_every_exchange_and_shown_after_the_line(server):  # D-12
    import io
    import re

    from tds.capture import Capture
    from tds.observe import Printer

    shown, captured = io.StringIO(), io.StringIO()

    async def go():
        async with await tds.connect(**server) as connection:  # off: timing is still kept
            async with connection.serial_channel() as channel:
                quiet = (await fetch(channel, "WAITFOR DELAY '00:00:00.2'; SELECT 1")).timing
                connection.observe, connection.capture = Printer(Level.OUTLINE, shown), Capture(captured)
                await fetch(channel, "WAITFOR DELAY '00:00:00.1'; SELECT 2")
                connection.observe = connection.capture = None
                return quiet

    t = run(go())
    assert t.sent < t.first_packet <= t.ended and t.until_first_packet >= 0.2 and t.until_end >= t.until_first_packet
    line = next(l for l in shown.getvalue().splitlines() if "← response" in l)
    first, done = (float(x) for x in re.search(r"first packet ([\d.]+) ms · done ([\d.]+) ms$", line).groups())
    assert 100 <= first <= done
    import json
    start = json.loads(captured.getvalue().splitlines()[0])
    assert start["t"] == 0 and start["start"].endswith("+00:00")  # the wall-clock start, to compare with server logs
