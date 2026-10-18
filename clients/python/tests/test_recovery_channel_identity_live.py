"""Prove channel continuity with real SQL, not just a successful recovery login.

The application holds the same connection/channel objects across a relay cut.
Only their physical transport and wire identities change. No interrupted SQL is
replayed; its old response retains only the old exchange's authority.
"""
import asyncio
import io

import pytest

import tds
from conftest import fetch
from tds.capture import Capture, replay
from test_session_recovery_live import Relay, value

pytestmark = pytest.mark.live


@pytest.mark.parametrize("version", ["7.4", "8.0"])
@pytest.mark.parametrize("mars", [False, True])
def test_nonzero_channels_keep_working_across_repeated_recovery(server, version, mars):
    outputs = []

    def recording():
        output = io.StringIO()
        outputs.append(output)
        return Capture(output)

    async def go():
        async with asyncio.timeout(20), Relay(server) as relay, await tds.connect(
                **{**server, "port": relay.port}, tds_version=version, mars=mars,
                capture_factory=recording) as connection:
            retired = connection.serial_channel()
            await fetch(retired, "SELECT 10 AS retired")
            await retired.close()
            channel = connection.serial_channel()
            close_channel, close_connection = channel.close, connection.close  # permissions obtained before recovery
            sibling = connection.serial_channel() if mars else None
            assert channel.id == 1
            await fetch(channel, "SET LANGUAGE Deutsch")
            retained = await fetch(channel, "SELECT 11 AS retained")
            if sibling is not None:
                assert await value(sibling, "SELECT 12") == (12,)

            for cycle in range(3):
                old = connection._core
                relay.cut()
                await connection._reading
                assert not connection.alive
                if cycle == 1:
                    await connection.recover()  # other iterations recover on the next exchange
                assert await value(channel, "SELECT @@LANGUAGE, 22") == ("Deutsch", 22)
                assert connection._core is not old and connection.recoveries == cycle + 1
                state = connection._core.link.channels[channel.id]
                assert state.owner is asyncio.current_task()
                assert state.wire_id == (0 if mars else None)
                # Retired logical id 0 now differs from channel 1's wire id 0.
                await asyncio.create_task(retired.close())
                with pytest.raises(tds.ChannelClosed):
                    await retired.exchange(tds.Batch("SELECT -1"))
                if sibling is not None:
                    assert connection._core.link.channels[sibling.id].wire_id == 1
                    # Submit both before reading, then consume in reverse order.
                    first = await channel.exchange(tds.Batch("SELECT 23"))
                    second = await sibling.exchange(tds.Batch("SELECT 24"))
                    assert (await second.fetch()).result_sets[0].rows == ((24,),)
                    assert (await first.fetch()).result_sets[0].rows == ((23,),)
                assert retained.result_sets[0].rows == ((11,),)

            later = connection.serial_channel() if mars else None
            if later is not None:
                assert later.id == 3 and connection._core.link.channels[later.id].wire_id == 2
                assert await value(later, "SELECT 25") == (25,)
                await later.close()
            await asyncio.create_task(close_channel())  # original logical close permission still works
            with pytest.raises(tds.ChannelClosed):
                await channel.exchange(tds.Batch("SELECT -1"))
            if sibling is not None:
                assert await value(sibling, "SELECT 26") == (26,)
                await sibling.close()
            await asyncio.create_task(close_connection())
            assert not connection.alive

    asyncio.run(go())
    assert len(outputs) == 4  # original physical connection plus three replacements
    for output in outputs:
        received = []

        def observe(event):
            if event.kind == "receive" and event.node is not None:
                assert "can't be decoded" not in event.node.shown
                received.extend(int.from_bytes(node.raw[1:], "little", signed=True)
                                for node in event.node.children if node.name == "ROW" and len(node.raw) == 5)

        replay(io.StringIO(output.getvalue()), observe)
        assert (11 in received) == (output is outputs[0])
        if mars and output is not outputs[0]:
            assert 23 in received and 24 in received  # independent logical-channel packet attribution


@pytest.mark.parametrize("version", ["7.4", "8.0"])
@pytest.mark.parametrize("mars", [False, True])
def test_old_response_cannot_read_cancel_or_close_a_recovered_exchange(server, version, mars):
    events = []

    async def first_row(response):
        result = await anext(aiter(response))
        return await anext(aiter(result))

    async def go():
        async with asyncio.timeout(20), Relay(server) as relay, await tds.connect(
                **{**server, "port": relay.port}, tds_version=version, mars=mars, observe=events.append) as connection:
            retired = connection.serial_channel()
            await fetch(retired, "SELECT 10")
            await retired.close()
            channel = connection.serial_channel()
            old = await channel.exchange(tds.Batch(
                "SELECT 11; RAISERROR ('ready', 0, 1) WITH NOWAIT; WAITFOR DELAY '00:00:10'; SELECT 12"))
            assert await first_row(old) == (11,)  # server executing, response unfinished
            assert not old.ended
            relay.cut()
            await connection._reading
            await connection.recover()  # explicit: the interrupted request must never be replayed
            current = await channel.exchange(tds.Batch(
                "SELECT 22; RAISERROR ('ready', 0, 1) WITH NOWAIT; WAITFOR DELAY '00:00:00.2'; SELECT 23"))
            assert await first_row(current) == (22,)
            assert not current.ended
            old.cancel()
            with pytest.raises(ConnectionError, match="never sends it again"):
                await old.finish()
            with pytest.raises(ConnectionError, match="never sends it again"):
                await old.close()
            assert not any(event.kind == "send" and "attention · cancel" in event.text for event in events)
            remaining = [row async for result in current async for row in result]
            assert remaining == [(23,)]
            assert await value(channel, "SELECT 24") == (24,)
            assert connection.alive and connection.recoveries == 1
            await channel.close()

    asyncio.run(go())
