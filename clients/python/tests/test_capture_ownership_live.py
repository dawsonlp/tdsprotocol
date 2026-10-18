"""Independent pool recordings remain replayable despite reversed consumption."""
import asyncio
import io

import pytest

import tds
from conftest import fetch
from tds.capture import Capture, replay

pytestmark = pytest.mark.live


@pytest.mark.parametrize("version", ["7.4", "8.0"])
@pytest.mark.parametrize("mars", [False, True])
def test_pool_records_each_transport_separately_and_reuses_its_recording(server, version, mars):
    outputs, recordings = [], []

    def recording():
        output = io.StringIO()
        capture = Capture(output)
        outputs.append(output)
        recordings.append(capture)
        return capture

    async def go():
        async with tds.Pool(**server, size=2, mars=mars, tds_version=version,
                            capture_factory=recording) as pool:
            async with pool.connection() as first, pool.connection() as second:
                async with first.serial_channel() as a, second.serial_channel() as b:
                    ra = await a.exchange(tds.Batch("SELECT 11 AS a"))
                    rb = await b.exchange(tds.Batch("SELECT 22 AS a"))
                    async with rb:
                        assert (await rb.fetch()).result_sets[0].rows == ((22,),)
                    async with ra:
                        assert (await ra.fetch()).result_sets[0].rows == ((11,),)
            async with pool.connection() as reused:
                assert reused.capture in recordings and len(outputs) == 2
                async with reused.serial_channel() as channel:
                    await fetch(channel, "SELECT 33 AS a")
        return outputs

    asyncio.run(go())
    replayed = []
    for output in outputs:
        rows = []

        def observe(event):
            if event.kind == "receive" and event.node is not None:
                rows.extend(int.from_bytes(node.raw[1:], "little", signed=True)
                            for node in event.node.children if node.name == "ROW")

        replay(io.StringIO(output.getvalue()), observe)
        replayed.append(rows)
    assert 11 in replayed[0] and 22 not in replayed[0]
    assert 22 in replayed[1] and 11 not in replayed[1]
    assert sum(rows.count(33) for rows in replayed) == 1


@pytest.mark.parametrize("version", ["7.4", "8.0"])
@pytest.mark.parametrize("mars", [False, True])
def test_recovery_creates_a_new_recording_for_the_new_transport(server, version, mars):
    from test_session_recovery_live import Relay
    outputs = []

    def recording():
        output = io.StringIO()
        outputs.append(output)
        return Capture(output)

    async def go():
        async with Relay(server) as relay, await tds.connect(**{**server, "port": relay.port},
                tds_version=version, mars=mars, capture_factory=recording) as connection:
            async with connection.serial_channel() as channel:
                assert (await fetch(channel, "SELECT 11 AS a")).result_sets[0].rows == ((11,),)
                relay.cut()
                await asyncio.wait_for(connection._reading, 5)  # observe the break, without a scheduling sleep
                assert not connection.alive
                assert (await fetch(channel, "SELECT 22 AS a")).result_sets[0].rows == ((22,),)
                assert connection.recoveries == 1

    asyncio.run(go())
    assert len(outputs) == 2
    assert "SELECT 11" in outputs[0].getvalue() and "SELECT 22" not in outputs[0].getvalue()
    assert "SELECT 22" in outputs[1].getvalue() and "SELECT 11" not in outputs[1].getvalue()
    for output in outputs:
        replay(io.StringIO(output.getvalue()), lambda event: None)
