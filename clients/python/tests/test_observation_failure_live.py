"""Approved diagnostic-failure policy on actual SQL Server, both transports."""
import asyncio
import io

import pytest

import tds
from conftest import fetch
from tds.capture import Capture

pytestmark = pytest.mark.live


@pytest.mark.parametrize("version", ["7.4", "8.0"])
@pytest.mark.parametrize("mars", [False, True])
@pytest.mark.parametrize("kind", ["channel", "send", "receive"])
def test_broken_live_log_does_not_change_results_or_prevent_reuse(server, version, mars, kind):
    async def go():
        failure, calls, recording = RuntimeError("display failed"), [], io.StringIO()

        def observer(event):
            calls.append(event)
            if event.kind == kind:
                raise failure

        async with await tds.connect(**server, mars=mars, tds_version=version) as connection:
            connection.observe, connection.capture = observer, Capture(recording)
            async with connection.serial_channel() as channel:
                assert (await fetch(channel, "SELECT 41")).result_sets[0].rows == ((41,),)
                count = len(calls)
                assert connection.observation_error is failure and connection.observe is None
                assert (await fetch(channel, "SELECT 42")).result_sets[0].rows == ((42,),)
                assert len(calls) == count and connection.alive
        assert "SELECT 42" in recording.getvalue()  # capture still receives events

    asyncio.run(go())


@pytest.mark.parametrize("version", ["7.4", "8.0"])
@pytest.mark.parametrize("mars", [False, True])
@pytest.mark.parametrize("where", ["channel", "send", "receive", "close"])
def test_broken_recording_discards_the_connection(server, version, mars, where):
    async def go():
        failure = OSError("recording output unavailable")

        class Recording:
            def __call__(self, event):
                if (where == "channel" and event.kind == "channel") or (
                        where == "close" and event.kind == "step" and event.text == "close"):
                    raise failure

            def packet(self, direction, channel, packet):
                if direction == where:
                    raise failure

        connection = await tds.connect(**server, mars=mars, tds_version=version)
        connection.capture = Recording()
        try:
            with pytest.raises(tds.CaptureError) as caught:
                if where == "close":
                    await connection.close()
                else:
                    async with connection.serial_channel() as channel:
                        await fetch(channel, "SELECT 42")
            assert caught.value.cause is failure
            assert not connection.alive and connection._writer.is_closing()
            assert "saved recording" in connection._core.recovery_refusal()
            with pytest.raises(ConnectionError):
                connection.serial_channel()
        finally:
            await connection.close()

    asyncio.run(go())
