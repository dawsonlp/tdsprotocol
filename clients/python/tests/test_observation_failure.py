"""Diagnostics have no authority to strand channels or pool reservations."""
import asyncio
import io

import pytest

import tds
from tds.capture import Capture
from tds.connection import shell
from tds.connection.core import ConnectionCore, Event, Options


def test_failed_live_observer_is_disabled_but_capture_still_sees_the_event():
    failure, events, calls = RuntimeError("broken display"), [], []

    def observer(event):
        calls.append(event)
        raise failure

    core = ConnectionCore(Options("unused", 1433, "test", "unused"), observer)
    core.set_capture(events.append)
    channel, _ = core.open_channel("owner")
    assert channel == 0 and len(core.link.channels) == 1
    assert core.failure is None and core.observation_error is failure
    assert core._observer is None and len(calls) == 1
    core.observe(Event("step", "still recording"))
    assert [event.kind for event in events] == ["channel", "step"]
    assert core.options.record  # don't change decoding mode during a procedure
    core.set_observe(None)
    assert core.observation_error is None and not core.options.record


class Writer:
    closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


@pytest.mark.parametrize("where", ["event", "packet"])
def test_recording_failure_synchronously_closes_the_socket_and_wakes_waiters(where):
    async def go():
        failure = OSError("recording unavailable")

        class Recording:
            def __call__(self, event):
                if where == "event":
                    raise failure

            def packet(self, *args):
                raise failure

        core = ConnectionCore(Options("unused", 1433, "test", "unused"))
        writer = Writer()
        connection = shell.Connection(core, asyncio.StreamReader(), writer)
        inbox = connection._inboxes[99] = shell.Inbox(1)
        waiting = asyncio.create_task(inbox.get())
        core.set_capture(Recording())
        with pytest.raises(tds.CaptureError) as caught:
            if where == "event":
                connection.serial_channel()
            else:
                core.link.capture("send", None, b"packet")
        assert writer.closed and not connection.alive
        assert core.failure is caught.value and caught.value.cause is failure
        with pytest.raises(tds.CaptureError) as woken:
            await waiting
        assert woken.value is caught.value
        with pytest.raises(ConnectionError):
            connection.serial_channel()
        await connection.close()  # teardown doesn't call the broken recorder again

    asyncio.run(go())


@pytest.mark.parametrize("where", ["write", "short write", "flush"])
def test_capture_detects_buffered_and_short_writes(where):
    class Output(io.StringIO):
        def write(self, text):
            if where == "write":
                raise OSError("write failed")
            return len(text) - 1 if where == "short write" else super().write(text)

        def flush(self):
            if where == "flush":
                raise OSError("flush failed")

    with pytest.raises(OSError):
        Capture(Output())(Event("step", "hello"))


def test_broken_pool_observer_cannot_orphan_a_completed_loan(monkeypatch):
    async def go():
        failure = RuntimeError("pool display failed")

        def observer(event):
            raise failure

        class Session:
            session_id, alive = 42, True

            def _release(self):
                return True

            async def close(self):
                self.alive = False

        session = Session()

        async def connect(*args, **kwargs):
            return session

        monkeypatch.setattr(shell, "connect", connect)
        pool = tds.Pool("unused", 1433, size=1, observe=observer)
        async with pool.connection() as borrowed:
            assert borrowed is session and pool.in_use == 1
            assert pool.observation_error is failure
        assert pool.in_use == 0 and pool.idle == 1
        async with pool.connection() as borrowed:
            assert borrowed is session
        await pool.close()
        assert not session.alive

    asyncio.run(go())


def test_inbox_abort_wakes_a_producer_waiting_for_capacity():
    async def go():
        inbox, failure = shell.Inbox(1), RuntimeError("connection failed")
        await inbox.put("already recorded")
        waiting = asyncio.create_task(inbox.put("unrecorded"))
        await asyncio.sleep(0)  # let the producer reach its capacity wait
        inbox.abort(failure)
        with pytest.raises(RuntimeError) as caught:
            await waiting
        assert caught.value is failure
        assert await inbox.get() == "already recorded"
        with pytest.raises(RuntimeError):
            await inbox.get()

    asyncio.run(go())


def test_cleanup_preserves_recording_failure_and_cannot_recover_it():
    async def go():
        core = ConnectionCore(Options("unused", 1433, "test", "unused"))
        connection = shell.Connection(core, asyncio.StreamReader(), Writer())
        channel = connection.serial_channel()

        class Recording:
            def __call__(self, event):
                raise OSError("recording failed during channel close")

        connection.capture = Recording()
        with pytest.raises(tds.ChannelCleanupError) as caught:
            await channel.close()
        assert isinstance(caught.value.cleanup, tds.CaptureError)
        assert "saved recording" in core.recovery_refusal()
        await connection.close()

    asyncio.run(go())


def test_recording_failure_on_pool_return_frees_capacity_and_preserves_both_errors():
    async def go():
        failure, cleanup = tds.CaptureError(OSError("recording failed")), OSError("close failed")

        class Session:
            async def close(self):
                raise cleanup

            def _release(self):
                raise failure

        pool, session = shell.Pool("unused", 1433, size=1), Session()
        pool._lent.add(session)
        with pytest.raises(tds.CaptureError) as caught:
            await pool._give_back(session)
        assert caught.value is failure and caught.value.pool_cleanup is cleanup
        assert pool.in_use == pool.idle == pool._opening == 0
        await pool.close()

    asyncio.run(go())
