"""A recording's owner is a physical lifetime, never a channel or pool loan."""
import asyncio
import io

import pytest

import tds
from tds.capture import Capture
from tds.connection.core import ConnectionCore, Options


def core():
    return ConnectionCore(Options("unused", 1433, "test", "unused"))


def test_capture_cannot_be_shared_or_moved_even_after_detaching():
    first, second, recording = core(), core(), Capture(io.StringIO())
    first.set_capture(recording)
    with pytest.raises(ValueError, match="physical connection"):
        second.set_capture(recording)
    assert second._capture is None and second.failure is None
    first.set_capture(None)
    first.set_capture(recording)  # the same physical lifetime may resume its recording
    first.set_capture(None)
    with pytest.raises(ValueError, match="physical connection"):
        second.set_capture(recording)


def test_failed_attachment_preserves_the_previous_recording():
    first, second = core(), core()
    a, b = Capture(io.StringIO()), Capture(io.StringIO())
    first.set_capture(a)
    second.set_capture(b)
    with pytest.raises(ValueError):
        second.set_capture(a)
    assert second._capture is b


def test_pool_refuses_a_shared_capture_before_opening_any_socket():
    with pytest.raises(ValueError, match="capture_factory"):
        tds.Pool("unused", 1433, capture=Capture(io.StringIO()))
    with pytest.raises(TypeError, match="callable"):
        tds.Pool("unused", 1433, capture_factory=42)


def test_connection_refuses_ambiguous_recording_options_before_io():
    async def go():
        with pytest.raises(ValueError, match="not both"):
            await tds.connect("unused", 1433, user="test", capture=Capture(io.StringIO()),
                              capture_factory=lambda: Capture(io.StringIO()))
    asyncio.run(go())


def test_factory_failure_does_not_strand_pool_capacity():
    async def go():
        failure = OSError("cannot create recording")

        def recording():
            raise failure

        pool = tds.Pool("unused", 1433, user="test", capture_factory=recording, size=1)
        with pytest.raises(OSError) as caught:
            await pool._borrow()
        assert caught.value is failure
        assert pool.in_use == pool.idle == pool._opening == 0
        await pool.close()
        pool = tds.Pool("unused", 1433, user="test", capture_factory=lambda: None, size=1)
        with pytest.raises(TypeError, match="must return a recording"):
            await pool._borrow()
        assert pool.in_use == pool.idle == pool._opening == 0
        await pool.close()
    asyncio.run(go())
