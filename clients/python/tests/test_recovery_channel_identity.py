"""Application authority survives recovery; physical SMP identities do not."""
import pytest

from tds.connection.core import ConnectionCore, MARS_HEADER, MarsData, MarsFlags, Options, SerialChannelMisuse
from tds.session import Recovery, SessionState
from test_mars_framing import frame


def test_a_paused_old_procedure_cannot_write_to_the_replacement_transport():
    import asyncio
    from tds.connection.core import Obtain, Send
    from tds.connection.shell import Connection
    from test_channel_close import Writer

    async def go():
        old, original_writer, replacement_writer = core(), Writer(), Writer()
        connection = Connection(old, asyncio.StreamReader(), original_writer)
        entered, resume = asyncio.Event(), asyncio.Event()

        async def callback():
            entered.set()
            await resume.wait()

        def procedure():
            yield Obtain(callback, ())
            yield Send(b"old request bytes")

        advancing = asyncio.create_task(connection._run(procedure()))
        await entered.wait()
        old.failure = ConnectionError("controlled transport break")
        connection._core, connection._writer = core(), replacement_writer
        resume.set()
        with pytest.raises(ConnectionError, match="failed physical connection"):
            await advancing
        assert original_writer.sent == replacement_writer.sent == []
        assert not replacement_writer.closed
        await connection.close()

    asyncio.run(go())


def core():
    result = ConnectionCore(Options("localhost", 1433, "unused", "unused"))
    result.link.mars = True
    result.recovery = Recovery(SessionState(), {})
    return result


def test_adoption_remaps_both_directions_and_keeps_lifetime_owners():
    old = core()
    retired, _ = old.open_channel("retired owner")
    old.close_channel(retired)
    first, _ = old.open_channel("first owner")
    second, _ = old.open_channel("second owner")
    replacement = core()
    sends = replacement.adopt(old)
    assert [MARS_HEADER.decode(s.data[:16]).session_id for s in sends] == [0, 1]
    assert [(c.id, c.wire_id, c.owner) for c in replacement.link.channels.values()] == [
        (first, 0, "first owner"), (second, 1, "second owner")]
    assert replacement.feed(frame(0, payload=b"first")) == [(first, MarsData(b"first"))]
    assert replacement.feed(frame(1, payload=b"second")) == [(second, MarsData(b"second"))]
    assert replacement.close_channel(retired) == []  # old id 0 cannot close new wire id 0
    third, sends = replacement.open_channel("third owner")
    assert third == 3 and MARS_HEADER.decode(sends[0].data).session_id == 2
    assert MARS_HEADER.decode(replacement.close_channel(first)[0].data).session_id == 0
    assert replacement.feed(frame(0, MarsFlags.FIN, sequence=1)) == [(first, None)]


def test_application_ids_can_outgrow_the_per_transport_wire_namespace():
    connection = core()
    connection._next_channel = 70000
    channel, sends = connection.open_channel("owner")
    assert channel == 70000 and MARS_HEADER.decode(sends[0].data).session_id == 0
    connection.link._next_wire_channel = 65535
    last, sends = connection.open_channel("owner")
    assert MARS_HEADER.decode(sends[0].data).session_id == 65535
    connection.close_channel(last)
    with pytest.raises(SerialChannelMisuse, match="wire identities are exhausted"):
        connection.open_channel("owner")
    replacement = core()
    replacement.adopt(connection)
    next_id, sends = replacement.open_channel("owner")
    assert next_id == 70002 and MARS_HEADER.decode(sends[0].data).session_id == 1
