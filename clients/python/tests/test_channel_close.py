"""Delegated-close races through the actual shell/core, without a network server.

The controlled writer captures actual request/Attention packets; the inbox is fed
with complete or deliberately malformed server packets. No timing assumptions
about SQL Server flushing are needed here.
"""
import asyncio

import pytest
import tds

from tds import Batch, ChannelClosed, ChannelCleanupError, Cancelled
from tds.connection.core import ConnectionCore, Options, TooManySerialChannels
from tds.connection.shell import Connection
from tds.packet import Packet, PacketType, Status


class Writer:
    def __init__(self):
        self.sent = []
        self.attention = asyncio.Event()
        self.closed = False
        self.fail_attention = False

    def write(self, data):
        if data[0] == 6 and self.fail_attention:
            raise OSError("controlled Attention write failure")
        self.sent.append(data)
        if data[0] == 6:
            self.attention.set()

    async def drain(self):
        await asyncio.sleep(0)

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed

    async def wait_closed(self):
        pass


def connection():
    con = Connection(ConnectionCore(Options("localhost", 1433, "sa", "unused")), asyncio.StreamReader(), Writer())
    con._start_reading()
    return con


def packet(status=0, *, last=True, body=None):
    body = body if body is not None else b"\xfd" + status.to_bytes(2, "little") + bytes(10)
    return Packet(PacketType.SERVER_MESSAGE, Status.LAST if last else Status(0), body, None)


def test_delegated_close_waits_for_ack_and_preserves_lifetime_isolation():
    async def go():
        con = connection()
        channel = con.serial_channel()
        response = await channel.exchange(Batch("SELECT 1"))
        closing = asyncio.create_task(channel.close())
        await con._writer.attention.wait()
        with pytest.raises(TooManySerialChannels):
            con.serial_channel()
        await con._inboxes[channel.id].put(packet())  # ordinary DONE is not an ACK
        await asyncio.sleep(0)
        assert not closing.done()
        await con._inboxes[channel.id].put(packet(0x20, last=False))
        await asyncio.sleep(0)
        assert not closing.done()  # neither is an ACK without its message boundary
        await con._inboxes[channel.id].put(packet(body=b""))
        await closing
        with pytest.raises(Cancelled) as canceled:
            await response.finish()
        assert canceled.value.response.completions[-1].status & 0x20
        replacement = con.serial_channel()
        assert replacement.id != channel.id
        current = await replacement.exchange(Batch("SELECT 2"))
        await channel.close()  # stale close cannot cancel or close the replacement
        assert len([data for data in con._writer.sent if data[0] == 6]) == 1
        with pytest.raises(ChannelClosed):
            await channel.exchange(Batch("SELECT 3"))
        await con._inboxes[replacement.id].put(packet())
        await current.finish()
        await replacement.close()
        await con.close()
    asyncio.run(go())


def test_delegated_close_wakes_the_owner_read_after_cleanup():
    async def go():
        con = connection()
        channel = con.serial_channel()
        response = await channel.exchange(Batch("SELECT 1"))

        async def closer():
            while channel._operation is None:
                await asyncio.sleep(0)
            await channel.close()

        task = asyncio.create_task(closer())

        async def acknowledge():
            await con._writer.attention.wait()
            await con._inboxes[channel.id].put(packet(0x20))

        peer = asyncio.create_task(acknowledge())
        with pytest.raises(ChannelClosed) as closed:
            await response.finish()
        assert closed.value.response.completions[-1].status & 0x20
        await task
        await peer
        assert con.alive
        await con.close()
    asyncio.run(go())


@pytest.mark.parametrize("failure", ["timeout", "malformed", "write"])
def test_failed_close_preserves_both_causes_and_discards(failure):
    async def go():
        con = connection()
        con.cleanup_timeout = 0.03
        channel = con.serial_channel()
        response = await channel.exchange(Batch("SELECT 1"))
        con._writer.fail_attention = failure == "write"
        closing = asyncio.create_task(channel.close())
        if failure != "write":
            await con._writer.attention.wait()
            if failure == "malformed":
                await con._inboxes[channel.id].put(packet(body=b"\xab\x01\x00\x00"))
            else:
                await con._inboxes[channel.id].put(packet())  # missing ACK must time out
        with pytest.raises(ChannelCleanupError) as failed:
            await closing
        assert isinstance(failed.value.original, ChannelClosed)
        assert isinstance(failed.value.cleanup, TimeoutError) == (failure == "timeout")
        assert not con.alive
        # Dispose the response without invoking another network cleanup.
        response._closed = True
        await con.close()
    asyncio.run(go())


def test_canceling_a_channel_close_waiter_discards():
    async def go():
        con = connection()
        channel = con.serial_channel()
        response = await channel.exchange(Batch("SELECT 1"))
        closing = asyncio.create_task(channel.close())
        await con._writer.attention.wait()
        closing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await closing
        assert not con.alive
        response._closed = True
        await con.close()
    asyncio.run(go())


def test_scope_exit_preserves_an_original_error_if_cleanup_also_fails():
    async def go():
        con = connection()
        con.cleanup_timeout = 0.01
        with pytest.raises(ValueError, match="application failure") as failed:
            async with con.serial_channel() as channel:
                response = await channel.exchange(Batch("SELECT 1"))
                raise ValueError("application failure")
        assert isinstance(failed.value.channel_cleanup, ChannelCleanupError)
        assert isinstance(failed.value.channel_cleanup.cleanup, TimeoutError)
        assert not con.alive
        response._closed = True
        await con.close()
    asyncio.run(go())


def test_fatal_server_error_during_close_discards_even_if_ack_follows():
    import response_samples

    async def go():
        con = connection()
        channel = con.serial_channel()
        response = await channel.exchange(Batch("SELECT 1"))
        closing = asyncio.create_task(channel.close())
        await con._writer.attention.wait()
        body = bytearray(response_samples.MESSAGES[:51])
        body[0], body[8] = 0xaa, 20
        await con._inboxes[channel.id].put(packet(body=bytes(body)))
        await con._inboxes[channel.id].put(packet(0x20))
        with pytest.raises(ChannelCleanupError) as failed:
            await closing
        assert isinstance(failed.value.cleanup, tds.ServerError)
        assert failed.value.cleanup.errors[0].severity == 20
        assert not con.alive
        response._closed = True
        await con.close()
    asyncio.run(go())


@pytest.mark.live
@pytest.mark.parametrize("version", ["7.4", "8.0"])
@pytest.mark.parametrize("mars", [False, True])
def test_live_busy_close_reopen_and_stale_authority(server, version, mars):
    from conftest import fetch

    async def go():
        async with await tds.connect(**server, tds_version=version, mars=mars, database="tds_test") as con:
            old = con.serial_channel()
            response = await old.exchange(Batch("SELECT TOP (100000) 11 FROM sys.all_objects a CROSS JOIN sys.all_objects b; WAITFOR DELAY '00:00:10'; SELECT 12"))
            result_set = await anext(aiter(response))
            assert await anext(aiter(result_set)) == (11,)
            sibling = con.serial_channel() if mars else None
            closing = asyncio.create_task(old.close())  # a task with close permission, not read ownership
            with pytest.raises((ChannelClosed, Cancelled)):
                await response.finish()
            await closing
            assert con.alive
            if sibling is not None:
                assert (await fetch(sibling, "SELECT 41")).result_sets[0].rows == ((41,),)
                await sibling.close()
            replacement = con.serial_channel()
            assert replacement.id != old.id
            await old.close()
            response.cancel()  # stale controls grant no permission over a replacement
            with pytest.raises(ChannelClosed):
                await old.exchange(Batch("SELECT 999"))
            assert (await fetch(replacement, "SELECT 42")).result_sets[0].rows == ((42,),)
            await replacement.close()
            await response.close()
    asyncio.run(asyncio.wait_for(go(), 15))


@pytest.mark.live
@pytest.mark.parametrize("mars", [False, True])
def test_live_close_discards_unclaimed_large_values_and_undoes_a_partial_send(server, mars):
    from conftest import fetch
    from tds import types

    async def go():
        async with await tds.connect(**server, mars=mars, database="tds_test") as con:
            old = con.serial_channel()
            response = await old.exchange(Batch("SELECT REPLICATE(CAST(N'x' AS nvarchar(max)), 50000)"))
            await anext(aiter(response))  # metadata only; do not claim/read the large row
            await old.close()
            await response.close()
            partial = con.serial_channel()
            sending = asyncio.Event()

            async def pieces():
                yield b"x" * 100000
                sending.set()
                await asyncio.Future()  # delegated close interrupts the producer

            async def closer():
                await sending.wait()
                await partial.close()

            closing = asyncio.create_task(closer())
            with pytest.raises(ChannelClosed):
                await partial.exchange(tds.Call(tds.Builtin.SP_EXECUTESQL,
                    tds.Param("@stmt", types.nvarchar(4000), "SELECT DATALENGTH(@v)"),
                    tds.Param("@params", types.nvarchar(4000), "@v varbinary(max)"),
                    tds.Param("@v", types.varbinary(types.MAX), pieces())))
            await closing
            assert con.alive
            replacement = con.serial_channel()
            assert (await fetch(replacement, "SELECT 43")).result_sets[0].rows == ((43,),)
            await replacement.close()
    asyncio.run(asyncio.wait_for(go(), 15))
