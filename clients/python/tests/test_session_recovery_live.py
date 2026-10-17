"""Tests of session recovery (M14, D-57) against the live SQL Server 2025.

A session is broken by KILL from a second connection, which closes its connection as a failover or a network fault
would. The tests cover recovery by the next exchange and by connection.recover(), which state comes back and which
doesn't, what the server refuses to recover, and a request in progress, which is never sent again.
"""

import asyncio

import pytest

import tds
from conftest import fetch
from tds import Feature, SessionNotRecovered

pytestmark = pytest.mark.live

SETTINGS = ("SELECT DB_NAME(), @@LANGUAGE, @@DATEFIRST, CAST(SESSIONPROPERTY('ANSI_NULLS') AS int), @@TEXTSIZE, "
            "@@LOCK_TIMEOUT, CAST(CONTEXT_INFO() AS varbinary(2)), "
            "(SELECT transaction_isolation_level FROM sys.dm_exec_sessions WHERE session_id = @@SPID)")
CHANGED = ("USE tempdb; SET LANGUAGE Deutsch; SET DATEFIRST 3; SET ANSI_NULLS OFF; SET TEXTSIZE 100; SET LOCK_TIMEOUT 5; "
           "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE; DECLARE @c varbinary(128) = 0x0102; SET CONTEXT_INFO @c")


async def value(channel, sql):
    return (await fetch(channel, sql)).result_sets[0].rows[0]


async def kill(server, connection):
    """End the connection's session from another connection, and wait until the driver sees its connection close."""
    async with await tds.connect(**server) as admin:
        async with admin.serial_channel() as channel:
            await fetch(channel, f"KILL {connection.session_id}")
    for _ in range(100):
        if not connection.alive:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("the killed connection still looks alive")


def test_the_next_exchange_recovers_a_session_broken_while_idle(server):
    steps = []

    async def go():
        async with await tds.connect(**server, observe=lambda e: steps.append(e.text) if e.kind == "step" else None) as c:
            async with c.serial_channel() as channel:
                await fetch(channel, CHANGED + "; EXEC sp_set_session_context N'k', N'v'")
                before = await value(channel, SETTINGS)
                await kill(server, c)
                after = await value(channel, SETTINGS)  # recovered first, then sent
                context = await value(channel, "SELECT SESSION_CONTEXT(N'k')")
                return before, after, context, c.recoveries, c.alive

    before, after, context, recoveries, alive = asyncio.run(go())
    assert before == ("tempdb", "Deutsch", 3, 0, 100, 5, b"\x01\x02", 4)
    assert after == before and recoveries == 1 and alive
    assert context == (None,)  # the server doesn't report session context as a state, so it isn't recovered
    assert any(s.startswith("recover · session ") for s in steps)
    assert any(s.startswith("recovered · session ") and "database tempdb" in s for s in steps)


def test_recovering_explicitly(server):
    async def go():
        async with await tds.connect(**server) as c:
            async with c.serial_channel() as channel:
                await fetch(channel, "SET LANGUAGE Deutsch")
                with pytest.raises(SessionNotRecovered, match="isn't broken: there is nothing to recover"):
                    await c.recover()
                await kill(server, c)
                await c.recover()
                return c.alive, c.recoveries, await value(channel, "SELECT @@LANGUAGE")

    assert asyncio.run(go()) == (True, 1, ("Deutsch",))


@pytest.mark.parametrize("sql, reason", [
    ("CREATE TABLE #t (a int)", "a temporary table exists"),
    ("BEGIN TRANSACTION", "a transaction is open"),
    ("EXECUTE AS LOGIN = 'sa'", "the session is impersonating another login (EXECUTE AS)"),
])
def test_what_the_server_wont_let_be_recovered(server, sql, reason):
    async def go():
        async with await tds.connect(**server) as c:
            async with c.serial_channel() as channel:
                await fetch(channel, sql)
                await kill(server, c)
                with pytest.raises(SessionNotRecovered) as e:
                    await fetch(channel, "SELECT 1")
                return str(e.value)

    said = asyncio.run(go())
    assert f"the server marked it not recoverable after the SQL batch “{sql}”: {reason}" in said
    assert said.endswith("The connection broke: the server closed the connection")


def test_what_cleared_it_lets_it_be_recovered_again(server):
    async def go():
        async with await tds.connect(**server) as c:
            async with c.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE #t (a int); DROP TABLE #t; BEGIN TRANSACTION; COMMIT")
                await kill(server, c)
                return await value(channel, "SELECT 1"), c.recoveries

    assert asyncio.run(go()) == ((1,), 1)


class Relay:
    """A TCP relay between the client and the server, which the test can cut as a network fault would.

    A cut resets the connections on both sides and sends nothing more. The relay continues to accept new connections.
    """

    def __init__(self, server):
        self._to = (server["host"], server["port"])
        self._writers = []

    async def __aenter__(self):
        self._listening = await asyncio.start_server(self._accept, self._to[0], 0)
        self.port = self._listening.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.cut()
        self._listening.close()

    async def _accept(self, reader, writer):
        up_reader, up_writer = await asyncio.open_connection(*self._to)
        self._writers += [writer, up_writer]
        for source, sink in ((reader, up_writer), (up_reader, writer)):
            asyncio.create_task(self._pipe(source, sink))

    @staticmethod
    async def _pipe(source, sink):
        try:
            while data := await source.read(65536):
                sink.write(data)
        except ConnectionError:
            pass

    def cut(self):
        for writer in self._writers:
            writer.transport.abort()
        self._writers = []


def test_a_cut_connection_is_recovered_by_the_next_exchange(server):
    async def go():
        async with Relay(server) as relay, await tds.connect(**{**server, "port": relay.port}) as c:
            async with c.serial_channel() as channel:
                await fetch(channel, "SET LANGUAGE Deutsch")
                relay.cut()
                while c.alive:
                    await asyncio.sleep(0.01)
                return await value(channel, "SELECT @@LANGUAGE"), c.recoveries

    assert asyncio.run(go()) == (("Deutsch",), 1)


def test_a_request_in_flight_is_never_sent_again(server):
    async def go():
        async with Relay(server) as relay, await tds.connect(**{**server, "port": relay.port}) as c:
            async with c.serial_channel() as channel:
                await fetch(channel, "SET LANGUAGE Deutsch")
                response = await channel.exchange(tds.Batch("WAITFOR DELAY '00:00:02'"))
                asyncio.get_running_loop().call_later(0.3, relay.cut)
                with pytest.raises(ConnectionError) as in_flight:
                    await response.fetch()
                with pytest.raises(ConnectionError) as next_one:  # not recovered by itself
                    await fetch(channel, "SELECT 1")
                await c.recover()  # the application's choice
                return str(in_flight.value), str(next_one.value), await value(channel, "SELECT @@LANGUAGE")

    in_flight, next_one, language = asyncio.run(go())
    assert "broke while the SQL batch “WAITFOR DELAY '00:00:02'” was in progress" in in_flight
    assert "never sends it again (D-57)" in in_flight
    assert "isn't recovered by itself" in next_one and "connection.recover()" in next_one
    assert language == ("Deutsch",)


def test_a_session_killed_mid_request_isnt_recovered(server):
    async def go():
        async with await tds.connect(**server) as c:
            async with c.serial_channel() as channel:
                response = await channel.exchange(tds.Batch("WAITFOR DELAY '00:00:05'"))
                killing = asyncio.create_task(kill(server, c))
                with pytest.raises(tds.ServerError) as killed:  # the server ends the response, then the connection
                    await response.fetch()
                await killing
                with pytest.raises(SessionNotRecovered) as refused:  # its last SESSIONSTATE said so
                    await fetch(channel, "SELECT 1")
                return killed.value.errors[0].number, str(refused.value)

    number, refused = asyncio.run(go())
    assert number == 596
    assert "after the SQL batch “WAITFOR DELAY '00:00:05'”: the session was killed (KILL) while a request ran" in refused


def test_without_the_feature_there_is_nothing_to_recover_with(server):
    async def go():
        features = [f for f in tds.DEFAULT_FEATURES if f != Feature.SESSION_RECOVERY]
        async with await tds.connect(**server, features=features) as c:
            async with c.serial_channel() as channel:
                await kill(server, c)
                with pytest.raises(SessionNotRecovered) as e:
                    await fetch(channel, "SELECT 1")
                return str(e.value)

    assert "the login didn't ask for session recovery" in asyncio.run(go())


def test_under_mars_every_serial_channel_comes_back(server):
    async def go():
        async with await tds.connect(**server, mars=True) as c:
            async with c.serial_channel() as first, c.serial_channel() as second:
                await fetch(first, "SET LANGUAGE Deutsch")
                await kill(server, c)
                return (await value(second, "SELECT @@LANGUAGE"), await value(first, "SELECT @@LANGUAGE"),
                        (first.id, second.id), c.recoveries)

    assert asyncio.run(go()) == (("Deutsch",), ("Deutsch",), (0, 1), 1)


def test_under_tds_8(server):
    async def go():
        async with await tds.connect(**server, tds_version="8.0") as c:
            async with c.serial_channel() as channel:
                await fetch(channel, "SET DATEFIRST 3")
                await kill(server, c)
                return await value(channel, "SELECT @@DATEFIRST"), c.recoveries

    assert asyncio.run(go()) == ((3,), 1)
