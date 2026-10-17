"""Tests of the pool against the live SQL Server 2025.

Connections are lent whole and are reset when given back. A connection given back with a request still in progress is
never lent again (D-36).
"""

import asyncio
import gc
import warnings

import pytest

import tds
from conftest import fetch

pytestmark = pytest.mark.live


def run(coroutine):
    return asyncio.run(coroutine)


def db_name(result) -> str:
    return result.result_sets[0].rows[0][0]


async def run_sql(connection, sql: str):
    async with connection.serial_channel() as channel:
        return await fetch(channel, sql)


def test_borrowers_get_separate_sessions(server):
    async def go():
        async with tds.Pool(**server, size=2) as pool:
            async with pool.connection() as a, pool.connection() as b:
                return a.session_id, b.session_id

    first, second = run(go())
    assert first != second


def test_when_every_connection_is_lent_borrowers_wait(server):
    async def go():
        async with tds.Pool(**server, size=1) as pool:
            order, release = [], asyncio.Event()

            async def holder():
                async with pool.connection() as connection:
                    order.append(("holder", connection.session_id))
                    await release.wait()

            async def waiter():
                async with pool.connection() as connection:
                    order.append(("waiter", connection.session_id))

            held = asyncio.create_task(holder())
            await asyncio.sleep(0.1)
            waiting = asyncio.create_task(waiter())
            await asyncio.sleep(0.1)
            assert order == [order[0]] and pool.in_use == 1  # the waiter is waiting
            release.set()
            await asyncio.gather(held, waiting)
            return order

    (_, first), (_, second) = run(go())
    assert first == second  # the same session, lent again after it came back


def test_giving_back_resets_the_session(server):
    async def go():
        async with tds.Pool(**server, size=1) as pool:
            async with pool.connection() as connection:
                await run_sql(connection, "USE tempdb")
                assert connection.session.database == "tempdb"
                first = connection.session_id
            async with pool.connection() as connection:
                assert connection.session_id == first  # the same connection…
                result = await run_sql(connection, "SELECT DB_NAME()")
                return db_name(result), connection.session.database  # …but its session starts clean

    assert run(go()) == ("master", "master")


def test_a_request_cancelled_on_the_way_out_leaves_the_connection_clean_and_lent_again(server):
    """`async with` on the response cancels the request when its task is canceled.

    It reads until the server's acknowledgement, so no request is in progress when the connection is given back
    (D-34, D-36).
    """
    async def go():
        async with tds.Pool(**server, size=1) as pool:
            lent = []

            async def slow():
                async with pool.connection() as connection:
                    lent.append(connection)
                    await run_sql(connection, "WAITFOR DELAY '00:00:05'")

            task = asyncio.create_task(slow())
            await asyncio.sleep(0.5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            async with pool.connection() as connection:
                lent.append(connection)
                return lent, connection.alive, db_name(await run_sql(connection, "SELECT DB_NAME()"))

    (first, second), alive, name = run(go())
    assert second is first and alive and name == "master"


def test_a_connection_given_back_mid_request_is_closed_not_lent(server):
    """A response abandoned without `async with` leaves its request in progress.

    The connection is closed and never lent again, because its next borrower would read that request's response (D-36).
    """
    async def go():
        async with tds.Pool(**server, size=1) as pool:
            lent = []

            async def slow():
                async with pool.connection() as connection:
                    lent.append(connection)
                    async with connection.serial_channel() as channel:
                        response = await channel.exchange(tds.Batch("WAITFOR DELAY '00:00:05'"))
                        await response.fetch()  # without `async with`, nothing cancels it

            task = asyncio.create_task(slow())
            await asyncio.sleep(0.5)
            task.cancel()
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", ResourceWarning)  # the abandoned response warns, as it should
                with pytest.raises(asyncio.CancelledError):
                    await task
                gc.collect()
            async with pool.connection() as connection:
                lent.append(connection)
                return lent, db_name(await run_sql(connection, "SELECT DB_NAME()"))

    (dirty, fresh), name = run(go())
    # A new connection, not the one whose request is still in progress. The test compares the connections themselves,
    # because SQL Server reuses session ids and the new connection can get the old one's id.
    assert fresh is not dirty and not dirty.alive and name == "master"


def test_each_borrower_starts_with_a_clean_session(server):
    async def go():
        async with tds.Pool(**server, size=1) as pool:
            async with pool.connection() as connection:
                await run_sql(connection, "USE tempdb")
            async with pool.connection() as connection:
                return db_name(await run_sql(connection, "SELECT DB_NAME()"))

    assert run(go()) == "master"
