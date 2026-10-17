"""Tests of transaction-manager requests against the live SQL Server 2025 (M10, D-51).

Each request works, and the session follows its announcements. Every behavior documented on Requests, Request Response
and Token Stream holds, including the deviations from MS-TDS.
"""

import asyncio

import pytest

import tds
from conftest import fetch
from tds.requests import HEADERS, Encoded, headers
from tds.packet import PacketType
from tds.response import Announcement
from tds.tokens import EnvKind
from tds.transactions import Begin, Commit, CoordinatorAddress, Isolation, Promote, Propagate, Rollback, Save

pytestmark = pytest.mark.live


def run(coroutine):
    return asyncio.run(coroutine)


def announced(fetched) -> list[EnvKind]:
    return [i.kind for i in fetched.sequence if isinstance(i, Announcement)]


async def state(channel) -> tuple[int, int]:
    """@@TRANCOUNT, and the session's isolation level."""
    rs = (await fetch(channel, "SELECT @@TRANCOUNT, CAST(transaction_isolation_level AS int) FROM sys.dm_exec_sessions "
                               "WHERE session_id = @@SPID")).result_sets[0]
    return rs.rows[0]


async def refused(channel, request) -> tuple[list[int], list[EnvKind]]:
    with pytest.raises(tds.ServerError) as e:
        await fetch(channel, request)
    return [x.number for x in e.value.errors], announced(e.value.response)


def test_begin_nest_save_roll_back_and_commit(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                seen = []

                async def step(label, request):
                    fetched = await fetch(channel, request)
                    seen.append((label, announced(fetched), connection.session.transaction != 0, *await state(channel)))

                await fetch(channel, "CREATE TABLE #t (a int)")
                await step("begin", Begin())
                await step("nested begin", Begin())
                await fetch(channel, "INSERT #t VALUES (1)")
                await step("save", Save("before two"))
                await fetch(channel, "INSERT #t VALUES (2)")
                await step("back to the savepoint", Rollback("before two"))
                await step("inner commit", Commit())
                await step("outer commit", Commit())
                rows = (await fetch(channel, "SELECT a FROM #t")).result_sets[0].rows
                await step("begin named", Begin(name="named"))
                await step("roll back by name", Rollback("named"))
                return seen, rows

    seen, rows = run(go())
    assert seen == [  # label, what was announced, whether the session holds a descriptor, @@TRANCOUNT, isolation
        ("begin", [EnvKind.BEGIN_TRANSACTION], True, 1, 2),
        ("nested begin", [], True, 2, 2),  # only the outermost transaction is announced
        ("save", [], True, 2, 2),
        ("back to the savepoint", [], True, 2, 2),
        ("inner commit", [], True, 1, 2),
        ("outer commit", [EnvKind.COMMIT_TRANSACTION], False, 0, 2),
        ("begin named", [EnvKind.BEGIN_TRANSACTION], True, 1, 2),
        ("roll back by name", [EnvKind.ROLLBACK_TRANSACTION], False, 0, 2),
    ]
    assert rows == ((1,),)  # the row after the savepoint was rolled back


def test_commit_and_begin_another_keeps_its_isolation_level(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, Begin())
                first = connection.session.transaction
                fetched = await fetch(channel, Commit(begin=Begin(Isolation.SERIALIZABLE)))
                second = connection.session.transaction
                during = await state(channel)
                await fetch(channel, Rollback())
                return announced(fetched), first != second != 0, during, await state(channel)

    kinds, new_descriptor, during, after = run(go())
    assert kinds == [EnvKind.COMMIT_TRANSACTION, EnvKind.BEGIN_TRANSACTION]  # one request, both announced
    assert new_descriptor and during == (1, 4)
    assert after == (0, 4)  # serializable stays for the session after the transaction ends


def test_what_the_server_refuses_and_what_follows(server):
    class OddName:  # a savepoint name of 3 bytes. The API always writes UTF-16LE, so this request is built by hand.
        kind, label, metadata = PacketType.TRANSACTION_MANAGER, "transaction manager", ()

        def encode(self, context, record):
            return Encoded(HEADERS.encode(headers(context), False)[0] + b"\x09\x00\x03abc", None)

    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                out = {"commit, none open": await refused(channel, Commit()),
                       "rollback, none open": await refused(channel, Rollback()),
                       "save, none open": await refused(channel, Save("sp"))}
                for label, request in (("empty savepoint name", Save("")), ("odd byte count", OddName())):
                    await fetch(channel, Begin())
                    out[label] = await refused(channel, request)
                    out[label + ": afterwards"] = (connection.session.transaction, *await state(channel))
                return out

    out = run(go())
    assert out["commit, none open"] == ([3902], [])
    assert out["rollback, none open"] == ([3903], [])
    assert out["save, none open"] == ([628], [])
    # a refused savepoint name rolls back the open transaction, and the server announces it
    assert out["empty savepoint name"] == ([3977], [EnvKind.ROLLBACK_TRANSACTION])
    assert out["odd byte count"] == ([3976], [EnvKind.ROLLBACK_TRANSACTION])
    assert out["empty savepoint name: afterwards"] == out["odd byte count: afterwards"] == (0, 0, 2)


def test_a_refusal_says_what_the_server_did_next(server):  # literate errors
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, Begin())
                with pytest.raises(tds.ServerError) as refused:
                    await fetch(channel, Save(""))
                return str(refused.value)

    message = run(go())
    assert message.startswith("SQL Server reported 1 error for the transaction-manager request Save(“”):")
    assert "Error · Msg 3977, Level 16, State 1" in message and "The savepoint name cannot be NULL." in message
    assert message.endswith("Then: the server announced rollback transaction; the response ended.")


def test_distributed_transactions(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                address = await fetch(channel, CoordinatorAddress())
                await fetch(channel, Begin())
                promoted = await fetch(channel, Promote())
                await fetch(channel, Rollback())
                await fetch(channel, "BEGIN TRANSACTION")  # begun in T-SQL. MS-TDS says that promote refuses it.
                promoted_tsql = await fetch(channel, Promote())
                await fetch(channel, Rollback())
                propagate = await refused(channel, Propagate(b"not a cookie"))
                return address, promoted, promoted_tsql, propagate, (await fetch(channel, "SELECT 1")).result_sets[0].rows

    address, promoted, promoted_tsql, propagate, after = run(go())
    [rs] = address.result_sets
    assert len(rs.columns) == 1 and len(rs.rows) == 1 and isinstance(rs.rows[0][0], bytes) and rs.rows[0][0]
    assert announced(address) == []  # no transaction-manager-address announcement, though MS-TDS mentions one
    for fetched in (promoted, promoted_tsql):  # the token, read past the announcement's length of 1
        [token] = [i.new for i in fetched.sequence if isinstance(i, Announcement) and i.kind == EnvKind.PROMOTE_TRANSACTION]
        assert len(token) > 100
    assert propagate == ([8509], [])  # Propagate is not tested further, because it needs a coordinator's cookie
    assert after == ((1,),)  # and the connection still works
