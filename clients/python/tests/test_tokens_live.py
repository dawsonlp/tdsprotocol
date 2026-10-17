"""Tests of the tokens that the local SQL Server 2025 can be made to send (M11).

These are browse mode's TABNAME and COLINFO. The server sends them for FOR BROWSE, under SET NO_BROWSETABLE ON, and for
every server cursor. Before M11, each of these ended the connection.
"""

import asyncio
from decimal import Decimal

import pytest

import tds
from conftest import fetch
from tds import types
from tds.response import ColumnInfo
from tds.tokens import ColumnInfoStatus as S

pytestmark = pytest.mark.live


def run(coroutine):
    return asyncio.run(coroutine)


async def table(channel) -> None:
    await fetch(channel, "CREATE TABLE #o (id int PRIMARY KEY, total money, note nvarchar(10), rv rowversion); "
                         "INSERT #o (id, total, note) VALUES (1, 9.5, N'x'), (2, 3, NULL)")


def test_browse_mode_says_where_each_column_came_from(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await table(channel)
                [rs] = (await fetch(channel, "SELECT total AS amount, note, id + 1 AS next FROM #o FOR BROWSE")).result_sets
                [join] = (await fetch(channel, "SELECT o.note, p.total FROM #o AS o JOIN #o AS p ON p.id = o.id FOR BROWSE")).result_sets
                return rs, join

    rs, join = run(go())
    assert rs.tables == (("#o",),)
    assert [c.name for c in rs.columns] == ["amount", "note", "next", "id", "rv"]  # the key and rowversion are added
    assert rs.column_info == (
        ColumnInfo(1, 1, S.DIFFERENT_NAME, "total"),  # an alias names its base column
        ColumnInfo(2, 1, S(0), None),
        ColumnInfo(3, 0, S.EXPRESSION, None),  # no table
        ColumnInfo(4, 1, S.KEY | S.HIDDEN, None),  # not asked for, but added because it is the key
        ColumnInfo(5, 1, S.HIDDEN, None))
    assert rs.rows[0][:3] == (Decimal("9.5000"), "x", 2) and rs.rows[0][3] == 1
    assert join.tables == (("#o",), ("#o",)) and [c.table for c in join.column_info] == [1, 2, 1, 1, 2, 2]


def test_no_browsetable_and_server_cursors_send_browse_tokens(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await table(channel)
                [plain] = (await fetch(channel, "SET NO_BROWSETABLE ON; SELECT note FROM #o; SET NO_BROWSETABLE OFF")).result_sets
                cursors = []
                for scroll in (1, 2, 4, 8, 16):  # keyset, dynamic, forward-only, static, fast forward
                    call = tds.Call(tds.Builtin.SP_CURSOROPEN, tds.Param("@cursor", types.int, None, output=True),
                                    tds.Param("@stmt", types.nvarchar(100), "SELECT total FROM #o"),
                                    tds.Param("@scrollopt", types.int, scroll, output=True),
                                    tds.Param("@ccopt", types.int, 1, output=True), tds.Param("@rowcount", types.int, None, output=True))
                    [rs] = (await fetch(channel, call)).result_sets
                    cursors.append((rs.tables, rs.column_info[0]))
                return plain, cursors

    plain, cursors = run(go())
    assert plain.tables == (("#o",),) and [c.status for c in plain.column_info] == [S(0), S.KEY | S.HIDDEN, S.HIDDEN]
    assert all(tables == (("#o",),) and info.table == 1 for tables, info in cursors)
