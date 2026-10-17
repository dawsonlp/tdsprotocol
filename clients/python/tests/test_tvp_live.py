"""Tests of table-valued parameters against the live SQL Server 2025 (M8).

A table with a column of every short type reaches a procedure exactly, from a list or from a source. The tests also
cover columns that the server fills, DEFAULT, the ordering tokens, and what the server refuses (D-48, D-49).
"""

import asyncio
from decimal import Decimal

import pytest

import tds
from conftest import fetch
from tds import types
from tds.types import Order
from test_calls_live import projection
from test_types_live import COLUMNS, LIMITS

pytestmark = pytest.mark.live
TEXT = types.nvarchar(4000)


def run(coroutine):
    return asyncio.run(coroutine)


async def errors(channel, request) -> list[int]:
    with pytest.raises(tds.ServerError) as refused:
        await fetch(channel, request)
    return [e.number for e in refused.value.errors]


@pytest.mark.parametrize("given_as", ["list", "source"])
def test_a_table_of_every_short_type_reaches_a_procedure_exactly(server, given_as):
    names = list(COLUMNS)
    columns = ", ".join(f"{n} {declared} NULL" for n, (declared, _) in COLUMNS.items())

    async def go():
        async with await tds.connect(**server, database="tds_test") as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "IF SCHEMA_ID('shop') IS NULL EXEC('CREATE SCHEMA shop')")
                await fetch(channel, "DROP PROCEDURE IF EXISTS shop.copy_short_types; "
                                     "DROP TABLE IF EXISTS shop.tvp_source, shop.tvp_copy; "
                                     "DROP TYPE IF EXISTS shop.short_types_row")
                await fetch(channel, f"CREATE TABLE shop.tvp_source (id int IDENTITY, {columns}); "
                                     f"CREATE TABLE shop.tvp_copy (id int, {columns}); "
                                     f"CREATE TYPE shop.short_types_row AS TABLE (id int, {columns})")
                await fetch(channel, "CREATE PROCEDURE shop.copy_short_types @rows shop.short_types_row READONLY AS "
                                     "INSERT shop.tvp_copy SELECT * FROM @rows")
                generated = ", ".join(expr for _, expr in COLUMNS.values())
                await fetch(channel, f"INSERT shop.tvp_source ({', '.join(names)}) SELECT TOP 200 {generated} FROM sys.all_objects")
                for side in (0, 1):
                    await fetch(channel, f"INSERT shop.tvp_source ({', '.join(names)}) VALUES ({', '.join(LIMITS[n][side] for n in names)})")
                await fetch(channel, f"INSERT shop.tvp_source ({', '.join(names)}) VALUES ({', '.join('NULL' for _ in names)})")

                source = (await fetch(channel, f"SELECT id, {', '.join(names)} FROM shop.tvp_source ORDER BY id")).result_sets[0]
                table = types.table("shop.short_types_row", *[c.type for c in source.columns])
                rows = list(source.rows)

                async def produce():
                    for row in rows:
                        yield row

                value = rows if given_as == "list" else produce()
                async with await channel.exchange(tds.Call("shop.copy_short_types", tds.Param("@rows", table, value))) as response:
                    [returned] = await response.returns(unread=tds.Unread.DISCARD)
                assert not returned.failed and returned.status == 0

                exact = ", ".join(projection(n, COLUMNS[n][0]) for n in names)
                differences = await fetch(channel, f"""
                    SELECT COUNT(*) FROM (SELECT id, {exact} FROM shop.tvp_source EXCEPT SELECT id, {exact} FROM shop.tvp_copy) AS a;
                    SELECT COUNT(*) FROM (SELECT id, {exact} FROM shop.tvp_copy EXCEPT SELECT id, {exact} FROM shop.tvp_source) AS b""")
                copy = (await fetch(channel, f"SELECT id, {', '.join(names)} FROM shop.tvp_copy ORDER BY id")).result_sets[0]
                return rows, copy.rows, [rs.rows[0][0] for rs in differences.result_sets]

    source, copy, differences = run(go())
    assert len(source) == 203 and differences == [0, 0]  # equal on the server, byte for byte
    assert list(copy) == source  # and in Python


def test_columns_the_server_fills_default_and_the_ordering_tokens(server):
    changes = types.table("shop.tvp_price_change", types.int, types.decimal(10, 2))
    rows = [(1, Decimal("9.99")), (2, None), (3, Decimal("-0.01"))]

    async def go():
        async with await tds.connect(**server, database="tds_test") as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "IF SCHEMA_ID('shop') IS NULL EXEC('CREATE SCHEMA shop')")
                await fetch(channel, "DROP PROCEDURE IF EXISTS shop.show_changes, shop.show_lines; "
                                     "DROP TYPE IF EXISTS shop.tvp_price_change; DROP TYPE IF EXISTS shop.tvp_order_line")
                await fetch(channel, "CREATE TYPE shop.tvp_price_change AS TABLE (product_id int PRIMARY KEY, price decimal(10, 2)); "
                                     "CREATE TYPE shop.tvp_order_line AS TABLE (line int IDENTITY, product int, qty int, "
                                     "total AS qty * 2, note nvarchar(20) DEFAULT N'none')")
                await fetch(channel, "CREATE PROCEDURE shop.show_changes @changes shop.tvp_price_change READONLY AS "
                                     "SELECT * FROM @changes ORDER BY product_id")
                await fetch(channel, "CREATE PROCEDURE shop.show_lines @lines shop.tvp_order_line READONLY AS SELECT * FROM @lines")

                async def rows_of(table, value, procedure="shop.show_changes", name="@changes"):
                    return (await fetch(channel, tds.Call(procedure, tds.Param(name, table, value)))).result_sets[0].rows

                seen = {"rows": await rows_of(changes, rows), "default": await rows_of(changes, tds.DEFAULT),
                        "empty": await rows_of(changes, [])}
                filled = types.table("shop.tvp_order_line", types.default(types.int), types.int, types.int,
                                     types.default(types.int), types.default(types.nvarchar(20)))
                seen["filled"] = await rows_of(filled, [(7, 2), (9, 1)], "shop.show_lines", "@lines")
                hinted = types.table("shop.tvp_price_change", types.int, types.decimal(10, 2),
                                     order=[(1, Order.ASCENDING)], unique=[1])
                seen["hinted"] = await rows_of(hinted, rows)
                seen["unsorted"] = await errors(channel, tds.Call("shop.show_changes", tds.Param("@changes", hinted, rows[::-1])))
                swapped = types.table("shop.tvp_price_change", types.int, types.decimal(10, 2), send_order=[2, 1])
                seen["swapped"] = await rows_of(swapped, rows)
                identity = types.table("shop.tvp_order_line", types.int, types.int, types.int, types.default(types.int),
                                       types.default(types.nvarchar(20)))
                seen["identity sent"] = await errors(channel, tds.Call("shop.show_lines", tds.Param("@lines", identity, [(5, 7, 2)])))
                statement = [tds.Param("@stmt", TEXT, "SELECT SUM(price) FROM @c"),
                             tds.Param("@params", TEXT, "@c shop.tvp_price_change READONLY")]
                seen["named"] = (await fetch(channel, tds.Call(tds.Builtin.SP_EXECUTESQL, *statement,
                                                               tds.Param("@c", changes, rows)))).result_sets[0].rows
                unnamed = types.table("", types.int, types.decimal(10, 2))
                seen["unnamed"] = await errors(channel, tds.Call(tds.Builtin.SP_EXECUTESQL, *statement, tds.Param("@c", unnamed, rows)))
                seen["unnamed, to a procedure"] = await rows_of(unnamed, rows)
                return seen

    seen = run(go())
    assert seen["rows"] == seen["hinted"] == seen["swapped"] == seen["unnamed, to a procedure"] == tuple(rows)
    assert seen["default"] == seen["empty"] == ()  # DEFAULT: no table, so the procedure sees an empty one
    assert seen["filled"] == ((1, 7, 2, 4, "none"), (2, 9, 1, 2, "none"))  # numbered, computed, defaulted by the server
    assert 4819 in seen["unsorted"]  # the sort hint is checked: rows out of order are refused
    assert 1077 in seen["identity sent"]  # an identity column without the default flag is refused
    assert seen["named"] == ((Decimal("9.98"),),)
    assert 8059 in seen["unnamed"]  # sp_executesql has no procedure that names the type, so the name must be sent


def test_the_server_refuses_what_the_driver_sends_unchecked(server):  # D-50's rule: let the server say what's wrong
    async def go():
        async with await tds.connect(**server, database="tds_test") as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "IF SCHEMA_ID('shop') IS NULL EXEC('CREATE SCHEMA shop')")
                await fetch(channel, "DROP PROCEDURE IF EXISTS shop.tvp_refusals; DROP TYPE IF EXISTS shop.tvp_refused; "
                                     "DROP TYPE IF EXISTS shop.tvp_refused_line")
                await fetch(channel, "CREATE TYPE shop.tvp_refused AS TABLE (id int PRIMARY KEY, price decimal(10, 2)); "
                                     "CREATE TYPE shop.tvp_refused_line AS TABLE (line int IDENTITY, qty int)")
                await fetch(channel, "CREATE PROCEDURE shop.tvp_refusals @t shop.tvp_refused READONLY AS SELECT * FROM @t")
                pc = types.table("shop.tvp_refused", types.int, types.decimal(10, 2))
                rows = [(1, Decimal("1.00")), (2, None)]

                def call(table, value, output=False):
                    return tds.Call("shop.tvp_refusals", tds.Param("@t", table, value, output=output))

                cases = {
                    "None": call(pc, None),
                    "output": call(pc, rows, output=True),
                    "a column too many": call(types.table("shop.tvp_refused", types.int, types.decimal(10, 2), types.int), [(1, None, 3)]),
                    "1,025 columns": call(types.table("shop.tvp_refused", *[types.int] * 1025), [tuple(range(1025))]),
                    "a table in a table": call(types.table("shop.tvp_refused", types.int, types.table("shop.tvp_refused", types.int)), [(1, [(2,)])]),
                    "a column twice in the hint": call(types.table("shop.tvp_refused", types.int, types.decimal(10, 2),
                                                                   order=[(1, Order.ASCENDING), (1, Order.ASCENDING)]), rows),
                    "a hint on a column the server fills": tds.Call(
                        tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, "SELECT COUNT(*) FROM @t"),
                        tds.Param("@params", TEXT, "@t shop.tvp_refused_line READONLY"),
                        tds.Param("@t", types.table("shop.tvp_refused_line", types.default(types.int), types.int, unique=[1]), [(5,)])),
                    "the second of two calls": tds.Calls(call(pc, rows), call(pc, None)),
                }
                out = {}
                for label, request in cases.items():
                    with pytest.raises(tds.ServerError) as refused:
                        await fetch(channel, request)
                    out[label] = (refused.value.errors[0].number, str(refused.value))
                await fetch(channel, "DROP PROCEDURE shop.tvp_refusals; DROP TYPE shop.tvp_refused; DROP TYPE shop.tvp_refused_line")
                return out

    out = run(go())
    assert {label: number for label, (number, _) in out.items()} == {
        "None": 8060, "output": 8162, "a column too many": 500, "1,025 columns": 8050, "a table in a table": 8032,
        "a column twice in the hint": 8054, "a hint on a column the server fills": 8057, "the second of two calls": 8060}
    number, message = out["the second of two calls"]  # the error says which call, and what the server said in full
    assert "Error · Msg 8060, Level 16, State 1, Line 1" in message and "null and not set to default" in message
    assert "(in call 2 of 2: shop.tvp_refusals)" in message and message.endswith("Then: the response ended.")
