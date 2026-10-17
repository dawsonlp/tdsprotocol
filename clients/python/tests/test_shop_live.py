"""Tests of the shop scenario against the live SQL Server 2025 (Building the Client §4).

M8 is done when all of the scenario round-trips. A `shop` schema in `tds_test` grows with the milestones:

- M1–M3: customers, products and orders using every short type, and a procedure that returns an output
- M4: photos, descriptions and legacy notes
- M5: attributes as sql_variant
- M6: json details and a vector embedding
- M7: a geography store location
- M8: bulk price updates through a table-valued parameter

Every value that the server generates is sent back exactly (D-48).
"""

import asyncio
from decimal import Decimal

import pytest

import tds
from conftest import fetch
from tds import types
from test_variant_live import BASES, PROPERTIES

pytestmark = pytest.mark.live
TEXT = types.nvarchar(4000)
RANDOM = "ABS(CHECKSUM(NEWID()))"

TABLES = {  # table: rows, then {column: (declaration, a value the server generates)}
    "customers": (60, {
        "name": ("nvarchar(100)", "CONVERT(nvarchar(100), CRYPT_GEN_RANDOM(2 * (1 + ABS(CHECKSUM(NEWID())) % 50)))"),
        "email": ("varchar(100)", "CONVERT(varchar(100), CRYPT_GEN_RANDOM(1 + ABS(CHECKSUM(NEWID())) % 100))"),
        "code": ("char(10)", "CONVERT(char(10), CRYPT_GEN_RANDOM(10))"),
        "country": ("nchar(2)", "CONVERT(nchar(2), CRYPT_GEN_RANDOM(4))"),
        "login": ("sysname", "CONVERT(nvarchar(64), CRYPT_GEN_RANDOM(128))"),
        "joined": ("datetime2(7)", "DATEADD(nanosecond, ABS(CHECKSUM(NEWID())) % 1000000000, SYSDATETIME())"),
        "birthday": ("date", "DATEADD(day, CHECKSUM(NEWID()) % 30000, CAST(SYSDATETIME() AS date))"),
        "last_seen": ("datetimeoffset(7)", "SWITCHOFFSET(SYSDATETIMEOFFSET(), CHECKSUM(NEWID()) % 841)"),
        "usual_time": ("time(7)", "CAST(DATEADD(nanosecond, ABS(CHECKSUM(NEWID())) % 1000000000, SYSDATETIME()) AS time(7))"),
        "created": ("datetime", "DATEADD(millisecond, ABS(CHECKSUM(NEWID())) % 1000, GETDATE())"),
        "touched": ("smalldatetime", "CAST(SYSDATETIME() AS smalldatetime)"),
        "vip": ("bit", f"{RANDOM} % 2"),
        "credit": ("smallmoney", "CAST((RAND(CHECKSUM(NEWID())) - 0.5) * 1e5 AS smallmoney)"),
        "rating": ("tinyint", f"{RANDOM} % 256"),
        "visits": ("smallint", "CHECKSUM(NEWID()) % 32768"),
        "points": ("bigint", "CAST(CHECKSUM(NEWID()) AS bigint) * CHECKSUM(NEWID())"),
        "pin": ("binary(8)", "CRYPT_GEN_RANDOM(8)"),
        "token": ("varbinary(50)", "CRYPT_GEN_RANDOM(1 + ABS(CHECKSUM(NEWID())) % 50)"),
        "guid": ("uniqueidentifier", "NEWID()"),
    }),
    "products": (40, {
        "name": ("nvarchar(100)", "CONVERT(nvarchar(100), CRYPT_GEN_RANDOM(2 * (1 + ABS(CHECKSUM(NEWID())) % 50)))"),
        "price": ("decimal(10, 2)", f"CAST({RANDOM} % 10000000 / 100.0 AS decimal(10, 2))"),
        "weight": ("real", "CAST(RAND(CHECKSUM(NEWID())) * 1e3 AS real)"),
        "density": ("float", "(RAND(CHECKSUM(NEWID())) - 0.5) * POWER(CAST(10 AS float), ABS(CHECKSUM(NEWID())) % 600 - 300)"),
        "cost": ("money", "CAST((RAND(CHECKSUM(NEWID())) - 0.5) * 1e12 AS money)"),
        "ratio": ("numeric(38, 10)", "CAST((RAND(CHECKSUM(NEWID())) - 0.5) * 1e20 AS numeric(38, 10))"),
        "photo": ("varbinary(max)", "CAST(REPLICATE(CONVERT(varbinary(max), CRYPT_GEN_RANDOM(4000)), 1 + ABS(CHECKSUM(NEWID())) % 5) AS varbinary(max))"),
        "description": ("nvarchar(max)", "REPLICATE(CONVERT(nvarchar(max), CRYPT_GEN_RANDOM(4000)), 1 + ABS(CHECKSUM(NEWID())) % 5)"),
        "notes": ("ntext", "CONVERT(nvarchar(max), CRYPT_GEN_RANDOM(6000))"),
        "details": ("json", "JSON_OBJECT('sku': CAST(NEWID() AS nvarchar(36)), 'size': RAND(CHECKSUM(NEWID())), 'note': N'é😀')"),
        "embedding": ("vector(3)", "CAST(JSON_ARRAY(RAND(CHECKSUM(NEWID())), RAND(CHECKSUM(NEWID())) * 1e30, -RAND(CHECKSUM(NEWID()))) AS vector(3))"),
    }),
    "product_attributes": (len(BASES) * 3, {
        "product_id": ("int", f"1 + {RANDOM} % 40"),
        "name": ("varchar(50)", "CONVERT(varchar(50), CRYPT_GEN_RANDOM(1 + ABS(CHECKSUM(NEWID())) % 50))"),
        "value": ("sql_variant", None),  # one of every base type, below
    }),
    "stores": (20, {
        "name": ("nvarchar(100)", "CONVERT(nvarchar(100), CRYPT_GEN_RANDOM(2 * (1 + ABS(CHECKSUM(NEWID())) % 50)))"),
        "location": ("geography", "geography::Point(RAND(CHECKSUM(NEWID())) * 170 - 85, RAND(CHECKSUM(NEWID())) * 360 - 180, 4326)"),
        "area": ("geometry", "geometry::Point(RAND(CHECKSUM(NEWID())) * 1000, RAND(CHECKSUM(NEWID())) * 1000, 0).STBuffer(1 + RAND(CHECKSUM(NEWID())) * 10)"),
        "region": ("hierarchyid", "CAST('/' + CAST(ABS(CHECKSUM(NEWID())) % 100 AS varchar(10)) + '/' AS hierarchyid)"),
    }),
    "orders": (0, {  # placed through shop.place_order
        "customer_id": ("int", None),
        "placed": ("datetimeoffset(7)", None),
        "total": ("money", None),
    }),
}


def exact(name: str, declared: str) -> str:
    """A column as exact bytes and values, for EXCEPT."""
    if declared in ("json", "vector(3)", "ntext"):  # not comparable, so compare their text as bytes
        return f"CAST(CAST({name} AS nvarchar(max)) AS varbinary(max)) AS {name}_bytes, DATALENGTH({name}) AS {name}_length"
    if declared == "sql_variant":
        return f"{PROPERTIES.replace('(v,', f'({name},')}, CONVERT(varbinary(8000), {name}) AS {name}_bytes"
    if declared in ("geography", "geometry", "hierarchyid") or declared.endswith("(max)"):
        return f"CAST({name} AS varbinary(max)) AS {name}_bytes, DATALENGTH({name}) AS {name}_length"
    if declared.startswith(("char", "varchar", "nchar", "nvarchar", "sysname", "binary", "varbinary")):
        size = 256 if declared == "sysname" else int(declared.split("(")[1][:-1]) * (2 if declared.startswith("n") else 1)
        return f"CAST({name} AS binary({size})) AS {name}_bytes, DATALENGTH({name}) AS {name}_length"
    if declared.startswith("datetimeoffset"):
        return f"CONVERT(nvarchar(50), {name}, 121) AS {name}_text"
    return name


async def build(channel) -> None:
    for table in TABLES:
        await fetch(channel, f"DROP TABLE IF EXISTS shop.{table}, shop.{table}_copy")
    await fetch(channel, "DROP PROCEDURE IF EXISTS shop.place_order, shop.update_prices; DROP TYPE IF EXISTS shop.price_change")
    for table, (count, columns) in TABLES.items():
        declared = ", ".join(f"{name} {declaration} NULL" for name, (declaration, _) in columns.items())
        await fetch(channel, f"CREATE TABLE shop.{table} (id int IDENTITY PRIMARY KEY, {declared}); "
                             f"CREATE TABLE shop.{table}_copy (id int PRIMARY KEY, {declared})")
        if count and table != "product_attributes":
            names = ", ".join(columns)
            generated = ", ".join(expression for _, expression in columns.values())
            await fetch(channel, f"INSERT shop.{table} ({names}) SELECT TOP {count} {generated} FROM sys.all_objects")
            await fetch(channel, f"INSERT shop.{table} ({names}) VALUES ({', '.join('NULL' for _ in columns)})")
    _, attributes = TABLES["product_attributes"]
    for base in BASES:
        await fetch(channel, f"INSERT shop.product_attributes (product_id, name, value) SELECT TOP 3 "
                             f"{attributes['product_id'][1]}, {attributes['name'][1]}, CAST({base} AS sql_variant) FROM sys.all_objects")
    await fetch(channel, "CREATE TYPE shop.price_change AS TABLE (product_id int PRIMARY KEY, price decimal(10, 2))")
    await fetch(channel, """CREATE PROCEDURE shop.place_order @customer int, @total money, @order int OUTPUT AS
        BEGIN
            INSERT shop.orders (customer_id, placed, total) VALUES (@customer, SYSDATETIMEOFFSET(), @total);
            SET @order = SCOPE_IDENTITY();
            RETURN 0
        END""")
    await fetch(channel, """CREATE PROCEDURE shop.update_prices @changes shop.price_change READONLY AS
        BEGIN
            UPDATE p SET price = c.price FROM shop.products AS p JOIN @changes AS c ON c.product_id = p.id;
            RETURN @@ROWCOUNT
        END""")


async def copy(channel, table: str) -> tuple[int, list[int]]:
    """Read the table and write every row to its copy through calls with each column's type.

    Return the number of rows and the number of differences in each direction, compared exactly on the server.
    """
    columns = TABLES[table][1]
    source = (await fetch(channel, f"SELECT id, {', '.join(columns)} FROM shop.{table} ORDER BY id")).result_sets[0]
    names = ["id", *columns]
    statement = f"INSERT shop.{table}_copy ({', '.join(names)}) VALUES ({', '.join(f'@{n}' for n in names)})"
    declared = ", ".join(["@id int"] + [f"@{n} {d}" for n, (d, _) in columns.items()])
    calls = [tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, statement), tds.Param("@params", TEXT, declared),
                      *[tds.Param(f"@{c.name}", c.type, v) for c, v in zip(source.columns, row)])
             for row in source.rows]
    async with await channel.exchange(tds.Calls(*calls)) as response:
        assert not any(r.failed for r in await response.returns(unread=tds.Unread.DISCARD))
    projection = ", ".join(["id"] + [exact(n, d) for n, (d, _) in columns.items()])
    differences = await fetch(channel, f"""
        SELECT COUNT(*) FROM (SELECT {projection} FROM shop.{table} EXCEPT SELECT {projection} FROM shop.{table}_copy) AS a;
        SELECT COUNT(*) FROM (SELECT {projection} FROM shop.{table}_copy EXCEPT SELECT {projection} FROM shop.{table}) AS b""")
    again = (await fetch(channel, f"SELECT id, {', '.join(columns)} FROM shop.{table}_copy ORDER BY id")).result_sets[0]
    assert again.rows == source.rows, table  # equal in Python too
    return len(source.rows), [rs.rows[0][0] for rs in differences.result_sets]


def test_the_shop_round_trips(server):
    async def go():
        async with await tds.connect(**server, database="tds_test") as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "IF SCHEMA_ID('shop') IS NULL EXEC('CREATE SCHEMA shop')")
                await build(channel)

                # orders are placed through a procedure, which returns each new order's id as an output
                customers = (await fetch(channel, "SELECT TOP 30 id, credit FROM shop.customers WHERE credit IS NOT NULL")).result_sets[0]
                placed = []
                for customer, credit in customers.rows:
                    call = tds.Call("shop.place_order", tds.Param("@customer", types.int, customer),
                                    tds.Param("@total", types.money, abs(credit)), tds.Param("@order", types.int, None, output=True))
                    async with await channel.exchange(call) as response:
                        [returned] = await response.returns(unread=tds.Unread.KEEP)
                    placed.append((returned.status, returned.outputs["@order"].value))
                ids = (await fetch(channel, "SELECT id FROM shop.orders ORDER BY id")).result_sets[0].rows

                # new prices that the server picks are sent as one table, then read back
                new = (await fetch(channel, f"SELECT id, CAST({RANDOM} % 10000000 / 100.0 AS decimal(10, 2)) FROM shop.products "
                                            "WHERE price IS NOT NULL")).result_sets[0]
                changes = types.table("shop.price_change", *[c.type for c in new.columns])
                async with await channel.exchange(tds.Call("shop.update_prices", tds.Param("@changes", changes, new.rows))) as response:
                    [updated] = await response.returns(unread=tds.Unread.KEEP)
                prices = (await fetch(channel, "SELECT id, price FROM shop.products WHERE price IS NOT NULL ORDER BY id")).result_sets[0]

                copies = {table: await copy(channel, table) for table in TABLES}
                return placed, ids, new.rows, updated.status, prices.rows, copies

    placed, ids, new, updated, prices, copies = asyncio.run(go())
    assert placed == [(0, i) for (i,) in ids] and len(placed) == 30  # each output is the order's id
    assert updated == len(new) == 40 and prices == new  # every price, exactly as the server picked it
    assert all(isinstance(p, Decimal) for _, p in prices)
    assert {table: differences for table, (_, differences) in copies.items()} == {table: [0, 0] for table in TABLES}
    assert {table: rows for table, (rows, _) in copies.items()} == {
        "customers": 61, "products": 41, "product_attributes": len(BASES) * 3, "stores": 21, "orders": 30}
