"""CLR types against the live SQL Server 2025 (M7).

hierarchyid, geometry and geography arrive as their bytes and full names, and values the server generates round-trip
exactly (D-43, D-48). So does a user CLR type, built from clr/Point.cs.
"""

import asyncio
import hashlib
from pathlib import Path

import pytest

import tds
from conftest import fetch
from tds import types
from tds.tokens import ColumnFlags

pytestmark = pytest.mark.live
TEXT = types.nvarchar(4000)


def test_hierarchyid_geometry_and_geography_round_trip_exactly(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE #source (id int IDENTITY, h hierarchyid, g geometry, p geography); "
                                     "CREATE TABLE #copy (id int, h hierarchyid, g geometry, p geography)")
                await fetch(channel, """
                    INSERT #source (h, g, p) SELECT TOP 40
                        CAST('/' + CAST(ABS(CHECKSUM(NEWID())) % 100 AS varchar(10)) + '/' + CAST(ABS(CHECKSUM(NEWID())) % 100 AS varchar(10)) + '/' AS hierarchyid),
                        geometry::Point(RAND(CHECKSUM(NEWID())) * 1000, RAND(CHECKSUM(NEWID())) * 1000, 0).STBuffer(RAND(CHECKSUM(NEWID())) * 10),
                        geography::Point(RAND(CHECKSUM(NEWID())) * 170 - 85, RAND(CHECKSUM(NEWID())) * 360 - 180, 4326)
                    FROM sys.all_objects;
                    INSERT #source (h, g, p) VALUES (NULL, NULL, NULL)""")
                source = (await fetch(channel, "SELECT id, h, g, p FROM #source ORDER BY id")).result_sets[0]
                names = [str(c.type) for c in source.columns[1:]]
                calls = [tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, "INSERT #copy VALUES (@id, @h, @g, @p)"),
                                  tds.Param("@params", TEXT, "@id int, @h hierarchyid, @g geometry, @p geography"),
                                  *[tds.Param(f"@{c.name}", c.type, v) for c, v in zip(source.columns, row)])
                         for row in source.rows]
                async with await channel.exchange(tds.Calls(*calls)) as response:
                    assert not any(r.failed for r in await response.returns(unread=tds.Unread.DISCARD))
                exact = "id, CAST(h AS varbinary(max)) AS h, CAST(g AS varbinary(max)) AS g, CAST(p AS varbinary(max)) AS p"
                differences = await fetch(channel, f"""
                    SELECT COUNT(*) FROM (SELECT {exact} FROM #source EXCEPT SELECT {exact} FROM #copy) AS a;
                    SELECT COUNT(*) FROM (SELECT {exact} FROM #copy EXCEPT SELECT {exact} FROM #source) AS b""")
                copy = (await fetch(channel, "SELECT id, h, g, p FROM #copy ORDER BY id")).result_sets[0]
                return names, source.rows, copy.rows, [rs.rows[0][0] for rs in differences.result_sets]

    names, source, copy, differences = asyncio.run(go())
    assert names == ["tempdb.sys.hierarchyid", "tempdb.sys.geometry", "tempdb.sys.geography"]  # the database the column is in
    assert differences == [0, 0] and copy == source and len(source) == 41
    assert max(len(g) for _, _, g, _ in source[:-1]) > 1000  # buffered shapes give values of a realistic size


DLL = Path(__file__).parent / "clr" / "TdsTestTypes.dll"  # built from clr/Point.cs by clr/build.sh


async def load_point(channel) -> None:
    """Loads the user CLR type dbo.Point into tds_test. It enables CLR and trusts the assembly by its hash."""
    dll = DLL.read_bytes()
    digest = hashlib.sha512(dll).hexdigest()
    await fetch(channel, "EXEC sp_configure 'clr enabled', 1; RECONFIGURE")
    await fetch(channel, f"IF NOT EXISTS (SELECT 1 FROM sys.trusted_assemblies WHERE hash = 0x{digest}) "
                         f"EXEC sys.sp_add_trusted_assembly 0x{digest}, N'TdsTestTypes'")
    await fetch(channel, "USE tds_test; IF SCHEMA_ID('shop') IS NULL EXEC('CREATE SCHEMA shop'); "
                         "DROP TABLE IF EXISTS shop.point_source, shop.point_copy; "
                         "IF TYPE_ID('dbo.Point') IS NOT NULL DROP TYPE dbo.Point; "
                         "IF EXISTS (SELECT 1 FROM sys.assemblies WHERE name = 'TdsTestTypes') DROP ASSEMBLY TdsTestTypes")
    await fetch(channel, f"CREATE ASSEMBLY TdsTestTypes FROM 0x{dll.hex()} WITH PERMISSION_SET = SAFE")
    await fetch(channel, "CREATE TYPE dbo.Point EXTERNAL NAME TdsTestTypes.Point")


def test_a_user_clr_type_round_trips_exactly(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await load_point(channel)
                await fetch(channel, "CREATE TABLE shop.point_source (id int IDENTITY, p dbo.Point); "
                                     "CREATE TABLE shop.point_copy (id int, p dbo.Point)")
                await fetch(channel, """
                    INSERT shop.point_source (p) SELECT TOP 100
                        CAST(CAST(CHECKSUM(NEWID()) AS varchar(11)) + ',' + CAST(CHECKSUM(NEWID()) AS varchar(11)) AS dbo.Point)
                    FROM sys.all_objects;
                    INSERT shop.point_source (p) VALUES (CAST('-2147483648,2147483647' AS dbo.Point)), (NULL)""")
                source = (await fetch(channel, "SELECT id, p FROM shop.point_source ORDER BY id")).result_sets[0]
                column = source.columns[1]
                calls = [tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, "INSERT shop.point_copy VALUES (@id, @p)"),
                                  tds.Param("@params", TEXT, "@id int, @p dbo.Point"),
                                  tds.Param("@id", types.int, id), tds.Param("@p", types.clr("dbo.Point"), p))
                         for id, p in source.rows]
                async with await channel.exchange(tds.Calls(*calls)) as response:
                    assert not any(r.failed for r in await response.returns(unread=tds.Unread.DISCARD))
                exact = "id, CAST(p AS varbinary(max)) AS p"
                differences = await fetch(channel, f"""
                    SELECT COUNT(*) FROM (SELECT {exact} FROM shop.point_source EXCEPT SELECT {exact} FROM shop.point_copy) AS a;
                    SELECT COUNT(*) FROM (SELECT {exact} FROM shop.point_copy EXCEPT SELECT {exact} FROM shop.point_source) AS b""")
                copy = (await fetch(channel, "SELECT id, p FROM shop.point_copy ORDER BY id")).result_sets[0]
                return column, source.rows, copy.rows, [rs.rows[0][0] for rs in differences.result_sets]

    column, source, copy, differences = asyncio.run(go())
    assert str(column.type) == "tds_test.dbo.Point" and column.type.max_size == 9
    assert column.type.assembly.startswith("Point, TdsTestTypes,")
    assert column.flags & ColumnFlags.FIXED_LENGTH_CLR_TYPE  # Native format: every value is 9 bytes
    assert differences == [0, 0] and copy == source and len(source) == 102
    assert all(len(p) == 9 for _, p in source[:-1]) and source[-1][1] is None
