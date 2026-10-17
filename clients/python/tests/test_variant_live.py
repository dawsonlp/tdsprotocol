"""Tests of sql_variant against the live SQL Server 2025 (M5).

Every base type that a sql_variant can hold round-trips exactly, and each value reports its base type (D-48).
"""

import asyncio

import pytest

import tds
from conftest import fetch
from tds import types

pytestmark = pytest.mark.live

BASES = [  # each base type a sql_variant can hold, with a value the server generates
    "CAST(ABS(CHECKSUM(NEWID())) % 256 AS tinyint)", "CAST(CHECKSUM(NEWID()) % 32768 AS smallint)",
    "CHECKSUM(NEWID())", "CAST(CHECKSUM(NEWID()) AS bigint) * CHECKSUM(NEWID())", "CAST(ABS(CHECKSUM(NEWID())) % 2 AS bit)",
    "CAST(RAND(CHECKSUM(NEWID())) AS real)", "RAND(CHECKSUM(NEWID())) * 1e100",
    "CAST(RAND(CHECKSUM(NEWID())) * 1e9 AS money)", "CAST(RAND(CHECKSUM(NEWID())) * 1e5 AS smallmoney)",
    "CAST((RAND(CHECKSUM(NEWID())) - 0.5) * 1e20 AS decimal(38, 10))", "CAST(RAND(CHECKSUM(NEWID())) * 1e7 AS numeric(10, 2))",
    "GETDATE()", "CAST(SYSDATETIME() AS smalldatetime)", "CAST(SYSDATETIME() AS date)", "CAST(SYSDATETIME() AS time(7))",
    "SYSDATETIME()", "CAST(SYSDATETIME() AS datetime2(3))", "SYSDATETIMEOFFSET()", "NEWID()",
    "CAST(CRYPT_GEN_RANDOM(8) AS binary(8))", "CRYPT_GEN_RANDOM(1 + ABS(CHECKSUM(NEWID())) % 100)",
    "CONVERT(varchar(100), CRYPT_GEN_RANDOM(1 + ABS(CHECKSUM(NEWID())) % 100))", "CONVERT(char(10), CRYPT_GEN_RANDOM(10))",
    "CONVERT(nvarchar(100), CRYPT_GEN_RANDOM(2 * (1 + ABS(CHECKSUM(NEWID())) % 50)))", "CONVERT(nchar(10), CRYPT_GEN_RANDOM(20))",
]
PROPERTIES = ", ".join(f"CAST(SQL_VARIANT_PROPERTY(v, '{p}') AS nvarchar(128)) AS {p}"
                       for p in ("BaseType", "Precision", "Scale", "TotalBytes", "Collation", "MaxLength"))


def test_every_base_type_round_trips_exactly(server):
    text = types.nvarchar(4000)

    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE #source (id int IDENTITY, v sql_variant); CREATE TABLE #copy (id int, v sql_variant)")
                for expression in BASES:
                    await fetch(channel, f"INSERT #source (v) SELECT TOP 4 CAST({expression} AS sql_variant) FROM sys.all_objects")
                await fetch(channel, "INSERT #source (v) VALUES (NULL)")
                source = (await fetch(channel, "SELECT id, v FROM #source ORDER BY id")).result_sets[0]
                calls = [tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", text, "INSERT #copy VALUES (@id, @v)"),
                                  tds.Param("@params", text, "@id int, @v sql_variant"),
                                  tds.Param("@id", types.int, i), tds.Param("@v", types.sql_variant, v)) for i, v in source.rows]
                async with await channel.exchange(tds.Calls(*calls)) as response:
                    assert not any(r.failed for r in await response.returns(unread=tds.Unread.DISCARD))
                exact = f"id, {PROPERTIES}, CONVERT(varbinary(8000), v) AS bytes"
                differences = await fetch(channel, f"""
                    SELECT COUNT(*) FROM (SELECT {exact} FROM #source EXCEPT SELECT {exact} FROM #copy) AS a;
                    SELECT COUNT(*) FROM (SELECT {exact} FROM #copy EXCEPT SELECT {exact} FROM #source) AS b""")
                copy = (await fetch(channel, "SELECT id, v FROM #copy ORDER BY id")).result_sets[0]
                bases = (await fetch(channel, "SELECT DISTINCT CAST(SQL_VARIANT_PROPERTY(v, 'BaseType') AS nvarchar(128)) FROM #source")).result_sets[0]
                return source.rows, copy.rows, [rs.rows[0][0] for rs in differences.result_sets], {b for (b,) in bases.rows}

    source, copy, differences, bases = asyncio.run(go())
    assert len(bases - {None}) >= 21  # every base type is present (some share a name, such as the date and time types)
    assert differences == [0, 0] and [(i, v) for i, v in copy] == list(source)
    for _, value in source:
        if value is not None:
            assert isinstance(value, types.SqlVariant) and value.value is not None  # each reports its base type
