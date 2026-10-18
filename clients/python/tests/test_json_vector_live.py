"""json and vector against the live SQL Server 2025 (M6).

The login asks for both features (D-8), the server sends both as their real types, and values the server generates
round-trip exactly (D-48).
"""

import asyncio

import pytest

import tds
from conftest import fetch
from tds import login7, types
from tds.types import SqlVector, VectorElement

pytestmark = pytest.mark.live
TEXT = types.nvarchar(4000)


def run(coroutine):
    return asyncio.run(coroutine)


def test_the_login_asks_for_json_and_vector_and_the_server_says_which_versions(server):
    async def go():
        async with await tds.connect(**server) as connection:
            return connection.features

    features = run(go())
    assert features[login7.Feature.JSON_SUPPORT] == b"\x01"
    assert features[login7.Feature.VECTOR_SUPPORT] in (b"\x01", b"\x02")  # a supported downgrade, or float16 too


def test_float16_vectors_match_the_negotiated_server_capability(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                if connection.features[login7.Feature.VECTOR_SUPPORT][0] < 2:
                    with pytest.raises(tds.ServerError) as refused:
                        await fetch(channel, "SELECT CAST(N'[1,2]' AS vector(2, float16))")
                    assert "float16" in refused.value.errors[0].text
                else:
                    result = await fetch(channel, "SELECT CAST(N'[1,2]' AS vector(2, float16))")
                    assert result.result_sets[0].rows[0][0] == SqlVector(VectorElement.FLOAT16, (1.0, 2.0))

    run(go())


def test_json_and_vectors_round_trip_exactly(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE #source (id int IDENTITY, j json, v vector(3)); CREATE TABLE #copy (id int, j json, v vector(3))")
                await fetch(channel, """
                    INSERT #source (j, v) SELECT TOP 30
                        JSON_OBJECT('id': CAST(NEWID() AS nvarchar(36)), 'n': RAND(CHECKSUM(NEWID())), 'note': N'é😀'),
                        CAST(JSON_ARRAY(RAND(CHECKSUM(NEWID())), RAND(CHECKSUM(NEWID())) * 1e30, -RAND(CHECKSUM(NEWID()))) AS vector(3))
                    FROM sys.all_objects;
                    INSERT #source (j, v) VALUES (NULL, NULL)""")
                source = (await fetch(channel, "SELECT id, j, v FROM #source ORDER BY id")).result_sets[0]
                assert [str(c.type) for c in source.columns] == ["int", "json", "vector(3)"]
                calls = [tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, "INSERT #copy VALUES (@id, @j, @v)"),
                                  tds.Param("@params", TEXT, "@id int, @j json, @v vector(3)"),
                                  tds.Param("@id", types.int, i), tds.Param("@j", types.json, j), tds.Param("@v", types.vector(3), v))
                         for i, j, v in source.rows]
                async with await channel.exchange(tds.Calls(*calls)) as response:
                    assert not any(r.failed for r in await response.returns(unread=tds.Unread.DISCARD))
                exact = "id, CAST(CAST(j AS nvarchar(max)) AS varbinary(max)) AS j, CAST(CAST(v AS nvarchar(max)) AS varbinary(max)) AS v"
                differences = await fetch(channel, f"""
                    SELECT COUNT(*) FROM (SELECT {exact} FROM #source EXCEPT SELECT {exact} FROM #copy) AS a;
                    SELECT COUNT(*) FROM (SELECT {exact} FROM #copy EXCEPT SELECT {exact} FROM #source) AS b""")
                copy = (await fetch(channel, "SELECT id, j, v FROM #copy ORDER BY id")).result_sets[0]
                return source.rows, copy.rows, [rs.rows[0][0] for rs in differences.result_sets]

    source, copy, differences = run(go())
    assert differences == [0, 0] and copy == source and len(source) == 31
    assert all(isinstance(v, SqlVector) and v.element == VectorElement.FLOAT32 for _, _, v in source[:-1])


def test_json_can_be_sent_from_a_source(server):
    async def pieces():
        yield '{"items": ['
        for i in range(2000):
            yield f'{{"n": {i}, "note": "é😀"}},'
        yield '{"n": -1}]}'

    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                async with await channel.exchange(tds.Call(
                        tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, "SELECT JSON_VALUE(@j, '$.items[1999].note'), DATALENGTH(@j)"),
                        tds.Param("@params", TEXT, "@j json"), tds.Param("@j", types.json, pieces()))) as response:
                    return (await response.fetch()).result_sets[0].rows[0]

    note, size = run(go())
    assert note == "é😀" and size > 8000


def test_json_arrives_as_utf16_without_utf8_support(server):  # observed: the login's UTF-8 support decides it
    async def go():
        features = [f for f in tds.DEFAULT_FEATURES if f is not tds.Feature.UTF8_SUPPORT]
        async with await tds.connect(**server, features=features) as connection:
            async with connection.serial_channel() as channel:
                [rs] = (await fetch(channel, "SELECT CAST(N'{\"note\":\"é😀\"}' AS json) AS j")).result_sets
                return rs.columns[0].type.utf8, rs.rows

    utf8, rows = run(go())
    assert utf8 is False and rows == (('{"note":"é😀"}',),)
