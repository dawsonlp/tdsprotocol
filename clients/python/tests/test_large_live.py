"""Large values against the live SQL Server 2025 (M4).

They round-trip exactly, read whole or value by value. 1 GB streams each way in bounded memory. A request that fails
or is canceled partway is undone (D-41, D-47, D-48).
"""

import asyncio
import hashlib
import io
import resource
import sys

import pytest

import tds
from conftest import fetch
from test_types_live import CODE_PAGES
from tds import types
from tds.observe import Level, Printer

pytestmark = pytest.mark.live

TEXT = types.nvarchar(4000)
LARGE = {  # name: (declaration, a value the server generates)
    "nmax": ("nvarchar(max)", "REPLICATE(CONVERT(nvarchar(max), CRYPT_GEN_RANDOM(400)), 1 + ABS(CHECKSUM(NEWID())) % 60)"),
    "vmax": ("varchar(max)", "REPLICATE(CONVERT(varchar(max), CRYPT_GEN_RANDOM(400)), 1 + ABS(CHECKSUM(NEWID())) % 60)"),
    "bmax": ("varbinary(max)", "CAST(REPLICATE(CONVERT(varbinary(max), CRYPT_GEN_RANDOM(400)), 1 + ABS(CHECKSUM(NEWID())) % 60) "
                               "AS varbinary(max))"),  # REPLICATE of binary returns varchar
    "x": ("xml", "CAST(N'<order id=\"' + CAST(NEWID() AS nvarchar(36)) + N'\"><note>é😀</note></order>' AS xml)"),
    "t": ("text", "CONVERT(varchar(max), CRYPT_GEN_RANDOM(8000)) + CONVERT(varchar(max), CRYPT_GEN_RANDOM(8000))"),
    "nt": ("ntext", "CONVERT(nvarchar(max), CRYPT_GEN_RANDOM(8000)) + CONVERT(nvarchar(max), CRYPT_GEN_RANDOM(8000))"),
    "img": ("image", "CONVERT(varbinary(max), CRYPT_GEN_RANDOM(8000)) + CONVERT(varbinary(max), CRYPT_GEN_RANDOM(8000))"),
}


def run(coroutine):
    return asyncio.run(coroutine)


def exact(name: str, declared: str) -> str:
    """A large value as exact bytes, for EXCEPT (xml and the legacy types can't be compared directly)."""
    via = {"xml": "nvarchar(max)", "text": "varchar(max)", "ntext": "nvarchar(max)"}.get(declared)
    value = f"CAST({name} AS {via})" if via else name  # text can't become varbinary directly
    return f"CAST({value} AS varbinary(max)) AS {name}_bytes, DATALENGTH({name}) AS {name}_length"


def test_every_large_type_round_trips_exactly(server):  # D-48
    names = list(LARGE)
    columns = ", ".join(f"{n} {declared} NULL" for n, (declared, _) in LARGE.items())

    async def go():
        async with await tds.connect(**server, database="tempdb") as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, f"CREATE TABLE #source (id int IDENTITY, {columns}); CREATE TABLE #copy (id int, {columns})")
                generated = ", ".join(expr for _, expr in LARGE.values())
                await fetch(channel, f"INSERT #source ({', '.join(names)}) SELECT TOP 40 {generated} FROM sys.all_objects; "
                                     f"INSERT #source ({', '.join(names)}) VALUES ({', '.join('NULL' for _ in names)})")
                source = (await fetch(channel, f"SELECT id, {', '.join(names)} FROM #source ORDER BY id")).result_sets[0]
                kinds = [c.type for c in source.columns]
                statement = f"INSERT #copy (id, {', '.join(names)}) VALUES (@id, {', '.join(f'@{n}' for n in names)})"
                declared = ", ".join(["@id int"] + [f"@{n} {t}" for n, t in zip(names, kinds[1:])])
                calls = [tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, statement), tds.Param("@params", TEXT, declared),
                                  *[tds.Param(f"@{c.name}", t, v) for c, t, v in zip(source.columns, kinds, row)])
                         for row in source.rows]
                async with await channel.exchange(tds.Calls(*calls)) as response:
                    assert not any(r.failed for r in await response.returns(unread=tds.Unread.DISCARD))
                projection = ", ".join(exact(n, LARGE[n][0]) for n in names)
                differences = await fetch(channel, f"""
                    SELECT COUNT(*) FROM (SELECT id, {projection} FROM #source EXCEPT SELECT id, {projection} FROM #copy) AS a;
                    SELECT COUNT(*) FROM (SELECT id, {projection} FROM #copy EXCEPT SELECT id, {projection} FROM #source) AS b""")
                copy = (await fetch(channel, f"SELECT id, {', '.join(names)} FROM #copy ORDER BY id")).result_sets[0]
                return [str(t) for t in kinds[1:]], source.rows, copy.rows, [rs.rows[0][0] for rs in differences.result_sets]

    declared, source, copy, differences = run(go())
    assert declared == ["nvarchar(max)", "varchar(max)", "varbinary(max)", "xml", "text", "ntext", "image"]
    assert differences == [0, 0] and copy == source and len(source) == 41
    assert max(len(row[1]) for row in source if row[1]) > 8000  # values larger than any short type


async def read_both_ways(channel, sql: str):
    async with await channel.exchange(tds.Batch(sql)) as response:
        whole = (await response.fetch()).result_sets[0].rows
    streamed = []
    async with await channel.exchange(tds.Batch(sql)) as response:
        async for rs in response:
            async for row in rs.streamed():
                values = []
                async for value in row:
                    if isinstance(value, tds.ValueStream):
                        pieces = [piece async for piece in value]
                        values.append((type(pieces[0]) if pieces else None)().join(pieces) if pieces else value.column.type.assemble(b""))
                    else:
                        values.append(value)
                streamed.append(tuple(values))
    return whole, tuple(streamed)


@pytest.mark.parametrize("page", sorted(CODE_PAGES) + [65001])
def test_both_ways_of_reading_agree_and_text_is_never_split(server, page):  # D-47
    collation = CODE_PAGES.get(page, "Latin1_General_100_CI_AS_SC_UTF8")
    text = {932: "日本語のテキスト", 936: "中文文本", 949: "한국어", 950: "中文文本", 65001: "é😀日本"}.get(page, "abc")

    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                return await read_both_ways(channel, f"""
                    SELECT CAST(REPLICATE(CAST(N'{text}' AS nvarchar(max)), 4000) AS varchar(max)) COLLATE {collation} AS v,
                           REPLICATE(CAST(N'😀é{text}' AS nvarchar(max)), 4000) AS n, 7 AS after""")

    whole, streamed = run(go())
    assert streamed == whole and whole[0][2] == 7 and len(whole[0][0]) >= 4000
    assert not any("\udc80" <= c <= "\udcff" for c in whole[0][0])  # no character was split into escapes


def test_a_large_value_and_the_value_after_it_when_its_rest_is_discarded(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                async with await channel.exchange(tds.Batch(
                        "SELECT REPLICATE(CAST(N'x' AS nvarchar(max)), 100000) AS big, 7 AS after")) as response:
                    async for rs in response:
                        async for row in rs.streamed():
                            async for value in row:
                                if isinstance(value, tds.ValueStream):
                                    async for piece in value:
                                        break  # read one piece only, so the rest is discarded
                                else:
                                    return value

    assert run(go()) == 7


GIGABYTE = 1024 ** 3


def test_a_gigabyte_streams_both_ways_in_bounded_memory(server):  # Done When M4 item 4
    def peak() -> int:  # bytes on macOS, kilobytes on Linux
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return rss if sys.platform == "darwin" else rss * 1024

    block = bytes(range(256)) * 4096  # 1 MB

    async def source():
        for _ in range(GIGABYTE // len(block)):
            yield block

    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                before, digest, size = peak(), hashlib.sha256(), 0
                async with await channel.exchange(tds.Batch(
                        f"SELECT CAST(REPLICATE(CAST(0x0123456789ABCDEF AS varbinary(max)), {GIGABYTE // 8}) AS varbinary(max))")) as response:
                    async for rs in response:
                        async for row in rs.streamed():
                            async for value in row:
                                async for piece in value:
                                    digest.update(piece)
                                    size += len(piece)
                read = size, digest.hexdigest()
                call = tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, "SELECT DATALENGTH(@v), HASHBYTES('SHA2_256', @v)"),
                                tds.Param("@params", TEXT, "@v varbinary(max)"), tds.Param("@v", types.varbinary(types.MAX), source()))
                async with await channel.exchange(call) as response:
                    sent = (await response.fetch()).result_sets[0].rows[0]
                return read, sent, peak() - before

    (read_size, read_digest), (sent_size, sent_digest), grew = run(go())
    expected = hashlib.sha256(bytes.fromhex("0123456789ABCDEF") * (GIGABYTE // 8)).hexdigest()
    assert read_size == GIGABYTE and read_digest == expected
    whole = hashlib.sha256()
    for _ in range(GIGABYTE // len(block)):
        whole.update(block)
    assert sent_size == GIGABYTE and sent_digest == whole.digest()
    assert grew < 200 * 1024 * 1024, f"memory grew by {grew:,} bytes"


def test_sources_in_call_and_calls(server):  # D-41
    async def letters(n):
        for i in range(n):
            yield "é😀" * 1000

    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                length = lambda source: tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, "SELECT LEN(@v)"),
                                                 tds.Param("@params", TEXT, "@v nvarchar(max)"),
                                                 tds.Param("@v", types.nvarchar(types.MAX), source))
                one = await fetch_call(channel, length(letters(3)))
                two = await fetch_call(channel, tds.Calls(length(letters(5)), length(letters(7))))
                return one, two

    one, two = run(go())
    assert [rs.rows for rs in one.result_sets] == [((9000,),)]  # LEN counts the emoji's surrogate pair as two
    assert [rs.rows for rs in two.result_sets] == [((15000,),), ((21000,),)]


async def fetch_call(channel, request):
    async with await channel.exchange(request) as response:
        return await response.fetch()


def test_without_the_odbc_flag_large_values_arrive_cut_to_textsize(server):  # D-9
    async def go():
        async with await tds.connect(**server, odbc=False) as connection:
            async with connection.serial_channel() as channel:
                return await fetch(channel, "SELECT REPLICATE(CAST('x' AS varchar(max)), 10000), REPLICATE(CAST(N'x' AS nvarchar(max)), 10000)")

    v, n = run(go()).result_sets[0].rows[0]
    assert len(v) == 4096 and len(n) == 2048  # 4,096 bytes each, as the server sent them


def test_observability_never_holds_a_large_value_whole(server):  # D-47
    events = []

    async def go():
        async with await tds.connect(**server, observe=events.append) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "SELECT REPLICATE(CAST(0x01 AS varbinary(max)), 1000000)")
                await fetch_call(channel, tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, "SELECT DATALENGTH(@v)"),
                                                   tds.Param("@params", TEXT, "@v varbinary(max)"),
                                                   tds.Param("@v", types.varbinary(types.MAX), bytes(1000000))))

    run(go())

    def largest(node) -> int:
        return max([len(node.raw), *(largest(child) for child in node.children)])

    assert max(largest(e.node) for e in events if e.node is not None) <= 8192
    shown = io.StringIO()
    printer = Printer(Level.FULL, shown)
    for event in events:
        printer(event)
    assert "1000000 bytes in" in shown.getvalue()


# --------------------------------------------------------------------------- undoing a request partway (D-41)


def test_a_failing_source_is_abandoned_and_nothing_runs(server):
    async def failing():
        yield b"x" * 100_000
        raise OSError("disk failed")

    shown = io.StringIO()

    async def go():
        async with await tds.connect(**server, observe=Printer(Level.OUTLINE, shown)) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE #photos (photo varbinary(max))")
                with pytest.raises(OSError, match="disk failed"):
                    await channel.exchange(tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, "INSERT #photos VALUES (@v)"),
                                                    tds.Param("@params", TEXT, "@v varbinary(max)"),
                                                    tds.Param("@v", types.varbinary(types.MAX), failing())))
                return await fetch(channel, "SELECT COUNT(*) FROM #photos")  # the channel works, and nothing ran

    assert run(go()).result_sets[0].rows == ((0,),)
    out = shown.getvalue()
    answer = out[out.index("request abandoned · ignore + last"):].splitlines()[1]
    assert "← response" in answer and answer.split(" · ")[3] == "ERROR DONE"  # MS-TDS says a DONE alone, but SQL Server
    # also sends error 4002, which says the stream ended unexpectedly


def test_a_piece_that_doesnt_fit_is_refused_and_the_request_undone(server):
    async def pieces():
        yield "fine " * 3000
        yield "Ā"  # not in code page 1252

    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                with pytest.raises(types.ValueRefused, match="1252"):
                    await channel.exchange(tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, "SELECT LEN(@v)"),
                                                    tds.Param("@params", TEXT, "@v varchar(max)"),
                                                    tds.Param("@v", types.varchar(types.MAX), pieces())))
                return await fetch(channel, "SELECT 1")

    assert run(go()).result_sets[0].rows == ((1,),)


@pytest.mark.parametrize("mars", [False, True], ids=["plain", "mars"])
def test_a_task_cancelled_mid_send_undoes_its_request_and_the_connection_is_lent_again(server, mars):
    async def go():
        sending = asyncio.Event()

        async def slow():
            yield b"x" * 100_000
            sending.set()
            await asyncio.sleep(30)  # the task is canceled while the source waits
            yield b"never"

        async with tds.Pool(**server, mars=mars, size=1) as pool:
            lent = []

            async def upload():
                async with pool.connection() as connection:
                    lent.append(connection)
                    async with connection.serial_channel() as channel:
                        await channel.exchange(tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, "SELECT DATALENGTH(@v)"),
                                                        tds.Param("@params", TEXT, "@v varbinary(max)"),
                                                        tds.Param("@v", types.varbinary(types.MAX), slow())))

            task = asyncio.create_task(upload())
            await sending.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            async with pool.connection() as connection:
                async with connection.serial_channel() as channel:
                    after = await fetch(channel, "SELECT 2")
                return lent[0] is connection, connection.alive, after.result_sets[0].rows

    same, alive, rows = run(go())
    assert same and alive and rows == ((2,),)  # undone, not abandoned, so the pool lends the same connection again
