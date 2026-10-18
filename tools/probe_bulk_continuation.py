"""Observe abandonment after INSERT BULK succeeds, before rows are sent.

Run with the Python client venv. Uses existing Docker credentials/CA without
printing them. Raw requests deliberately bypass the client's continuation guard;
this is an experiment, not a proposed application API. Temporary tables isolate
normal cases. The close/rollback case drops its unique permanent table in finally.
No driver policy or production implementation is changed by this probe.
"""
import asyncio
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "clients/python"), str(ROOT / "clients/python/tests")]
import tds
from conftest import HOST, PORT, _password, fetch, trust_test_authority
from tds import types
from tds.packet import PacketType
from tds.requests import Encoded, HEADERS, headers
from tds.response import Column
from tds.tokens import ColumnFlags


class Raw:
    metadata = ()
    label = "bulk continuation experiment"
    continues = "bulk load"

    def __init__(self, kind, sql=None):
        self.kind, self.sql = kind, sql

    def encode(self, context, record):
        body = b"" if self.sql is None else HEADERS.encode(headers(context), False)[0] + self.sql.encode("utf-16-le")
        return Encoded(body, None)


async def outcome(channel, request):
    try:
        async with asyncio.timeout(2):
            result = await fetch(channel, request)
        return dict(rows=[s.rows for s in result.result_sets], status=[int(c.status) for c in result.completions])
    except tds.ServerError as e:
        return dict(errors=[x.number for x in e.errors])
    except Exception as e:
        causes = []
        cause = e.__cause__
        while cause is not None and len(causes) < 8:
            causes.append(type(cause).__name__)
            cause = cause.__cause__
        return dict(failure=type(e).__name__, causes=causes)


async def open_bulk(connection):
    channel = connection.serial_channel()
    await fetch(channel, "CREATE TABLE #b(a int)")
    await fetch(channel, tds.BulkInsert("INSERT BULK #b(a int)"))
    return channel


async def mode(options):
    result = {}
    async with await tds.connect(**options) as connection:
        channel = await open_bulk(connection)
        result["unrelated_request"] = await outcome(channel, Raw(PacketType.SQL_BATCH, "INSERT #b VALUES(99); SELECT 99"))
        result["after_unrelated"] = await outcome(channel, "SELECT COUNT(*) FROM #b")
    async with await tds.connect(**options) as connection:
        channel = await open_bulk(connection)
        column = Column("a", types.int, True, ColumnFlags.NULLABLE, 0)
        result["empty_completion"] = await outcome(channel, tds.BulkRows([column], []))
        result["after_empty"] = await outcome(channel, "SELECT COUNT(*),@@TRANCOUNT FROM #b")
    async with await tds.connect(**options) as connection:
        channel = await open_bulk(connection)
        result["attention"] = await outcome(channel, Raw(PacketType.CANCEL))
        result["after_attention"] = await outcome(channel, "SELECT COUNT(*),@@TRANCOUNT FROM #b")
    async with await tds.connect(**options) as connection:
        channel = connection.serial_channel()
        await fetch(channel, "SET XACT_ABORT OFF; CREATE TABLE #b(a int)")
        await fetch(channel, tds.transactions.Begin())
        await fetch(channel, "INSERT #b VALUES(-1)")
        await fetch(channel, tds.BulkInsert("INSERT BULK #b(a int)"))
        result["attention_in_transaction"] = await outcome(channel, Raw(PacketType.CANCEL))
        result["after_attention_in_transaction"] = await outcome(channel, "SELECT COUNT(*),@@TRANCOUNT,XACT_STATE() FROM #b")
        await fetch(channel, tds.transactions.Rollback())
    async with await tds.connect(**options) as connection:
        channel = await open_bulk(connection)
        await channel.close()
        replacement = connection.serial_channel()
        result["after_channel_close"] = await outcome(replacement, "SELECT COUNT(*) FROM #b")
        result["after_channel_close_retry"] = await outcome(replacement, "SELECT 7")
    async with tds.Pool(**options, size=1) as pool:
        async with pool.connection() as connection:
            original_core = connection._core
            channel = connection.serial_channel()
            spid = (await fetch(channel, "SELECT @@SPID")).result_sets[0].rows[0][0]
            await fetch(channel, "CREATE TABLE #b(a int)")
            await fetch(channel, tds.BulkInsert("INSERT BULK #b(a int)"))
        async with pool.connection() as connection:
            result["pool_reused_protocol_core"] = connection._core is original_core
            channel = connection.serial_channel()
            result["after_pool_return"] = await outcome(channel, "SELECT @@SPID,OBJECT_ID('tempdb..#b')")
            result["pool_original_spid"] = spid
            result["after_pool_return_retry"] = await outcome(channel, "SELECT 8")
    # Closing the whole connection also rolls back work BEFORE bulk preparation
    # in an explicit transaction; a previously committed marker survives.
    table = "tds_bulk_close_" + uuid.uuid4().hex
    async with await tds.connect(**options) as observer:
        admin = observer.serial_channel()
        await fetch(admin, f"CREATE TABLE dbo.[{table}](a int)")
        try:
            async with await tds.connect(**options) as connection:
                channel = connection.serial_channel()
                await fetch(channel, f"INSERT dbo.[{table}] VALUES(1)")
                await fetch(channel, tds.transactions.Begin())
                await fetch(channel, f"INSERT dbo.[{table}] VALUES(2)")
                await fetch(channel, tds.BulkInsert(f"INSERT BULK dbo.[{table}](a int)"))
            result["rows_after_connection_close"] = (await fetch(admin, f"SELECT a FROM dbo.[{table}] ORDER BY a")).result_sets[0].rows
        finally:
            await fetch(admin, f"DROP TABLE dbo.[{table}]")
    return result


async def main():
    password = _password()
    if not password:
        raise SystemExit("Existing Docker credentials unavailable")
    for version in ["7.4", "8.0"]:
        for mars in [False, True]:
            options = dict(host=HOST, port=PORT, user="sa", password=password,
                           database="tds_test", ssl_context=trust_test_authority(),
                           tds_version=version, mars=mars, cleanup_timeout=0.5)
            observed = await mode(options)
            assert observed["unrelated_request"] == dict(errors=[4022])
            assert observed["after_unrelated"]["rows"] == [((0,),)]
            assert observed["after_empty"]["rows"] == [((0, 0),)]
            assert any(status & 0x20 for status in observed["attention"]["status"])
            assert observed["after_attention"]["rows"] == [((0, 0),)]
            assert observed["after_attention_in_transaction"]["rows"] == [((1, 1, 1),)]
            assert observed["rows_after_connection_close"] == ((1,),)
            # These paths originally exposed the continuation to a replacement
            # user. Keep the same experiment as a regression for the shared fix.
            assert observed["after_channel_close"]["rows"] == [((0,),)]
            assert not observed["pool_reused_protocol_core"]
            assert observed["after_pool_return"]["rows"][0][0][1] is None
            print(json.dumps(dict(version=version, mars=mars, observed=observed)), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
