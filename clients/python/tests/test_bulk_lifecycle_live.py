"""A bulk continuation remains an obligation after its preparation response."""
import asyncio
import pytest
import tds
from conftest import fetch

pytestmark = pytest.mark.live


@pytest.mark.parametrize("version", ["7.4", "8.0"])
@pytest.mark.parametrize("mars", [False, True])
def test_close_bulk_gap_cancels_without_rolling_back_prior_work_and_pool_discards(server, version, mars):
    async def go():
        options = {**server, "tds_version": version, "mars": mars}
        async with await tds.connect(**options) as connection:
            channel = connection.serial_channel()
            await fetch(channel, "SET XACT_ABORT OFF; CREATE TABLE #b(a int)")
            await fetch(channel, tds.transactions.Begin())
            await fetch(channel, "INSERT #b VALUES(7)")
            await fetch(channel, tds.BulkInsert("INSERT BULK #b(a int)"))
            await channel.close()
            replacement = connection.serial_channel()
            kept = await fetch(replacement, "SELECT COUNT(*),@@TRANCOUNT,XACT_STATE() FROM #b")
            assert kept.result_sets[0].rows == ((1, 1, 1),)
            await fetch(replacement, tds.transactions.Rollback())
        async with tds.Pool(**options, size=1) as pool:
            async with pool.connection() as connection:
                original = connection._core
                channel = connection.serial_channel()
                await fetch(channel, "CREATE TABLE #b(a int)")
                await fetch(channel, tds.BulkInsert("INSERT BULK #b(a int)"))
            async with pool.connection() as connection:
                assert connection._core is not original
                channel = connection.serial_channel()
                assert (await fetch(channel, "SELECT 8")).result_sets[0].rows == ((8,),)

    asyncio.run(go())
