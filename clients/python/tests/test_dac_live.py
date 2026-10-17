"""The dedicated administrator connection (M14).

It is SQL Server's spare connection for an administrator when the server is too busy, or not responding, for a normal
one. It is ordinary TDS on its own port (1434, forwarded as 14345). Only one is allowed at a time, and only for
sysadmin. The test container accepts it from outside after remote admin connections are turned on.
"""

import asyncio

import pytest

import tds
from conftest import DAC_PORT, fetch
from tds.connection.core import ConnectError

pytestmark = pytest.mark.live


def test_the_dedicated_administrator_connection(server):
    async def go():
        async with await tds.connect(**server) as connection:  # on, so the server also listens for it from outside
            async with connection.serial_channel() as channel:
                await fetch(channel, "EXEC sp_configure 'remote admin connections', 1; RECONFIGURE")
        async with await tds.connect(**{**server, "port": DAC_PORT}, timeout=10) as dac:
            async with dac.serial_channel() as channel:
                endpoint = (await fetch(channel, "SELECT e.name FROM sys.dm_exec_sessions AS s JOIN sys.endpoints AS e "
                                                 "ON e.endpoint_id = s.endpoint_id WHERE s.session_id = @@SPID")).result_sets[0].rows
            with pytest.raises(ConnectError) as second:  # one at a time
                await tds.connect(**{**server, "port": DAC_PORT}, timeout=10)
            return endpoint, second.value

    endpoint, second = asyncio.run(go())
    assert endpoint == (("Dedicated Admin Connection",),)
    assert second.step == "hello" and "error log" in str(second) and "dedicated administrator connection" in str(second)
