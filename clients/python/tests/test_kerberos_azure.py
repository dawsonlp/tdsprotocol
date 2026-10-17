"""Kerberos (M17, D-55), from the Linux runner inside the Azure test network (D-62).

The runner gets a ticket from the domain controller (kinit), then makes a Windows login to SQL Server on Windows by its
full host name, MSSQLSvc/tdssql.tds.test:1433.

infra/azure/kerberos.sh runs these tests on the runner, after it gets the ticket. They are skipped anywhere else.
"""

import asyncio
import os
import ssl

import pytest

import tds
from conftest import fetch
from tds.adapters.spnego import Spnego

pytestmark = pytest.mark.azure
HOST = os.environ.get("TDS_KERBEROS_HOST")


@pytest.fixture
def kerberos():
    if not HOST:
        pytest.skip("Kerberos runs on the Azure runner: infra/azure/kerberos.sh")
    context = ssl.create_default_context()
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE  # SQL Server's own certificate (D-10: 7.4)
    return {"host": HOST, "port": 1433, "ssl_context": context}


def test_kerberos_with_the_tickets_user(kerberos):
    async def go():
        provider = Spnego(protocol="kerberos")  # the ticket that kinit got
        async with await tds.connect(**kerberos, login=tds.WindowsLogin(provider)) as connection:
            async with connection.serial_channel() as channel:
                return (await fetch(channel, "SELECT SUSER_SNAME(), auth_scheme FROM sys.dm_exec_connections "
                                             "WHERE session_id = @@SPID")).result_sets[0].rows[0]

    name, scheme = asyncio.run(go())
    assert name.upper() == "TDS\\TDSUSER" and scheme == "KERBEROS"


def test_negotiate_chooses_kerberos(kerberos):
    async def go():
        async with await tds.connect(**kerberos, login=tds.WindowsLogin(Spnego())) as connection:
            async with connection.serial_channel() as channel:
                return (await fetch(channel, "SELECT auth_scheme FROM sys.dm_exec_connections "
                                             "WHERE session_id = @@SPID")).result_sets[0].rows[0][0]

    assert asyncio.run(go()) == "KERBEROS"
