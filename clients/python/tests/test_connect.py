"""Log in to the live SQL Server 2025, run SELECT 1 and close, with and without MARS. The failure cases are here too."""

import asyncio
import io

import pytest

import tds
from conftest import fetch
from tds.connection.core import TooManySerialChannels
from tds.observe import Level, Printer

pytestmark = pytest.mark.live


def run(coroutine):
    return asyncio.run(coroutine)


def test_select_1(server):
    async def go():
        async with await tds.connect(**server) as connection:
            assert tds.login7.tds_version_name(connection.server.tds_version) == "TDS 7.4"
            assert connection.session.database == "master"
            async with connection.serial_channel() as channel:
                return await fetch(channel, "SELECT 1")

    result = run(go())
    assert result.result_sets[0].rows == ((1,),)


def test_without_mars_one_serial_channel(server):  # D-20
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                with pytest.raises(TooManySerialChannels):
                    connection.serial_channel()
                return await fetch(channel, "SELECT 1")  # the first is unaffected

    assert run(go()).result_sets[0].rows == ((1,),)


def test_mars_channels_share_one_session(server):
    async def go():
        async with await tds.connect(**server, mars=True) as connection:
            async with connection.serial_channel() as a, connection.serial_channel() as b:
                return await fetch(a, "SELECT @@SPID"), await fetch(b, "SELECT @@SPID")

    first, second = run(go())
    assert first.result_sets[0].rows == second.result_sets[0].rows  # the channels take turns on one session, not two


def test_wrong_password_is_rejected_with_the_servers_reason(server):
    with pytest.raises(tds.LoginRejected) as rejected:
        run(tds.connect(**{**server, "password": "not-the-password-1A!"}))
    assert rejected.value.errors[0].number == 18456  # SQL Server's "Login failed"
    message = str(rejected.value)  # the server's report in full, as SQL Server writes it
    assert "Msg 18456, Level 14, State 1" in message and "Login failed for user" in message
    assert "an error the user can correct: security, such as permission denied" in message  # what level 14 means
    assert "the reason, such as a wrong password" in message and "server's error log" in message  # what the driver adds


def test_server_errors_are_reported(server):
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "SELECT * FROM no_such_table")

    with pytest.raises(tds.ServerError) as failed:
        run(go())
    assert failed.value.errors[0].number == 208  # invalid object name


def test_a_server_error_is_literate(server):  # every field the server sent, and what the driver knows
    async def go():
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                with pytest.raises(tds.ServerError) as failed:
                    await fetch(channel, "SELECT 1; SELECT 1/0; PRINT 'after'; SELECT 2")
                return str(failed.value), connection.server

    message, _ = run(go())
    assert message.startswith("SQL Server reported 1 error for the SQL batch “SELECT 1; SELECT 1/0; PRINT 'after'; SELECT 2”:")
    assert "Error · Msg 8134, Level 16, State 1, Line 1 · server " in message and "Divide by zero error encountered." in message
    assert "Message · Msg 0, Level 0" in message and "\n  after" in message  # what came with it, in order
    assert "· an error the user can correct\n  Divide by zero" in message and "· information\n  after" in message
    assert message.endswith("Then: the server went on, with 2 more completions.")


def test_full_observation_never_shows_the_password(server):  # Done When › the runtime shows, item 5
    shown = io.StringIO()

    async def go():
        async with await tds.connect(**server, observe=Printer(Level.FULL, shown)) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "SELECT 1")

    run(go())
    out = shown.getvalue()
    utf16 = server["password"].encode("utf-16-le")
    forms = (server["password"], utf16.hex(" ").upper(), tds.login7.scramble(utf16).hex(" ").upper(),
             utf16[:12].hex(" ").upper(), tds.login7.scramble(utf16)[:12].hex(" ").upper())
    leaked = sum(form in out for form in forms)  # a count, so a failure report can't print the password itself
    assert leaked == 0, f"the password appeared in the observation output ({leaked} forms)"
    assert "•••• (hidden)" in out


def test_the_password_shows_only_when_revealed_for_that_session(server):  # D-12 item 6
    revealed, other = io.StringIO(), io.StringIO()

    async def go():
        async with await tds.connect(**server, observe=Printer(Level.FULL, revealed, reveal_password=True)):
            pass
        async with await tds.connect(**server, observe=Printer(Level.FULL, other)):  # another session: hidden
            pass

    run(go())
    shown = "“" + server["password"] + "” (revealed)"  # the real text (an f-string would format the masked fixture).
    # It is compared, never printed, so a failure reports only the counts.
    assert (revealed.getvalue().count(shown), other.getvalue().count(shown)) == (1, 0)


@pytest.mark.parametrize("mars", [False, True], ids=["plain", "mars"])
def test_a_request_larger_than_the_starting_mars_window(server, mars):
    text = "x" * 20000  # 40 KB of UTF-16: 10 packets at 4096, more than MARS's starting credit of 4

    async def go():
        async with await tds.connect(**server, mars=mars) as connection:
            async with connection.serial_channel() as channel:
                return await fetch(channel, f"SELECT LEN(N'{text}')")

    assert run(go()).result_sets[0].rows == ((20000,),)


@pytest.mark.parametrize("mars", [False, True], ids=["plain", "mars"])
def test_a_result_larger_than_the_starting_mars_window(server, mars):
    async def go():  # 30 rows × 8 KB: about 60 packets, so the client must keep raising the server's window
        async with await tds.connect(**server, mars=mars) as connection:
            async with connection.serial_channel() as channel:
                return await fetch(channel, "SELECT TOP 30 REPLICATE(N'y', 4000) FROM sys.all_objects")

    rows = run(go()).result_sets[0].rows
    assert len(rows) == 30 and all(row == ("y" * 4000,) for row in rows)


SESSION = ("SELECT CAST(SESSIONPROPERTY('ANSI_NULLS') AS int), CAST(SESSIONPROPERTY('ANSI_PADDING') AS int), "
           "CAST(SESSIONPROPERTY('ANSI_WARNINGS') AS int), CAST(SESSIONPROPERTY('CONCAT_NULL_YIELDS_NULL') AS int), "
           "CAST(SESSIONPROPERTY('QUOTED_IDENTIFIER') AS int), CAST(SESSIONPROPERTY('ARITHABORT') AS int), @@TEXTSIZE")


@pytest.mark.parametrize("odbc, expected", [(False, (0, 0, 0, 0, 0, 0, 4096)), (True, (1, 1, 1, 1, 1, 0, -1))],
                         ids=["server defaults", "odbc"])
def test_the_odbc_flag_chooses_the_sessions_starting_options(server, odbc, expected):  # D-9
    shown = io.StringIO()

    async def go():
        async with await tds.connect(**server, odbc=odbc, observe=Printer(Level.OUTLINE, shown)) as connection:
            async with connection.serial_channel() as channel:
                return await fetch(channel, SESSION)

    assert run(go()).result_sets[0].rows == (expected,)
    assert f"ODBC flag {'on' if odbc else 'off'}" in shown.getvalue()  # the login line says which was asked for


def test_without_the_odbc_flag_a_filtered_index_refuses_writes(server):  # D-9: why odbc=True is the usual practice
    async def go():
        async with await tds.connect(**server, odbc=True) as setup:
            async with setup.serial_channel() as channel:
                await fetch(channel, "USE tempdb; DROP TABLE IF EXISTS dbo.tds_filtered; "
                                     "CREATE TABLE dbo.tds_filtered (id int, email nvarchar(100)); "
                                     "CREATE UNIQUE INDEX one_email ON dbo.tds_filtered (email) WHERE email IS NOT NULL")
        results = {}
        for odbc in (False, True):
            async with await tds.connect(**server, odbc=odbc, database="tempdb") as connection:
                async with connection.serial_channel() as channel:
                    try:
                        await fetch(channel, f"INSERT dbo.tds_filtered VALUES ({int(odbc)}, N'{odbc}@example.com')")
                        results[odbc] = "inserted"
                    except tds.ServerError as e:
                        results[odbc] = e.errors[0].number
        async with await tds.connect(**server, odbc=True, database="tempdb") as cleanup:
            async with cleanup.serial_channel() as channel:
                await fetch(channel, "DROP TABLE dbo.tds_filtered")
        return results

    assert run(go()) == {False: 1934, True: "inserted"}  # 1934: SET options have incorrect settings
