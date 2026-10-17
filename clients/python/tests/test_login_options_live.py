"""Tests of login features and identity options (M14, D-8, D-9) against the live SQL Server 2025.

They cover the feature list and the features the client can't ask for yet, data classification as an application reads
it, how the session identifies itself, its language, read-only intent, and the database the login starts in.
"""

import asyncio
import os
import secrets
import subprocess
import sys

import pytest

import tds
from conftest import fetch
from tds import Feature
from tds.connection.core import ConnectError, LoginRejected

pytestmark = pytest.mark.live


def run(coroutine):
    return asyncio.run(coroutine)


def test_the_features_asked_for_and_what_cant_be_asked_yet(server):
    async def go():
        async with await tds.connect(**server) as connection:
            return dict(connection.features)

    accepted = run(go())
    assert set(accepted) >= {Feature.JSON_SUPPORT, Feature.VECTOR_SUPPORT, Feature.UTF8_SUPPORT, Feature.DATA_CLASSIFICATION}
    assert accepted[Feature.DATA_CLASSIFICATION][0] == 2  # version 2, which has ranks
    with pytest.raises(ValueError, match=r"can't ask for FEDERATED_AUTH yet: it is the login's own: connect\(login=EntraToken"):
        run(tds.connect(**server, features=[*tds.DEFAULT_FEATURES, Feature.FEDERATED_AUTH]))
    with pytest.raises(ValueError, match="can't ask for USER_AGENT yet"):
        run(tds.connect(**server, features=[Feature.USER_AGENT]))


@pytest.mark.parametrize("on", [True, False])
def test_data_classification_as_an_application_reads_it(server, on):
    features = tds.DEFAULT_FEATURES if on else [f for f in tds.DEFAULT_FEATURES if f is not Feature.DATA_CLASSIFICATION]

    async def go():
        async with await tds.connect(**server, database="tds_test", features=features) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "DROP TABLE IF EXISTS dbo.classified; CREATE TABLE dbo.classified (email varchar(50), n int); "
                                     "INSERT dbo.classified VALUES ('a@b.c', 1); ADD SENSITIVITY CLASSIFICATION TO dbo.classified.email "
                                     "WITH (LABEL = 'Confidential', INFORMATION_TYPE = 'Contact Info', RANK = MEDIUM)")
                fetched = await fetch(channel, "SELECT email, n FROM dbo.classified; SELECT 1 AS plain")
                await fetch(channel, "DROP TABLE dbo.classified")
                return fetched.result_sets

    classified, plain = run(go())
    assert plain.classification is None
    if not on:
        assert classified.classification is None
        return
    email, n = classified.classification.columns
    [s] = email
    assert s.label[0] == "Confidential" and s.information_type[0] == "Contact Info" and s.rank == 20  # medium
    assert n == () and classified.classification.rank == 20


def test_the_session_identifies_itself(server):
    async def go():
        async with await tds.connect(**server, app_name="shop-service", host_name="shop-host-1", language="Deutsch") as connection:
            async with connection.serial_channel() as channel:
                rows = (await fetch(channel, "SELECT program_name, host_name, host_process_id, @@LANGUAGE "
                                             "FROM sys.dm_exec_sessions WHERE session_id = @@SPID")).result_sets[0].rows
                return rows[0], connection.session.language

    (program, host, pid, language), session_language = run(go())
    assert (program, host, pid, language) == ("shop-service", "shop-host-1", os.getpid(), "Deutsch")
    assert session_language == "Deutsch"
    with pytest.raises(LoginRejected) as refused:
        run(tds.connect(**server, language="Klingon"))
    assert "Msg 4019" in str(refused.value) and "Klingon" in str(refused.value)


def test_read_only_intent_is_a_hint_that_doesnt_stop_writes(server):
    async def go():
        async with await tds.connect(**server, read_only_intent=True) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE #w (a int); INSERT #w VALUES (1)")
                return (await fetch(channel, "SELECT COUNT(*) FROM #w")).result_sets[0].rows

    assert run(go()) == ((1,),)  # observed: a standalone server accepts it and still allows writes (D-9)


def test_the_command_line_notes_what_read_only_intent_does():
    result = subprocess.run([sys.executable, "-m", "tds", "--read-only-intent", "--port", "1", "--timeout", "1"],
                            capture_output=True, text=True, env={**os.environ, "MSSQL_SA_PASSWORD": "unused"})
    assert "note: --read-only-intent is a routing hint" in result.stderr and "writes still work" in result.stderr


def test_a_default_database_that_cant_be_opened_fails_and_says_why(server):
    password = "Tds!" + secrets.token_hex(8)

    async def admin(sql):
        async with await tds.connect(**server) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, sql)

    run(admin("IF DB_ID('default_db_gone') IS NULL CREATE DATABASE default_db_gone; "
              "IF SUSER_ID('default_db_user') IS NOT NULL DROP LOGIN default_db_user"))
    run(admin(f"CREATE LOGIN default_db_user WITH PASSWORD = '{password}', DEFAULT_DATABASE = default_db_gone, CHECK_POLICY = OFF"))
    run(admin("USE default_db_gone; CREATE USER default_db_user FOR LOGIN default_db_user"))
    user = {**server, "user": "default_db_user", "password": password}
    try:
        async def where():
            async with await tds.connect(**user) as connection:
                return connection.session.database

        assert run(where()) == "default_db_gone"  # no database is named, so this is the login's default, as announced
        run(admin("ALTER DATABASE default_db_gone SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE default_db_gone"))
        with pytest.raises(LoginRejected) as refused:
            run(where())
        message = str(refused.value)
        assert "Msg 4064" in message and "The login's default database can't be opened" in message
        assert "database=" in message and "ALTER LOGIN" in message  # the message says what to do
    finally:
        run(admin("IF SUSER_ID('default_db_user') IS NOT NULL DROP LOGIN default_db_user; "
                  "IF DB_ID('default_db_gone') IS NOT NULL DROP DATABASE default_db_gone"))


# --------------------------------------------------------------------------- SQL Server login variants (M17, D-54)

def test_an_expired_password_is_changed_as_the_login_happens(server):
    old, new = "Old-" + secrets.token_hex(8) + "aA1!", "New-" + secrets.token_hex(8) + "aA1!"

    async def go():
        async with await tds.connect(**server) as admin:
            async with admin.serial_channel() as channel:
                await fetch(channel, "IF SUSER_ID('tds_expiring') IS NOT NULL DROP LOGIN tds_expiring; "
                                     f"CREATE LOGIN tds_expiring WITH PASSWORD = '{old}' MUST_CHANGE, "
                                     "CHECK_POLICY = ON, CHECK_EXPIRATION = ON")
        user = {**server, "user": "tds_expiring", "password": old}
        with pytest.raises(LoginRejected) as refused:
            await tds.connect(**user)
        async with await tds.connect(**user, new_password=new) as changed:
            changed_id = changed.session_id
        async with await tds.connect(**{**user, "password": new}) as again:
            return str(refused.value), changed_id, again.session_id

    refused, changed, again = run(go())
    assert "Msg 18488" in refused and "connect(…, new_password=…) changes it as it logs in" in refused
    assert changed and again


def test_a_contained_database_user_names_its_database(server):
    password = "Cu-" + secrets.token_hex(8) + "aA1!"

    async def go():
        async with await tds.connect(**server) as admin:
            async with admin.serial_channel() as channel:
                await fetch(channel, "EXEC sp_configure 'contained database authentication', 1; RECONFIGURE")
                await fetch(channel, "IF DB_ID('tds_contained') IS NOT NULL BEGIN ALTER DATABASE tds_contained SET "
                                     "SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE tds_contained END; "
                                     "CREATE DATABASE tds_contained CONTAINMENT = PARTIAL")
                await fetch(channel, f"USE tds_contained; CREATE USER tds_cu WITH PASSWORD = '{password}'")
        user = {**server, "user": "tds_cu", "password": password}
        with pytest.raises(LoginRejected) as without:
            await tds.connect(**user)  # the server has no such login
        async with await tds.connect(**user, database="tds_contained") as contained:
            async with contained.serial_channel() as channel:
                who = (await fetch(channel, "SELECT USER_NAME(), DB_NAME()")).result_sets[0].rows
        return str(without.value), who

    without, who = run(go())
    assert "Msg 18456" in without
    assert who == (("tds_cu", "tds_contained"),)
