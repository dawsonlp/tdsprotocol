"""Credential rotation and recovery with isolated, disposable SQL logins."""
import asyncio
import dataclasses
import secrets
import uuid

import pytest
import tds
from conftest import Secret, fetch
from test_session_recovery_live import Relay

pytestmark = pytest.mark.live


async def credential_sql(channel, sql):
    try:
        await fetch(channel, sql)
    except tds.ServerError:
        raise AssertionError("disposable login setup or rotation failed") from None


async def drop_login(channel, name):
    # TCP close completion is local; SQL Server may retire its session later.
    deadline = asyncio.get_running_loop().time() + 5
    while True:
        try:
            await fetch(channel, f"DROP LOGIN [{name}]")
            return
        except tds.ServerError as error:
            if error.errors[0].number != 15434 or asyncio.get_running_loop().time() >= deadline:
                raise
            await asyncio.sleep(0.02)


class Source:
    def __init__(self, value):
        self.value, self.calls = value, 0

    async def read(self):
        self.calls += 1
        return self.value


@pytest.mark.parametrize("version", ["7.4", "8.0"])
@pytest.mark.parametrize("mars", [False, True])
def test_rotation_failed_login_and_borrowed_recovery_after_pool_close(server, version, mars):
    async def go():
        name = "tds_config_" + uuid.uuid4().hex
        a, b, c = [Secret("Aa1!" + secrets.token_urlsafe(24)) for _ in range(3)]
        async with await tds.connect(**server) as admin:
            channel = admin.serial_channel()
            await credential_sql(channel, f"CREATE LOGIN [{name}] WITH PASSWORD='{a[:]}', CHECK_POLICY=OFF")
            pool = None
            try:
                async with Relay(server) as relay:
                    source = Source(tds.ConnectionConfig(server["host"], relay.port, name, a,
                                                        tds_version=version, mars=mars))
                    pool = tds.Pool.from_config(source, size=2,
                                               services=tds.ConnectionServices(ssl_context=server["ssl_context"]))
                    first = await pool._borrow()
                    original = first.serial_channel()
                    await fetch(original, "SELECT 11")
                    await credential_sql(channel, f"ALTER LOGIN [{name}] WITH PASSWORD='{b[:]}'")
                    # A failed opening does not retry or poison this pool.
                    with pytest.raises(tds.LoginRejected):
                        await pool._borrow()
                    assert source.calls == 2 and pool.in_use == 1
                    source.value = dataclasses.replace(source.value, password=b)
                    second = await pool._borrow()
                    assert source.calls == 3
                    assert (await fetch(original, "SELECT 12")).result_sets[0].rows == ((12,),)
                    await pool._give_back(first)
                    assert not first.alive
                    await pool._give_back(second)
                    second = await pool._borrow()
                    assert source.calls == 3  # idle checkout does not read configuration
                    active = second.serial_channel()
                    await fetch(active, "SELECT 21")  # apply the deferred reset
                    await credential_sql(channel, f"ALTER LOGIN [{name}] WITH PASSWORD='{c[:]}'")
                    source.value = dataclasses.replace(source.value, password=c)
                    relay.cut()
                    await second._reading
                    await pool.close()
                    source.value = dataclasses.replace(source.value, database="tempdb")
                    with pytest.raises(tds.SessionNotRecovered) as refused:
                        await second.recover()
                    assert isinstance(refused.value.__cause__, tds.ConfigurationError)
                    assert refused.value.__cause__.phase == "compatibility"
                    source.value = dataclasses.replace(source.value, database="")
                    await second.recover()  # no pool owner or spare capacity required
                    assert source.calls == 5 and second.recoveries == 1
                    assert (await fetch(active, "SELECT 33")).result_sets[0].rows == ((33,),)
                    await pool._give_back(second)
            finally:
                if pool is not None:
                    await pool.close()
                await drop_login(channel, name)
    asyncio.run(go())


def test_root_close_interrupts_a_borrowed_configuration_read(server):
    async def go():
        entered, canceled = asyncio.Event(), asyncio.Event()

        class Waiting(Source):
            async def read(self):
                if self.calls:
                    entered.set()
                    try:
                        await asyncio.Future()
                    finally:
                        canceled.set()
                return await super().read()

        async with Relay(server) as relay:
            source = Waiting(tds.ConnectionConfig(server["host"], relay.port, server["user"], server["password"]))
            pool = tds.Pool.from_config(source, size=1,
                                       services=tds.ConnectionServices(ssl_context=server["ssl_context"]))
            async with pool.connection() as connection:
                await fetch(connection.serial_channel(), "SELECT 1")
                relay.cut()
                await connection._reading
                recovery = asyncio.create_task(connection.recover())
                await entered.wait()
                await connection.close()
                with pytest.raises(tds.SessionNotRecovered):
                    await asyncio.wait_for(recovery, 1)
                assert canceled.is_set() and connection.recoveries == 0
            await pool.close()
    asyncio.run(go())


def test_recovery_candidate_superseded_by_a_new_opening_is_closed(server, monkeypatch):
    async def go():
        ready, finish = asyncio.Event(), asyncio.Event()
        async with Relay(server) as relay:
            source = Source(tds.ConnectionConfig(server["host"], relay.port, server["user"], server["password"]))
            pool = tds.Pool.from_config(source, size=2,
                                       services=tds.ConnectionServices(ssl_context=server["ssl_context"]))
            old = await pool._borrow()
            await fetch(old.serial_channel(), "SELECT 1")
            original_run = tds.Connection._run

            async def pause_candidate(connection, procedure, **kwargs):
                result = await original_run(connection, procedure, **kwargs)
                if connection is not old and connection._core.options.app_name == "tds (python)":
                    ready.set()
                    await finish.wait()
                return result

            monkeypatch.setattr(tds.Connection, "_run", pause_candidate)
            relay.cut()
            await old._reading
            recovery = asyncio.create_task(old.recover())
            await ready.wait()
            source.value = dataclasses.replace(source.value, app_name="changed")
            newer = await pool._borrow()
            finish.set()
            with pytest.raises(tds.SessionNotRecovered) as caught:
                await recovery
            assert isinstance(caught.value.__cause__, tds.ConfigurationError)
            assert caught.value.__cause__.phase == "superseded"
            assert old.recoveries == 0 and not old.alive
            await pool._give_back(old)
            await pool._give_back(newer)
            await pool.close()
    asyncio.run(asyncio.wait_for(go(), 10))


@pytest.mark.parametrize("version", ["7.4", "8.0"])
def test_successful_direct_password_change_is_used_for_recovery(server, version):
    async def go():
        name = "tds_change_" + uuid.uuid4().hex
        a, b = [Secret("Aa1!" + secrets.token_urlsafe(24)) for _ in range(2)]
        async with await tds.connect(**server) as admin:
            channel = admin.serial_channel()
            await credential_sql(channel, f"CREATE LOGIN [{name}] WITH PASSWORD='{a[:]}', CHECK_POLICY=OFF")
            try:
                async with Relay(server) as relay:
                    options = {**server, "port": relay.port, "user": name, "password": a, "tds_version": version}
                    async with await tds.connect(**options, new_password=b) as connection:
                        original = connection.serial_channel()
                        await fetch(original, "SELECT 1")
                        assert connection._core.options.password == b
                        assert not connection._core.options.new_password
                        relay.cut()
                        await connection._reading
                        await connection.recover()
                        assert (await fetch(original, "SELECT 2")).result_sets[0].rows == ((2,),)
            finally:
                await drop_login(channel, name)
    asyncio.run(go())
