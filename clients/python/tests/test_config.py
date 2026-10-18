"""Demand-driven configuration without a SQL Server, watcher or timing sleeps."""
import asyncio
import dataclasses
import traceback

import pytest
import tds
from tds.config import _ConfigState
from tds.connection import shell


def config(password="artificial-A", **changes):
    return dataclasses.replace(tds.ConnectionConfig("unused", 1433, "fixture-user", password), **changes)


class Source:
    def __init__(self, value=None):
        self.value, self.calls = value or config(), 0

    async def read(self):
        self.calls += 1
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class Session:
    session_id, alive = 42, True

    def _release(self):
        return True

    async def close(self):
        self.alive = False


def test_value_equality_immutability_features_and_safe_representation():
    first = config(features=list(reversed(tds.DEFAULT_FEATURES)))
    assert first == config() and "artificial" not in repr(first)
    assert config("different") != first
    assert config("different").compatible_with(first)
    assert not config(database="elsewhere").compatible_with(first)
    with pytest.raises(dataclasses.FrozenInstanceError):
        first.password = "mutated"
    for change in ({"port": 0}, {"port": True}, {"mars": 1}, {"tds_version": "bad"}, {"features": [255]}):
        with pytest.raises(tds.ConfigurationError):
            config(**change)


def test_bad_source_is_safe_does_not_fall_back_and_can_be_corrected(monkeypatch):
    async def go():
        source, sessions = Source(ValueError("SECRET IN SOURCE FAILURE")), []

        async def connect(*args, **kwargs):
            sessions.append(Session())
            return sessions[-1]

        monkeypatch.setattr(shell, "connect", connect)
        pool = tds.Pool.from_config(source, size=1)
        assert source.calls == 0
        with pytest.raises(tds.ConfigurationError) as caught:
            await pool._borrow()
        error = caught.value
        assert error.phase == "read" and isinstance(error.source_error, ValueError)
        assert "SECRET" not in "".join(traceback.format_exception(error))
        assert not sessions and pool._opening == 0
        source.value = config()
        async with pool.connection() as first:
            assert source.calls == 2
        async with pool.connection() as again:
            assert first is again and source.calls == 2
        await pool.close()
    asyncio.run(go())


def test_changed_settings_retire_returns_and_idle_but_not_active_borrowers(monkeypatch):
    async def go():
        source, sessions = Source(), []

        async def connect(*args, **kwargs):
            sessions.append(Session())
            return sessions[-1]

        monkeypatch.setattr(shell, "connect", connect)
        pool = tds.Pool.from_config(source, size=3)
        old, idle = await pool._borrow(), await pool._borrow()
        await pool._give_back(idle)
        # Hold that idle session as well, forcing a fresh read for the third.
        reused = await pool._borrow()
        assert reused is idle and source.calls == 2
        source.value = config("artificial-B")
        fresh = await pool._borrow()
        assert old.alive and reused.alive
        await pool._give_back(old)
        assert not old.alive
        await pool._give_back(fresh)
        await pool._give_back(reused)
        assert not reused.alive and pool.idle == 1
        again = await pool._borrow()
        assert again is fresh and source.calls == 3
        await pool._give_back(again)
        await pool.close()
    asyncio.run(go())


def test_slow_login_cannot_publish_after_a_new_snapshot(monkeypatch):
    async def go():
        source = Source()
        entered, finish = asyncio.Event(), asyncio.Event()
        old = Session()

        async def connect(*args, **kwargs):
            if kwargs["password"] == "artificial-A":
                entered.set()
                await finish.wait()
                return old
            return Session()

        monkeypatch.setattr(shell, "connect", connect)
        pool = tds.Pool.from_config(source, size=2)
        opening = asyncio.create_task(pool._borrow())
        await entered.wait()
        source.value = config("artificial-B")
        newer = await pool._borrow()
        finish.set()
        with pytest.raises(tds.ConfigurationError, match="superseded"):
            await opening
        assert not old.alive and pool._opening == 0 and pool.in_use == 1
        await pool._give_back(newer)
        await pool.close()
    asyncio.run(go())


@pytest.mark.parametrize("action", ["cancel", "close"])
def test_source_wait_is_interruptible_without_leaking_capacity(action):
    async def go():
        entered, canceled = asyncio.Event(), asyncio.Event()

        class Waiting:
            async def read(self):
                entered.set()
                try:
                    await asyncio.Future()
                finally:
                    canceled.set()

        pool = tds.Pool.from_config(Waiting(), size=1)
        opening = asyncio.create_task(pool._borrow())
        await entered.wait()
        if action == "cancel":
            opening.cancel()
            with pytest.raises(asyncio.CancelledError):
                await opening
        else:
            await pool.close()
            with pytest.raises(RuntimeError, match="pool is closed"):
                await opening
        assert canceled.is_set() and pool._opening == pool.in_use == 0
        await pool.close()
    asyncio.run(go())


def test_source_gate_is_serial_but_not_shared_between_pools():
    async def go():
        first, release = asyncio.Event(), asyncio.Event()

        class Ordered(Source):
            async def read(self):
                self.calls += 1
                if self.calls == 1:
                    first.set()
                    await release.wait()
                return self.value

        source = Ordered()
        state = _ConfigState(source)
        deadline = asyncio.get_running_loop().time() + 2
        pending = asyncio.create_task(state.read(deadline))
        await first.wait()
        another = _ConfigState(source)
        assert await another.read(deadline) == config()
        source.value = config("artificial-B")
        release.set()
        assert await pending == config("artificial-B")
        assert another.current == config()
    asyncio.run(go())


def test_a_source_deadline_fails_loudly_and_frees_its_gate():
    async def go():
        source = Source()
        state = _ConfigState(source)
        await state._gate.acquire()
        with pytest.raises(tds.ConfigurationError, match="timeout"):
            await state.read(asyncio.get_running_loop().time())
        state._gate.release()
        assert source.calls == 0
        assert await state.read(asyncio.get_running_loop().time() + 1) == config()
    asyncio.run(go())


def test_pool_rejects_a_one_time_server_password_change():
    with pytest.raises(ValueError, match="cannot change the server password"):
        tds.Pool("unused", 1433, user="fixture-user", password="A", new_password="B")
