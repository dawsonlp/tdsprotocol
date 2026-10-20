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


@pytest.mark.parametrize("number", [18452, 18456])
@pytest.mark.parametrize("changed", [False, True])
def test_authentication_refusal_rereads_once_and_retries_only_changed_configuration(monkeypatch, number, changed):
    from tds.connection.core import LoginRejected
    from tds.wire import Record

    async def go():
        source, attempts = Source(), []
        refusal = LoginRejected([Record(number=number, severity=14, state=1, procedure="", line=1,
                                        message="Artificial refusal", server_name="fixture")])

        async def connect(*args, **kwargs):
            attempts.append(kwargs)
            if len(attempts) == 1:
                if changed:
                    source.value = config("artificial-B")
                raise refusal
            return Session()

        monkeypatch.setattr(shell, "connect", connect)
        pool = tds.Pool.from_config(source, size=1)
        if changed:
            connection = await pool._borrow()
            assert connection._configuration[1] == source.value
            assert len(attempts) == 2 and attempts[1]['timeout'] <= attempts[0]['timeout']
            await pool._give_back(connection)
        else:
            with pytest.raises(LoginRejected) as caught:
                await pool._borrow()
            assert caught.value is refusal and len(attempts) == 1
        assert source.calls == 2 and pool._opening == 0
        await pool.close()
    asyncio.run(go())


@pytest.mark.parametrize("second", ["unchanged", "refused-again", "unrelated", "source-error", "source-timeout"])
def test_opening_refresh_is_bounded_and_preserves_failures(monkeypatch, second):
    from tds.connection.core import LoginRejected
    from tds.wire import Record

    def rejected(number):
        return LoginRejected([Record(number=number, severity=14, state=1, procedure="", line=1,
                                     message="Artificial refusal", server_name="fixture")])

    async def go():
        attempts = []
        class Changing(Source):
            async def read(self):
                if self.calls == 1:
                    if second == "source-error":
                        self.calls += 1
                        raise ValueError("ARTIFICIAL-SOURCE-SECRET")
                    if second == "source-timeout":
                        self.calls += 1
                        await asyncio.Future()
                return await super().read()
        source = Changing()
        original = rejected(4060 if second == "unrelated" else 18456)
        another = rejected(18456)
        async def connect(*args, **kwargs):
            attempts.append(kwargs)
            if len(attempts) == 1:
                if second != "unchanged":
                    source.value = config("artificial-B")
                raise original
            raise another
        monkeypatch.setattr(shell, "connect", connect)
        pool = tds.Pool.from_config(source, size=1, timeout=0.03 if second == "source-timeout" else 1)
        expected = tds.ConfigurationError if second == "source-error" else TimeoutError if second == "source-timeout" else LoginRejected
        with pytest.raises(expected) as caught:
            await pool._borrow()
        if second == "refused-again":
            assert caught.value is another and len(attempts) == 2
        elif second in ("unrelated", "unchanged"):
            assert caught.value is original and len(attempts) == 1
        else:
            assert len(attempts) == 1
            assert "ARTIFICIAL-SOURCE-SECRET" not in ''.join(traceback.format_exception(caught.value))
        assert source.calls == (1 if second == "unrelated" else 2)
        assert pool._opening == pool.in_use == pool.idle == 0
        await pool.close()
    asyncio.run(go())


@pytest.mark.parametrize("action", ["cancel", "close"])
def test_second_opening_is_cancellable_and_cannot_leak_pool_capacity(monkeypatch, action):
    from tds.connection.core import LoginRejected
    from tds.wire import Record

    async def go():
        source, entered, retired = Source(), asyncio.Event(), asyncio.Event()
        attempts = []
        async def connect(*args, **kwargs):
            attempts.append(kwargs)
            if len(attempts) == 1:
                source.value = config("artificial-B")
                raise LoginRejected([Record(number=18456, severity=14, state=1, procedure="", line=1,
                                            message="Artificial refusal", server_name="fixture")])
            entered.set()
            try:
                await asyncio.Future()
            finally:
                retired.set()
        monkeypatch.setattr(shell, "connect", connect)
        pool = tds.Pool.from_config(source, size=1)
        opening = asyncio.create_task(pool._borrow())
        await entered.wait()
        if action == "cancel":
            opening.cancel()
        else:
            await pool.close()
        with pytest.raises(asyncio.CancelledError if action == "cancel" else RuntimeError):
            await opening
        assert retired.is_set() and len(attempts) == source.calls == 2
        assert pool._opening == pool.in_use == pool.idle == 0
        await pool.close()
    asyncio.run(go())


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


@pytest.mark.parametrize("changed", [False, True])
def test_a_windows_configuration_rereads_a_rotated_password_after_18452(monkeypatch, changed):
    """C3: explicit Windows credentials are comparable values; each opening makes its own Spnego provider from the
    current values, so a pool picks up a rotated password after one refusal, as Rust's does."""
    from tds.adapters.spnego import Spnego
    from tds.connection.core import LoginRejected
    from tds.logins import WindowsLogin
    from tds.wire import Record

    async def go():
        source, attempts = Source(config("old-password", user="TDS\\fixture", windows="ntlm")), []
        refusal = LoginRejected([Record(number=18452, severity=14, state=1, procedure="", line=1,
                                        message="Artificial refusal", server_name="fixture")])

        async def connect(*args, **kwargs):
            attempts.append(kwargs)
            if len(attempts) == 1:
                if changed:
                    source.value = config("new-password", user="TDS\\fixture", windows="ntlm")
                raise refusal
            return Session()

        monkeypatch.setattr(shell, "connect", connect)
        pool = tds.Pool.from_config(source, size=1)
        if changed:
            await pool._give_back(await pool._borrow())
        else:
            with pytest.raises(LoginRejected):
                await pool._borrow()
        providers = [a["login"].provider for a in attempts]
        assert all(isinstance(a["login"], WindowsLogin) and a["user"] == a["password"] == "" for a in attempts)
        assert providers[0] == Spnego("TDS\\fixture", "old-password", "ntlm")
        assert [p.password for p in providers] == (["old-password", "new-password"] if changed else ["old-password"])
        await pool.close()
    asyncio.run(go())


def test_windows_settings_compare_like_sql_ones():
    old = config("old-password", user="TDS\\fixture", windows="ntlm")
    assert config("new-password", user="TDS\\fixture", windows="ntlm").compatible_with(old)  # a credential refresh
    assert not config("old-password", user="TDS\\fixture", windows="kerberos").compatible_with(old)
    assert not config("old-password", user="TDS\\fixture").compatible_with(old)  # SQL instead of Windows
    with pytest.raises(tds.ConfigurationError, match="windows must be"):
        config(windows="digest")
    assert "old-password" not in repr(old)
