"""Pool opening races without a server, scheduling delay or real credentials."""
import asyncio
import pytest
from tds.connection import shell


class Session:
    session_id = 42
    alive = True

    async def close(self):
        self.alive = False


def test_shutdown_refuses_a_login_that_finishes_after_it_closed(monkeypatch):
    async def go():
        opened, finish = asyncio.Event(), asyncio.Event()
        connection = Session()

        async def connect(*args, **kwargs):
            opened.set()
            await finish.wait()
            return connection

        monkeypatch.setattr(shell, "connect", connect)
        pool = shell.Pool("unused", 1433, size=1)
        opening = asyncio.create_task(pool._borrow())
        await opened.wait()
        waiting = asyncio.create_task(pool._borrow())
        await pool.close()
        with pytest.raises(RuntimeError, match="pool is closed"):
            await waiting
        finish.set()
        with pytest.raises(RuntimeError, match="pool is closed"):
            await opening
        assert not connection.alive
        assert pool._opening == pool.in_use == pool.idle == 0

    asyncio.run(go())


def test_cancellation_during_login_commit_closes_the_session_and_frees_capacity(monkeypatch):
    async def go():
        opened, finish, returned = asyncio.Event(), asyncio.Event(), asyncio.Event()
        connection = Session()

        async def connect(*args, **kwargs):
            opened.set()
            await finish.wait()
            returned.set()
            return connection

        monkeypatch.setattr(shell, "connect", connect)
        pool = shell.Pool("unused", 1433, size=1)
        opening = asyncio.create_task(pool._borrow())
        await opened.wait()
        async with pool._changed:
            finish.set()
            await returned.wait()  # connect returned; commit is waiting on this lock
            opening.cancel()
        with pytest.raises(asyncio.CancelledError):
            await opening
        assert not connection.alive
        assert pool._opening == pool.in_use == pool.idle == 0
        await pool.close()

    asyncio.run(go())
