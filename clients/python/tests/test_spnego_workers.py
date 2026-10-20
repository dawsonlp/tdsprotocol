"""The built-in Spnego adapter runs pyspnego's blocking calls in bounded workers (roadmap backlog: the Kerberos opening
deadline). A fake pyspnego module blocks as a KDC that never answers would: on GCP, the real one held a 1.5 s opening
for more than 4 s, with the event loop stalled."""

import asyncio
import sys
import threading
import time
import types

import pytest

import tds
from conftest import trust_test_authority
from tds.adapters import spnego as adapter
from tds.connection.core import ConnectError
from tds.logins import WindowsLogin
from test_logins import FakeServer, logged_in, login_ack

TOKEN = b"NTLMSSP\x00artificial-first-token"


class FakePyspnego:
    """pyspnego's client(), which blocks until released when `block` is true. It counts what native work began,
    finished, and stepped."""

    def __init__(self, block: bool):
        self.block, self.release, self.lock = block, threading.Event(), threading.Lock()
        self.entered = self.finished = self.steps = 0

    def module(self) -> types.ModuleType:
        module = types.ModuleType("spnego")
        module.client = self.client
        return module

    def client(self, username, password, hostname, service, protocol):
        with self.lock:
            self.entered += 1
        if self.block:
            self.release.wait(10)
        with self.lock:
            self.finished += 1
        fake = self

        class Context:
            def step(self, challenge):
                with fake.lock:
                    fake.steps += 1
                return TOKEN if challenge is None else b""

        return Context()


def install(monkeypatch, block: bool) -> FakePyspnego:
    fake = FakePyspnego(block)
    monkeypatch.setitem(sys.modules, "spnego", fake.module())
    return fake


def wait_until(condition, seconds: float = 5) -> None:
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "timed out waiting"
        time.sleep(0.01)


def opening(port: int, timeout: float):
    return tds.connect("localhost", port, login=WindowsLogin(adapter.Spnego("TDS\\fixture", "unused", "ntlm")),
                       tds_version="8.0", ssl_context=trust_test_authority(), timeout=timeout)


def test_a_blocked_provider_cannot_hold_the_opening_past_its_deadline(monkeypatch):
    fake = install(monkeypatch, block=True)

    async def go():
        server = FakeServer([])
        port = await server.start()
        ticks = 0

        async def heartbeat():
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0.01)

        beat = asyncio.create_task(heartbeat())
        started = time.monotonic()
        try:
            with pytest.raises(ConnectError) as failed:
                await opening(port, 0.5)
            return time.monotonic() - started, ticks, failed.value
        finally:
            beat.cancel()
            server.server.close()

    try:
        elapsed, ticks, error = asyncio.run(go())
        assert elapsed < 1.5, elapsed  # the deadline holds
        assert ticks > 20, ticks  # the event loop kept running other work
        assert "timer ran out" in str(error), error
        assert fake.entered == 1
    finally:
        fake.release.set()
    wait_until(lambda: fake.finished == 1)
    time.sleep(0.05)
    assert fake.steps == 0  # the late context is released: never stepped, never installed


def test_canceled_openings_cannot_queue_unbounded_native_work(monkeypatch):
    fake = install(monkeypatch, block=True)
    count = adapter.WORKERS + 3

    async def go():
        server = FakeServer([])
        port = await server.start()
        try:
            return await asyncio.gather(*(opening(port, 0.4) for _ in range(count)), return_exceptions=True)
        finally:
            server.server.close()

    try:
        results = asyncio.run(go())
        assert all(isinstance(r, ConnectError) for r in results), results
        assert fake.entered == adapter.WORKERS  # only the pool's workers began native work
    finally:
        fake.release.set()
    wait_until(lambda: fake.finished == adapter.WORKERS)
    time.sleep(0.1)
    assert fake.entered == adapter.WORKERS  # queued calls were dropped, not run late
    assert fake.steps == 0


def test_the_adapter_still_logs_in_through_its_workers(monkeypatch):
    fake = install(monkeypatch, block=False)
    received = logged_in(FakeServer([login_ack()]), WindowsLogin(adapter.Spnego("TDS\\fixture", "unused", "ntlm")))
    assert TOKEN in received[0][1]  # LOGIN7 carries the first token, made in a worker
    assert (fake.entered, fake.steps) == (1, 1)
