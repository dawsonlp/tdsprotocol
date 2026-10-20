"""The azure-identity adapter (PY-AZ-03): a synchronous credential runs in a worker thread, so it cannot stall the
event loop; an asynchronous one is awaited. Live, the synchronous Azure CLI credential stalled the loop for 0.42 s
per login before this."""

import asyncio
import time
from types import SimpleNamespace

from tds.adapters.entra import fetch, token


class SlowSync:
    def __init__(self):
        self.scopes = []

    def get_token(self, scope):
        self.scopes.append(scope)
        time.sleep(0.4)  # as `az account get-access-token` does
        return SimpleNamespace(token="sync-token")


class Async:
    def __init__(self):
        self.scopes = []

    async def get_token(self, scope):
        self.scopes.append(scope)
        await asyncio.sleep(0)
        return SimpleNamespace(token="async-token")


async def longest_stall(work) -> tuple[float, object]:
    gaps, last = [], time.monotonic()

    async def heartbeat():
        nonlocal last
        while True:
            await asyncio.sleep(0.01)
            now = time.monotonic()
            gaps.append(now - last)
            last = now

    beat = asyncio.create_task(heartbeat())
    result = await work
    beat.cancel()
    return max(gaps), result


def test_a_synchronous_credential_does_not_stall_the_event_loop():
    credential = SlowSync()
    stall, result = asyncio.run(longest_stall(token(credential)()))
    assert result == "sync-token" and credential.scopes == ["https://database.windows.net/.default"]
    assert stall < 0.2, stall  # the 0.4 s call ran in a worker


def test_an_asynchronous_credential_is_awaited_and_the_server_spn_becomes_the_scope():
    credential = Async()
    result = asyncio.run(fetch(credential)("https://database.windows.net/", "https://login.example/tenant"))
    assert result == "async-token" and credential.scopes == ["https://database.windows.net/.default"]


def test_an_abandoned_synchronous_call_cannot_hold_the_caller():
    async def go():
        started = time.monotonic()
        try:
            await asyncio.wait_for(token(SlowSync())(), 0.05)
        except TimeoutError:
            return time.monotonic() - started

    assert asyncio.run(go()) < 0.3  # the caller returns at its deadline; the worker finishes and its token is dropped
