"""Read-only diagnostic for the recovery identity checkpoint in RUST_CHECKLIST.

Run from the repo root with clients/python/.venv/bin/python. Uses the existing
Docker test endpoint/CA and ignored credentials. SELECTs, relay cuts and private
core controls are deliberate diagnostic interventions, not application examples.
No credentials or packet bodies are printed. A timeout is evidence of this run's
failure, not proof of its cause or a universal SMP session-number requirement.
"""
import asyncio
import ssl
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "clients/python"), str(ROOT / "clients/python/tests")]

import tds
from conftest import HOST, PORT, TEST_CA, _password
from test_session_recovery_live import Relay


async def query(channel, value):
    response = await channel.exchange(tds.Batch(f"SELECT {value}"))
    # Same task as channel creation; wait_for(fetch(...)) would change ownership.
    async with asyncio.timeout(2):
        return (await response.fetch()).result_sets[0].rows


async def fresh(server, number):
    connection = await tds.connect(**server, mars=True, timeout=4, cleanup_timeout=1)
    try:
        connection._core.link._next_wire_channel = number
        channel = connection.serial_channel()
        print("fresh first protocol id", number, "rows", await query(channel, 11), flush=True)
        await channel.close()
    except Exception as failure:
        print("fresh first protocol id", number, "failure", type(failure).__name__, flush=True)
        await connection._discard(failure)
    finally:
        await connection.close()


async def recover(server, number):
    async with Relay(server) as relay:
        connection = await tds.connect(**{**server, "port": relay.port}, mars=True, timeout=4, cleanup_timeout=1)
        try:
            channel = connection.serial_channel()
            if number == 1:
                await query(channel, 1)
                await channel.close()
                channel = connection.serial_channel()
            print("surviving channel", channel.id, "before break", await query(channel, 11), flush=True)
            relay.cut()
            async with asyncio.timeout(5):
                await connection._reading
                await connection.recover()
            print("recovery login count", connection.recoveries, "application/wire ids",
                  [(c.id, c.wire_id) for c in connection._core.link.channels.values()], flush=True)
            print("surviving channel", channel.id, "after recovery", await query(channel, 22), flush=True)
            await channel.close()
        except Exception as failure:
            print("surviving channel", number, "failure", type(failure).__name__, "recoveries", connection.recoveries,
                  "alive", connection.alive, "core failure", type(connection._core.failure).__name__, flush=True)
            await connection._discard(failure)
        finally:
            await connection.close()


async def main():
    password = _password()
    if password is None:
        raise SystemExit("Configure the Docker SQL Server test credentials first")
    server = dict(host=HOST, port=PORT, user="sa", password=password,
                  ssl_context=ssl.create_default_context(cafile=TEST_CA))
    for number in [0, 1]:
        await fresh(server, number)
    for number in [0, 1]:
        await recover(server, number)


if __name__ == "__main__":
    asyncio.run(main())
