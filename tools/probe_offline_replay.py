"""Fresh two-client replay acceptance against the existing Docker SQL Server.

Only temporary recordings/tables and uniquely named SQL type/procedure objects
are used. Credentials and packet contents are never printed. Run serially with
other live mutation suites, using clients/python/.venv/bin/python.
"""
import asyncio
import base64
import io
import json
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "clients/python"), str(ROOT / "clients/python/tests")]
import tds
from tds import types
from tds.capture import Capture, replay
from conftest import HOST, PORT, _password, fetch, trust_test_authority
from test_session_recovery_live import Relay

BINARY = ROOT / "clients/rust/target/debug/tds"


def check(path):
    result = subprocess.run([str(BINARY), "--replay", str(path), "--observe", "off"],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, f"Rust replay {path.name}: {result.stdout[-3000:]}"
    assert "0 issues" in result.stdout
    events = []
    replay(io.StringIO(path.read_text()), events.append)

    def walk(node):
        yield node
        for child in node.children:
            yield from walk(child)

    for event in events:
        if event.node:
            assert all("can't be decoded" not in node.shown for node in walk(event.node)), path.name
    login = b"".join(packet[8:] for line in map(json.loads, path.read_text().splitlines())
                     if line.get("packet") == "send"
                     and (packet := base64.b64decode(line["bytes"]))[0] == 0x10)
    assert login
    for field in (44, 86):
        offset = int.from_bytes(login[field:field + 2], "little")
        size = 2 * int.from_bytes(login[field + 2:field + 4], "little")
        assert login[offset:offset + size] == bytes(size)


async def python_recording(options, path):
    recording = Capture(path)
    name = "tds_replay_" + uuid.uuid4().hex
    try:
        async with await tds.connect(**options, capture=recording) as connection:
            channel = connection.serial_channel()
            await fetch(channel, f"CREATE TYPE dbo.[{name}] AS TABLE(id int IDENTITY,a int,b nvarchar(max),c AS(a*2))")
            try:
                await fetch(channel, f"CREATE PROCEDURE dbo.[{name}_p] @t dbo.[{name}] READONLY,@out int OUTPUT AS "
                            "SELECT a,b FROM @t ORDER BY a; SET @out=42; RETURN 17")
                declaration = types.table(f"dbo.{name}", types.default(types.int), types.int,
                                          types.nvarchar(types.MAX), types.default(types.int), send_order=(4, 3, 2, 1))
                async def rows():
                    yield (7, "é🦀" * 10000)
                    yield (9, None)
                result = await fetch(channel, tds.Call(f"dbo.{name}_p", tds.Param("@t", declaration, rows()),
                                                       tds.Param("@out", types.int, 0, output=True)))
                assert result.result_sets[0].rows == ((7, "é🦀" * 10000), (9, None))
                await fetch(channel, "CREATE TABLE #replay_bulk(a int,b nvarchar(max))")
                metadata = (await fetch(channel, "SELECT TOP 0 a,b FROM #replay_bulk")).result_sets[0].columns
                await fetch(channel, tds.BulkInsert("INSERT BULK #replay_bulk(a int,b nvarchar(max))"))
                await fetch(channel, tds.BulkRows(metadata, [(11, "bulk🦀")]))
                await fetch(channel, tds.BulkInsert("INSERT BULK #replay_bulk(a int,b nvarchar(max))"))
                await channel.close()  # explicit Attention in the prepared gap
                channel = connection.serial_channel()
                assert (await fetch(channel, "SELECT a,b FROM #replay_bulk")).result_sets[0].rows == ((11, "bulk🦀"),)
                # Two outstanding MARS channels are consumed in reverse order.
                if options["mars"]:
                    other = connection.serial_channel()
                    first = await channel.exchange(tds.Batch("SELECT 23 AS a"))
                    second = await other.exchange(tds.Batch("SELECT 24 AS a"))
                    async with second:
                        assert (await second.fetch()).result_sets[0].rows == ((24,),)
                    async with first:
                        assert (await first.fetch()).result_sets[0].rows == ((23,),)
                    await other.close()
            finally:
                await fetch(channel, f"DROP PROCEDURE IF EXISTS dbo.[{name}_p]; DROP TYPE IF EXISTS dbo.[{name}]")
    finally:
        recording.close()


async def python_recovery(options, directory, label):
    paths, recordings = [], []
    def factory():
        path = directory / f"python-recovery-{label}-{len(paths)}.jsonl"
        paths.append(path)
        capture = Capture(path)
        recordings.append(capture)
        return capture
    try:
        async with Relay(options) as relay, await tds.connect(**{**options, "port": relay.port}, capture_factory=factory) as connection:
            channel = connection.serial_channel()
            assert (await fetch(channel, "SELECT 31 AS a")).result_sets[0].rows == ((31,),)
            relay.cut()
            await asyncio.wait_for(connection._reading, 5)
            assert (await fetch(channel, "SELECT 32 AS a")).result_sets[0].rows == ((32,),)
            assert connection.recoveries == 1
    finally:
        for recording in recordings:
            recording.close()
    assert len(paths) == 2
    return paths


def main():
    options = dict(host=HOST, port=PORT, user="sa", password=_password(), database="tds_test",
                   ssl_context=trust_test_authority())
    assert options["password"], "existing SQL Server credential configuration is required"
    count = 0
    with tempfile.TemporaryDirectory(prefix="tds-offline-replay-") as temporary:
        directory = Path(temporary)
        source = directory / "input.bin"
        source.write_bytes(b"\x5a" * 2_100_000)
        for version in ("7.4", "8.0"):
            for mars in (False, True):
                label = f"{version}-{mars}"
                for demo in ("query", "transactions", "bulk", "special", "stream"):
                    path = directory / f"rust-{demo}-{label}.jsonl"
                    command = [str(BINARY), "--observe", "off", "--tds-version", version, "--capture", str(path)]
                    if mars:
                        command.append("--mars")
                    if demo in ("transactions", "bulk"):
                        command.append(f"--demo-{demo}")
                    elif demo == "query":
                        command += ["--query", "SELECT 42 AS answer, N'é🦀' AS label"]
                    elif demo == "stream":
                        command += ["--stream", "--proc", "sp_executesql", "--param",
                                    "@stmt:nvarchar(max)=SELECT @b AS bytes", "--param",
                                    "@params:nvarchar(max)=@b varbinary(max)", "--param-file", f"@b:varbinary(max)={source}"]
                    else:
                        command += ["--proc", "sp_executesql", "--param",
                                    "@stmt:nvarchar(max)=SELECT @j AS document,@v AS embedding,CAST(42 AS sql_variant) AS variant,geometry::Point(1,2,0) AS shape", "--param",
                                    "@params:nvarchar(max)=@j json OUTPUT,@v vector(3)", "--output",
                                    '@j:json={"note":"é🦀"}', "--param", "@v:vector(3)=[1,2.5,3]"]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                    assert result.returncode == 0, f"Rust recording failed: {demo}/{label}"
                    check(path)
                    count += 1
                configured = {**options, "tds_version": version, "mars": mars}
                path = directory / f"python-tables-bulk-{label}.jsonl"
                asyncio.run(python_recording(configured, path))
                check(path)
                count += 1
                for path in asyncio.run(python_recovery(configured, directory, label)):
                    check(path)
                    count += 1
                print(f"Replay {label}: Rust/Python, tables/bulk/cancel/stream/recovery passed", flush=True)
    print(f"{count} fresh physical recordings passed both replay readers and LOGIN7 masking")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        paths = sorted(Path(sys.argv[1]).glob("*.jsonl"))
        assert paths, "no physical recordings found"
        for path in paths:
            check(path)
        print(f"{len(paths)} saved physical recordings passed both replay readers and LOGIN7 masking")
    elif len(sys.argv) == 1:
        main()
    else:
        raise SystemExit("usage: probe_offline_replay.py [recording-directory]")
