"""Run the Rust CLI in four Docker modes, replay its recordings with Python.

Build clients/rust/target/debug/tds first, then run with the Python client venv.
Only synthetic SQL data are requested. Temporary recordings are removed; no
credential/packet bodies are printed. Uses existing Docker credentials and CA.
"""
import base64
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "clients/python"))
from tds.capture import replay


def walk(node):
    yield node
    for child in node.children:
        yield from walk(child)


def main():
    binary = ROOT / "clients/rust/target/debug/tds"
    with tempfile.TemporaryDirectory(prefix="tds-rust-rpc-") as temporary:
        for version in ["7.4", "8.0"]:
            for mars in [False, True]:
                path = Path(temporary) / f"{version}-{mars}.jsonl"
                command = [str(binary), "--observe", "off", "--tds-version", version,
                           "--capture", str(path), "--proc", "sp_executesql",
                           "--param", "@stmt:nvarchar(4000)=SELECT @n AS answer; SET @n=42",
                           "--param", "@params:nvarchar(4000)=@n int OUTPUT", "--output", "@n:int=7"]
                if mars:
                    command.append("--mars")
                result = subprocess.run(command, capture_output=True, text=True)
                assert result.returncode == 0, "Rust CLI request failed"
                assert "answer\n7\n" in result.stdout and "output @n [2] = 42" in result.stdout
                events = []
                replay(io.StringIO(path.read_text()), events.append)
                names = set()
                for event in events:
                    if event.node:
                        assert "can't be decoded" not in event.node.shown
                        names.update(node.name for node in walk(event.node))
                assert {"ROW", "RETURNSTATUS", "RETURNVALUE"} <= names
                assert any(event.kind == "send" and "RPC" in event.text and event.node for event in events)
                lines = [json.loads(line) for line in path.read_text().splitlines()]
                sent = [base64.b64decode(line["bytes"]) for line in lines if line.get("packet") == "send"]
                login = b"".join(packet[8:] for packet in sent if packet[0] == 0x10)
                assert login
                for field in [44, 86]:
                    offset = int.from_bytes(login[field:field + 2], "little")
                    size = 2 * int.from_bytes(login[field + 2:field + 4], "little")
                    assert login[offset:offset + size] == bytes(size)
    print("4 Rust CLI recordings: typed RPC, rows/outputs, Python replay and LOGIN7 redaction passed")


if __name__ == "__main__":
    main()
