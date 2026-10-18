"""Run Rust streamed file/RPC/response conversations, then replay with Python.

Uses only synthetic bytes, existing Docker credentials and CA. Temporary files
and recordings are removed; no password or packet bodies are printed.
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
    with tempfile.TemporaryDirectory(prefix="tds-rust-stream-") as temporary:
        source = Path(temporary) / "source.bin"
        source.write_bytes(b"\x5a" * 2_100_000)
        for version in ["7.4", "8.0"]:
            for mars in [False, True]:
                path = Path(temporary) / f"{version}-{mars}.jsonl"
                command = [str(ROOT / "clients/rust/target/debug/tds"), "--observe", "off",
                           "--tds-version", version, "--stream", "--capture", str(path),
                           "--proc", "sp_executesql",
                           "--param", "@stmt:nvarchar(max)=SELECT @b AS bytes; SET @n=42",
                           "--param", "@params:nvarchar(max)=@b varbinary(max),@n int OUTPUT",
                           "--param-file", f"@b:varbinary(max)={source}", "--output", "@n:int=7"]
                if mars:
                    command.append("--mars")
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                assert result.returncode == 0, "Rust streaming CLI failed"
                assert "end · 2100000 bytes" in result.stdout and "output @n [3] = 42" in result.stdout
                events = []
                replay(io.StringIO(path.read_text()), events.append)
                names = set()
                for event in events:
                    if event.node:
                        assert "can't be decoded" not in event.node.shown
                        names.update(node.name for node in walk(event.node))
                assert {"ROW", "RETURNSTATUS", "RETURNVALUE"} <= names, sorted(names)
                assert any(event.kind == "send" and "RPC" in event.text and event.node for event in events)
                sent = [base64.b64decode(line["bytes"]) for line in map(json.loads, path.read_text().splitlines())
                        if line.get("packet") == "send"]
                login = b"".join(packet[8:] for packet in sent if packet[0] == 0x10)
                assert login
                for field in [44, 86]:
                    offset = int.from_bytes(login[field:field + 2], "little")
                    size = 2 * int.from_bytes(login[field + 2:field + 4], "little")
                    assert login[offset:offset + size] == bytes(size)
    print("4 streamed Rust CLI recordings: file input, chunked rows, output, Python replay and LOGIN7 redaction passed")


if __name__ == "__main__":
    main()
