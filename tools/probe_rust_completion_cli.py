"""Cross-replay the Rust transaction and special-value CLI demonstrations.

Run with the Python client venv after building Rust's `tds` binary. Uses the
existing Docker server, temporary recordings and synthetic values. No credentials
or packet contents are printed. These are local interoperability checks.
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


def check_recording(path):
    events = []
    replay(io.StringIO(path.read_text()), events.append)
    names = set()
    for event in events:
        if event.node:
            for node in walk(event.node):
                assert "can't be decoded" not in node.shown
                names.add(node.name)
    assert "ROW" in names and "ENVCHANGE" in names
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    sent = [base64.b64decode(line["bytes"]) for line in lines if line.get("packet") == "send"]
    login = b"".join(packet[8:] for packet in sent if packet[0] == 0x10)
    assert login
    for field in [44, 86]:
        offset = int.from_bytes(login[field:field + 2], "little")
        size = 2 * int.from_bytes(login[field + 2:field + 4], "little")
        assert login[offset:offset + size] == bytes(size)
    return names


def main():
    binary = ROOT / "clients/rust/target/debug/tds"
    with tempfile.TemporaryDirectory(prefix="tds-rust-completion-") as temporary:
        for version in ["7.4", "8.0"]:
            for mars in [False, True]:
                for demo in ["transactions", "special", "bulk"]:
                    path = Path(temporary) / f"{demo}-{version}-{mars}.jsonl"
                    command = [str(binary), "--observe", "off", "--tds-version", version, "--capture", str(path)]
                    if mars:
                        command.append("--mars")
                    if demo in ("transactions", "bulk"):
                        command.append(f"--demo-{demo}")
                    else:
                        command += ["--proc", "sp_executesql",
                                    "--param", "@stmt:nvarchar(max)=SELECT @j AS document,@v AS embedding,@label AS label,CAST(42 AS sql_variant) AS variant,geometry::Point(1,2,0) AS shape",
                                    "--param", "@params:nvarchar(max)=@j json OUTPUT,@v vector(3),@label varchar(max)",
                                    "--output", '@j:json={"note":"é🦀"}',
                                    "--param", "@v:vector(3)=[1,2.5,3]",
                                    "--param", "@label:varchar(max)=café"]
                    result = subprocess.run(command, capture_output=True, text=True)
                    assert result.returncode == 0, f"Rust CLI {demo} failed"
                    names = check_recording(path)
                    if demo == "transactions":
                        assert "commit: transaction descriptor 0" in result.stdout
                    elif demo == "bulk":
                        assert "bulk finish: 2 rows" in result.stdout
                        assert "bulk abort: acknowledged; earlier rows preserved" in result.stdout
                        assert "1\t6\n2\t1200000" in result.stdout
                    else:
                        assert {"RETURNSTATUS", "RETURNVALUE"} <= names
                        assert "document\tembedding\tlabel\tvariant\tshape" in result.stdout
                        assert "café" in result.stdout and "output @j" in result.stdout
    print("12 Rust CLI recordings: transactions/special values/bulk, Python replay and LOGIN7 masking passed")


if __name__ == "__main__":
    main()
