"""Independent field ranges from Python's actual inspection definitions.

Run: PYTHONPATH=clients/python clients/python/.venv/bin/python tools/generate_rust_inspection.py
Only artificial committed fixture inputs are used. No network or credentials.
"""
import json
import struct
from pathlib import Path

from tds import login7, packet, prelogin, tokens
from tds.wire import Reader

ROOT = Path(__file__).resolve().parents[1]
cases = []


def add(family, data, node, paths, **extra):
    fields = []
    for python_path, rust_path in paths:
        field = node.find(*python_path)
        fields.append(dict(path=rust_path, start=field.start - node.start,
                           end=field.end - node.start, raw=field.raw.hex()))
    cases.append(dict(family=family, body=data.hex(), fields=fields, **extra))


header = bytes.fromhex("0101000800000100")
add("packet", header, packet.HEADER.decode(header).node,
    [([name], [name]) for name in ("type", "status", "length", "session id", "packet number")])
body = (ROOT / "clients/rust/tests/fixtures/login7/default.bin").read_bytes()
login = login7.LOGIN7.decode(body)
add("login", body, login.node,
    [([name], [name]) for name in ("length", "tds version", "packet size")],
    version=login.tds_version)
body, node = prelogin.PRELOGIN.encode(dict(options=dict(
    version=dict(major=17, minor=0, build=5015, sub_build=0),
    encryption=prelogin.Encryption.ON, instance=b"\x00", thread_id=0, mars=prelogin.OnOff.ON)))
add("prelogin", body, prelogin.PRELOGIN.decode(body).node,
    [(["options", "data", name], [name]) for name in ("version", "encryption", "instance", "mars")]
    + [(["options", "data", "version", name], ["version", name]) for name in ("major", "minor", "build", "sub build")])

done = b"\xfd" + struct.pack("<HHQ", 0x10, 0xc1, 42)
add("token", done, tokens.TOKENS.decode(done)[0].node,
    [(["status"], ["status"]), (["current command"], ["command"]), (["row count"], ["row count"])])
ack_body = b"\x01" + bytes.fromhex("74000004") + b"\x03" + "SQL".encode("utf-16-le") + bytes([17, 0, 0x13, 0x97])
ack = b"\xad" + struct.pack("<H", len(ack_body)) + ack_body
add("token", ack, tokens.TOKENS.decode(ack)[0].node,
    [(["interface"], ["interface"]), (["tds version"], ["tds version"]), (["server program"], ["program"]), (["server version"], ["server version"])])
for tag in (0xaa, 0xab):
    msg = struct.pack("<IBBH", 50001, 1, 16 if tag == 0xaa else 0, 4) + "test".encode("utf-16-le") + b"\x01s\x00\x01p\x00" + struct.pack("<I", 42)
    body = bytes([tag]) + struct.pack("<H", len(msg)) + msg
    add("token", body, tokens.TOKENS.decode(body)[0].node,
        [([name], [name]) for name in ("number", "state", "severity", "server", "procedure", "line")])

metadata = bytes.fromhex("8101000000000001002604016100")
row = bytes.fromhex("d1042a000000")
r = Reader(metadata + row, record=True)
columns = tokens.TOKENS.read_one(r)
add("token", metadata, columns.node,
    [(["count"], ["column count"]),
     (["columns", "column 1", "user type"], ["column 1", "user type"]),
     (["columns", "column 1", "flags"], ["column 1", "flags"]),
     (["columns", "column 1", "type", "type"], ["column 1", "type information", "type code"]),
     (["columns", "column 1", "type", "size"], ["column 1", "type information", "maximum length"]),
     (["columns", "column 1", "name"], ["column 1", "name"])])
add("row", row, tokens.TOKENS.read_one(r).node, [(["values", "a"], ["cell 1"])], metadata=metadata.hex())

path = ROOT / "clients/rust/tests/fixtures/inspection/python.json"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(cases, indent=2) + "\n")
print(f"Wrote {len(cases)} artificial Python inspection cases to {path.relative_to(ROOT)}")
