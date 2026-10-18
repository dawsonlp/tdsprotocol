"""Deterministic scalar fixtures from Python's actual codec and existing limits.

Run at the repo root:
  PYTHONPATH=clients/python:clients/python/tests clients/python/.venv/bin/python clients/rust/tests/fixtures/scalars/generate.py
No server, credentials or captured application data are involved.
"""
import datetime as dt
import json
import struct
from decimal import Decimal
from pathlib import Path

from tds import types
from tds.wire import Reader, Writer
from test_types import EXACT, LATIN1


def view(t, v):
    if v is None:
        return None
    if isinstance(t, types.Integer):
        return {"integer": str(v)}
    if isinstance(t, types.Bit):
        return {"bit": v}
    if isinstance(t, types.Float):
        return {"real" if t.size == 4 else "float": struct.pack("<f" if t.size == 4 else "<d", v).hex()}
    if isinstance(t, types.Decimal):
        sign, digits, exponent = v.as_tuple()
        return {"decimal": [bool(sign), str(int("".join(map(str, digits)))), -exponent]}
    if isinstance(t, types.Money):
        return {"money": str(types._decimal_digits(v, 4, "fixture"))}
    if isinstance(t, types.Date):
        return {"date": (v - dt.date(1, 1, 1)).days}
    if isinstance(t, types.Time):
        return {"time": v.ticks}
    if isinstance(t, types.DateTime2):
        return {"datetime2": [(v.date - dt.date(1, 1, 1)).days, v.ticks]}
    if isinstance(t, types.DateTimeOffset):
        return {"datetimeoffset": [(v.utc_date - dt.date(1, 1, 1)).days, v.utc_ticks, v.offset_minutes]}
    if isinstance(t, types.DateTime):
        return {"datetime": [v.days, v.ticks]}
    if isinstance(t, types.SmallDateTime):
        return {"smalldatetime": [(v.date() - dt.date(1900, 1, 1)).days, v.hour * 60 + v.minute]}
    if isinstance(t, types.Character):
        if t.unicode:
            raw = v.encode("utf-16-le", "surrogatepass")
            return {"unicode": list(struct.unpack("<" + "H" * (len(raw) // 2), raw))}
        return {"text": [t.encode(v, LATIN1).hex(), (t.collation or LATIN1).raw.hex()]}
    if isinstance(t, types.Binary):
        return {"binary": v.hex()}
    if isinstance(t, types.UniqueIdentifier):
        return {"guid": v.bytes.hex()}
    raise AssertionError(type(t))


cases = []
for t, values in [*EXACT, (types.decimal(38, 38), [Decimal("-0." + "0" * 38)])]:
    for v in [*values, None]:
        w = Writer(record=False)
        w.context["collation"] = LATIN1
        t.write_info(w)
        info = bytes(w.buf)
        w = Writer(record=False)
        w.context["collation"] = LATIN1
        t.write_value(w, v)
        payload = bytes(w.buf)
        read_type = types.TypeInfo().read(Reader(info, record=False))
        r = Reader(payload, record=False)
        got = read_type.read_value(r)
        assert r.pos == r.end
        cases.append(dict(name=str(t), info=info.hex(), value=payload.hex(), expected=view(read_type, got)))

for raw in ["30ff", "34ffff", "38ffffffff", "7fffffffffffffffff", "3201", "3b00000080",
            "3e0000000000000080", "7affffffff", "3cffffffffffffffff", "3d0000000001000000", "3a00000100"]:
    r = Reader(bytes.fromhex(raw), record=False)
    t = types.TypeInfo().read(r)
    info = bytes.fromhex(raw)[:r.pos]
    payload = bytes.fromhex(raw)[r.pos:]
    got = t.read_value(r)
    assert r.pos == r.end
    cases.append(dict(name="fixed " + str(t), info=info.hex(), value=payload.hex(), expected=view(t, got)))

out = Path(__file__).with_name("python.json")
out.write_text(json.dumps(cases, indent=2) + "\n")
print(f"{len(cases)} Python scalar cases")
