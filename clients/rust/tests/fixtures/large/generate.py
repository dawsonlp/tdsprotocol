"""Python codec parity for PLP and legacy whole parameters and result payloads.
Run with PYTHONPATH=clients/python:clients/python/tests and the client venv.
All data are synthetic; no server or credentials are involved.
"""
import json
from pathlib import Path
from tds import types
from tds.wire import Writer
from test_types import LATIN1

cases = []
for t, sample in [(types.nvarchar(types.MAX), "a🦀\ud800"), (types.varchar(types.MAX, collation=LATIN1), "café"),
                  (types.varbinary(types.MAX), b"\x00\xff"), (types.xml, "<x>hi</x>"),
                  (types.ntext, "old🦀\ud800"), (types.text, "café"), (types.image, b"\x00\x01\xff"), (types.clr("sys.hierarchyid"), b"\x58")]:
    for value in [None, sample[:0], sample]:
        w = Writer(record=False); w.context["collation"] = LATIN1; t.write_info(w)
        info = bytes(w.buf)
        w = Writer(record=False); w.context["collation"] = LATIN1; t.write_value(w, value)
        parameter = info + bytes(w.buf)
        legacy = isinstance(t, (types.LegacyText, types.Image))
        if legacy:
            # RPC legacy inputs have a length; rows additionally carry a pointer
            # and timestamp. Result TYPE_INFO includes table provenance.
            result_info = info + b"\x00"
            result = b"\x00" if value is None else b"\x01\x00" + bytes(8) + bytes(w.buf)
        elif isinstance(t, types.Clr):
            assembly = "Synthetic.Assembly".encode("utf-16-le")
            result_info = info[:1] + (892).to_bytes(2, "little") + info[1:] + (len(assembly)//2).to_bytes(2, "little") + assembly
            result = bytes(w.buf)
        else:
            result_info, result = info, bytes(w.buf)
        if isinstance(value, str):
            raw = t.encode(value, LATIN1) if hasattr(t, "encode") else value.encode("utf-16-le", "surrogatepass")
        else:
            raw = value
        cases.append(dict(name=str(t), info=result_info.hex(), payload=result.hex(), parameter=parameter.hex(), raw=None if raw is None else raw.hex()))
Path(__file__).with_name("python.json").write_text(json.dumps(cases, indent=2) + "\n")
print(f"{len(cases)} Python large-value cases")
