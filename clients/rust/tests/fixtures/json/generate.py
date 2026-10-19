"""Synthetic native JSON result/parameter bytes from Python's actual codecs."""
import json
from pathlib import Path
from tds import types
from tds.wire import Writer

cases = []
for utf8 in [False, True]:
    for text in [None, "", "{}", '{"note":"é🦀"}', '"\ud800"', '"\udc80"']:
        raw = None if text is None else text.encode("utf-8" if utf8 else "utf-16-le", "surrogatepass")
        payload = (2**64-1).to_bytes(8, "little") if raw is None else len(raw).to_bytes(8, "little") + len(raw).to_bytes(4, "little") + raw + (bytes(4) if raw else b"")
        assert types.Json(utf8=utf8).assemble(raw) == text
        try:
            w = Writer(record=False)
            types.json.write_info(w)
            types.json.write_value(w, text)
            parameter = bytes(w.buf).hex()
        except types.ValueRefused:
            parameter = None
        utf16 = None if text is None else text.encode("utf-16-le", "surrogatepass")
        units = None if utf16 is None else [int.from_bytes(utf16[i:i+2], "little") for i in range(0, len(utf16), 2)]
        cases.append(dict(utf8=utf8, payload=payload.hex(), units=units, parameter=parameter))
Path(__file__).with_name("python.json").write_text(json.dumps(cases, indent=2) + "\n")
print(f"{len(cases)} native JSON cases")
