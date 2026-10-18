"""Actual Python TVP request bodies; synthetic types/rows, no server required."""
import json
from pathlib import Path
import tds
from tds import types
from tds.requests import Context

collation = types.Collation(bytes.fromhex("09 04 D0 00 34"))
context = Context(17, 2, collation.raw)
cases = []
for defaulted, hints in [(False, False), (True, False), (True, True)]:
    columns = ([types.default(types.int)] if defaulted else []) + [types.int, types.Character(types.MAX, True, True, collation)]
    options = dict(order=((2, types.Order.ASCENDING),), unique=(2,), send_order=(3, 2, 1)) if hints else {}
    table = types.table("dbo.lines", *columns, **options)
    for rows, default in [(None, False), (None, True), ([], False), ([(7, "é🦀\ud800"), (9, None)], False)]:
        param = tds.Param("@t", table, tds.DEFAULT if default else rows)
        request = tds.Call("#p", param).encode(context, record=False).body
        cases.append(dict(defaulted=defaulted, hints=hints, count=None if rows is None else len(rows), default=default, body=request.hex()))
Path(__file__).with_name("python.json").write_text(json.dumps(cases, indent=2) + "\n")
print(f"{len(cases)} Python TVP cases")
