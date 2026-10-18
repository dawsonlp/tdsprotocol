"""Artificial RPC bodies from Python's actual request definitions; no server.

PYTHONPATH=clients/python clients/python/.venv/bin/python clients/rust/tests/fixtures/rpc/generate.py
"""
import json
from pathlib import Path
from tds import types
from tds.requests import Call, Calls, Param, Builtin, Context, DEFAULT, CallOptions

context = Context(17, 2, bytes.fromhex("0904d00034"))
cases = [
    Call("dbo.p", Param("@x", types.int, 42, output=True),
         Param("@label", types.nvarchar(8), "D🦀"), Param("@fallback", types.int, DEFAULT),
         options=CallOptions.RECOMPILE | CallOptions.REUSE_METADATA),
    Calls(Call(Builtin.SP_EXECUTESQL, Param("@stmt", types.nvarchar(4000), "SELECT @n"),
               Param("@params", types.nvarchar(4000), "@n int"), Param("@n", types.int, None)),
          Call("dbo.next")),
    Call("dbo.saved", options=CallOptions.NO_METADATA, columns=(({},),)),
]
Path(__file__).with_name("python.json").write_text(json.dumps([case.encode(context, False).body.hex() for case in cases], indent=2) + "\n")
print(f"{len(cases)} deterministic RPC bodies")
