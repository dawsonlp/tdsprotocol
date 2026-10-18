"""Saved TVPs retain declarations and exact row values without executing SQL."""
import base64
import io
import json
from pathlib import Path

import pytest
import tds
from tds import types
from tds.capture import replay
from tds.packet import PacketType, split
from tds.requests import Context, RPC
from tds.wire import MalformedMessage


@pytest.mark.parametrize("case", json.loads((Path(__file__).parent / "fixtures/tvp_replay.json").read_text()))
def test_python_generated_tvp_request_corpus_decodes_metadata_and_values(case):
    body = bytes.fromhex(case["body"])
    decoded = RPC.decode(body, True)
    parameter = decoded.calls[0].parameters[0]
    value = parameter.value
    assert isinstance(value, types.TableInput)
    assert value.table.schema == "dbo" and value.table.name == "lines"
    assert (None if value.rows is None else len(value.rows)) == case["count"]
    assert bool(parameter.status & 2) == case["default"]
    if value.rows:
        assert value.rows == ((7, "é🦀\ud800"), (9, None))
    if value.rows is not None:
        assert isinstance(value.table.columns[0], types.DefaultColumn) == case["defaulted"]
        if case["hints"]:
            assert value.table.order == ((2, types.Order.ASCENDING),)
            assert value.table.unique == (2,)
            assert value.table.send_order == (3, 2, 1)
    at = body.index(b"\xf3")
    for end in range(at + 1, len(body)):
        with pytest.raises(MalformedMessage):
            RPC.decode(body[:end], True)


@pytest.mark.parametrize("size", [9, 31, 4096])
def test_capture_replays_tables_following_parameters_and_batched_calls(size):
    table = types.table("dbo.lines", types.default(types.int), types.int, types.nvarchar(types.MAX),
                        send_order=(3, 1, 2))
    request = tds.Calls(tds.Call("p", tds.Param("@rows", table, [(42, "é🦀")]), tds.Param("@after", types.int, 7)),
                        tds.Call("next", tds.Param("@rows", table, [])))
    body = request.encode(Context(0, 1, bytes.fromhex("0904d00034")), record=False).body
    decoded = RPC.decode(body, True)
    assert decoded.calls[0].parameters[1].value == 7
    assert decoded.calls[1].parameters[0].value.rows == ()
    lines = [dict(t=0, packet="send", channel=42, bytes=base64.b64encode(p).decode())
             for p in split(PacketType.RPC, body, size, record=False)[0]]
    lines.append(dict(t=1, event="send", text="→ RPC · channel 42"))
    events = []
    replay(io.StringIO("\n".join(map(json.dumps, lines))), events.append)

    def walk(node):
        yield node
        for child in node.children:
            yield from walk(child)

    nodes = list(walk(events[-1].node))
    assert all("can't be decoded" not in node.shown for node in nodes)
    assert any("é🦀" in node.shown for node in nodes)
    assert any(node.name == "row 1 column 2" and "42" in node.shown for node in nodes)


def test_invalid_tvp_metadata_rows_and_placement_are_refused_with_offsets():
    case = json.loads((Path(__file__).parent / "fixtures/tvp_replay.json").read_text())[-1]
    body = bytes.fromhex(case["body"])
    # The last byte terminates rows; an unknown row tag cannot be mistaken for a
    # following parameter or RPC separator.
    with pytest.raises(MalformedMessage):
        RPC.decode(body[:-1] + b"\x7f", True)
    marker = b"\x11\x03\x00\x03\x00\x02\x00\x01\x00"
    assert marker in body
    with pytest.raises(MalformedMessage):
        RPC.decode(body.replace(marker, marker[:-2] + b"\x02\x00"), True)
