"""Replay inspects large rows without needing a live application to claim them."""
import base64
import io
import json

import pytest

from tds.capture import replay
from tds.packet import PacketType, split
from test_large import large_response


@pytest.mark.parametrize("utf8", [False, True])
@pytest.mark.parametrize("classification", [1, 2])
def test_replay_uses_accepted_json_encoding_and_classification_version(utf8, classification):
    def packets(body):
        return [dict(t=0, packet="receive", channel=None, bytes=base64.b64encode(p).decode())
                for p in split(PacketType.SERVER_MESSAGE, body, 17, record=False)[0]]

    features = b"\xae\x0a\x01\x00\x00\x00" + bytes([utf8]) + b"\x09\x02\x00\x00\x00" + bytes([classification, 1]) + b"\xff"
    lines = packets(features + b"\xfd" + bytes(12))
    lines.append(dict(t=1, event="receive", text="← login reply"))
    text = '{"note":"é🦀"}'
    data = text.encode("utf-8" if utf8 else "utf-16-le")
    plp = len(data).to_bytes(8, "little") + len(data).to_bytes(4, "little") + data + bytes(4)
    metadata = b"\x81\x01\x00" + bytes(6) + b"\xf4\x00"
    sensitivity = b"\xa3" + bytes(4) + (bytes(4) if classification == 2 else b"") + b"\x01\x00\x00\x00"
    output = b"\xac\x00\x00\x02" + "@o".encode("utf-16-le") + b"\x01" + bytes(6) + b"\xf4" + plp
    lines += packets(metadata + sensitivity + b"\xd1" + plp + output + b"\xfe" + bytes(12))
    lines.append(dict(t=2, event="receive", text="← response"))
    events = []
    replay(io.StringIO("\n".join(map(json.dumps, lines))), events.append)

    def walk(node):
        yield node
        for child in node.children:
            yield from walk(child)

    nodes = list(walk(events[-1].node))
    assert {"DATACLASSIFICATION", "ROW", "RETURNVALUE", "DONEPROC"} <= {n.name for n in nodes}
    assert any("é🦀" in n.shown for n in nodes)


@pytest.mark.parametrize("packet_size", [13, 4096])
def test_replay_advances_past_large_rows_to_outputs_and_completion(packet_size):
    row = large_response("a🦀" * 3000)[:-13]
    status = b"\x79" + (23).to_bytes(4, "little", signed=True)
    output = (b"\xac\x00\x00\x02" + "@o".encode("utf-16-le") + b"\x01" + bytes(6)
              + b"\x26\x04\x04" + (42).to_bytes(4, "little", signed=True))
    done = b"\xfe" + bytes(12)
    packets, _ = split(PacketType.SERVER_MESSAGE, row + status + output + done, packet_size, record=False)
    lines = [dict(t=0, packet="receive", channel=None, bytes=base64.b64encode(p).decode()) for p in packets]
    lines.append(dict(t=1, event="receive", text="← response"))
    events = []
    replay(io.StringIO("\n".join(map(json.dumps, lines))), events.append)
    response = events[-1].node
    assert response is not None
    names = [node.name for node in response.children]
    assert names.index("ROW") < names.index("RETURNSTATUS") < names.index("RETURNVALUE") < names.index("DONEPROC")
    row = next(node for node in response.children if node.name == "ROW")
    assert "18000 bytes" in row.children[0].shown
