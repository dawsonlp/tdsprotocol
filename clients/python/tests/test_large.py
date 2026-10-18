"""Tests of large values (M4) against the core alone.

They cover PLP and text-pointer values read in any split, rows with large values read whole or value by value without
splitting a character (D-47), requests sent from sources, and a request that is undone when it fails partway (D-41).
"""

import asyncio

import pytest

import tds
from tds import types
from tds.connection.core import ConnectionCore, Options, Produce, Receive, Send
from tds.packet import HEADER_SIZE, Packet, PacketType, PacketWriter, Status
from tds.requests import Context
from tds.response import Response, ResponseReader
from tds.types import Collation, PlpValue, TextPointerValue, ValueRefused
from test_response import Feed

LATIN1 = bytes.fromhex("09 04 D0 00 34")
CONTEXT = Context(transaction=0, outstanding_requests=1, collation=LATIN1)


def plp(data: bytes | None, chunk: int = 1000, known: bool = True) -> bytes:
    if data is None:
        return b"\xff" * 8
    out = bytearray(len(data).to_bytes(8, "little") if known else b"\xfe" + b"\xff" * 7)
    for i in range(0, len(data), chunk):
        piece = data[i : i + chunk]
        out += len(piece).to_bytes(4, "little") + piece
    return bytes(out + bytes(4))


def read_in(reader, data: bytes, size: int):
    pieces, at, view = [], 0, memoryview(b"")
    held = b""
    for i in range(0, len(data) + size, size):
        held += data[i : i + size]
        view = memoryview(held)
        at, found = reader.read(view, at)
        pieces += found
        if reader.done:
            break
    return pieces


@pytest.mark.parametrize("size", [1, 3, 7, 4096])
def test_a_plp_value_reads_the_same_however_it_arrives(size):
    value = bytes(range(256)) * 20
    for encoded, expected in ((plp(value), value), (plp(value, known=False), value), (plp(b""), b""), (plp(None), None)):
        reader = PlpValue()
        pieces = read_in(reader, encoded + b"rest", size)
        assert reader.done and (None if reader.null else b"".join(pieces)) == expected


@pytest.mark.parametrize("size", [1, 5, 4096])
def test_a_text_pointer_value_reads_the_same_however_it_arrives(size):
    value = b"legacy text" * 100
    encoded = b"\x10" + bytes(16) + bytes(8) + len(value).to_bytes(4, "little") + value
    reader = TextPointerValue()
    assert b"".join(read_in(reader, encoded, size)) == value and reader.done
    null = TextPointerValue()
    read_in(null, b"\x00", size)
    assert null.done and null.null


def large_response(text: str) -> bytes:
    """A result with an nvarchar(max) column `n`, then an int `i`, and one row."""
    columns = (b"\x81\x02\x00"
               + bytes(4) + b"\x01\x00" + b"\xe7\xff\xff" + LATIN1 + b"\x01n\x00"
               + bytes(4) + b"\x00\x00" + b"\x38" + b"\x01i\x00")
    row = b"\xd1" + plp(text.encode("utf-16-le", "surrogatepass"), chunk=7) + (42).to_bytes(4, "little")
    return columns + row + bytes.fromhex("FD 10 00 C1 00 01 00 00 00 00 00 00 00")


TEXT = "😀é日" * 300 + "\ud800"  # a surrogate pair, accents, an unpaired surrogate


def run(coroutine):
    return asyncio.run(coroutine)


def live(body: bytes, size: int) -> Response:
    source = Feed(body, size)
    source.reader = ResponseReader(record=True, announce=lambda change: None)
    return Response(source.reader, source)


@pytest.mark.parametrize("size", [1, 3, 64])
def test_a_large_value_reads_whole_in_a_tuple(size):
    async def go():
        response = live(large_response(TEXT), size)
        return [[row async for row in rs] async for rs in response]

    assert run(go()) == [[(TEXT, 42)]]


@pytest.mark.parametrize("size", [1, 3, 64])
def test_a_large_value_streams_without_splitting_a_character(size):
    async def go():
        response = live(large_response(TEXT), size)
        values = []
        async for rs in response:
            async for row in rs.streamed():
                async for value in row:
                    values.append([piece async for piece in value] if isinstance(value, tds.ValueStream) else value)
        return values

    pieces, number = run(go())
    assert "".join(pieces) == TEXT and number == 42
    assert len(pieces) > 1 or size == 64
    assert all(not ("\ud800" <= p[-1] <= "\udbff") for p in pieces[:-1])  # no piece ends inside a surrogate pair


def test_moving_on_discards_the_rest_of_a_large_value():
    async def go():
        response = live(large_response(TEXT), 5)
        async for rs in response:
            async for row in rs.streamed():
                async for value in row:
                    if isinstance(value, tds.ValueStream):
                        async for piece in value:
                            break  # read one piece, then go to the next value
                    else:
                        return value

    assert run(go()) == 42


def test_a_large_result_set_waits_until_the_application_chooses_how_to_read_it():
    reader = ResponseReader(record=False, announce=lambda change: None)
    reader.feed(large_response("x" * 10), last=True)
    assert reader.paused and not reader.result_sets[0].rows_read  # nothing assembled yet


def test_varchar_text_in_a_double_byte_code_page_is_never_split_at_a_lead_byte():
    japanese = Collation(bytes.fromhex("11 04 D0 30 00"))
    data = japanese.encode("日本語のテキスト" * 50)
    decoder = japanese.decoder()
    pieces = [decoder.decode(data[i : i + 3]) for i in range(0, len(data), 3)] + [decoder.decode(b"", final=True)]
    assert "".join(pieces) == "日本語のテキスト" * 50 and all("\udc80" > c or c > "\udcff" for p in pieces for c in p)


# --------------------------------------------------------------------------- sending large values


def test_a_whole_large_value_is_sent_as_plp_with_its_length():
    call = tds.Call("#p", tds.Param("@v", types.varbinary(types.MAX), b"\x01\x02\x03"))
    body = call.encode(CONTEXT, record=False).body
    assert body.endswith(b"\xa5\xff\xff" + plp(b"\x01\x02\x03"))


def test_a_source_is_registered_where_its_chunks_go():
    async def chunks():
        yield b"x"

    call = tds.Call("#p", tds.Param("@v", types.varbinary(types.MAX), chunks()), tds.Param("@n", types.int, 1))
    encoded = call.encode(CONTEXT, record=False)
    [stream] = encoded.streams
    assert encoded.body[stream.offset - 8 : stream.offset] == b"\xfe" + b"\xff" * 7  # length unknown
    assert encoded.body[stream.offset :].startswith(b"\x02@\x00n\x00")  # the next parameter follows the chunks


def test_legacy_text_and_xml_parameters():
    body = tds.Call("#p", tds.Param("@t", types.ntext, "hé")).encode(CONTEXT, record=False).body
    assert body.endswith(b"\x63\xff\xff\xff\x7f" + LATIN1 + b"\x04\x00\x00\x00h\x00\xe9\x00")
    body = tds.Call("#p", tds.Param("@x", types.xml, "<a/>")).encode(CONTEXT, record=False).body
    assert body.endswith(b"\xf1\x00" + plp("<a/>".encode("utf-16-le")))
    with pytest.raises(ValueRefused, match="can't come from a source"):
        async def chunks():
            yield "x"
        types.ntext.check(chunks(), Collation(LATIN1))


def test_a_packet_writer_cuts_as_bytes_arrive_and_can_abandon():
    writer = PacketWriter(PacketType.RPC, 4096, record=False)
    assert writer.add(b"x" * 4088) == []  # a whole packet of bytes is kept, because the last packet must carry LAST
    [full] = writer.add(b"y")
    assert full[1] == 0 and len(full) == 4096 and writer.started
    abandoned = writer.abandon()
    assert abandoned[1] == Status.IGNORE | Status.LAST and len(abandoned) == HEADER_SIZE


def ready() -> tuple[ConnectionCore, int]:
    core = ConnectionCore(Options("localhost", 1433, "sa", "unused"))
    channel, _ = core.open_channel("alice")
    return core, channel


def test_a_source_that_fails_before_anything_is_sent_leaves_nothing_to_undo():
    async def chunks():
        yield b""

    core, channel = ready()
    call = tds.Call("#p", tds.Param("@v", types.varbinary(types.MAX), chunks()))
    exchange = core.exchange(channel, "alice", call)
    assert isinstance(next(exchange), Produce)
    with pytest.raises(OSError):
        exchange.throw(OSError("disk failed"))
    assert not core.link.channels[channel].busy


def test_a_source_that_fails_partway_is_abandoned_with_ignore_and_the_answer_is_read():
    async def chunks():
        yield b""

    core, channel = ready()
    call = tds.Call("#p", tds.Param("@v", types.varbinary(types.MAX), chunks()))
    exchange = core.exchange(channel, "alice", call)
    assert isinstance(next(exchange), Produce)
    action = exchange.send(b"x" * 10_000)  # more than a packet, so part of the request is already sent
    assert isinstance(action, Send)
    while isinstance(action, Send):
        action = exchange.send(None)
    assert isinstance(action, Produce)
    action = exchange.throw(OSError("disk failed"))
    assert isinstance(action, Send) and action.data[1] == Status.IGNORE | Status.LAST  # ignore + last
    assert isinstance(exchange.send(None), Receive)
    answer = Packet(PacketType.SERVER_MESSAGE, Status.LAST, bytes.fromhex("FD 02 00 00 00 00 00 00 00 00 00 00 00"), None)
    with pytest.raises(OSError, match="disk failed"):
        exchange.send(answer)  # a DONE marked error, as MS-TDS says. SQL Server sends a message first (live tests).
    assert not core.link.channels[channel].busy

@pytest.mark.parametrize("size", [1, 3, 64])
@pytest.mark.parametrize("total,payload", [(0, b"x"), (2, b"x"), (1, b"xy")])
def test_plp_rejects_payload_that_contradicts_known_total(size, total, payload):
    from tds.wire import MalformedMessage

    encoded = (total.to_bytes(8, "little") + len(payload).to_bytes(4, "little")
               + payload + bytes(4))
    with pytest.raises(MalformedMessage, match="PLP"):
        read_in(PlpValue(), encoded, size)
