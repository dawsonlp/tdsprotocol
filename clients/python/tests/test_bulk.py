"""Bulk load (M9), checked against the core alone.

The bulk data is laid out as the server describes the columns, with fixed-size codes for NOT NULL columns and large
values in chunks of unknown length. Rows from a source are framed as rows. The serial channel keeps BulkInsert and
BulkRows together (D-50).
"""

import pytest

import tds
from tds import types
from tds.connection.core import ConnectionCore, Options, OutOfTurn, Receive
from tds.packet import Packet, PacketType, Status
from tds.requests import BULK_DONE, Context
from tds.response import Column
from tds.tokens import ColumnFlags
from tds.types import TypeCode, ValueRefused
from test_serial_channels import ALICE, sent

LATIN1 = bytes.fromhex("09 04 D0 00 34")
CONTEXT = Context(transaction=0, outstanding_requests=1, collation=LATIN1)
ID = Column("id", types.Integer(4, code=TypeCode.INT), False, ColumnFlags(0), 0)  # NOT NULL: the fixed-size code
PHOTO = Column("photo", types.varbinary(types.MAX), True, ColumnFlags.NULLABLE, 0)
NOTE = Column("note", types.varchar(10, collation=types.Collation(LATIN1)), True, ColumnFlags.NULLABLE, 0)


def body(columns, rows) -> str:
    return tds.BulkRows(columns, rows).encode(CONTEXT, record=False).body.hex(" ").upper()


def test_the_bulk_data_is_laid_out_as_the_server_describes_the_columns():
    assert body([ID, PHOTO, NOTE], [(1, b"xy", "é"), (2, None, None)]) == " ".join((
        "81 03 00",  # COLMETADATA, 3 columns, with no headers before it
        "00 00 00 00 00 00 38 02 69 00 64 00",  # id: no flags (NOT NULL) · 38, int's fixed-size code · "id"
        "00 00 00 00 01 00 A5 FF FF 05 70 00 68 00 6F 00 74 00 6F 00",  # photo: nullable · varbinary(max)
        "00 00 00 00 01 00 A7 0A 00 09 04 D0 00 34 04 6E 00 6F 00 74 00 65 00",  # note: varchar(10), its collation
        "D1 01 00 00 00",  # a row: 1, without a length (fixed size)
        "FE FF FF FF FF FF FF FF 02 00 00 00 78 79 00 00 00 00",  # length unknown, one chunk, then the end chunk
        "01 00 E9",  # "é" in cp1252, with a u16 length
        "D1 02 00 00 00 FF FF FF FF FF FF FF FF FF FF",  # NULL photo (PLP NULL) and NULL note
        "FD 00 00 00 00 00 00 00 00 00 00 00 00",  # DONE: the end of the rows
    )).replace("  ", " ")


def test_what_cant_be_encoded_is_refused_before_sending():
    with pytest.raises(ValueRefused, match="NOT NULL"):
        body([ID], [(None,)])  # a fixed-size code has no NULL
    with pytest.raises(ValueRefused, match="tuple of 1"):
        body([ID], [(1, 2)])
    with pytest.raises(ValueRefused, match="outside int"):
        body([ID], [(1 << 40,)])  # values are checked as parameters are (D-48)


def test_rows_from_a_source_are_framed_as_rows_and_end_with_done():
    async def rows():
        yield (1,)

    encoded = tds.BulkRows([ID], rows()).encode(CONTEXT, record=False)
    [stream] = encoded.streams
    assert stream.unit == "rows" and stream.end == BULK_DONE and stream.offset == len(encoded.body)
    assert stream.encode((7,)) == bytes.fromhex("D1 07 00 00 00")


def finish(core, channel, done: str) -> None:
    """Read a one-packet response to its end."""
    reading = core.read(channel, ALICE)
    assert next(reading) == Receive(channel)
    with pytest.raises(StopIteration):
        reading.send(Packet(PacketType.SERVER_MESSAGE, Status.LAST, bytes.fromhex(done), None))


OK = "FD 00 00 C1 00 00 00 00 00 00 00 00 00"
FAILED = "FD 02 00 C1 00 00 00 00 00 00 00 00 00"  # marked error


def test_the_channel_keeps_bulk_insert_and_bulk_rows_together():
    core = ConnectionCore(Options("localhost", 1433, "sa", "unused"))
    channel, _ = core.open_channel(ALICE)
    with pytest.raises(OutOfTurn, match="none is open"):
        next(core.exchange(channel, ALICE, tds.BulkRows([ID], [])))  # no BulkInsert before it

    sent(core.exchange(channel, ALICE, tds.BulkInsert("INSERT BULK t (id int NOT NULL)")))
    finish(core, channel, FAILED)
    with pytest.raises(OutOfTurn):  # a failed statement opens nothing
        next(core.exchange(channel, ALICE, tds.BulkRows([ID], [])))

    sent(core.exchange(channel, ALICE, tds.BulkInsert("INSERT BULK t (id int NOT NULL)")))
    finish(core, channel, OK)
    with pytest.raises(OutOfTurn, match="bulk load is open"):
        next(core.exchange(channel, ALICE, tds.Batch("SELECT 1")))  # only BulkRows may come next
    assert sent(core.exchange(channel, ALICE, tds.BulkRows([ID], [(1,)])))  # sent
    finish(core, channel, "FD 10 00 00 00 01 00 00 00 00 00 00 00")
    with pytest.raises(OutOfTurn):
        next(core.exchange(channel, ALICE, tds.BulkRows([ID], [])))  # one BulkRows per BulkInsert


def test_pending_bulk_is_not_released_or_recovered_and_close_drains_attention():
    core = ConnectionCore(Options("localhost", 1433, "sa", "unused"))
    channel, _ = core.open_channel(ALICE)
    sent(core.exchange(channel, ALICE, tds.BulkInsert("INSERT BULK t(id int NOT NULL)")))
    finish(core, channel, OK)
    assert not core.release()[0]
    assert "bulk" in core.recovery_refusal()
    with pytest.raises(RuntimeError, match="bulk continuation"):
        core.close_channel(channel)
    assert core.begin_channel_close(channel)
    assert core.link.channels[channel].reader.cancelling
    drain = core.drain_channel(channel)
    assert next(drain) == Receive(channel)
    # A normal final DONE cannot release the prepared operation while its
    # Attention acknowledgement is still outstanding.
    assert drain.send(Packet(PacketType.SERVER_MESSAGE, Status.LAST, bytes.fromhex(OK), None)) == Receive(channel)
    assert core.link.channels[channel].busy
    with pytest.raises(StopIteration):
        drain.send(Packet(PacketType.SERVER_MESSAGE, Status.LAST, b"\xfd\x22\x00" + bytes(10), None))
    assert not core.link.channels[channel].busy
    core.close_channel(channel)
