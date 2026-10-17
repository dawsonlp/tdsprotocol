"""Tests of table-valued parameters (M8) against the core alone.

A table is sent as MS-TDS defines it. Columns that the server fills are described but get no values. The tests also
cover the optional ordering tokens and rows from a source (D-49).
"""

import pytest

import tds
from tds import types
from tds.requests import Context
from tds.types import Order, ValueRefused

CONTEXT = Context(transaction=0, outstanding_requests=1, collation=bytes.fromhex("09 04 D0 00 34"))
HEADERS = "16 00 00 00 12 00 00 00 02 00 00 00 00 00 00 00 00 00 01 00 00 00"
CALL = " 02 00 23 00 70 00 00 00"  # "#p", no options
PARAM = " 02 40 00 74 00"  # "@t"
TYPE_NAME = " F3 00 04 73 00 68 00 6F 00 70 00 02 70 00 63 00"  # table: no database, "shop", "pc"


def body(*params) -> str:
    return tds.Call("#p", *params).encode(CONTEXT, record=False).body.hex(" ").upper()


def test_a_table_its_columns_and_its_rows():
    pc = types.table("shop.pc", types.int, types.default(types.int))
    assert body(tds.Param("@t", pc, [(5,), (None,)])) == HEADERS + CALL + PARAM + " 00" + TYPE_NAME + (
        " 02 00"  # two columns
        " 00 00 00 00 01 00 26 04 00"  # user type 0 · nullable · int · no name
        " 00 00 00 00 01 02 26 04 00"  # the same, plus the default flag 0x200 (the server fills it)
        " 00"  # the end of the metadata
        " 01 04 05 00 00 00"  # a row: only the first column's value, 5
        " 01 00"  # a row: NULL
        " 00")  # the end of the rows


def test_the_ordering_tokens_and_the_order_values_are_sent_in():
    pc = types.table("shop.pc", types.int, types.int, order=[(2, Order.DESCENDING)], unique=[1, 2], send_order=[2, 1])
    assert body(tds.Param("@t", pc, [(5, 6)])) == HEADERS + CALL + PARAM + " 00" + TYPE_NAME + (
        " 02 00 00 00 00 00 01 00 26 04 00 00 00 00 00 01 00 26 04 00"
        " 10 02 00  02 00 06  01 00 04"  # TVP_ORDER_UNIQUE: column 2 descending and unique, column 1 unique
        " 11 02 00  02 00 01 00"  # TVP_COLUMN_ORDERING: column 2's values first
        " 00"
        " 01 04 06 00 00 00 04 05 00 00 00"  # the row (5, 6), sent as 6, then 5
        " 00").replace("  ", " ")


def test_default_sends_no_table_with_the_default_bit():
    pc = types.table("shop.pc", types.int)
    assert body(tds.Param("@t", pc, tds.DEFAULT)).endswith(PARAM + " 02" + TYPE_NAME + " FF FF 00 00")


def test_rows_from_a_source_are_framed_as_rows():
    async def rows():
        yield (1,)

    encoded = tds.Call("#p", tds.Param("@t", types.table("shop.pc", types.int), rows())).encode(CONTEXT, record=False)
    [stream] = encoded.streams
    assert encoded.body[stream.offset - 1 : stream.offset] == b"\x00"  # rows go after the metadata's end
    assert stream.unit == "rows" and stream.end == b"\x00"
    assert stream.encode((7,)) == bytes.fromhex("01 04 07 00 00 00")
    with pytest.raises(ValueRefused, match="tuple of 1 values"):
        stream.encode((7, 8))


def test_what_a_table_refuses():
    pc = types.table("shop.pc", types.int, types.nvarchar(2))
    assert body(tds.Param("@t", pc, None)).endswith("00" + TYPE_NAME + " FF FF 00 00")  # sent. The server refuses it.
    with pytest.raises(ValueRefused, match="tuple of 2 values"):
        body(tds.Param("@t", pc, [(1,)]))
    with pytest.raises(ValueRefused, match="don't fit"):
        body(tds.Param("@t", pc, [(1, "abc")]))  # each value is checked against its column (D-48)

    async def chunks():
        yield "x"

    with pytest.raises(ValueRefused, match="sent whole"):
        body(tds.Param("@t", pc, [(1, chunks())]))


def test_a_table_type_is_checked_only_where_the_encoding_needs_it():
    with pytest.raises(ValueError, match="database is never sent"):
        types.table("db.shop.pc", types.int)  # there is no field for it
    with pytest.raises(ValueError, match="every column"):
        types.table("pc", types.int, types.int, send_order=[1])  # the row's values couldn't be placed
    with pytest.raises(ValueError, match="ASCENDING or"):
        types.table("pc", types.int, order=[(1, Order.UNIQUE)])  # the API's spelling of the sort flag
    types.table("pc", types.default(types.int), types.int, unique=[1])  # sent, and the server decides if it is valid
    types.table("pc", types.table("inner", types.int))
    assert str(types.table("shop.pc", types.int)) == "shop.pc"
