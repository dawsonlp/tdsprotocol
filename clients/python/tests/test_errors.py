"""Literate errors (D-53), checked against the core alone.

A refused value says where it was: the call, parameter, row and column. It also says whether it was refused before
sending, while the request was being encoded, or while a source was producing it.
"""

from decimal import Decimal

import pytest

import tds
from tds import types
from tds.connection.core import ConnectionCore, Options, Produce
from tds.requests import Context
from tds.response import Column
from tds.tokens import ColumnFlags
from tds.types import TypeCode, ValueRefused

CONTEXT = Context(transaction=0, outstanding_requests=1, collation=bytes.fromhex("09 04 D0 00 34"))


def refusal(request) -> str:
    with pytest.raises(ValueRefused) as refused:
        request.encode(CONTEXT, record=False)
    return str(refused.value)


def test_a_parameter_refused_before_sending_names_the_call_and_the_parameter():
    message = refusal(tds.Calls(tds.Call("#ok", tds.Param("@a", types.int, 1)),
                                tds.Call("#p", tds.Param("@a", types.int, 1), tds.Param("@b", types.tinyint, 256))))
    assert message == "the call to #p › parameter @b (tinyint): 256 is outside tinyint's range, 0 to 255"


def test_a_table_value_names_its_row_and_column():
    pc = types.table("shop.pc", types.int, types.decimal(10, 2))
    rows = [(1, Decimal("1.00")), (2, Decimal("1.005"))]
    message = refusal(tds.Call("shop.update_prices", tds.Param("@changes", pc, rows)))
    assert message.startswith("the call to shop.update_prices › parameter @changes (shop.pc) › row 2 › column 2 (decimal(10, 2)): ")


def test_a_bulk_value_names_its_row_and_column():
    columns = [Column("id", types.Integer(4, code=TypeCode.INT), False, ColumnFlags(0), 0),
               Column("note", types.varchar(3, collation=types.Collation(CONTEXT.collation)), True, ColumnFlags.NULLABLE, 0)]
    message = refusal(tds.BulkRows(columns, [(1, "abc"), (2, "abcd")]))
    assert message.startswith("the bulk data › row 2 › column note (varchar(3)): ")


def test_a_piece_refused_while_its_source_produces_names_where_the_source_sits():
    async def rows():
        yield (1, Decimal("1.00"))

    core = ConnectionCore(Options("localhost", 1433, "sa", "unused"))
    channel, _ = core.open_channel("alice")
    pc = types.table("shop.pc", types.int, types.decimal(10, 2))
    exchange = core.exchange(channel, "alice", tds.Call("shop.update_prices", tds.Param("@changes", pc, rows())))
    assert isinstance(next(exchange), Produce)
    exchange.send((1, Decimal("1.00")))  # row 1 fits
    with pytest.raises(ValueRefused) as refused:
        action = exchange.send((2, "not a number"))  # row 2 doesn't
        while True:
            action = exchange.send(None)
    assert str(refused.value).startswith(
        "the call to shop.update_prices › parameter @changes (shop.pc) › row 2 › column 2 (decimal(10, 2)): ")
