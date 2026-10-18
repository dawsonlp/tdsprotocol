"""Tests of requests (M3) against the core alone.

Calls are encoded exactly as MS-TDS defines them. Values are refused before anything is sent. A result set sent without
metadata is read with the columns that the call supplied.
"""

import pytest

import tds
from tds import types
from tds.connection.core import ConnectionCore, Options, Send
from tds.requests import Context
from tds.response import ResponseReader
from tds.types import ValueRefused

CONTEXT = Context(transaction=0, outstanding_requests=1, collation=bytes.fromhex("09 04 D0 00 34"))
HEADERS = "16 00 00 00 12 00 00 00 02 00 00 00 00 00 00 00 00 00 01 00 00 00"


@pytest.mark.parametrize("sql_type,sample", [
    (types.json, '{"note":"é🦀"}'), (types.clr("sys.hierarchyid"), b"\x58"),
    (types.ntext, "é🦀"), (types.text, "café"), (types.image, b"\x00\xff"),
])
@pytest.mark.parametrize("which", ["null", "empty", "sample"])
def test_input_only_layouts_are_recorded_and_replayed_independently_of_result_encoding(sql_type, sample, which):
    from tds.requests import RPC
    value = None if which == "null" else sample[:0] if which == "empty" else sample
    encoded = tds.Call("#input", tds.Param("@p", sql_type, value)).encode(CONTEXT, record=True)
    for utf8 in [False, True]:
        call = RPC.decode(encoded.body, True, {"utf8_support": utf8}).calls[0]
        assert call.parameters[0].value == value
        if isinstance(sql_type, types.LegacyText):
            from dataclasses import replace
            expected = replace(sql_type, collation=types.Collation(CONTEXT.collation))
        else:
            expected = sql_type
        assert call.parameters[0].type == expected
        if isinstance(sql_type, types.Clr):
            assert call.parameters[0].type.max_size is None
            assert call.parameters[0].type.assembly == ""


def body(request) -> str:
    return request.encode(CONTEXT, record=False).body.hex(" ").upper()


def test_a_call_by_name_with_an_output_parameter():
    call = tds.Call("#bump", tds.Param("@a", types.int, 41, output=True))
    assert body(call) == HEADERS + (
        " 05 00 23 00 62 00 75 00 6D 00 70 00"  # the name: 5 code units, "#bump"
        " 00 00"  # options: none
        " 02 40 00 61 00"  # parameter name "@a"
        " 01"  # by reference: an output parameter
        " 26 04"  # int, 4 bytes
        " 04 29 00 00 00")  # 41


def test_a_builtin_a_default_and_two_calls_in_one_request():
    calls = tds.Calls(tds.Call("#a"), tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@d", types.int, tds.DEFAULT)))
    assert body(calls) == HEADERS + (
        " 02 00 23 00 61 00 00 00"  # "#a", no options, no parameters
        " FF"  # the BATCH separator
        " FF FF 0A 00 00 00"  # built-in procedure 10 (sp_executesql), no options
        " 02 40 00 64 00 02 26 04 00")  # "@d", default value, int, NULL


def test_text_parameters_carry_the_sessions_collation_unless_given_one():
    call = tds.Call("#t", tds.Param("@v", types.varchar(3), "a€"))
    assert body(call).endswith("02 40 00 76 00 00 A7 03 00 09 04 D0 00 34 02 00 61 80")  # € is 0x80 in cp1252


def test_options_are_sent_as_tds_defines_them():
    call = tds.Call("#p", options=tds.CallOptions.RECOMPILE | tds.CallOptions.REUSE_METADATA)
    assert body(call) == HEADERS + " 02 00 23 00 70 00 05 00"


def test_a_no_metadata_call_must_supply_its_columns():
    with pytest.raises(ValueError, match="supply the columns"):
        tds.Call("#p", options=tds.CallOptions.NO_METADATA)


def test_a_value_that_doesnt_fit_is_refused_before_anything_is_sent():
    core = ConnectionCore(Options("localhost", 1433, "sa", "unused"))
    channel, _ = core.open_channel("alice")
    exchange = core.exchange(channel, "alice", tds.Call("#p", tds.Param("@a", types.tinyint, 256)))
    with pytest.raises(ValueRefused, match="outside tinyint"):
        next(exchange)
    assert not core.link.channels[channel].busy  # nothing was sent, so the channel is free
    first = next(core.exchange(channel, "alice", tds.Batch("SELECT 1")))
    assert isinstance(first, Send)


def test_a_result_set_without_metadata_is_read_with_the_columns_the_call_supplied():
    earlier = ResponseReader(record=False, announce=lambda change: None)
    earlier.feed(bytes.fromhex("81 01 00 00 00 00 00 00 00 26 04 01 61 00  D1 04 07 00 00 00"
                               "  FD 10 00 C1 00 01 00 00 00 00 00 00 00"), last=True)
    columns = earlier.result_sets[0].columns
    call = tds.Call("#p", options=tds.CallOptions.NO_METADATA, columns=[columns])
    reader = ResponseReader(record=False, announce=lambda change: None, metadata=call.metadata)
    reader.keep_new = True
    reader.feed(bytes.fromhex("81 FF FF  D1 04 2A 00 00 00  FD 10 00 C1 00 01 00 00 00 00 00 00 00"), last=True)
    [rs] = reader.result_sets
    assert rs.columns == columns and rs.rows == ((42,),)


@pytest.mark.parametrize("utf8", [False, True])
def test_saved_json_columns_follow_the_current_sessions_encoding(utf8):
    from tds.response import Column
    from tds.tokens import ColumnFlags
    columns = (Column("j", types.Json(utf8=not utf8), True, ColumnFlags.NULLABLE, 0),)
    reader = ResponseReader(False, lambda change: None, metadata=[columns], negotiated={"utf8_support": utf8})
    reader.keep_new = True
    text = '{"note":"é🦀"}'
    raw = text.encode("utf-8" if utf8 else "utf-16-le")
    body = b"\x81\xff\xff\xd1" + len(raw).to_bytes(8, "little") + len(raw).to_bytes(4, "little") + raw + bytes(4) + b"\xfd" + bytes(12)
    for i, byte in enumerate(body):
        reader.feed(bytes([byte]), last=i == len(body) - 1)
        if reader.paused:
            reader.resume()
    assert reader.result_sets[0].rows == ((text,),)
    assert reader.result_sets[0].columns[0].type.utf8 == utf8
    assert columns[0].type.utf8 != utf8


@pytest.mark.parametrize("transaction,count", [(0, 1), (17, 2)])
@pytest.mark.parametrize("query", [tds.Batch("SELECT 1"), tds.Call("#header_test")])
def test_autocommit_header_is_one_and_explicit_transactions_count_active_requests(transaction, count, query):
    encoded = query.encode(Context(transaction, 2, CONTEXT.collation), record=False).body
    assert encoded[:10] == bytes.fromhex("16 00 00 00 12 00 00 00 02 00")
    assert encoded[10:18] == transaction.to_bytes(8, "little")
    assert encoded[18:22] == count.to_bytes(4, "little")
