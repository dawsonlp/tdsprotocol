"""json and vector (M6), checked against the core alone.

The tests cover the login's feature list, the server's acknowledgement, and both types' description and values, which
are read and written exactly.
"""

import pytest

from tds import login7, types
from tds.tokens import TOKENS
from tds.types import SqlVector, TypeInfo, ValueRefused, VectorElement
from tds.wire import Field, Reader, Struct, Writer


def values() -> dict:
    return {"tds_version": login7.TDS_7_4, "packet_size": 4096, "client_library_version": 0, "client_process_id": 0,
            "connection_id": 0, "option_flags_1": login7.OptionFlags1(0), "option_flags_2": login7.OptionFlags2(0),
            "type_flags": login7.TypeFlags(0), "option_flags_3": login7.OptionFlags3(0), "time_zone": 0, "locale": 0x0409,
            "variable_part": {"host_name": "h", "user_name": "u", "password": "", "app_name": "a", "server_name": "s",
                              "extension": b"", "library_name": "l", "language": "", "database": "", "client_id": bytes(6),
                              "windows_auth": b"", "attach_file": "", "new_password": "", "large_windows_auth_length": 0}}


def test_the_login_points_its_extension_entry_at_the_feature_list():
    features = {login7.Feature.JSON_SUPPORT: b"\x01", login7.Feature.VECTOR_SUPPORT: b"\x02"}
    body, _ = login7.login(values(), features)
    decoded = login7.LOGIN7.decode(body)
    offset = int.from_bytes(decoded.variable_part.extension, "little")
    assert login7.OptionFlags3.FEATURE_LIST_PRESENT in decoded.option_flags_3
    assert body[offset:] == b"\x0d\x01\x00\x00\x00\x01" + b"\x0e\x01\x00\x00\x00\x02" + b"\xff"  # then the list ends
    assert decoded.length == len(body)


def test_a_login_without_features_is_unchanged():
    body, _ = login7.login(values(), {})
    decoded = login7.LOGIN7.decode(body)
    assert decoded.variable_part.extension == b"" and decoded.features == b""


def test_the_servers_acknowledgement_names_what_it_accepted():
    [ack] = TOKENS.decode(bytes.fromhex("AE 0D 01 00 00 00 01 0E 01 00 00 00 01 FF"))
    assert ack.token == "FEATUREEXTACK"
    assert ack.features == {login7.Feature.JSON_SUPPORT: b"\x01", login7.Feature.VECTOR_SUPPORT: b"\x01"}


def round_trip(sql_type, value):
    w = Writer(record=False)
    sql_type.check(value)
    sql_type.write_info(w)
    sql_type.write_value(w, value)
    r = Reader(bytes(w.buf), record=False)
    read_type = r.read(Field("type", TypeInfo()))
    return read_type, read_type.read_value(r)


def test_a_vector_comes_back_exactly_in_both_element_types():
    for element, numbers in ((VectorElement.FLOAT32, (1.0, 2.5, -3.4028234663852886e38)), (VectorElement.FLOAT16, (1.0, 2.5, -65504.0))):
        sql_type = types.vector(3, element)
        value = SqlVector(element, numbers)
        assert round_trip(sql_type, value) == (sql_type, value)
        assert round_trip(sql_type, None) == (sql_type, None)
    assert str(types.vector(3)) == "vector(3)" and str(types.vector(2, VectorElement.FLOAT16)) == "vector(2, float16)"


def test_the_servers_vector_bytes():  # observed: CAST(N'[1,2.5,3]' AS vector(3))
    r = Reader(bytes.fromhex("F5 14 00 00 14 00 A9 01 03 00 00 00 00 00 00 00 80 3F 00 00 20 40 00 00 40 40"), False)
    sql_type = r.read(Field("type", TypeInfo()))
    assert sql_type == types.vector(3) and sql_type.read_value(r) == SqlVector(VectorElement.FLOAT32, (1.0, 2.5, 3.0))


def test_a_vector_value_that_doesnt_fit_is_refused():
    for value in (SqlVector(VectorElement.FLOAT32, (1.0, 2.0)), SqlVector(VectorElement.FLOAT16, (1.0, 2.0, 3.0)),
                  SqlVector(VectorElement.FLOAT32, (0.1, 1.0, 2.0)), (1.0, 2.0, 3.0)):
        with pytest.raises(ValueRefused):
            types.vector(3).check(value)
    with pytest.raises(ValueRefused, match="exact float16"):
        types.vector(1, VectorElement.FLOAT16).check(SqlVector(VectorElement.FLOAT16, (0.1,)))


def test_json_arrives_as_utf16_and_is_sent_as_utf8():
    r = Reader(bytes.fromhex("F4") + bytes.fromhex("FE FF FF FF FF FF FF FF") + (4).to_bytes(4, "little")
               + "{}".encode("utf-16-le") + bytes(4), False)
    sql_type = r.read(Field("type", TypeInfo()))
    assert sql_type == types.json and sql_type.read_value(r) == "{}"
    w = Writer(record=False)
    types.json.write_value(w, '{"é":1}')
    assert bytes(w.buf) == len('{"é":1}'.encode()).to_bytes(8, "little") + len('{"é":1}'.encode()).to_bytes(4, "little") \
        + '{"é":1}'.encode() + bytes(4)

@pytest.mark.parametrize("at", [0, 2, 4, 5])
def test_vector_bounded_layout_count_element_and_reserved_must_match_type(at):
    from tds.wire import MalformedMessage
    value = types.SqlVector(VectorElement.FLOAT32, (1.0, 2.0, 3.0))
    w = Writer(record=False)
    types.vector(3).write_value(w, value)
    data = bytearray(w.buf)
    data[2 + at] ^= 1
    with pytest.raises(MalformedMessage):
        types.vector(3).read_value(Reader(bytes(data), False))


def test_vector_unknown_element_is_a_protocol_error():
    from tds.wire import MalformedMessage
    w = Writer(record=False)
    types.vector(1).write_value(w, SqlVector(VectorElement.FLOAT32, (1.0,)))
    data = bytearray(w.buf)
    data[6] = 255
    with pytest.raises(MalformedMessage):
        types.vector(1).read_value(Reader(bytes(data), False))


def test_vector_short_bounded_payload_is_malformed_instead_of_index_error():
    from tds.wire import MalformedMessage
    with pytest.raises(MalformedMessage, match="width"):
        types.vector(3).read_value(Reader(b"\x01\x00\x00", False))
