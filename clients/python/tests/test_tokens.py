"""Tests of every token that TDS 7.4 defines (M11) against the core alone, with bytes built from MS-TDS.

What each token says is in the response record, and no token ends the connection as an unknown tag. Browse mode and
server cursors are also tested live (test_tokens_live.py). Data classification and session state need login features
(M14). SQL Server no longer sends the COMPUTE tokens. SSPI and FEDAUTHINFO belong to other logins (M17).
"""

import pytest

from tds.response import ResponseReader, SessionState
from tds.tokens import TOKENS, Aggregate, FedAuthInfoId, _fed_auth_info
from tds.wire import MalformedMessage

COLUMNS = bytes.fromhex("81 01 00 00 00 00 00 00 00 38 01 61 00")  # one NOT NULL int column, named a
ROW = bytes.fromhex("D1 07 00 00 00")  # 7
DONE = bytes.fromhex("FD 10 00 C1 00 01 00 00 00 00 00 00 00")


def text(value: str) -> bytes:  # u8 character count, then UTF-16LE
    return bytes([len(value)]) + value.encode("utf-16-le")


def read(*tokens: bytes, **context):
    reader = ResponseReader(record=True, announce=lambda change: None)
    reader._context.update(context)  # what the login negotiated, as the connection sets it
    reader.feed(b"".join(tokens), last=True)
    assert reader.ended
    return reader


@pytest.mark.parametrize("version", [1, 2])
def test_data_classification_with_and_without_ranks(version):
    rank = (10).to_bytes(4, "little") if version >= 2 else b""
    classification = (b"\xa3"
                      + (1).to_bytes(2, "little") + text("Confidential") + text("L1")  # one label
                      + (1).to_bytes(2, "little") + text("Financial") + text("T1")  # one information type
                      + rank  # the result set's rank, from version 2
                      + (1).to_bytes(2, "little")  # detail for 1 column
                      + (2).to_bytes(2, "little")  # two sensitivities on it
                      + bytes(2) + bytes(2) + (20).to_bytes(4, "little")[: len(rank)]  # label 0, type 0
                      + b"\xff\xff" + bytes(2) + (30).to_bytes(4, "little")[: len(rank)])  # no label, type 0
    [rs] = read(COLUMNS, classification, ROW, DONE, data_classification_version=version).result_sets
    c = rs.classification
    assert c.labels == (("Confidential", "L1"),) and c.information_types == (("Financial", "T1"),)
    [(first, second)] = c.columns
    assert first.label == ("Confidential", "L1") and second.label is None and second.information_type == ("Financial", "T1")
    assert (c.rank, first.rank, second.rank) == ((10, 20, 30) if version >= 2 else (None, None, None))


def test_compute_totals():
    totals = (b"\x88" + (1).to_bytes(2, "little") + (1).to_bytes(2, "little")  # one total, id 1
              + b"\x00"  # no grouping columns
              + b"\x4d" + (1).to_bytes(2, "little") + bytes(4) + bytes(2) + b"\x38" + b"\x00")  # SUM(column 1): int
    alt_row = b"\xd3" + (1).to_bytes(2, "little") + (7).to_bytes(4, "little")
    [rs] = read(COLUMNS, totals, ROW, alt_row, DONE).result_sets
    [(aggregate, operand, sql_type, name)] = rs.totals[1].columns
    assert aggregate == Aggregate.SUM and operand == 1 and str(sql_type) == "int"
    assert rs.total_rows == [(1, (7,))] and rs.rows_read == 1


def test_session_state_with_a_long_value():
    long = bytes(range(256))
    body = (bytes(4) + b"\x01"  # sequence 0, recoverable
            + b"\x01" + b"\x03abc"  # state 1: 3 bytes
            + b"\x02" + b"\xff" + len(long).to_bytes(4, "little") + long)  # state 2: FF, then a 4-byte length
    reader = read(b"\xe4" + len(body).to_bytes(4, "little") + body, DONE)
    [state] = [i for i in reader.sequence if isinstance(i, SessionState)]
    assert state == SessionState(0, True, {1: b"abc", 2: long})


def test_login_tokens_are_read_and_refused_in_a_requests_response():
    sts, spn = "https://login.example/token", "https://database.example/"
    a, b = sts.encode("utf-16-le"), spn.encode("utf-16-le")
    start = 4 + 9 * 2  # offsets count from the option count
    body = ((2).to_bytes(4, "little")
            + b"\x01" + len(a).to_bytes(4, "little") + start.to_bytes(4, "little")
            + b"\x02" + len(b).to_bytes(4, "little") + (start + len(a)).to_bytes(4, "little") + a + b)
    [info, sspi] = TOKENS.decode(b"\xee" + len(body).to_bytes(4, "little") + body + b"\xed\x03\x00abc")
    assert _fed_auth_info(info) == {FedAuthInfoId.STS_URL: sts, FedAuthInfoId.SPN: spn} and sspi.buffer == b"abc"
    with pytest.raises(MalformedMessage, match="SSPI doesn't belong in a request's response"):
        read(b"\xed\x03\x00abc", DONE)


def test_a_result_sets_description_outside_one_is_malformed():
    with pytest.raises(MalformedMessage, match="TABNAME arrived outside a result set"):
        read(bytes.fromhex("A4 05 00 01 01 00 74 00"), DONE)
