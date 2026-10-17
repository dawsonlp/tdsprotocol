"""Tests of transaction-manager requests (M10) against the core alone.

Each request is encoded as MS-TDS defines it, with names as UTF-16LE, as observed. The announcements that answer the
requests are read, including the promote announcement's length (D-51).
"""

import pytest

from tds import transactions
from tds.requests import Context
from tds.response import ResponseReader
from tds.session import SessionState
from tds.tokens import EnvKind
from tds.transactions import Begin, Commit, CoordinatorAddress, Isolation, Promote, Propagate, Rollback, Save
from tds.types import ValueRefused

DESCRIPTOR = bytes.fromhex("01 00 00 00 3D 00 00 00")
CONTEXT = Context(transaction=int.from_bytes(DESCRIPTOR, "little"), outstanding_requests=1, collation=b"")
HEADERS = "16 00 00 00 12 00 00 00 02 00 01 00 00 00 3D 00 00 00 01 00 00 00"


def body(request) -> str:
    return request.encode(CONTEXT, record=False).body.hex(" ").upper()


@pytest.mark.parametrize("request_, payload", [
    (Begin(Isolation.SERIALIZABLE, "t"), "05 00  04  02 74 00"),  # begin · serializable · "t", 2 bytes of UTF-16LE
    (Begin(), "05 00  00  00"),  # isolation unchanged, no name
    (Commit(), "07 00  00  00"),  # no name, no flags
    (Commit(begin=Begin(Isolation.SNAPSHOT, "u")), "07 00  00  01  05  02 75 00"),  # then begin another: snapshot, "u"
    (Rollback("sp"), "08 00  04 73 00 70 00  00"),  # back to the savepoint "sp"
    (Save("sp"), "09 00  04 73 00 70 00"),
    (Promote(), "06 00"),
    (Propagate(b"\xab\xcd"), "01 00  02 00 AB CD"),  # the cookie, with a u16 length
    (CoordinatorAddress(), "00 00  00 00"),  # empty, with a u16 length
])
def test_each_request_is_laid_out_as_ms_tds_defines_it(request_, payload):
    assert body(request_) == HEADERS + " " + " ".join(payload.split())


def test_only_a_name_that_cant_be_encoded_is_refused():
    body(Save(""))  # sent, because the server refuses it and says why
    body(Save("x" * 127))
    with pytest.raises(ValueRefused, match="127"):
        body(Save("x" * 128))  # its byte count doesn't fit a u8


def test_a_promote_announcement_is_read_past_its_length():
    token = bytes(range(208))
    promote = bytes.fromhex("E3 01 00 0F") + len(token).to_bytes(4, "little") + token + b"\x00"  # the length says 1
    reader = ResponseReader(record=True, announce=lambda change: None)
    reader.feed(promote + bytes.fromhex("FD 00 00 FD 00 00 00 00 00 00 00 00 00"), last=True)
    [announcement] = [i for i in reader.sequence if getattr(i, "kind", None) == EnvKind.PROMOTE_TRANSACTION]
    assert announcement.new == token and reader.ended


@pytest.mark.parametrize("kind, new, expected", [
    (EnvKind.BEGIN_TRANSACTION, DESCRIPTOR, 0x3D00000001),
    (EnvKind.COMMIT_TRANSACTION, b"", 0),
    (EnvKind.ROLLBACK_TRANSACTION, b"", 0),
    (EnvKind.ENLIST_DTC_TRANSACTION, DESCRIPTOR, 0x3D00000001),  # unobserved: the rule follows the new value
    (EnvKind.DEFECT_TRANSACTION, b"", 0),
    (EnvKind.TRANSACTION_ENDED, b"", 0),
])
def test_the_session_keeps_its_descriptor_from_the_new_value(kind, new, expected):
    from tds.wire import Record

    session = SessionState(transaction=5)
    session.apply(Record(kind=kind, new=new, old=b""))
    assert session.transaction == expected


def test_the_module_is_tds_transactions():
    import tds

    assert tds.transactions is transactions
