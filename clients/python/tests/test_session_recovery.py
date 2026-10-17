"""Tests of session recovery (M14, D-57) against constructed bytes.

The recovery login's data is MS-TDS's own example (§4.16). The session's state follows SESSIONSTATE tokens as MS-TDS
says and as the server was observed to do.
"""

from mstds_samples import SESSION_RECOVERY_DATA
from tds.session import RECOVERY, Recovery, SessionState
from tds.tokens import TOKENS
from tds.wire import Record

INITIAL = {0: bytes.fromhex("00 60 81 14 FF E7 FF FF 00"), 2: b"\x07\x01", 4: b"\x00", 5: b"\xff" * 4, 6: b"\x00",
           7: b"\x02", 8: bytes(8), 9: b"\xff" * 4}
LOGIN = SessionState(database="master", language="us_english", collation=bytes.fromhex("09 04 D0 00 34"))


def token(sequence: int, recoverable: bool, **states: bytes) -> Record:
    return Record(token="SESSIONSTATE", sequence=sequence, status=1 if recoverable else 0,
                  states=[Record(id=int(k[1:]), value=v) for k, v in states.items()])


def test_the_recovery_data_is_mstds_example():
    recovery = Recovery(LOGIN, INITIAL)
    recovery.follow(token(1, True, s9=bytes.fromhex("28 23 00 00")), "the SQL batch “SET TEXTSIZE 9000”")
    data, _ = RECOVERY.encode(recovery.data(LOGIN), False)
    assert data == SESSION_RECOVERY_DATA


def test_the_recovery_data_reads_back():
    data = RECOVERY.decode(SESSION_RECOVERY_DATA)
    assert (data.initial.database, data.initial.language, len(data.initial.states)) == ("master", "us_english", 8)
    assert (data.now.database, data.now.collation, [(s.id, s.value) for s in data.now.states]) == \
        ("", b"", [(9, bytes.fromhex("28 23 00 00"))])


def test_only_what_changed_is_sent_as_now():
    recovery = Recovery(LOGIN, INITIAL)
    recovery.follow(token(1, True, s2=b"\x01\x02"), "SET LANGUAGE Deutsch")
    now = SessionState(database="tempdb", language="Deutsch", collation=LOGIN.collation)
    data = recovery.data(now)["now"]
    assert (data["database"], data["collation"], data["language"]) == ("tempdb", b"", "Deutsch")
    assert data["states"] == [{"id": 2, "value": b"\x01\x02"}]


def test_after_a_reset_now_is_the_login():
    recovery = Recovery(LOGIN, INITIAL)
    recovery.follow(token(1, True, s2=b"\x01\x02"), "SET LANGUAGE Deutsch")
    now = recovery.data(SessionState(database="tempdb"), reset=True)["now"]
    assert now == {"database": "", "collation": b"", "language": "", "states": []}


def test_a_state_marked_not_recoverable_names_the_reason_and_the_request():
    recovery = Recovery(LOGIN, INITIAL)
    recovery.follow(token(6, False, s254=b"\x05\x00\x00\x00"), "the SQL batch “CREATE TABLE #t (a int)”")
    why = recovery.refusal()
    assert why.startswith("the server marked it not recoverable after the SQL batch “CREATE TABLE #t (a int)”: "
                          "a temporary table exists (state 254, reason 5, as observed")
    recovery.follow(token(7, True, s254=bytes(4)), "the SQL batch “DROP TABLE #t”")
    assert recovery.refusal() is None


def test_an_unknown_reason_is_shown_as_it_came():
    recovery = Recovery(LOGIN, INITIAL)
    recovery.follow(token(1, False, s254=b"\x63\x00\x00\x00"), "a request")
    assert "state 254, reason 99, which the driver hasn't seen before" in recovery.refusal()


def test_older_news_is_ignored():
    recovery = Recovery(LOGIN, INITIAL)
    recovery.follow(token(5, True, s2=b"\x01\x02"), "later")
    recovery.follow(token(4, True, s2=b"\x07\x03"), "earlier")
    assert recovery.states[2] == b"\x01\x02"


def test_the_last_sequence_number_turns_recovery_off():
    recovery = Recovery(LOGIN, INITIAL)
    recovery.follow(token(0xFFFFFFFF, False, s0=INITIAL[0]), "a request")
    assert "reached FFFFFFFF" in recovery.refusal()
    recovery.reset()
    assert recovery.refusal().startswith("its session state's sequence number reached FFFFFFFF")


def test_a_reset_clears_what_blocked_recovery():
    recovery = Recovery(LOGIN, INITIAL)
    recovery.follow(token(1, False, s254=b"\x04\x00\x00\x00"), "BEGIN TRAN")
    recovery.reset()
    assert recovery.refusal() is None and recovery.states == INITIAL


def test_a_sessionstate_token_reads():
    body = bytes.fromhex("E4 0B 00 00 00 06 00 00 00 00 FE 04 05 00 00 00")
    [rec] = TOKENS.decode(body)
    assert (rec.token, rec.sequence, int(rec.status)) == ("SESSIONSTATE", 6, 0)
    assert (rec.states[0].id, rec.states[0].value) == (254, b"\x05\x00\x00\x00")


def test_the_mirroring_partner_is_kept_not_acted_on():
    """Database mirroring's partner, as the login reply names it (ENVCHANGE 13), is shown on the session (D-58)."""
    partner = "MIRROR\\SQL2".encode("utf-16-le")
    body = bytes([0xE3]) + (1 + 1 + len(partner) + 1).to_bytes(2, "little") + bytes([13, len(partner) // 2]) + partner + b"\x00"
    [change] = TOKENS.decode(body)
    session = SessionState()
    session.apply(change)
    assert session.mirroring_partner == "MIRROR\\SQL2"
