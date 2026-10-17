"""Tests of MS-TDS's own sample messages. Each decodes to the values MS-TDS gives and re-encodes byte for byte."""

from mstds_samples import HELLO, LOGIN, LOGIN_REPLY

from tds import login7, packet, prelogin, tokens
from tds.prelogin import Encryption, OnOff
from tds.tokens import EnvKind


def body(message: bytes) -> bytes:
    [joined] = packet.Joiner().feed(message)
    return joined.body


def test_hello_decodes_and_reencodes():
    hello = prelogin.PRELOGIN.decode(body(HELLO))
    assert hello.options.version.major == 9
    assert hello.options.encryption == Encryption.ON
    assert hello.options.instance == prelogin.INSTANCE_MATCH
    assert hello.options.thread_id == 3512
    assert hello.options.mars == OnOff.ON
    assert prelogin.PRELOGIN.encode(hello)[0] == body(HELLO)


def test_login_decodes_and_reencodes():
    login = login7.LOGIN7.decode(body(LOGIN))
    assert login7.tds_version_name(login.tds_version) == "TDS 7.2"
    assert login.variable_part.host_name == "lpdtest1"
    assert login.variable_part.user_name == "sa"
    assert login.variable_part.app_name == "OSQL-32"
    assert login.variable_part.library_name == "ODBC"
    assert login7.LOGIN7.encode(login)[0] == body(LOGIN)


def test_login_reply_tokens():
    reply = tokens.TOKENS.decode(body(LOGIN_REPLY))
    assert [t.token for t in reply] == ["ENVCHANGE", "INFO", "ENVCHANGE", "ENVCHANGE", "ENVCHANGE", "INFO", "LOGINACK", "DONE"]
    assert (reply[0].kind, reply[0].new) == (EnvKind.DATABASE, "master")
    assert reply[1].number == 5701
    assert (reply[4].kind, reply[4].new) == (EnvKind.PACKET_SIZE, "4096")
    assert login7.tds_version_name(reply[6].tds_version) == "TDS 7.2"


def test_password_scrambling_round_trips():
    raw = "a".encode("utf-16-le")
    assert login7.scramble(raw) == bytes.fromhex("B3 A5")  # the example on the LOGIN7 reference page
    assert login7.unscramble(login7.scramble(raw)) == raw


def test_split_and_join_large_message():
    payload = bytes(range(256)) * 40  # 10 240 bytes, three packets at 4096
    packets, _ = packet.split(packet.PacketType.SQL_BATCH, payload, 4096)
    assert [len(p) for p in packets] == [4096, 4096, 10240 - 2 * 4088 + 8]
    [joined] = packet.Joiner().feed(b"".join(packets))
    assert joined.body == payload
