"""Authentication privacy and completion boundaries use artificial token bytes."""
import base64
import io
import json
import traceback

import pytest

from tds.capture import Capture, replay
from tds.connection.core import ConnectionCore, ConnectError, Options
from tds.logins import WindowsLogin
from tds.packet import Message, PacketType, split
from test_logins import FakeServer, Provider, logged_in, login_ack

MARKER = b"ARTIFICIAL-SERVER-AUTHENTICATION-TOKEN"


def walk(node):
    if node is not None:
        yield node
        for child in node.children:
            yield from walk(child)


@pytest.mark.parametrize("size", [17, 4096])
def test_incoming_login_capture_is_redacted_and_replay_marks_missing_evidence(size):
    out = io.StringIO()
    core = ConnectionCore(Options("unused", 1433, "", "", login=WindowsLogin(Provider([]))))
    core.set_capture(Capture(out))
    core._authenticating = True
    body = b"\xed" + len(MARKER).to_bytes(2, "little") + MARKER + login_ack()
    for packet in split(PacketType.SERVER_MESSAGE, body, size, record=False)[0]:
        core._capture_packet("receive", None, packet)
    core._tokens(Message(PacketType.SERVER_MESSAGE, body, []), "login reply", final=False)
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    saved = b"".join(base64.b64decode(line['bytes']) for line in lines if 'packet' in line)
    assert MARKER not in saved
    assert all(MARKER not in base64.b64decode(line['safe_login_tokens'])
               for line in lines if 'safe_login_tokens' in line)
    events = []
    replay(io.StringIO(out.getvalue()), events.append)
    assert any("omitted" in node.shown for event in events for node in walk(event.node))
    assert any(node.name == 'LOGINACK' for event in events for node in walk(event.node))


def test_live_full_inspection_keeps_safe_records_without_authentication_payloads():
    events = []
    core = ConnectionCore(Options("unused", 1433, "", ""), events.append)
    body = b"\xed" + len(MARKER).to_bytes(2, "little") + MARKER + login_ack()
    core._tokens(Message(PacketType.SERVER_MESSAGE, body, []), "login reply", final=False)
    nodes = [node for event in events for node in walk(event.node)]
    assert any(node.name == "LOGINACK" for node in nodes)
    assert not any(MARKER in node.raw or MARKER.decode() in node.shown for node in nodes)


def test_malformed_windows_login_reply_does_not_echo_payload_bytes():
    core = ConnectionCore(Options("unused", 1433, "", ""))
    core._authenticating = True
    body = b"\xed\xff\xff" + MARKER
    with pytest.raises(ConnectError) as caught:
        core._malformed_is_a_connect_error("log in", lambda m: core._tokens(m, "login reply"),
                                          Message(PacketType.SERVER_MESSAGE, body, []))
    assert MARKER[:12].hex(" ").upper() not in str(caught.value)
    assert "hidden" in str(caught.value)


@pytest.mark.parametrize('malformed', [False, True])
def test_legacy_capture_authentication_payload_is_not_exposed_on_replay(malformed):
    body = b'\xed' + (b'\xff\xff' if malformed else len(MARKER).to_bytes(2, 'little')) + MARKER
    if not malformed:
        body += login_ack()
    lines = [dict(t=0, packet='receive', channel=None, bytes=base64.b64encode(packet).decode())
             for packet in split(PacketType.SERVER_MESSAGE, body, 17, record=False)[0]]
    lines.append(dict(t=1, event='receive', text='← login reply'))
    events = []
    replay(io.StringIO('\n'.join(map(json.dumps, lines))), events.append)
    nodes = [node for event in events for node in walk(event.node)]
    assert not any(MARKER in node.raw or MARKER.decode() in node.shown for node in nodes)
    assert any('hidden' in node.shown for node in nodes)


def test_secret_capture_remains_an_explicit_opt_in():
    out = io.StringIO()
    core = ConnectionCore(Options('unused', 1433, '', ''))
    core.set_capture(Capture(out, keep_password=True))
    core._authenticating = True
    packet = split(PacketType.SERVER_MESSAGE, MARKER, 4096, record=False)[0][0]
    core._capture_packet('receive', None, packet)
    line = next(json.loads(s) for s in out.getvalue().splitlines() if '"packet"' in s)
    assert MARKER in base64.b64decode(line['bytes']) and 'redacted' not in line


@pytest.mark.parametrize('challenges,accepted', [(7, True), (8, False)])
def test_windows_authentication_round_limit_counts_initial_step(challenges, accepted):
    provider = Provider([b'OUTPUT'] * (challenges + 1))
    server = FakeServer([b'\xed\x01\x00X'] * challenges + [login_ack()])
    if accepted:
        logged_in(server, WindowsLogin(provider))
    else:
        with pytest.raises(ConnectError, match='round limit'):
            logged_in(server, WindowsLogin(provider))
    assert len(provider.exchange.challenges) == 8


@pytest.mark.parametrize('direction', ['input', 'output'])
def test_oversized_windows_tokens_fail_before_provider_or_login_output(direction, monkeypatch):
    import test_logins
    monkeypatch.setattr(test_logins, 'packet', lambda kind, body: b''.join(
        split(PacketType(kind), body, 4096, record=False)[0]))
    oversized = b'X' * (48 * 1024 + 1)
    provider = Provider([oversized if direction == 'output' else b'INITIAL'])
    server = FakeServer([b'\xed' + len(oversized).to_bytes(2, 'little') + oversized])
    with pytest.raises(ConnectError, match='token limit'):
        logged_in(server, WindowsLogin(provider))
    assert provider.exchange.challenges == [None]
    if direction == 'output':
        assert not server.received


def test_fragmented_login_message_is_bounded_before_joining():
    core = ConnectionCore(Options('unused', 1433, '', ''))
    core._authenticating = True
    procedure = core._next_message('log in')
    next(procedure)
    data = b''.join(split(PacketType.SERVER_MESSAGE, b'X' * (64 * 1024 + 1), 4096, record=False)[0])
    with pytest.raises(ConnectError, match='message exceeds'):
        procedure.send(data)


def test_safe_login_records_preserve_feature_negotiation_during_replay():
    from tds.capture import _messages, _decoded, _tokens
    body = b'\xed\x01\x00X\xae\x0a\x01\x00\x00\x00\x00\xff' + login_ack()
    out = io.StringIO()
    core = ConnectionCore(Options('unused', 1433, '', ''))
    core.set_capture(Capture(out))
    core._authenticating = True
    for packet in split(PacketType.SERVER_MESSAGE, body, 17, record=False)[0]:
        core._capture_packet('receive', None, packet)
    core._tokens(Message(PacketType.SERVER_MESSAGE, body, []), 'login reply', final=False)
    lines = list(map(json.loads, out.getvalue().splitlines()))
    evidence = next(line['safe_login_tokens'] for line in lines if 'safe_login_tokens' in line)
    negotiated = {}
    saved = _messages(lines)[('receive', None)].popleft()
    node = _decoded('login reply', saved, _tokens('login reply', negotiated), evidence)
    assert negotiated['utf8_support'] is False
    assert any(child.name == 'LOGINACK' for child in walk(node))
    assert any('omitted' in child.shown for child in walk(node))


@pytest.mark.parametrize('phase', ['begin', 'step'])
def test_windows_provider_failure_diagnostics_do_not_echo_secrets(phase):
    class Failing:
        def begin(self, host, port):
            if phase == 'begin':
                raise PermissionError(MARKER.decode())
            return self
        def step(self, challenge):
            raise PermissionError(MARKER.decode())
    with pytest.raises(ConnectError, match='provider refused or failed') as caught:
        logged_in(FakeServer([login_ack()]), WindowsLogin(Failing()))
    assert MARKER.decode() not in ''.join(traceback.format_exception(caught.value))
    assert isinstance(caught.value.provider_error, PermissionError)


@pytest.mark.parametrize('direction', ['input', 'output'])
def test_token_at_exact_size_boundary_is_accepted(direction, monkeypatch):
    import test_logins
    monkeypatch.setattr(test_logins, 'packet', lambda kind, body: b''.join(
        split(PacketType(kind), body, 4096, record=False)[0]))
    boundary = b'B' * (48 * 1024)
    provider = Provider([boundary] if direction == 'output' else [b'INITIAL', b'REPLY'])
    answers = [login_ack()] if direction == 'output' else [b'\xed'+len(boundary).to_bytes(2,'little')+boundary, login_ack()]
    server = FakeServer(answers)
    logged_in(server, WindowsLogin(provider))
    if direction == 'input':
        assert provider.exchange.challenges[-1] == boundary
    else:
        record, _ = test_logins.login7(server.received[0][1])
        assert record.variable_part.windows_auth == boundary


def test_final_sspi_alongside_loginack_is_validated_once_without_an_extra_packet():
    provider = Provider([b'INITIAL', b''])
    server = FakeServer([b'\xed'+len(MARKER).to_bytes(2,'little')+MARKER+login_ack()])
    received = logged_in(server, WindowsLogin(provider))
    assert provider.exchange.challenges == [None, MARKER]
    assert len(received) == 1 and received[0][0] == 0x10


def test_provider_output_after_server_acceptance_refuses_the_opening():
    provider = Provider([b'INITIAL', b'UNEXPECTED-CONTINUATION'])
    server = FakeServer([b'\xed\x01\x00X'+login_ack()])
    with pytest.raises(ConnectError, match='another token after server acceptance'):
        logged_in(server, WindowsLogin(provider))


def test_invalid_final_server_token_cannot_be_skipped_by_coalesced_loginack():
    class Invalid:
        def begin(self, host, port):
            return self
        def step(self, challenge):
            if challenge is not None:
                raise PermissionError(MARKER.decode())
            return b'INITIAL'
    with pytest.raises(ConnectError, match='provider refused or failed'):
        logged_in(FakeServer([b'\xed\x01\x00X'+login_ack()]), WindowsLogin(Invalid()))


def test_two_challenges_in_one_reply_are_refused_before_provider_dispatch():
    provider = Provider([b'INITIAL'])
    with pytest.raises(ConnectError, match='multiple Windows authentication challenges'):
        logged_in(FakeServer([b'\xed\x01\x00X\xed\x01\x00Y'+login_ack()]), WindowsLogin(provider))
    assert provider.exchange.challenges == [None]
