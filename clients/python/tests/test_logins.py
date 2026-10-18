"""Tests of Windows and Entra ID logins (M17, D-55) against a fake server.

The fake server implements just enough TDS 8.0 to check what the client sends at each step of each login, and to answer
as MS-TDS says a server does. Its TLS is real and uses the test certificate. The live tests of these logins run on Azure
(D-62).
"""

import asyncio
import io
import json

import pytest

import tds
from conftest import TEST_CA, trust_test_authority
from tds import prelogin
from tds.capture import Capture
from tds.connection.core import ConnectError
from tds.login7 import LOGIN7, Feature, FeatureList
from tds.logins import EntraLogin, EntraToken, WindowsLogin, Workflow
from tds.wire import Reader

TLS = TEST_CA.parent
NONCE = bytes(range(32))
DONE = bytes.fromhex("FD 00 00 00 00 00 00 00 00 00 00 00 00")


def packet(kind: int, body: bytes) -> bytes:
    return bytes([kind, 0x01]) + (8 + len(body)).to_bytes(2, "big") + bytes([0, 0, 1, 0]) + body


def login_ack() -> bytes:
    name = "Fake".encode("utf-16-le")
    ack = b"\x01" + bytes.fromhex("74000004") + bytes([len(name) // 2]) + name + bytes.fromhex("10000000")
    return b"\xad" + len(ack).to_bytes(2, "little") + ack + DONE


def fed_auth_info(sts_url: str, spn: str) -> bytes:
    """A FEDAUTHINFO token (§2.2.7.12).

    It holds the option count, then each option (id, length, offset from the count), then the data.
    """
    data = [(1, sts_url.encode("utf-16-le")), (2, spn.encode("utf-16-le"))]
    at, options, payload = 4 + 9 * len(data), b"", b""
    for option, value in data:
        options += bytes([option]) + len(value).to_bytes(4, "little") + (at + len(payload)).to_bytes(4, "little")
        payload += value
    body = len(data).to_bytes(4, "little") + options + payload
    return b"\xee" + len(body).to_bytes(4, "little") + body


class FakeServer:
    """Answers a hello, then answers each step of a login.

    The answer to the hello offers a nonce if `nonce` is true, and says federated authentication is required if the
    client asks. Each received message is kept and is answered by the next item of `answers`.
    """

    def __init__(self, answers: list[bytes | None], nonce: bool = False):
        self.answers, self.nonce, self.received = answers, nonce, []

    async def start(self):
        import ssl
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(TLS / "server.pem", TLS / "server.key")
        context.set_alpn_protocols(["tds/8.0"])
        self.server = await asyncio.start_server(self.serve, "127.0.0.1", 0, ssl=context)
        return self.server.sockets[0].getsockname()[1]

    @staticmethod
    async def message(reader) -> tuple[int, bytes]:
        body, kind = b"", None
        while True:
            header = await reader.readexactly(8)
            kind = header[0]
            body += await reader.readexactly(int.from_bytes(header[2:4], "big") - 8)
            if header[1] & 0x01:
                return kind, body

    async def serve(self, reader, writer):
        try:
            _, hello = await self.message(reader)
            asked = prelogin.PRELOGIN.decode(hello, False).options
            options = {"version": {"major": 17, "minor": 0, "build": 0, "sub_build": 0},
                       "encryption": prelogin.Encryption.NOT_SUPPORTED, "instance": prelogin.INSTANCE_MATCH,
                       "thread_id": 0, "mars": prelogin.OnOff.OFF}
            if asked.get("fed_auth_required") is not None:
                options["fed_auth_required"] = 1
            if self.nonce:
                options["nonce"] = NONCE
            reply, _ = prelogin.PRELOGIN.encode({"options": options}, False)
            writer.write(packet(4, reply))
            for answer in self.answers:
                self.received.append(await self.message(reader))
                if answer is None:  # lose completion after accepting LOGIN7
                    writer.transport.abort()
                    return
                writer.write(packet(4, answer))
                await writer.drain()
            await reader.read()  # until the client closes
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


def logged_in(server: FakeServer, login, capture=None) -> list[tuple[int, bytes]]:
    async def go():
        port = await server.start()
        try:
            async with await tds.connect("localhost", port, login=login, tds_version="8.0",
                                         ssl_context=trust_test_authority(), capture=capture):
                pass
        finally:
            server.server.close()
        return server.received

    return asyncio.run(go())


def login7(body: bytes):
    record = LOGIN7.decode(body, False)
    features = {}
    if record.features:
        features = FeatureList().read(Reader(record.features, False))
    return record, features


def test_lost_password_change_completion_reports_uncertainty_and_never_retries():
    async def go():
        server = FakeServer([None])
        port = await server.start()
        try:
            with pytest.raises(tds.ConnectError) as caught:
                await tds.connect("localhost", port, user="artificial-user", password="artificial-A",
                                  new_password="artificial-B", tds_version="8.0",
                                  ssl_context=trust_test_authority())
            assert caught.value.password_change_uncertain
            assert any("may already have changed" in note for note in caught.value.__notes__)
            assert len(server.received) == 1
            record, _ = login7(server.received[0][1])
            assert record.variable_part.password == "artificial-A"
            assert record.variable_part.new_password == "artificial-B"
        finally:
            server.server.close()
            await server.server.wait_closed()
    asyncio.run(go())


class Exchange:
    """A security library's exchange, scripted. It holds the tokens it gives and the challenges it was given."""

    def __init__(self, tokens: list[bytes]):
        self.tokens, self.challenges = list(tokens), []

    def step(self, challenge):
        self.challenges.append(challenge)
        return self.tokens.pop(0) if self.tokens else None


class Provider:
    def __init__(self, tokens):
        self.tokens, self.begun = tokens, []

    def begin(self, host, port):
        self.begun.append((host, port))
        self.exchange = Exchange(self.tokens)
        return self.exchange


def test_a_windows_login_answers_the_servers_challenge():
    provider = Provider([b"NEGOTIATE", b"AUTHENTICATE"])
    sspi = b"CHALLENGE"
    server = FakeServer([b"\xed" + len(sspi).to_bytes(2, "little") + sspi, login_ack()])
    (login_kind, login_body), (answer_kind, answer) = logged_in(server, WindowsLogin(provider))
    record, _ = login7(login_body)
    assert login_kind == 0x10 and record.option_flags_2 & 0x80  # the Windows login flag
    assert (record.variable_part.user_name, record.variable_part.password) == ("", "")
    assert record.variable_part.windows_auth == b"NEGOTIATE"
    assert (answer_kind, answer) == (0x11, b"AUTHENTICATE")  # the SSPI message is the token alone
    assert provider.exchange.challenges == [None, b"CHALLENGE"] and provider.begun[0][0] == "localhost"


def test_an_entra_token_up_front_echoes_the_hello_and_its_nonce():
    server = FakeServer([login_ack()], nonce=True)
    [(kind, body)] = logged_in(server, EntraToken(lambda: "eyJ.token"))
    record, features = login7(body)
    data = features[Feature.FEDERATED_AUTH]
    token = "eyJ.token".encode("utf-16-le")
    assert data == bytes([0x01 << 1 | 1]) + len(token).to_bytes(4, "little") + token + NONCE  # library 1, echoed
    assert (record.variable_part.user_name, record.option_flags_2 & 0x80) == ("", 0)


def test_an_entra_token_fetched_mid_login():
    asked = []

    async def fetch(spn, sts_url):
        asked.append((spn, sts_url))
        return "eyJ.fetched"

    server = FakeServer([fed_auth_info("https://login.example/tenant", "https://database.windows.net/"), login_ack()])
    (_, body), (kind, token_message) = logged_in(server, EntraLogin(fetch, Workflow.INTERACTIVE))
    _, features = login7(body)
    assert features[Feature.FEDERATED_AUTH] == bytes([0x02 << 1 | 1, 0x03])  # library 2, echoed, and workflow 3
    assert asked == [("https://database.windows.net/", "https://login.example/tenant")]
    token = "eyJ.fetched".encode("utf-16-le")
    assert kind == 0x08 and token_message == (4 + len(token)).to_bytes(4, "little") + len(token).to_bytes(4, "little") + token


def test_a_token_function_that_fails_names_the_step():
    def fails():
        raise PermissionError("no credential found")

    with pytest.raises(ConnectError, match="log in: the Entra ID token couldn't be made: PermissionError: no credential"):
        logged_in(FakeServer([login_ack()]), EntraToken(fails))


def test_connect_needs_one_way_to_log_in():
    with pytest.raises(ValueError, match="connect needs a way to log in"):
        asyncio.run(tds.connect("localhost", 1))
    with pytest.raises(ValueError, match="logs in with its own tokens: user, password and new_password belong"):
        asyncio.run(tds.connect("localhost", 1, user="sa", login=EntraToken("t")))


def test_captures_hold_no_credential():
    for login, answers, secret in [
        (WindowsLogin(Provider([b"NEGOTIATE-SECRET", b"AUTHENTICATE-SECRET"])),
         [b"\xed\x09\x00CHALLENGE", login_ack()], [b"NEGOTIATE-SECRET", b"AUTHENTICATE-SECRET"]),
        (EntraToken("eyJ.secret-token"), [login_ack()], ["eyJ.secret-token".encode("utf-16-le")]),
        (EntraLogin(lambda spn, sts: "eyJ.fetched-secret"), [fed_auth_info("https://sts", "https://db"), login_ack()],
         ["eyJ.fetched-secret".encode("utf-16-le")]),
    ]:
        out = io.StringIO()
        logged_in(FakeServer(answers, nonce=True), login, Capture(out))
        import base64
        sent = b"".join(base64.b64decode(json.loads(line)["bytes"]) for line in out.getvalue().splitlines()
                        if '"packet": "send"' in line)
        assert sent and not any(s in sent for s in secret), f"a capture of {type(login).__name__} holds a credential"
