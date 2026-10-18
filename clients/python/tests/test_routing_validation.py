"""Validate a route in the pure core, before any routed socket can be opened."""
import pytest
from tds.connection.core import ConnectionCore, ConnectError, Options, Routed
from tds.tokens import TOKENS
from test_routing_live import login_reply_routing


@pytest.mark.parametrize("server,port,protocol,old", [
    ("unused", 1433, 1, 0), ("unused", 0, 0, 0), ("", 1433, 0, 0),
    ("bad\x00name", 1433, 0, 0), ("unused", 1433, 0, 1),
])
def test_invalid_route_is_refused_before_following(server, port, protocol, old):
    body = bytearray(login_reply_routing(server, port))
    at = body.index(0xe3)
    size = int.from_bytes(body[at + 1:at + 3], "little")
    body[at + 6] = protocol
    body[at + 3 + size - 2:at + 3 + size] = old.to_bytes(2, "little")
    core = ConnectionCore(Options("unused", 1433, "test", "unused"))
    with pytest.raises(ConnectError):
        core._read_login_reply(TOKENS.decode(bytes(body), False))


def test_tcp_route_preserves_the_exact_target():
    core = ConnectionCore(Options("unused", 1433, "test", "unused"))
    with pytest.raises(Routed) as caught:
        core._read_login_reply(TOKENS.decode(login_reply_routing("target.example", 1433), False))
    assert (caught.value.server, caught.value.port) == ("target.example", 1433)
