"""Tests of routing (M14, D-11).

A login reply that routes the connection is followed once, within one connection timer, and only to a server whose
certificate is valid for the routed name. The tests use a small fake router that implements just enough TDS 8.0 to
complete a login and route it to the live SQL Server 2025. Its TLS is real and uses the test certificate. Live routing
on Azure is part of M17.
"""

import asyncio
import io
import ssl

import pytest

import tds
from conftest import TEST_CA, fetch, trust_test_authority
from tds import prelogin
from tds.connection.core import ConnectError, Routed
from tds.observe import Level, Printer

pytestmark = pytest.mark.live
TLS = TEST_CA.parent


def packet(body: bytes) -> bytes:
    return bytes([0x04, 0x01]) + (8 + len(body)).to_bytes(2, "big") + bytes([0, 0, 1, 0]) + body


def login_reply_routing(server: str, port: int) -> bytes:
    """MS-TDS's login reply that routes.

    It is LOGINACK, then a routing announcement (ENVCHANGE 20), then the final DONE.
    """
    name = "Fake router".encode("utf-16-le")
    ack = b"\x01" + bytes.fromhex("74000004") + bytes([len(name) // 2]) + name + bytes.fromhex("10000000")
    target = server.encode("utf-16-le")
    route = b"\x00" + port.to_bytes(2, "little") + (len(target) // 2).to_bytes(2, "little") + target
    env = bytes([20]) + len(route).to_bytes(2, "little") + route + b"\x00\x00"
    return (b"\xad" + len(ack).to_bytes(2, "little") + ack + b"\xe3" + len(env).to_bytes(2, "little") + env
            + bytes.fromhex("FD 00 00 00 00 00 00 00 00 00 00 00 00"))


async def fake_router(routes_to: tuple[str, int]):
    """A TDS 8.0 server that answers the hello, reads the login, and routes it. Returns the server and its port."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(TLS / "server.pem", TLS / "server.key")
    context.set_alpn_protocols(["tds/8.0"])

    async def message(reader) -> bytes:
        body = b""
        while True:
            header = await reader.readexactly(8)
            body += await reader.readexactly(int.from_bytes(header[2:4], "big") - 8)
            if header[1] & 0x01:
                return body

    async def serve(reader, writer):
        try:
            await message(reader)  # the hello
            hello, _ = prelogin.PRELOGIN.encode({"options": {
                "version": {"major": 17, "minor": 0, "build": 0, "sub_build": 0}, "encryption": prelogin.Encryption.NOT_SUPPORTED,
                "instance": prelogin.INSTANCE_MATCH, "thread_id": 0, "mars": prelogin.OnOff.OFF}}, False)
            writer.write(packet(hello))
            await message(reader)  # the login
            writer.write(packet(login_reply_routing(*routes_to)))
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=context)
    return server, server.sockets[0].getsockname()[1]


def connecting(server, **options):
    async def go(router_routes_to, second=None):
        servers = []
        target = router_routes_to
        if second is not None:  # a router that routes to a router
            inner, inner_port = await fake_router(second)
            servers.append(inner)
            target = ("127.0.0.1", inner_port)
        outer, port = await fake_router(target)
        servers.append(outer)
        shown = io.StringIO()
        try:
            async with await tds.connect(**{**server, "port": port}, tds_version="8.0", observe=Printer(Level.OUTLINE, shown),
                                         **options) as connection:
                async with connection.serial_channel() as channel:
                    rows = (await fetch(channel, "SELECT @@SERVERNAME, DB_NAME()")).result_sets[0].rows
                return rows, connection.routed_from, port, shown.getvalue()
        finally:
            for s in servers:
                s.close()
    return go


def test_a_route_is_followed_once(server):
    rows, routed_from, port, shown = asyncio.run(connecting(server)(("localhost", server["port"])))
    assert rows[0][1] == "master" and routed_from == f"127.0.0.1:{port}"
    assert f"● routed · to localhost:{server['port']}" in shown
    assert shown.count("● log in") == 2  # once at the router, once at the server it routed to


def test_a_route_can_be_reported_instead(server):
    with pytest.raises(Routed) as routed:
        asyncio.run(connecting(server, follow_routing=False)(("localhost", server["port"])))
    assert (routed.value.server, routed.value.port) == ("localhost", server["port"])


def test_a_second_route_fails_and_names_the_chain(server):
    with pytest.raises(ConnectError, match=r"routed a second time: 127\.0\.0\.1:\d+ → 127\.0\.0\.1:\d+ → localhost:\d+\. "
                                           r"The driver follows one redirect"):
        asyncio.run(connecting(server)(None, second=("localhost", server["port"])))


def test_the_routed_server_must_carry_a_certificate_for_its_name(server):
    with pytest.raises(ConnectError) as failed:  # 127.0.0.1's certificate doesn't name wrong.example
        asyncio.run(connecting(server)(("wrong.example", server["port"])))
    assert failed.value.step in ("start", "secure")
