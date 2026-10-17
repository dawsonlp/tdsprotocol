"""Slice 1's failures (M12).

Each way connecting can fail is reported as a ConnectError that names the step, what was expected and what arrived
(D-53). The tests feed the hello and login replies to the core's connect procedure, which is sans-I/O. The connection
timer and an unreachable server use real local sockets.
"""

import asyncio
import socket

import pytest

import tds
from mstds_samples import LOGIN_REPLY
from tds import prelogin
from tds.connection.core import ConnectError, ConnectionCore, Options, Read, Send
from tds.prelogin import Encryption, OnOff
from tds.tokens import TOKENS


def packet(body: bytes, kind: int = 0x04) -> bytes:
    return bytes([kind, 0x01]) + (8 + len(body)).to_bytes(2, "big") + bytes([0, 0, 1, 0]) + body


def hello_reply(encryption=Encryption.ON, instance=prelogin.INSTANCE_MATCH) -> bytes:
    body, _ = prelogin.PRELOGIN.encode({"options": {
        "version": {"major": 17, "minor": 0, "build": 5015, "sub_build": 0}, "encryption": encryption,
        "instance": instance, "thread_id": 0, "mars": OnOff.OFF}}, False)
    return packet(body)


def connecting(*replies: bytes) -> ConnectError:
    """Run the connect procedure, answering each read with the next reply, until it fails."""
    core = ConnectionCore(Options("localhost", 1433, "sa", "unused"))
    procedure, replies = core.connect(), list(replies)
    action = next(procedure)
    with pytest.raises(ConnectError) as failed:
        while True:
            action = procedure.send(replies.pop(0) if isinstance(action, Read) else None)
    return failed.value


def test_a_server_that_cant_encrypt():
    e = connecting(hello_reply(Encryption.NOT_SUPPORTED))
    assert e.step == "hello" and "encryption not_supported" in str(e) and "can't be fully encrypted" in str(e)


def test_an_instance_mismatch():
    e = connecting(hello_reply(instance=b"\x01"))
    assert e.step == "hello" and "wrong server instance" in str(e)


def test_a_malformed_reply_says_what_arrived():
    e = connecting(packet(bytes.fromhex("00 00 99 00")))  # a directory entry pointing past the end
    assert e.step == "hello" and "the server's reply can't be read" in str(e) and "arrived as 4 bytes: 00 00 99 00" in str(e)


def test_the_server_closing_mid_connect():
    e = connecting(b"")
    assert e.step == "hello" and "the server closed the connection" in str(e)


def test_a_version_below_7_4():
    core = ConnectionCore(Options("localhost", 1433, "sa", "unused"))
    with pytest.raises(ConnectError) as failed:  # MS-TDS's own sample login reply acknowledges TDS 7.2
        core._read_login_reply(TOKENS.decode(LOGIN_REPLY[8:], False))
    assert failed.value.step == "log in" and "the server speaks TDS 7.2; TDS 7.4 or later is required" in str(failed.value)


def test_the_connection_timer_names_the_step_it_stopped_in():
    async def go():
        async def silent(reader, writer):  # accepts, reads the hello, never answers
            await reader.read(1024)
            await asyncio.sleep(10)

        server = await asyncio.start_server(silent, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            with pytest.raises(ConnectError) as failed:
                await tds.connect("127.0.0.1", port, user="sa", password="unused", timeout=0.3)
            return failed.value
        finally:
            server.close()

    e = asyncio.run(go())
    assert e.step == "hello" and "the connection timer ran out: 0.3 s passed" in str(e)


def test_an_unreachable_server():
    with socket.socket() as s:  # a port nothing listens on: bound, then closed
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with pytest.raises(ConnectError) as failed:
        asyncio.run(tds.connect("127.0.0.1", port, user="sa", password="unused", timeout=2))
    assert failed.value.step == "start" and f"couldn't reach 127.0.0.1:{port}" in str(failed.value)
