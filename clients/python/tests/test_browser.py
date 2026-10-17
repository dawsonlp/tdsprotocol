"""The Browser client (MC-SQLR), tested against constructed bytes (M14).

The requests and replies are MC-SQLR's own examples (§4). The functions that ask a Browser talk to a stand-in Browser
on a local UDP port. The live tests, against a Windows server, are in M17, because SQL Server on Linux has no Browser.
"""

import asyncio
import functools
import socket

import pytest

from tds import browser
from tds.browser import BrowserError, Instance, Message
from tds.types import ValueRefused
from tds.wire import MalformedMessage

# MC-SQLR §4.1: CLNT_UCAST_EX's reply, three instances on one machine
MACHINE_REPLY = bytes.fromhex("054701") + (
    b"ServerName;ILSUNG1;InstanceName;YUKONSTD;IsClustered;No;Version;9.00.1399.06;tcp;57137;;"
    b"ServerName;ILSUNG1;InstanceName;YUKONDEV;IsClustered;No;Version;9.00.1399.06;"
    b"np;\\\\ILSUNG1\\pipe\\MSSQL$YUKONDEV\\sql\\query;;"
    b"ServerName;ILSUNG1;InstanceName;MSSQLSERVER;IsClustered;No;Version;9.00.1399.06;tcp;1433;"
    b"np;\\\\ILSUNG1\\pipe\\sql\\query;;")
# §4.2: CLNT_UCAST_INST for YUKONSTD, and its reply
INSTANCE_REQUEST = bytes.fromhex("04 59 55 4b 4f 4e 53 54 44 00")
INSTANCE_REPLY = bytes.fromhex("055800") + (
    b"ServerName;ILSUNG1;InstanceName;YUKONSTD;IsClustered;No;Version;9.00.1399.06;tcp;57137;;")
# §4.3: CLNT_UCAST_DAC for YUKONSTD, and its reply (port 0xDF32)
DAC_REQUEST = bytes.fromhex("0f 01 59 55 4b 4f 4e 53 54 44 00")
DAC_REPLY = bytes.fromhex("05 06 00 01 32 df")


# --------------------------------------------------------------------------- the messages

def test_the_requests_are_mc_sqlrs_examples():
    assert browser.request(Message.MACHINE) == b"\x03"  # §4.1
    assert browser.request(Message.BROADCAST) == b"\x02"
    assert browser.request(Message.INSTANCE, "YUKONSTD") == INSTANCE_REQUEST  # §4.2
    assert browser.request(Message.DAC, "YUKONSTD") == DAC_REQUEST  # §4.3


def test_a_request_reads_back_with_its_fields_named():
    request = browser.REQUEST.decode(DAC_REQUEST)
    assert (request.message, request.protocol_version, request.instance) == (Message.DAC, 1, "YUKONSTD")
    assert request.node.shown == "CLNT_UCAST_DAC “YUKONSTD”"


def test_a_machines_reply_names_each_instance():
    found = browser.instances(browser.read_reply(MACHINE_REPLY, Message.MACHINE))
    assert [i.instance_name for i in found] == ["YUKONSTD", "YUKONDEV", "MSSQLSERVER"]
    assert found[0] == Instance("ILSUNG1", "YUKONSTD", False, "9.00.1399.06", {"tcp": "57137"})
    assert found[1].tcp_port is None and found[1].protocols == {"np": r"\\ILSUNG1\pipe\MSSQL$YUKONDEV\sql\query"}
    assert list(found[2].protocols) == ["tcp", "np"] and found[2].tcp_port == 1433


def test_an_instances_reply():
    [found] = browser.instances(browser.read_reply(INSTANCE_REPLY, Message.INSTANCE))
    assert (found.instance_name, found.tcp_port) == ("YUKONSTD", 57137)


def test_a_dac_reply_is_a_port_not_text():
    assert browser.read_reply(DAC_REPLY, Message.DAC) == 57138
    tree = browser.REPLY.decode(DAC_REPLY, context={"asked": Message.DAC}).node
    assert tree.find("answer").shown == "port 57138"


def test_the_text_is_not_case_sensitive():
    text = "SERVERNAME;A;instancename;B;ISCLUSTERED;YES;version;16.0.1000.6;TCP;1433;;"
    [found] = browser.instances(text)
    assert found.is_clustered and found.protocols == {"tcp": "1433"}


def test_banyan_vines_runs_to_the_next_endpoint():
    text = "ServerName;A;InstanceName;B;IsClustered;No;Version;8.00.194;bv;item;group;item;group;org;tcp;1433;;"
    [found] = browser.instances(text)
    assert found.protocols == {"bv": "item;group;item;group;org", "tcp": "1433"}


@pytest.mark.parametrize("text, says", [
    ("ServerName;A;InstanceName;B;IsClustered;No;Version;1.0;tcp;1433", "doesn't end with “;;”"),
    ("ServerName;A;Instance;B;IsClustered;No;Version;1.0;;", "instance 1 doesn't begin ServerName;…"),
    ("ServerName;A;InstanceName;B;IsClustered;Maybe;Version;1.0;;", "IsClustered is 'Maybe'"),
    ("ServerName;A;InstanceName;B;IsClustered;No;Version;1.0;ipx;1;;", "'ipx' isn't an endpoint MC-SQLR names"),
    ("ServerName;A;InstanceName;B;IsClustered;No;Version;1.0;tcp;1;tcp;2;;", "instance 1 names tcp twice"),
    ("ServerName;A;InstanceName;B;IsClustered;No;Version;1.0;tcp;;", "tcp has no value"),
])
def test_text_that_isnt_mc_sqlrs_is_reported(text, says):
    with pytest.raises(MalformedMessage, match=None) as e:
        browser.instances(text)
    assert says in str(e.value)


def test_a_dac_reply_with_the_wrong_size():
    with pytest.raises(MalformedMessage, match="a DAC reply's size is the whole reply's, 6; this one says 3"):
        browser.read_reply(bytes.fromhex("05 03 00 01 32 df"), Message.DAC)


def test_a_reply_that_isnt_svr_resp():
    with pytest.raises(MalformedMessage, match="not SVR_RESP"):
        browser.read_reply(bytes.fromhex("04 00 00"), Message.MACHINE)


def test_text_in_another_code_page_names_the_option():
    reply = b"\x05\x05\x00caf\xe9;"
    with pytest.raises(MalformedMessage, match=r"isn't ascii: byte 0xe9, 3 bytes in.*encoding=…"):
        browser.read_reply(reply, Message.MACHINE)
    assert browser.read_reply(reply, Message.MACHINE, "cp1252") == "café;"


@pytest.mark.parametrize("name, says", [
    ("Café", r"'é' can't be written in ascii.*encoding=…"),
    ("A" * 33, "is 33 bytes in ascii; an instance name is at most 32"),
    ("A\x00B", "holds a zero byte"),
])
def test_a_name_that_cant_be_sent_is_refused(name, says):
    with pytest.raises(ValueRefused, match=says) as e:
        browser.request(Message.INSTANCE, name)
    assert str(e.value).startswith("the Browser request: ")


def test_a_name_in_the_shared_code_page():
    assert browser.request(Message.INSTANCE, "Café", "cp1252") == b"\x04Caf\xe9\x00"


# --------------------------------------------------------------------------- asking a stand-in Browser

def running(test):
    """Run an async test in its own event loop."""
    return functools.wraps(test)(lambda: asyncio.run(test()))


class StandIn(asyncio.DatagramProtocol):
    """Answers each request with the replies given for its first byte, or nothing."""

    def __init__(self, replies: dict[int, bytes]):
        self.replies, self.heard = replies, []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.heard.append(data)
        for reply in self.replies.get(data[0], []):
            self.transport.sendto(reply, addr)


async def stand_in(replies: dict[int, list[bytes]]):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(lambda: StandIn(replies), local_addr=("127.0.0.1", 0))
    return transport, protocol, transport.get_extra_info("sockname")[1]


@running
async def test_asking_for_an_instance():
    transport, heard, port = await stand_in({0x04: [INSTANCE_REPLY]})
    try:
        found = await browser.instance("127.0.0.1", "YUKONSTD", port=port)
    finally:
        transport.close()
    assert heard.heard == [INSTANCE_REQUEST]
    assert (found.tcp_port, found.address) == (57137, "127.0.0.1")


@running
async def test_asking_a_machine_and_for_a_dac_port():
    transport, _, port = await stand_in({0x03: [MACHINE_REPLY], 0x0F: [DAC_REPLY]})
    try:
        found = await browser.machine("127.0.0.1", port=port)
        dac = await browser.dac_port("127.0.0.1", "YUKONSTD", port=port)
    finally:
        transport.close()
    assert len(found) == 3 and dac == 57138


@running
async def test_no_reply_names_what_was_asked_and_why_it_might_be():
    transport, _, port = await stand_in({})
    try:
        with pytest.raises(BrowserError) as e:
            await browser.instance("127.0.0.1", "NOSUCH", port=port, timeout_ms=200)
    finally:
        transport.close()
    said = str(e.value)
    assert said.startswith(f"CLNT_UCAST_INST for “NOSUCH” to 127.0.0.1:{port}: no reply within 200 ms.")
    assert "SQL Server on Linux has none" in said and "no instance has that name" in said


@running
async def test_nothing_listening_is_refused_or_unanswered():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with pytest.raises(BrowserError, match=f"CLNT_UCAST_EX to 127.0.0.1:{port}: (refused|no reply)"):
        await browser.machine("127.0.0.1", port=port, timeout_ms=200)


@running
async def test_an_unreadable_reply_carries_its_bytes():
    transport, _, port = await stand_in({0x03: [b"\x05\x02\x00;;"]})
    try:
        with pytest.raises(BrowserError) as e:
            await browser.machine("127.0.0.1", port=port)
    finally:
        transport.close()
    assert "the reply can't be read: instance 1 doesn't begin" in str(e.value) and "05 02 00 3B 3B" in str(e.value)
    assert e.value.reply == b"\x05\x02\x00;;"


@running
async def test_a_broadcast_gathers_replies_and_ignores_the_unreadable():
    transport, heard, port = await stand_in({0x02: [b"\x05\x00\x00", MACHINE_REPLY]})
    try:  # sent to loopback rather than broadcast, so only the stand-in hears it
        found = await browser.broadcast("127.0.0.1", port=port, timeout_ms=300)
    finally:
        transport.close()
    assert heard.heard == [b"\x02"]
    assert [i.instance_name for i in found] == ["YUKONSTD", "YUKONDEV", "MSSQLSERVER"]
    assert {i.address for i in found} == {"127.0.0.1"}
