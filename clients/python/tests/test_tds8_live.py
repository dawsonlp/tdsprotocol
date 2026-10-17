"""Tests of TDS 8.0 and certificate checking (M13, D-10) against the live SQL Server 2025.

The server uses its test certificate (docker/macos/tls/make-test-certificates.sh). The tests cover TLS first with ALPN
tds/8.0, a certificate that is always verified under 8.0, Python's ssl.SSLContext for every option, and literate errors
that say what the options are.
"""

import asyncio
import io
import ssl

import pytest

import tds
from conftest import fetch, trust_test_authority
from tds import login7
from tds.connection.core import ConnectError
from tds.observe import Level, Printer

pytestmark = pytest.mark.live


def run(coroutine):
    return asyncio.run(coroutine)


async def select_one(server, **options):
    shown = io.StringIO()
    async with await tds.connect(**{**server, **options}, observe=Printer(Level.OUTLINE, shown)) as connection:
        async with connection.serial_channel() as channel:
            rows = (await fetch(channel, "SELECT 1")).result_sets[0].rows
        return rows, connection.server.tds_version, shown.getvalue()


def refused(server, **options) -> ConnectError:
    with pytest.raises(ConnectError) as failed:
        run(select_one(server, **options))
    return failed.value


@pytest.mark.parametrize("choose", [{"tds_version": "8.0"}, {"strict": True}])
def test_tds_8_starts_with_tls(server, choose):
    rows, version, shown = run(select_one(server, **choose))
    assert rows == ((1,),)
    lines = [line.strip() for line in shown.splitlines()]
    assert lines[0].startswith("● secure · TDS 8.0: TLS first, ALPN tds/8.0 · at ")  # before the hello
    assert any(l.startswith("⇄ secure · TLSv1.3") and l.endswith("ALPN tds/8.0") for l in lines)
    hello = next(i for i, l in enumerate(lines) if l.startswith("● hello · at "))
    assert hello > lines.index(next(l for l in lines if l.startswith("⇄ secure")))
    assert "encryption not_supported" in shown  # observed: inside 8.0's TLS, the server answers "not supported"
    assert version == login7.TDS_7_4  # observed: the login reply still says TDS 7.4


def test_tds_7_4_agrees_encryption_in_the_hello(server):
    rows, version, shown = run(select_one(server))
    assert rows == ((1,),) and "⇄ secure · TLSv1.2" in shown  # 7.x stops at TLS 1.2


def test_mars_over_tds_8(server):
    async def go():
        async with await tds.connect(**server, tds_version="8.0", mars=True) as connection:
            async with connection.serial_channel() as a, connection.serial_channel() as b:
                return (await fetch(a, "SELECT 1")).result_sets[0].rows, (await fetch(b, "SELECT 2")).result_sets[0].rows

    assert run(go()) == (((1,),), ((2,),))


def test_certificates_that_arent_accepted(server):
    wrong_name = refused(server, server_hostname="wrong.example")
    assert wrong_name.step == "secure" and "certificate wasn't accepted: Hostname mismatch" in str(wrong_name)
    assert "server_hostname=" in str(wrong_name)  # says what the options are
    unknown_authority = refused(server, ssl_context=None)  # the system's authorities don't know the test authority
    assert "certificate wasn't accepted" in str(unknown_authority) and "cafile=" in str(unknown_authority)
    assert run(select_one(server, server_hostname="localhost"))[0] == ((1,),)  # a name the certificate carries


def test_tds_8_refuses_a_context_that_doesnt_verify(server):
    anything = ssl.create_default_context()
    anything.check_hostname, anything.verify_mode = False, ssl.CERT_NONE
    e = refused(server, tds_version="8.0", ssl_context=anything)
    assert e.step == "secure" and "TDS 8.0 requires verifying the server's certificate" in str(e)
    assert "man in the middle" in str(e) and "tds_version='7.4'" in str(e)
    assert run(select_one(server, ssl_context=anything))[0] == ((1,),)  # 7.4 allows it, as the application chose


def test_tls_1_3_only_needs_tds_8(server):
    modern = trust_test_authority()
    modern.minimum_version = ssl.TLSVersion.TLSv1_3
    assert run(select_one(server, tds_version="8.0", ssl_context=modern))[0] == ((1,),)
    e = refused(server, ssl_context=tls_1_3_only())
    assert e.step == "secure" and "negotiates TLS 1.2 at most" in str(e) and "TLSv1_3" in str(e)


def tls_1_3_only() -> ssl.SSLContext:
    context = trust_test_authority()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def test_choosing_the_version():
    with pytest.raises(ValueError, match="strict=True is TDS 8.0"):
        run(tds.connect("127.0.0.1", 1, user="sa", password="x", strict=True, tds_version="7.4"))
    with pytest.raises(ValueError, match='tds_version is "7.4" or "8.0"'):
        run(tds.connect("127.0.0.1", 1, user="sa", password="x", tds_version="7.3"))


def test_a_server_without_tds_8_says_what_to_do():
    async def go():
        async def closes(reader, writer):  # reads the TLS ClientHello and closes, as a 7.x-only server does
            await reader.read(1024)
            writer.close()

        server = await asyncio.start_server(closes, "127.0.0.1", 0)
        try:
            with pytest.raises(ConnectError) as failed:
                await tds.connect("127.0.0.1", server.sockets[0].getsockname()[1], user="sa", password="x",
                                  tds_version="8.0", timeout=5)
            return failed.value
        finally:
            server.close()

    e = asyncio.run(go())
    assert e.step == "secure" and "may not support TDS 8.0" in str(e) and "tds_version='7.4'" in str(e)
