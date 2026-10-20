"""The owner-approved policy for Azure features the driver does not implement (PY-AZ-06), as Rust has it: an explicit
request warns; an absent or disabled acknowledgement allows the login; an enabled one closes the connection before
any SQL, with no retry without the feature; an unrequested, malformed or duplicate acknowledgement is a protocol
error. Azure SQL enabled three of the four (1/1/0/1) in both live campaigns."""

import asyncio

import pytest

import tds
from conftest import trust_test_authority
from tds import Feature
from tds.connection.core import ConnectError
from test_logins import DONE, FakeServer, login_ack

UNSUPPORTED = [Feature.AZURE_SQL_SUPPORT, Feature.AZURE_DNS_CACHING, Feature.ENHANCED_ROUTING,
               Feature.GLOBAL_TRANSACTIONS]


def acknowledged(*entries: tuple[int, bytes]) -> bytes:
    """LOGINACK, a FEATUREEXTACK with these (feature, data) entries, then DONE."""
    features = b"".join(bytes([f]) + len(d).to_bytes(4, "little") + d for f, d in entries)
    return login_ack()[:-len(DONE)] + b"\xae" + features + b"\xff" + DONE


def opening(server: FakeServer, features):
    async def go():
        port = await server.start()
        try:
            async with await tds.connect("localhost", port, user="u", password="p", tds_version="8.0",
                                         ssl_context=trust_test_authority(),
                                         features=[*tds.DEFAULT_FEATURES, *features]) as connection:
                return dict(connection.features)
        finally:
            server.server.close()

    return asyncio.run(go())


@pytest.mark.parametrize("feature", UNSUPPORTED)
def test_a_request_warns_and_an_absent_or_disabled_acknowledgement_allows_the_login(feature):
    for answer in (login_ack(), acknowledged((feature, b"\x00"))):
        with pytest.warns(tds.UnsupportedFeatureWarning, match=feature.name):
            features = opening(FakeServer([answer, DONE]), [feature])
        assert features.get(feature) in (None, b"\x00")


@pytest.mark.parametrize("feature", UNSUPPORTED)
def test_an_enabled_acknowledgement_closes_the_connection_before_any_sql_and_is_not_retried(feature):
    server = FakeServer([acknowledged((feature, b"\x01")), DONE])
    with pytest.warns(tds.UnsupportedFeatureWarning), pytest.raises(tds.UnsupportedFeatureEnabled) as failed:
        opening(server, [feature])
    assert failed.value.feature == feature and failed.value.step == "log in"
    assert len(server.received) == 1  # LOGIN7 only: no SQL, and no second login without the feature


@pytest.mark.parametrize("answer", [
    acknowledged((Feature.GLOBAL_TRANSACTIONS, b"\x00")),  # unrequested
    acknowledged((Feature.AZURE_DNS_CACHING, b"\x02")),  # not 0 or 1
    acknowledged((Feature.AZURE_DNS_CACHING, b"\x01\x00")),  # too long
], ids=["unrequested", "value", "length"])
def test_unrequested_or_malformed_acknowledgements_are_protocol_errors(answer):
    with pytest.warns(tds.UnsupportedFeatureWarning), pytest.raises(ConnectError, match="unrequested or malformed"):
        opening(FakeServer([answer, DONE]), [Feature.AZURE_DNS_CACHING])


def test_a_duplicate_acknowledgement_is_a_protocol_error():
    answer = acknowledged((Feature.ENHANCED_ROUTING, b"\x00"), (Feature.ENHANCED_ROUTING, b"\x00"))
    with pytest.warns(tds.UnsupportedFeatureWarning), pytest.raises(Exception, match="appears twice"):
        opening(FakeServer([answer, DONE]), [Feature.ENHANCED_ROUTING])


def test_default_features_ask_for_none_of_them_and_do_not_warn(recwarn):
    opening(FakeServer([login_ack(), DONE]), [])
    assert not [w for w in recwarn if issubclass(w.category, tds.UnsupportedFeatureWarning)]
    assert not set(tds.DEFAULT_FEATURES) & set(UNSUPPORTED)
