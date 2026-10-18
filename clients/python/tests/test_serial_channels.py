"""Tests of the serial-channel rules (D-20 to D-23) against the core alone, with no server and no network."""

import pytest

from tds import Batch
from tds.connection.core import (MARS_HEADER, MARS_HEADER_SIZE, AwaitWindow, ConnectionCore, ExchangeInProgress,
                                 ChannelClosed, MarsFlags, NotTheOwner, Options, Receive, Send, TooManySerialChannels)

ALICE, BOB = object(), object()  # two tasks


def sent(procedure) -> list:
    """Run a procedure that only sends, to its end. Returns what it yielded."""
    actions = []
    try:
        while True:
            actions.append(procedure.send(None))
    except StopIteration:
        return actions


def ready(mars: bool = False) -> ConnectionCore:
    core = ConnectionCore(Options("localhost", 1433, "sa", "unused"))
    core.link.mars = mars  # as if connect() had just finished
    return core


def test_without_mars_a_second_channel_fails_and_the_first_is_unaffected():  # D-20
    core = ready()
    first, _ = core.open_channel(ALICE)
    with pytest.raises(TooManySerialChannels):
        core.open_channel(ALICE)
    assert not core.link.channels[first].closed


def test_a_closed_channel_can_be_replaced():
    core = ready()
    first, _ = core.open_channel(ALICE)
    core.close_channel(first)
    second, _ = core.open_channel(BOB)
    assert second != first
    assert len(core.link.channels) == 1  # closed plain lifetimes do not accumulate
    assert core.close_channel(first) == []
    assert not core.link.channels[second].closed
    with pytest.raises(ChannelClosed):
        next(core.exchange(first, ALICE, Batch("SELECT 2")))
    with pytest.raises(ChannelClosed):
        core.hand_over(first, ALICE, BOB)
    with pytest.raises(ChannelClosed):
        core.resume(first)


def test_busy_close_revokes_but_cannot_release_or_replace_until_acknowledgement():
    from tds.packet import Packet, PacketType, Status
    core = ready()
    channel, _ = core.open_channel(ALICE)
    sent(core.exchange(channel, ALICE, Batch("SELECT 1")))
    with pytest.raises(ExchangeInProgress):
        core.close_channel(channel)
    assert len(core.begin_channel_close(channel)) == 1
    assert core.begin_channel_close(channel) == []
    with pytest.raises(ChannelClosed):
        next(core.read(channel, ALICE))
    with pytest.raises(TooManySerialChannels):
        core.open_channel(BOB)
    assert core.release() == (False, [])
    draining = core.drain_channel(channel)
    assert next(draining) == Receive(channel)
    normal = Packet(PacketType.SERVER_MESSAGE, Status.LAST, bytes.fromhex("FD 00 00 00 00 00 00 00 00 00 00 00 00"), None)
    assert draining.send(normal) == Receive(channel)
    ack = Packet(PacketType.SERVER_MESSAGE, Status.LAST, bytes.fromhex("FD 20 00 00 00 00 00 00 00 00 00 00 00"), None)
    with pytest.raises(StopIteration):
        draining.send(ack)
    assert not core.link.channels[channel].busy
    core.close_channel(channel)
    replacement, _ = core.open_channel(BOB)
    assert replacement != channel
    assert core.cancel(channel) == []


def test_with_mars_channels_open_as_sessions():
    core = ready(mars=True)
    ids = [core.open_channel(ALICE)[0] for _ in range(3)]
    assert ids == [0, 1, 2]


def test_only_the_owner_may_send():  # D-21
    core = ready()
    channel, _ = core.open_channel(ALICE)
    with pytest.raises(NotTheOwner):
        next(core.exchange(channel, BOB, Batch("SELECT 1")))


def test_one_request_at_a_time():  # D-22
    core = ready()
    channel, _ = core.open_channel(ALICE)
    assert [type(a) for a in sent(core.exchange(channel, ALICE, Batch("SELECT 1")))] == [Send]
    assert next(core.read(channel, ALICE)) == Receive(channel)  # the response is still open
    with pytest.raises(ExchangeInProgress):
        next(core.exchange(channel, ALICE, Batch("SELECT 2")))


def test_known_connection_failure_precedes_busy_state_before_any_shell_wait():
    core = ready()
    channel, _ = core.open_channel(ALICE)
    sent(core.exchange(channel, ALICE, Batch("SELECT 1")))
    core.failure = OSError("connection lost")
    with pytest.raises(ConnectionError, match="can't continue"):
        core.exchange_channel(channel, ALICE)
    with pytest.raises(ConnectionError, match="can't continue"):
        next(core.exchange(channel, ALICE, Batch("SELECT 2")))


@pytest.mark.parametrize("mars", [False, True])
def test_recovery_never_revives_a_revoked_lifetime_or_reuses_its_identity(mars):
    from tds.session import Recovery, SessionState
    old = ready(mars)
    owner = object()
    channel, _ = old.open_channel(owner)
    sent(old.exchange(channel, owner, Batch("SELECT 1")))
    old.begin_channel_close(channel)  # as if transport failed before cleanup completed
    old.recovery = Recovery(SessionState(), {})
    recovered = ready(mars)
    recovered.adopt(old)
    assert channel not in recovered.link.channels
    replacement, _ = recovered.open_channel(owner)
    assert replacement != channel
    assert recovered.close_channel(channel) == []


def test_anyone_may_close():  # D-23
    core = ready()
    channel, _ = core.open_channel(ALICE)
    core.close_channel(channel)  # called for Bob, with no owner check
    assert core.link.channels[channel].closed


def test_ownership_can_be_handed_over():  # D-21
    core = ready()
    channel, _ = core.open_channel(ALICE)
    core.hand_over(channel, ALICE, BOB)
    assert isinstance(next(core.exchange(channel, BOB, Batch("SELECT 1"))), Send)


def test_mars_waits_for_the_servers_window_instead_of_failing():
    """A request that needs more data frames than the server's credit pauses, then resumes when the window grows."""
    core = ready(mars=True)
    channel, _ = core.open_channel(ALICE)
    request = core.exchange(channel, ALICE, Batch("SELECT '" + "x" * 12000 + "'"))  # 24 KB of UTF-16, 6 packets at 4096
    actions = [next(request)]
    while isinstance(actions[-1], Send):
        actions.append(request.send(None))
    assert [type(a) for a in actions] == [Send] * 4 + [AwaitWindow]  # the starting credit is 4 frames

    ack, _ = MARS_HEADER.encode({"id": 0x53, "flags": MarsFlags.ACK, "session_id": channel, "length": MARS_HEADER_SIZE,
                                 "sequence": 0, "window": 8})
    assert core.feed(ack) == []  # the server raises the window to 8
    assert [type(a) for a in sent(request)] == [Send, Send]  # the last two frames. The response is read next.


# --------------------------------------------------------------------------- giving a connection back (D-36)

def test_giving_back_with_a_request_in_flight_is_refused():
    core = ready()
    channel, _ = core.open_channel(ALICE)
    sent(core.exchange(channel, ALICE, Batch("WAITFOR DELAY '00:00:05'")))  # sent, and its response is not read yet
    reusable, _ = core.release()
    assert not reusable


def test_an_abandoned_request_stays_in_flight():
    """If the task making a request is canceled, the server can still send the response.

    The channel must therefore not look clean, or the pool would lend the connection to a borrower who would then read
    that response.
    """
    core = ready()
    channel, _ = core.open_channel(ALICE)
    sent(core.exchange(channel, ALICE, Batch("WAITFOR DELAY '00:00:05'")))
    reading = core.read(channel, ALICE)
    next(reading)  # waiting for the response
    reading.close()  # what Python does to a procedure whose task was canceled
    assert core.link.channels[channel].busy
    assert core.release() == (False, [])


def test_giving_back_resets_the_session_on_the_next_request():
    core = ready()
    channel, _ = core.open_channel(ALICE)
    reusable, _ = core.release()
    assert reusable and core.reset_pending
    channel, _ = core.open_channel(BOB)
    first = next(core.exchange(channel, BOB, Batch("SELECT 1")))
    status = first.data[1]  # no TLS in this test, so these are the first packet's own bytes
    assert status & 0x08, "the first packet carries the reset flag"
    assert not core.reset_pending


def test_a_value_that_fails_to_encode_leaves_the_channel_free_and_the_reset_pending():
    class Unencodable:
        kind, name = Batch.kind, "broken"

        def encode(self, context, record):
            raise ValueError("doesn't fit")

    core = ready()
    channel, _ = core.open_channel(ALICE)
    core.reset_pending = True
    with pytest.raises(ValueError):
        next(core.exchange(channel, ALICE, Unencodable()))
    assert not core.link.channels[channel].busy and core.reset_pending  # nothing was sent


def test_cancel_sends_attention_once_from_anyone():  # D-23
    core = ready()
    channel, _ = core.open_channel(ALICE)
    sent(core.exchange(channel, ALICE, Batch("WAITFOR DELAY '00:00:05'")))
    [attention] = core.cancel(channel)  # no owner check
    assert attention.data[0] == 0x06 and attention.data[1] & 0x01  # header only, marked last
    assert core.cancel(channel) == []  # already canceling


def test_mars_returns_credit_as_the_owner_reads_not_as_packets_arrive():
    core = ready(mars=True)
    channel, _ = core.open_channel(ALICE)
    sent(core.exchange(channel, ALICE, Batch("SELECT 1")))
    reading = core.read(channel, ALICE)
    assert next(reading) == Receive(channel)
    from tds.packet import Packet, PacketType, Status
    packet = Packet(PacketType.SERVER_MESSAGE, Status(0), bytes.fromhex("FD 01 00 C1 00 00 00 00 00 00 00 00 00"), None)
    acks = []
    for _ in range(3):  # three packets read. The window must open again before the server has no credit left.
        try:
            action = reading.send(packet)
            while isinstance(action, Send):
                acks.append(action)
                action = reading.send(None)
        except StopIteration:
            pass
        reading = core.read(channel, ALICE)
        next(reading)
    assert len(acks) == 1 and core.link.channels[channel].receive_window == 3 + 4  # reopened once 3 had been read
