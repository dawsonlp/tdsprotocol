"""MC-SMP frame validation and credit, independent of a server's packetization."""
import pytest
from tds.connection.core import (ConnectionCore, MARS_HEADER, MarsData, MarsFlags, Options, Receive, Send)
from tds.packet import PacketType, split
from tds.wire import MalformedMessage


def ready():
    core = ConnectionCore(Options("localhost", 1433, "unused", "unused"))
    core.link.mars = True
    channel, _ = core.open_channel("owner")
    return core, channel


def frame(channel, flags=MarsFlags.DATA, sequence=1, window=4, payload=b"", length=None):
    header, _ = MARS_HEADER.encode({"id": 0x53, "flags": flags, "session_id": channel,
                                    "length": 16 + len(payload) if length is None else length,
                                    "sequence": sequence, "window": window}, False)
    return header + payload


@pytest.mark.parametrize("length", [0, 15, 1 << 20 | 1, 0xffffffff])
def test_invalid_lengths_fail_before_buffering_or_looping(length):
    core, channel = ready()
    with pytest.raises(MalformedMessage):
        core.feed(frame(channel, length=length))


@pytest.mark.parametrize("flags", [0, 3, 6, 16])
def test_invalid_flags_fail(flags):
    core, channel = ready()
    raw = bytearray(frame(channel)); raw[1] = flags
    with pytest.raises(MalformedMessage):
        core.feed(raw)


def test_sequence_control_length_window_and_unknown_channel_are_checked():
    for raw in [frame(0, sequence=2), frame(0, MarsFlags.ACK, sequence=1),
                frame(0, MarsFlags.ACK, sequence=0, payload=b"x"),
                frame(0, MarsFlags.ACK, sequence=0, window=3), frame(1), frame(0, MarsFlags.SYN)]:
        core, _ = ready()
        with pytest.raises(MalformedMessage): core.feed(raw)
    core, channel = ready()
    for sequence in range(1, 5): core.feed(frame(channel, sequence=sequence))
    with pytest.raises(MalformedMessage): core.feed(frame(channel, sequence=5))


def test_each_byte_boundary_and_credit_for_split_or_combined_tds_packets():
    done = bytes.fromhex("FD 01 00 00 00 00 00 00 00 00 00 00 00")
    packet = split(PacketType.SERVER_MESSAGE, done, 4096, False)[0][0]
    raw = frame(0, payload=packet)
    for cut in range(len(raw) + 1):
        core, channel = ready()
        incoming = core.feed(raw[:cut]) + core.feed(raw[cut:])
        assert incoming == [(channel, MarsData(packet))]
    core, channel = ready()
    # One packet spanning four SMP frames: each consumed frame returns credit.
    procedure = core._receive_packet(core.link.channels[channel])
    assert next(procedure) == Receive(channel)
    acks = []
    for sequence, payload in enumerate([packet[:2], packet[2:4], packet[4:6], packet[6:]], 1):
        incoming = core.feed(frame(channel, sequence=sequence, payload=payload))[0][1]
        try:
            action = procedure.send(incoming)
            while isinstance(action, Send):
                acks.append(action); action = procedure.send(None)
            assert action == Receive(channel)
        except StopIteration as end:
            assert end.value.raw == packet
    assert core.link.channels[channel].consumed == 4 and len(acks) == 1
    # Two TDS packets in one frame consume only one unit of SMP credit.
    core, channel = ready()
    incoming = core.feed(frame(channel, payload=packet + packet))[0][1]
    procedure = core._receive_packet(core.link.channels[channel]); next(procedure)
    with pytest.raises(StopIteration) as end: procedure.send(incoming)
    assert end.value.value.raw == packet
    procedure = core._receive_packet(core.link.channels[channel])
    with pytest.raises(StopIteration) as end: next(procedure)
    assert end.value.value.raw == packet and core.link.channels[channel].consumed == 1


def test_wrapping_sequence_and_data_in_flight_after_fin():
    core, channel = ready(); state = core.link.channels[channel]
    state.received = state.consumed = 0xffffffff; state.receive_window = 3
    assert core.feed(frame(channel, sequence=0)) == [(channel, MarsData(b""))]
    core.close_channel(channel)
    assert core.feed(frame(channel, sequence=1)) == []
    assert core.feed(frame(channel, MarsFlags.FIN, sequence=1)) == [(channel, None)]
