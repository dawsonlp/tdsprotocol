"""Session state: what the client knows about the session. Only the server's announcements (ENVCHANGE, and
SESSIONSTATE when the login asked for session recovery) change it.

Reference: Login Response › ENVCHANGE; Connect › Session recovery. Checked against MS-TDS v20260617, §2.2.7.9,
§2.2.7.21, and §2.2.6.4 (the session recovery feature).
"""

from dataclasses import dataclass, field, replace

from .packet import DEFAULT_SIZE
from .tokens import SESSION_STATE, TRANSACTION_KINDS, EnvKind
from .wire import Blob, Field, Prefixed, Record, Repeat, Struct, Text, U8, U32


@dataclass
class SessionState:
    database: str = ""
    language: str = ""
    packet_size: int = DEFAULT_SIZE  # takes effect from the message after the one that announced it
    collation: bytes = b""
    transaction: int = 0  # the current transaction descriptor; 0 when none is open
    mirroring_partner: str = ""  # the server's database mirroring partner, if any. It is shown, not acted on (D-58)

    def apply(self, change: Record) -> None:
        match change.kind:
            case EnvKind.DATABASE:
                self.database = change.new
            case EnvKind.LANGUAGE:
                self.language = change.new
            case EnvKind.PACKET_SIZE:
                self.packet_size = int(change.new)
            case EnvKind.COLLATION:
                self.collation = change.new
            case EnvKind.MIRRORING_PARTNER:
                self.mirroring_partner = change.new
            case kind if kind in TRANSACTION_KINDS:  # the new value is the transaction descriptor, or empty for none
                self.transaction = int.from_bytes(change.new, "little")

    def snapshot(self) -> SessionState:
        return replace(self)

    def restore(self, login: SessionState) -> None:
        """After a session reset, put the session back to what login established. The transaction is left to the
        server's own announcements, because MS-TDS says that a reset doesn't reset distributed transactions."""
        self.database, self.language = login.database, login.language
        self.packet_size, self.collation = login.packet_size, login.collation


# =========================================================================== session recovery (D-57)
# A login that asks for session recovery gets the session's initial states in its acknowledgement. SESSIONSTATE
# tokens then report each change. To recover a broken connection, a new connection logs in carrying two snapshots:
# the session as login established it, and as it is now. The server rebuilds the session from them.

STATES = Repeat(None, SESSION_STATE)  # states one after another, to the end (§2.2.7.21)

INITIAL_STATES = Struct("initial session states", [Field("states", STATES)])  # the acknowledgement's data

RECOVERY_DATA = Struct("session", [
    Field("database", Text(U8)),  # in the “now” snapshot, empty when unchanged
    Field("collation", Blob(U8)),
    Field("language", Text(U8)),
    Field("states", STATES),  # in the “now” snapshot, only the states that changed
])

RECOVERY = Struct("session recovery", [  # a recovery login's data for the session recovery feature
    Field("initial", Prefixed(U32, RECOVERY_DATA)),
    Field("now", Prefixed(U32, RECOVERY_DATA)),
], source="§2.2.6.4")

NOT_RECOVERABLE = 0xFE  # observed: the state SQL Server uses to say the session can't be recovered, and why
REASONS = {  # its value, a u32, as observed from SQL Server 2025 (17.0.5015). MS-TDS defines neither state nor codes
    0x03: "the session was killed (KILL) while a request ran",
    0x04: "a transaction is open",
    0x05: "a temporary table exists",
    0x0D: "the session is impersonating another login (EXECUTE AS)",
}
LAST_SEQUENCE = 0xFFFFFFFF  # when a state's sequence number reaches this, recovery is off for the connection


@dataclass
class Recovery:
    """What recovering the session needs, as the server reported it (D-57). That is the session as login established
    it, and each state's latest value, with its sequence number and whether the server said it can be recovered."""

    initial: SessionState  # database, language and collation, from the first login's announcements
    initial_states: dict[int, bytes]  # from the first login's acknowledgement
    states: dict[int, bytes] = field(default_factory=dict)  # each state's latest value
    sequences: dict[int, int] = field(default_factory=dict)  # each state's latest sequence number, on this connection
    blocked: dict[int, tuple[bytes, str]] = field(default_factory=dict)  # states the server marked not recoverable,
    # with each one's value and the request after which the server said so
    exhausted: bool = False

    def __post_init__(self):
        if not self.states:
            self.states = dict(self.initial_states)

    def follow(self, token: Record, after: str) -> None:
        """Apply a SESSIONSTATE token: the states it carries changed. A change is ignored if its state is already known
        at the same or a later sequence number."""
        if token.sequence == LAST_SEQUENCE:
            self.exhausted = True
        recoverable = bool(token.status & 1)
        for s in token.states:
            if self.sequences.get(s.id, -1) >= token.sequence:
                continue
            self.sequences[s.id], self.states[s.id] = token.sequence, s.value
            if recoverable:
                self.blocked.pop(s.id, None)
            else:
                self.blocked[s.id] = (s.value, after)

    def reset(self) -> None:
        """The session was reset. It is back to what login established, and so are its states (§2.2.6.4)."""
        self.states, self.blocked = dict(self.initial_states), {}

    def refusal(self) -> str | None:
        """Why the session can't be recovered, or None if it can."""
        if self.exhausted:
            return ("its session state's sequence number reached FFFFFFFF, which turns session recovery off for the "
                    "rest of the connection (MS-TDS §2.2.7.21)")
        if self.blocked:
            return "; ".join(f"the server marked it not recoverable after {after}: {_reason(state, value)}"
                             for state, (value, after) in self.blocked.items())
        return None

    def data(self, now: SessionState, reset: bool = False) -> dict:
        """The recovery login's data: the session as login established it, and as it is now (only what differs).
        A state the server sent with no value is left out, as MS-TDS asks."""
        init, states = self.initial, self.initial_states
        current, current_states = (init, states) if reset else (now, self.states)
        return {
            "initial": {"database": init.database, "collation": init.collation, "language": init.language,
                        "states": [{"id": i, "value": v} for i, v in states.items() if v]},
            "now": {"database": current.database if current.database != init.database else "",
                    "collation": current.collation if current.collation != init.collation else b"",
                    "language": current.language if current.language != init.language else "",
                    "states": [{"id": i, "value": v} for i, v in current_states.items()
                               if v and i != NOT_RECOVERABLE and states.get(i) != v]},
        }


def _reason(state: int, value: bytes) -> str:
    if state != NOT_RECOVERABLE:
        return f"state {state} (value {value.hex(' ').upper()})"
    code = int.from_bytes(value, "little")
    known = REASONS.get(code)
    return (f"{known} (state {NOT_RECOVERABLE}, reason {code}, as observed: MS-TDS doesn't define them)" if known else
            f"state {NOT_RECOVERABLE}, reason {code}, which the driver hasn't seen before (MS-TDS doesn't define them)")
