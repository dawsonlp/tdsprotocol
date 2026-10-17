"""PRELOGIN (hello): the two sides exchange versions and agree on encryption before logging in.

Reference: PRELOGIN. Checked against MS-TDS v20260617, §2.2.6.5.
"""

import enum

from .wire import Directory, Field, Raw, Struct, U8, U16, U16BE, U32


class Encryption(enum.IntEnum):
    OFF = 0
    ON = 1
    NOT_SUPPORTED = 2
    REQUIRED = 3


class OnOff(enum.IntEnum):
    OFF = 0
    ON = 1


VERSION = Struct("version", [
    Field("major", U8),
    Field("minor", U8),
    Field("build", U16BE),
    Field("sub_build", U16),
], summary=lambda v: f"{v.major}.{v.minor}.{v.build}")

INSTANCE_MATCH = b"\x00"  # from the client it means the default instance, and from the server it means “that is me”

OPTIONS = Directory(option=U8, offset=U16BE, length=U16BE, terminator=0xFF, options={
    0x00: Field("version", VERSION),
    0x01: Field("encryption", U8, enum=Encryption),
    0x02: Field("instance", Raw(), fmt=lambda v: "match" if v == INSTANCE_MATCH else v.hex(" ").upper()),
    0x03: Field("thread_id", U32),
    0x04: Field("mars", U8, enum=OnOff),
    0x05: Field("trace_id", Raw(36)),
    0x06: Field("fed_auth_required", U8),
    0x07: Field("nonce", Raw(32)),
})

PRELOGIN = Struct("PRELOGIN", [Field("options", OPTIONS)], source="§2.2.6.5",
                  summary=lambda p: f"encryption {p.options.encryption.name.lower()} · MARS {p.options.get('mars', OnOff.OFF).name.lower()}")


def outcome(client: Encryption, server: Encryption) -> str:
    """The encryption outcome (7.4): 'full', 'login only', 'none', or 'refused' (the server closes the connection)."""
    if server in (Encryption.ON, Encryption.REQUIRED):
        return "full"
    if server == Encryption.OFF:
        return "refused" if client == Encryption.ON else "login only"
    return "refused" if client == Encryption.ON else "none"
