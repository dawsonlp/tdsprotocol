"""Always Encrypted with secure enclaves (D-60, M18): the enclave session, and the column keys sent to the enclave.

With an enclave, the server can compute on encrypted values (LIKE, ranges, in-place encryption) inside protected
memory that it can't read itself. The client sends the column keys a statement needs to the enclave, encrypted with
a key only the client and the enclave share. MS-TDS carries the bytes without describing them. Source:
SqlClient (NoneAttestationEnclaveProvider, EnclaveDelegate, KeyConverter, ColumnEncryptionKeyInfo).

Attestation proves to the client that the enclave is genuine, through Microsoft Azure Attestation or a Host Guardian
Service. This module runs the protocol without attestation ("None"), which Azure SQL Database's VBS enclaves offer.
Without attestation, the client trusts the server to run a real enclave. The steps:

  1. Describing a statement sends @attestationParameters: the protocol (u32: 2, None), an empty input (u32 0), and the
     client's ECDH public key on P-384 (u32 length, then a 104-byte blob: “ECK3”, u32 48, x, y).
  2. The describing call's third result set is the enclave's attestation info: an empty trusted-module part (u32 0),
     the size of what follows (u32), the session's handle (8 bytes), the enclave's public key's and signature's sizes
     (u32 each), the enclave's public key (the same blob layout), and its signature.
  3. The session key is SHA-256 of the ECDH shared secret.
  4. Each call that needs the enclave carries an enclave package. The package is the session handle, then the following,
     encrypted with the session key as a column key (randomized): a GUID, the session's counter (i64, incremented for
     each package), SHA-256 of the statement (UTF-16LE), and each column key as database id (u32), metadata version
     (8 bytes), key id (u16), the key.
"""

import hashlib
import struct
import uuid
from dataclasses import dataclass, field

from .backend import Backend
from .cell import CellKey, DecryptionFailed

NONE = 2  # attestation protocols: AAS 1, None 2, HGS 3 (SqlClient's numbering)
ECK3 = b"ECK3"  # an ECDH P-384 public key blob's magic
POINT = 48


def _blob(x: bytes, y: bytes) -> bytes:
    return ECK3 + POINT.to_bytes(4, "little") + x + y


def attestation_parameters(backend: Backend):
    """The describing call's @attestationParameters, and the private key the session will be derived from."""
    key, x, y = backend.ecdh_p384()
    blob = _blob(x, y)
    return NONE.to_bytes(4, "little") + bytes(4) + len(blob).to_bytes(4, "little") + blob, key


@dataclass
class EnclaveSession:
    handle: bytes  # 8 bytes, as the enclave named the session
    key: CellKey = field(repr=False)
    counter: int = 0

    def package(self, statement: str, keys: list[tuple[int, bytes, int, bytes]]) -> bytes:
        """The enclave package for one call: `keys` are (database id, metadata version, key id, column key)."""
        self.counter += 1
        body = (uuid.uuid4().bytes_le + struct.pack("<q", self.counter)
                + hashlib.sha256(statement.encode("utf-16-le")).digest()
                + b"".join(struct.pack("<I", db) + version + struct.pack("<H", key_id) + root
                           for db, version, key_id, root in keys))
        return self.handle + self.key.encrypt(body, deterministic=False)


def session(info: bytes, private_key, backend: Backend) -> EnclaveSession:
    """The session made from the enclave's attestation info (without attestation) and the client's private key."""
    try:
        trusted, _secure = struct.unpack_from("<II", info, 0)
        at = 8 + trusted
        handle = info[at : at + 8]
        public_size, _signature_size = struct.unpack_from("<II", info, at + 8)
        blob = info[at + 16 : at + 16 + public_size]
    except struct.error:
        raise DecryptionFailed(f"the enclave's attestation info is {len(info)} bytes: too short to read") from None
    if blob[:4] != ECK3 or len(blob) != 8 + 2 * POINT:
        raise DecryptionFailed(f"the enclave's public key isn't a P-384 ECDH key blob ({blob[:4]!r}, {len(blob)} bytes)")
    secret = backend.ecdh_shared(private_key, blob[8 : 8 + POINT], blob[8 + POINT :])
    return EnclaveSession(bytes(handle), CellKey(hashlib.sha256(secret).digest(), backend))
