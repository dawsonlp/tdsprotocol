"""How one value is encrypted: AEAD_AES_256_CBC_HMAC_SHA256, as SQL Server's drivers do it (D-60).

MS-TDS names the algorithm but does not describe it. Source: Microsoft's documentation of Always Encrypted
cryptography, and SqlClient (SqlAeadAes256CbcHmac256Algorithm, SqlAeadAes256CbcHmac256EncryptionKey).

A column key is 32 bytes. Three keys are derived from it. Each is an HMAC-SHA-256, keyed with the column key, over a
label in UTF-16LE:
  encryption key   "Microsoft SQL Server cell encryption key with encryption algorithm:… and key length:256"
  MAC key          "Microsoft SQL Server cell MAC key with …"
  IV key           "Microsoft SQL Server cell IV key with …"

How a value is encrypted. Its plaintext is normalized first (normalize.py).
  iv          randomized: 16 random bytes.
              deterministic: the first 16 bytes of HMAC-SHA-256(IV key, plaintext). The same plaintext then always
              gives the same ciphertext, so equality can be tested on the ciphertext.
  ciphertext  AES-256-CBC(encryption key, iv, plaintext), with PKCS#7 padding
  tag         HMAC-SHA-256(MAC key, version + iv + ciphertext + version's length, 1)
  the value   version (01) + tag (32 bytes) + iv (16 bytes) + ciphertext
Decrypting checks the tag first. Nothing is decrypted unless the tag matches.
"""

import hashlib
import hmac
import os

from .backend import Backend

ALGORITHM = "AEAD_AES_256_CBC_HMAC_SHA256"
VERSION = 0x01
KEY_SIZE = 32
BLOCK = 16
SMALLEST = 1 + KEY_SIZE + BLOCK + BLOCK  # version, tag, iv, and at least one block


class DecryptionFailed(ValueError):
    """A value couldn't be decrypted. The error says what was wrong with the value, never its bytes or the key's."""


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _derived(column_key: bytes, kind: str) -> bytes:
    label = f"Microsoft SQL Server cell {kind} with encryption algorithm:{ALGORITHM} and key length:{KEY_SIZE * 8}"
    return _hmac(column_key, label.encode("utf-16-le"))


class CellKey:
    """A column key, with the three keys derived from it."""

    def __init__(self, column_key: bytes, backend: Backend):
        if len(column_key) != KEY_SIZE:
            raise ValueError(f"a column key for {ALGORITHM} is {KEY_SIZE} bytes, not {len(column_key)}")
        self._closed = False
        self.root = bytearray(column_key)  # the column key itself, which is sent to an enclave (enclave.py)
        self._encryption = bytearray(_derived(column_key, "encryption key"))
        self._mac = bytearray(_derived(column_key, "MAC key"))
        self._iv = bytearray(_derived(column_key, "IV key"))
        self._backend = backend

    def close(self) -> None:
        """Overwrite owned buffers. Library/immutable temporary copies are outside this guarantee."""
        self._closed = True
        for name in ("root", "_encryption", "_mac", "_iv"):
            value = getattr(self, name, None)
            if value is not None:
                value[:] = bytes(len(value))

    def __del__(self):
        self.close()

    def _check(self):
        if self._closed:
            raise DecryptionFailed("the column key has been released")

    def encrypt(self, plaintext: bytes, deterministic: bool) -> bytes:
        self._check()
        iv = _hmac(self._iv, plaintext)[:BLOCK] if deterministic else os.urandom(BLOCK)
        ciphertext = self._backend.aes_cbc_encrypt(bytes(self._encryption), iv, plaintext)
        version = bytes([VERSION])
        tag = _hmac(self._mac, version + iv + ciphertext + b"\x01")
        return version + tag + iv + ciphertext

    def decrypt(self, value: bytes) -> bytes:
        self._check()
        if len(value) < SMALLEST:
            raise DecryptionFailed(f"the value is {len(value)} bytes: an encrypted value is at least {SMALLEST}")
        if value[0] != VERSION:
            raise DecryptionFailed(f"the value's version is {value[0]:#04x}; {ALGORITHM} knows version {VERSION:#04x}")
        tag, iv, ciphertext = value[1 : 1 + KEY_SIZE], value[1 + KEY_SIZE : SMALLEST - BLOCK], value[SMALLEST - BLOCK :]
        if len(ciphertext) % BLOCK:
            raise DecryptionFailed(f"the ciphertext is {len(ciphertext)} bytes, not whole {BLOCK}-byte blocks")
        if not hmac.compare_digest(tag, _hmac(self._mac, value[:1] + iv + ciphertext + b"\x01")):
            raise DecryptionFailed("its authentication tag doesn't match: it wasn't encrypted with this column key, "
                                   "or it was changed after it was encrypted")
        try:
            return self._backend.aes_cbc_decrypt(bytes(self._encryption), iv, ciphertext)
        except ValueError as e:  # bad padding after a matching tag means that a faulty encryptor wrote it
            raise DecryptionFailed(f"its tag matches, but its padding is wrong ({e})") from None
