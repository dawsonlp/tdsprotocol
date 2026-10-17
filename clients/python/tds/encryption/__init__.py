"""Always Encrypted: a protocol extension over a connection (D-60).

The core reads and writes Always Encrypted's wire elements and shows encrypted values as ciphertext. This package
adds what TDS doesn't carry: the keys, the cryptography, and the describing of a call's parameters before they are
encrypted. It needs a cryptography library, which pip install 'tds[encryption]' installs.

Read in this order: cell (how a value is encrypted) → keys (master keys and column keys) → normalize (a value's
plaintext) → context (the shared Encryption, and the connections and serial channels it wraps) → backend (what the
cryptography library provides).

    encryption = Encryption([LocalKeyStore("keys")])
    async with await encryption.connect(host, port, user=…, password=…, database=…) as connection:
        async with connection.serial_channel() as channel:
            await channel.exchange(tds.Call(tds.Builtin.SP_EXECUTESQL, …, tds.Param("@ssn", types.char(11), "…")))
"""

from .backend import Backend, CryptographyBackend
from .cell import DecryptionFailed
from .context import EncryptedConnection, EncryptedPool, EncryptedSerialChannel, Encryption, EncryptionNotAgreed
from .keys import KeyNotDecrypted, KeyStore, LocalKeyStore

__all__ = ["Encryption", "EncryptedConnection", "EncryptedSerialChannel", "EncryptedPool", "EncryptionNotAgreed",
           "KeyStore", "LocalKeyStore", "KeyNotDecrypted", "DecryptionFailed", "Backend", "CryptographyBackend"]
