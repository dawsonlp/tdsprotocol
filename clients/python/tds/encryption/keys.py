"""Keys: master keys in key stores, and the column keys they encrypt (D-60).

The server never holds a key it can use. It stores each column key encrypted by a master key, together with the
master key's key store and path. It sends these to the client, which asks the key store to decrypt the column key.
A key store is any object with a name and decrypt_column_key. The database names the store by the name given when the
master key was created (CREATE COLUMN MASTER KEY … KEY_STORE_PROVIDER_NAME).

An encrypted column key, as SQL Server's tools write it for RSA master keys (Source: SqlClient,
EncryptedColumnEncryptionKeyParameters; not in MS-TDS):
  version (01) · key path length (u16, bytes) · ciphertext length (u16) · key path (UTF-16LE)
  · ciphertext: the column key, RSA-OAEP (SHA-1) with the master key · signature: RSA PKCS#1 v1.5 (SHA-256) over all
  that came before
The signature proves that the master key's owner wrote the value, so a column key can't be replaced by another.
"""

import os
from pathlib import Path
from typing import Protocol

from .backend import Backend, CryptographyBackend

KEY_VERSION = 0x01
RSA_OAEP = "RSA_OAEP"


class KeyStore(Protocol):
    name: str  # as the database names the store

    def decrypt_column_key(self, key_path: str, algorithm: str, encrypted: bytes) -> bytes: ...

    # For enclaves. A master key's signature over its own metadata says whether its column keys may go to an enclave.
    def verify_master_key_metadata(self, key_path: str, enclaves: bool, signature: bytes) -> bool: ...


def master_key_metadata(store: str, key_path: str, enclaves: bool) -> bytes:
    """What a master key signs to allow or forbid enclave computations: its store, its path and the setting,
    lowercased, in UTF-16LE (Source: SqlClient, ColumnMasterKeyMetadata). The signature goes in
    CREATE COLUMN MASTER KEY's ENCLAVE_COMPUTATIONS (SIGNATURE = …)."""
    return f"{store}{key_path}{'true' if enclaves else 'false'}".lower().encode("utf-16-le")


class KeyNotDecrypted(ValueError):
    """A column key couldn't be decrypted. The error names the key store and the key path, and says why."""


def wrap(column_key: bytes, key_path: str, master_key, backend: Backend) -> bytes:
    """A column key, encrypted by an RSA master key, in the layout SQL Server's tools write."""
    path = key_path.encode("utf-16-le")
    ciphertext = backend.rsa_oaep_encrypt(master_key, column_key)
    body = (bytes([KEY_VERSION]) + len(path).to_bytes(2, "little") + len(ciphertext).to_bytes(2, "little") + path
            + ciphertext)
    return body + backend.rsa_sign(master_key, body)


def unwrap(encrypted: bytes, key_path: str, master_key, backend: Backend, store: str) -> bytes:
    """The column key, after checking the layout and the signature."""
    where = f"the column key encrypted by {store} master key “{key_path}”"
    size = backend.rsa_size(master_key)
    if len(encrypted) < 5 or encrypted[0] != KEY_VERSION:
        raise KeyNotDecrypted(f"{where}: not an encrypted column key this driver knows (version "
                              f"{encrypted[0] if encrypted else 'missing'}; expected {KEY_VERSION})")
    path_length = int.from_bytes(encrypted[1:3], "little")
    ciphertext_length = int.from_bytes(encrypted[3:5], "little")
    start = 5 + path_length
    if ciphertext_length != size or len(encrypted) != start + ciphertext_length + size:
        raise KeyNotDecrypted(f"{where}: its ciphertext is {ciphertext_length} bytes and the whole value "
                              f"{len(encrypted)}, but this master key is {size} bytes: it may be encrypted by "
                              "another master key")
    body, signature = encrypted[: start + ciphertext_length], encrypted[start + ciphertext_length :]
    if not backend.rsa_verify(master_key, signature, body):
        raise KeyNotDecrypted(f"{where}: its signature doesn't verify: it was encrypted by another master key, or "
                              "changed since")
    try:
        return backend.rsa_oaep_decrypt(master_key, body[start:])
    except ValueError as e:
        raise KeyNotDecrypted(f"{where}: the master key can't decrypt it ({e})") from None


class LocalKeyStore:
    """Master keys as RSA private keys in PEM files, in one directory. A key path is a file name in it.

        store = LocalKeyStore("keys")
        store.create_master_key("cmk.pem")                   # once
        value = store.encrypt_column_key("cmk.pem")           # for CREATE COLUMN ENCRYPTION KEY … ENCRYPTED_VALUE

    The files are the keys. Anyone who can read the files can read the data."""

    name = "TDS_LOCAL_KEYS"

    def __init__(self, directory: str | os.PathLike, backend: Backend | None = None):
        self.directory = Path(directory)
        self.backend = backend or CryptographyBackend()

    def _file(self, key_path: str) -> Path:
        path = (self.directory / key_path).resolve()
        if not path.is_relative_to(self.directory.resolve()):
            raise KeyNotDecrypted(f"{self.name} key path “{key_path}” leads outside {self.directory}: a key path names "
                                  "a file in the store's directory")
        return path

    def _master_key(self, key_path: str):
        path = self._file(key_path)
        try:
            return self.backend.rsa_key(path.read_bytes())
        except FileNotFoundError:
            raise KeyNotDecrypted(f"{self.name} has no master key “{key_path}”: no file {path}") from None
        except ValueError as e:
            raise KeyNotDecrypted(f"{self.name} master key “{key_path}” isn't an RSA private key in PEM ({e})") from None

    def create_master_key(self, key_path: str, bits: int = 2048) -> None:
        """Write a new RSA private key. It refuses to replace an existing key, because the data that the existing key's
        column keys protect would be lost."""
        path = self._file(key_path)
        if path.exists():
            raise FileExistsError(f"{path} exists: replacing a master key loses every column key it encrypts")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.backend.generate_rsa_key(bits))
        path.chmod(0o600)

    def encrypt_column_key(self, key_path: str, column_key: bytes | None = None) -> bytes:
        """A column key (32 random bytes unless given), encrypted by this master key."""
        return wrap(column_key if column_key is not None else os.urandom(32), key_path, self._master_key(key_path),
                    self.backend)

    def decrypt_column_key(self, key_path: str, algorithm: str, encrypted: bytes) -> bytes:
        if algorithm.upper() != RSA_OAEP:
            raise KeyNotDecrypted(f"{self.name} decrypts column keys encrypted with {RSA_OAEP}, not {algorithm}")
        return unwrap(encrypted, key_path, self._master_key(key_path), self.backend, self.name)

    def sign_master_key_metadata(self, key_path: str, enclaves: bool = True) -> bytes:
        """The signature for CREATE COLUMN MASTER KEY … ENCLAVE_COMPUTATIONS (SIGNATURE = …)."""
        return self.backend.rsa_sign(self._master_key(key_path), master_key_metadata(self.name, key_path, enclaves))

    def verify_master_key_metadata(self, key_path: str, enclaves: bool, signature: bytes) -> bool:
        return self.backend.rsa_verify(self._master_key(key_path), signature,
                                       master_key_metadata(self.name, key_path, enclaves))
