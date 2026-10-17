"""What Always Encrypted needs from a cryptography library, and the one that provides it by default (D-60).

Python itself has HMAC-SHA-256 and random bytes. It has no AES and no RSA, so these come from a library:
  - AES-256 in CBC mode with PKCS#7 padding: each value's encryption;
  - RSA with OAEP padding and SHA-1: a column key, encrypted by its master key;
  - RSA PKCS#1 v1.5 signatures with SHA-256: an encrypted column key's signature, and a master key's;
  - ECDH on P-384: the session key shared with a server's enclave.
SHA-1 and PKCS#1 v1.5 are not this driver's choice. They are what SQL Server's tools and drivers write
(CREATE COLUMN ENCRYPTION KEY).

To use another library instead of the default, give Encryption(backend=…) any object that has these methods.
"""

from typing import Any, Protocol


class Backend(Protocol):
    def aes_cbc_encrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes: ...
    def aes_cbc_decrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes: ...
    def generate_rsa_key(self, bits: int) -> bytes: ...  # a private key, as PEM
    def rsa_key(self, pem: bytes) -> Any: ...  # a private key, from PEM
    def rsa_size(self, key: Any) -> int: ...  # in bytes
    def rsa_oaep_encrypt(self, key: Any, data: bytes) -> bytes: ...
    def rsa_oaep_decrypt(self, key: Any, data: bytes) -> bytes: ...
    def rsa_sign(self, key: Any, data: bytes) -> bytes: ...
    def rsa_verify(self, key: Any, signature: bytes, data: bytes) -> bool: ...
    def ecdh_p384(self) -> tuple[Any, bytes, bytes]: ...  # a new private key, and its public point's x and y
    def ecdh_shared(self, key: Any, x: bytes, y: bytes) -> bytes: ...  # the shared secret with the peer's point


class CryptographyBackend:
    """The backend that uses the `cryptography` package, which pip install 'tds[encryption]' installs."""

    def __init__(self):
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes, padding, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, padding as rsa_padding, rsa
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError as e:
            raise ImportError("tds.encryption needs a cryptography library for AES and RSA, which Python doesn't have: "
                              "pip install 'tds[encryption]' installs the cryptography package, or pass "
                              "Encryption(backend=…) another") from e
        self._invalid, self._hashes, self._padding, self._serialization = InvalidSignature, hashes, padding, serialization
        self._rsa_padding, self._rsa, self._ec = rsa_padding, rsa, ec
        self._cipher, self._algorithms, self._modes = Cipher, algorithms, modes

    def _aes(self, key: bytes, iv: bytes):
        return self._cipher(self._algorithms.AES(key), self._modes.CBC(iv))

    def aes_cbc_encrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        padder = self._padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        encryptor = self._aes(key, iv).encryptor()
        return encryptor.update(padded) + encryptor.finalize()

    def aes_cbc_decrypt(self, key: bytes, iv: bytes, data: bytes) -> bytes:
        decryptor = self._aes(key, iv).decryptor()
        padded = decryptor.update(data) + decryptor.finalize()
        unpadder = self._padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    def generate_rsa_key(self, bits: int) -> bytes:
        key = self._rsa.generate_private_key(public_exponent=65537, key_size=bits)
        return key.private_bytes(self._serialization.Encoding.PEM, self._serialization.PrivateFormat.PKCS8,
                                 self._serialization.NoEncryption())

    def rsa_key(self, pem: bytes) -> Any:
        return self._serialization.load_pem_private_key(pem, password=None)

    def rsa_size(self, key: Any) -> int:
        return key.key_size // 8

    def _oaep(self):
        return self._rsa_padding.OAEP(mgf=self._rsa_padding.MGF1(self._hashes.SHA1()), algorithm=self._hashes.SHA1(),
                                      label=None)

    def rsa_oaep_encrypt(self, key: Any, data: bytes) -> bytes:
        return key.public_key().encrypt(data, self._oaep())

    def rsa_oaep_decrypt(self, key: Any, data: bytes) -> bytes:
        return key.decrypt(data, self._oaep())

    def rsa_sign(self, key: Any, data: bytes) -> bytes:
        return key.sign(data, self._rsa_padding.PKCS1v15(), self._hashes.SHA256())

    def rsa_verify(self, key: Any, signature: bytes, data: bytes) -> bool:
        try:
            key.public_key().verify(signature, data, self._rsa_padding.PKCS1v15(), self._hashes.SHA256())
            return True
        except self._invalid:
            return False

    def ecdh_p384(self) -> tuple[Any, bytes, bytes]:
        key = self._ec.generate_private_key(self._ec.SECP384R1())
        point = key.public_key().public_numbers()
        return key, point.x.to_bytes(48, "big"), point.y.to_bytes(48, "big")

    def ecdh_shared(self, key: Any, x: bytes, y: bytes) -> bytes:
        peer = self._ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                                   self._ec.SECP384R1()).public_key()
        return key.exchange(self._ec.ECDH(), peer)
