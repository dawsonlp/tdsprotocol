"""The Windows certificate store as an Always Encrypted key store (D-60). Windows only.

A master key is a certificate's RSA key. Its key path is “LocalMachine/My/<thumbprint>” or
“CurrentUser/My/<thumbprint>”, as SQL Server's tools write it (KEY_STORE_PROVIDER_NAME = N'MSSQL_CERTIFICATE_STORE').
Source: SqlClient (SqlColumnEncryptionCertificateStoreProvider).

The private key stays in the store. Windows' CNG uses it to decrypt column keys (RSA-OAEP, SHA-1) and to sign, whether
or not the key can be exported. The certificate's public key, read from the store, checks signatures and encrypts new
column keys. An encrypted column key has the layout in keys.py.

    store = WindowsCertificateStore()          # pip install 'tds[encryption]'
    Encryption([store])
"""

import ctypes
import hashlib
import os
import sys
from ctypes import POINTER, Structure, byref, c_ubyte, c_void_p, wintypes

from .backend import Backend, CryptographyBackend
from .keys import KeyNotDecrypted, master_key_metadata, unwrap, wrap

STORE_LOCATIONS = {"currentuser": 1 << 16, "localmachine": 2 << 16}  # CERT_SYSTEM_STORE_*
CERT_STORE_PROV_SYSTEM_W = 10
CERT_STORE_READONLY_FLAG = 0x8000
CERT_STORE_OPEN_EXISTING_FLAG = 0x4000
ENCODING = 0x00000001 | 0x00010000  # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
CERT_FIND_SHA1_HASH = 1 << 16
CRYPT_ACQUIRE_SILENT_FLAG = 0x40
CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x40000
NCRYPT_PAD_PKCS1_FLAG = 0x2
NCRYPT_PAD_OAEP_FLAG = 0x4


class _HashBlob(Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", POINTER(c_ubyte))]


class _CertContext(Structure):
    _fields_ = [("dwCertEncodingType", wintypes.DWORD), ("pbCertEncoded", POINTER(c_ubyte)),
                ("cbCertEncoded", wintypes.DWORD), ("pCertInfo", c_void_p), ("hCertStore", c_void_p)]


class _OaepPadding(Structure):
    _fields_ = [("pszAlgId", wintypes.LPCWSTR), ("pbLabel", c_void_p), ("cbLabel", wintypes.ULONG)]


class _Pkcs1Padding(Structure):
    _fields_ = [("pszAlgId", wintypes.LPCWSTR)]


class _Certificate:
    """One certificate from a store, with its private key's CNG handle. The caller closes it after use."""

    def __init__(self, key_path: str):
        if sys.platform != "win32":
            raise KeyNotDecrypted(f"MSSQL_CERTIFICATE_STORE “{key_path}”: the Windows certificate store exists only on "
                                  "Windows")
        parts = key_path.replace("\\", "/").split("/")
        if len(parts) != 3 or parts[0].lower() not in STORE_LOCATIONS:
            raise KeyNotDecrypted(f"MSSQL_CERTIFICATE_STORE “{key_path}”: a key path is "
                                  "LocalMachine/<store>/<thumbprint> or CurrentUser/<store>/<thumbprint>")
        location, store_name, thumbprint = parts
        self.crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        self.ncrypt = ctypes.WinDLL("ncrypt")
        self.crypt32.CertOpenStore.restype = c_void_p
        self.crypt32.CertOpenStore.argtypes = [c_void_p, wintypes.DWORD, c_void_p, wintypes.DWORD, wintypes.LPCWSTR]
        self.crypt32.CertFindCertificateInStore.restype = POINTER(_CertContext)
        self.crypt32.CertFindCertificateInStore.argtypes = [c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                                             c_void_p, c_void_p]
        self.store = self.crypt32.CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, None,
                                                STORE_LOCATIONS[location.lower()] | CERT_STORE_READONLY_FLAG
                                                | CERT_STORE_OPEN_EXISTING_FLAG, store_name)
        if not self.store:
            raise KeyNotDecrypted(f"MSSQL_CERTIFICATE_STORE “{key_path}”: the store {location}/{store_name} can't be "
                                  f"opened (error {ctypes.get_last_error()})")
        digest = bytes.fromhex(thumbprint)
        buffer = (c_ubyte * len(digest)).from_buffer_copy(digest)
        blob = _HashBlob(len(digest), ctypes.cast(buffer, POINTER(c_ubyte)))
        self.context = self.crypt32.CertFindCertificateInStore(self.store, ENCODING, 0, CERT_FIND_SHA1_HASH,
                                                               byref(blob), None)
        if not self.context:
            self.close()
            raise KeyNotDecrypted(f"MSSQL_CERTIFICATE_STORE “{key_path}”: no certificate with that thumbprint in "
                                  f"{location}/{store_name}")
        context = self.context.contents
        self.der = bytes(ctypes.string_at(context.pbCertEncoded, context.cbCertEncoded))
        self.key, self.free = None, False

    def private_key(self, key_path: str) -> int:
        if self.key is None:
            key, spec, free = ctypes.c_size_t(), wintypes.DWORD(), wintypes.BOOL()
            if not self.crypt32.CryptAcquireCertificatePrivateKey(
                    self.context, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, None,
                    byref(key), byref(spec), byref(free)):
                raise KeyNotDecrypted(f"MSSQL_CERTIFICATE_STORE “{key_path}”: the certificate's private key can't be "
                                      f"reached (error {ctypes.get_last_error()}): it may have none, or this account "
                                      "may not be allowed to use it")
            self.key, self.free = key.value, bool(free.value)
        return self.key

    def _call(self, name: str, *args) -> None:
        status = getattr(self.ncrypt, name)(*args)
        if status:
            raise KeyNotDecrypted(f"{name} failed: status {status & 0xFFFFFFFF:#010x}")

    def decrypt(self, key_path: str, data: bytes) -> bytes:
        padding = _OaepPadding("SHA1", None, 0)
        out, size = (c_ubyte * len(data))(), wintypes.DWORD()
        self._call("NCryptDecrypt", c_void_p(self.private_key(key_path)), data, len(data), byref(padding), out,
                   len(data), byref(size), NCRYPT_PAD_OAEP_FLAG)
        return bytes(out[: size.value])

    def sign(self, key_path: str, data: bytes) -> bytes:
        digest = hashlib.sha256(data).digest()
        padding = _Pkcs1Padding("SHA256")
        out, size = (c_ubyte * 1024)(), wintypes.DWORD()
        self._call("NCryptSignHash", c_void_p(self.private_key(key_path)), byref(padding), digest, len(digest), out,
                   1024, byref(size), NCRYPT_PAD_PKCS1_FLAG)
        return bytes(out[: size.value])

    def close(self) -> None:
        if getattr(self, "free", False) and self.key:
            self.ncrypt.NCryptFreeObject(c_void_p(self.key))
        if getattr(self, "context", None):
            self.crypt32.CertFreeCertificateContext(self.context)
        if self.store:
            self.crypt32.CertCloseStore(c_void_p(self.store), 0)


class _StoreKey:
    """A master key in the store, as keys.wrap and keys.unwrap use it. Public-key operations use the certificate's key
    (through cryptography). Private-key operations go to CNG."""

    def __init__(self, certificate: _Certificate, key_path: str, backend: CryptographyBackend):
        from cryptography import x509
        self.public = x509.load_der_x509_certificate(certificate.der).public_key()
        self.certificate, self.key_path, self.backend = certificate, key_path, backend


class _StoreBackend:
    """A backend for keys.wrap and keys.unwrap whose RSA operations go to the certificate store."""

    def __init__(self, backend: CryptographyBackend):
        self.backend = backend

    def rsa_size(self, key: _StoreKey) -> int:
        return key.public.key_size // 8

    def rsa_oaep_encrypt(self, key: _StoreKey, data: bytes) -> bytes:
        return key.public.encrypt(data, self.backend._oaep())

    def rsa_oaep_decrypt(self, key: _StoreKey, data: bytes) -> bytes:
        return key.certificate.decrypt(key.key_path, data)

    def rsa_sign(self, key: _StoreKey, data: bytes) -> bytes:
        return key.certificate.sign(key.key_path, data)

    def rsa_verify(self, key: _StoreKey, signature: bytes, data: bytes) -> bool:
        try:
            key.public.verify(signature, data, self.backend._rsa_padding.PKCS1v15(), self.backend._hashes.SHA256())
            return True
        except self.backend._invalid:
            return False


class WindowsCertificateStore:
    name = "MSSQL_CERTIFICATE_STORE"

    def __init__(self, backend: Backend | None = None):
        self.backend = backend or CryptographyBackend()
        self._store_backend = _StoreBackend(self.backend)

    def _with_key(self, key_path: str, work):
        certificate = _Certificate(key_path)
        try:
            return work(_StoreKey(certificate, key_path, self.backend))
        finally:
            certificate.close()

    def encrypt_column_key(self, key_path: str, column_key: bytes | None = None) -> bytes:
        """A column key (32 random bytes unless given), encrypted by the certificate's key."""
        key = column_key if column_key is not None else os.urandom(32)
        return self._with_key(key_path, lambda k: wrap(key, key_path, k, self._store_backend))

    def decrypt_column_key(self, key_path: str, algorithm: str, encrypted: bytes) -> bytes:
        if algorithm.upper() != "RSA_OAEP":
            raise KeyNotDecrypted(f"{self.name} decrypts column keys encrypted with RSA_OAEP, not {algorithm}")
        return self._with_key(key_path, lambda k: unwrap(encrypted, key_path, k, self._store_backend, self.name))

    def sign_master_key_metadata(self, key_path: str, enclaves: bool = True) -> bytes:
        return self._with_key(key_path, lambda k: k.certificate.sign(key_path, master_key_metadata(self.name, key_path,
                                                                                                    enclaves)))

    def verify_master_key_metadata(self, key_path: str, enclaves: bool, signature: bytes) -> bool:
        return self._with_key(key_path, lambda k: self._store_backend.rsa_verify(
            k, signature, master_key_metadata(self.name, key_path, enclaves)))


