"""Azure Key Vault as an Always Encrypted key store (D-60).

A master key is a Key Vault RSA key, and its key path is the key's URL. An encrypted column key has the layout that
SQL Server's tools write (keys.py), with its key path lowercased. Key Vault unwraps the column key (RSA-OAEP) and
checks its signature (RS256), so the master key never leaves the vault. Source: SqlClient
(SqlColumnEncryptionAzureKeyVaultProvider, AzureSqlKeyCryptographer).

    store = AzureKeyVaultKeyStore(DefaultAzureCredential())        # pip install 'tds[keyvault]'
    Encryption([store])
"""

import hashlib
import os

from .keys import KEY_VERSION, KeyNotDecrypted, master_key_metadata


class AzureKeyVaultKeyStore:
    name = "AZURE_KEY_VAULT"

    def __init__(self, credential):
        try:
            from azure.keyvault.keys.crypto import CryptographyClient, KeyWrapAlgorithm, SignatureAlgorithm
        except ImportError as e:
            raise ImportError("the Key Vault key store needs azure-keyvault-keys: pip install 'tds[keyvault]'") from e
        self._client, self._wrap, self._sign = CryptographyClient, KeyWrapAlgorithm.rsa_oaep, SignatureAlgorithm.rs256
        self.credential = credential
        self._clients: dict[str, object] = {}

    def _for(self, key_path: str):
        if key_path not in self._clients:
            self._clients[key_path] = self._client(key_path, self.credential)
        return self._clients[key_path]

    def encrypt_column_key(self, key_path: str, column_key: bytes | None = None) -> bytes:
        """A column key (32 random bytes unless given), wrapped and signed by this Key Vault key."""
        client = self._for(key_path)
        ciphertext = client.wrap_key(self._wrap, column_key if column_key is not None else os.urandom(32)).encrypted_key
        path = key_path.lower().encode("utf-16-le")
        body = (bytes([KEY_VERSION]) + len(path).to_bytes(2, "little") + len(ciphertext).to_bytes(2, "little") + path
                + ciphertext)
        return body + client.sign(self._sign, hashlib.sha256(body).digest()).signature

    def decrypt_column_key(self, key_path: str, algorithm: str, encrypted: bytes) -> bytes:
        where = f"the column key encrypted by {self.name} master key “{key_path}”"
        if algorithm.upper() != "RSA_OAEP":
            raise KeyNotDecrypted(f"{where}: {self.name} decrypts column keys encrypted with RSA_OAEP, not {algorithm}")
        if len(encrypted) < 5 or encrypted[0] != KEY_VERSION:
            raise KeyNotDecrypted(f"{where}: not an encrypted column key this driver knows")
        path_length = int.from_bytes(encrypted[1:3], "little")
        ciphertext_length = int.from_bytes(encrypted[3:5], "little")
        start = 5 + path_length
        body, signature = encrypted[: start + ciphertext_length], encrypted[start + ciphertext_length :]
        client = self._for(key_path)
        try:
            valid = client.verify(self._sign, hashlib.sha256(body).digest(), signature).is_valid
            if not valid:
                raise KeyNotDecrypted(f"{where}: its signature doesn't verify with this Key Vault key")
            return client.unwrap_key(self._wrap, body[start:]).key
        except KeyNotDecrypted:
            raise
        except Exception as e:  # the vault refused, or couldn't be reached. The error includes the vault's own message.
            raise KeyNotDecrypted(f"{where}: Key Vault refused ({type(e).__name__}: {str(e)[:300]})") from None

    def sign_master_key_metadata(self, key_path: str, enclaves: bool = True) -> bytes:
        """The signature for CREATE COLUMN MASTER KEY … ENCLAVE_COMPUTATIONS (SIGNATURE = …), made by the vault."""
        digest = hashlib.sha256(master_key_metadata(self.name, key_path, enclaves)).digest()
        return self._for(key_path).sign(self._sign, digest).signature

    def verify_master_key_metadata(self, key_path: str, enclaves: bool, signature: bytes) -> bool:
        digest = hashlib.sha256(master_key_metadata(self.name, key_path, enclaves)).digest()
        return self._for(key_path).verify(self._sign, digest, signature).is_valid
