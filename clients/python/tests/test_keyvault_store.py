"""The Key Vault key store's structural checks (PY-AZ-05), with a fake vault doing real RSA with the intentionally
public test key (as clients/rust/tests/fixtures/azure/key_providers.py does). Valid vault values were confirmed live;
these cases are the malformed ones the vault would never be asked about."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from tds.encryption.backend import CryptographyBackend
from tds.encryption.keys import KeyNotDecrypted
from tds.encryption.keyvault import AzureKeyVaultKeyStore

PATH = "https://fixture.vault.azure.net/keys/MyKey/Version1"
backend = CryptographyBackend()
master = backend.rsa_key((Path(__file__).parent.parent.parent / "rust/tests/fixtures/encryption/master.pem").read_bytes())


class Vault:
    calls: list[str] = []
    short_root = False

    def __init__(self, path, credential):
        if not path.startswith("https://"):
            raise ValueError("not a vault key URL")
        self.path = path

    def wrap_key(self, algorithm, value):
        return SimpleNamespace(encrypted_key=backend.rsa_oaep_encrypt(master, value))

    def unwrap_key(self, algorithm, value):
        Vault.calls.append("unwrap")
        key = backend.rsa_oaep_decrypt(master, value)
        return SimpleNamespace(key=key[:16] if Vault.short_root else key)

    def sign(self, algorithm, digest):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, utils
        return SimpleNamespace(signature=master.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())))

    def verify(self, algorithm, digest, signature):
        Vault.calls.append("verify")
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, utils
        try:
            master.public_key().verify(signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
            return SimpleNamespace(is_valid=True)
        except backend._invalid:
            return SimpleNamespace(is_valid=False)


@pytest.fixture
def store():
    Vault.calls, Vault.short_root = [], False
    store = AzureKeyVaultKeyStore(object())
    store._client = Vault
    return store


def test_a_wrapped_key_round_trips(store):
    wrapped = store.encrypt_column_key(PATH, bytes([3]) * 32)
    assert store.decrypt_column_key(PATH, "RSA_OAEP", wrapped) == bytes([3]) * 32
    assert Vault.calls == ["verify", "unwrap"]


def test_lengths_past_the_end_are_refused_before_any_vault_call(store):
    wrapped = store.encrypt_column_key(PATH, bytes([3]) * 32)
    overstated = wrapped[:3] + b"\xff\xff" + wrapped[5:]  # a ciphertext length past the value
    for broken in (wrapped[:40], overstated):
        with pytest.raises(KeyNotDecrypted, match="past the end"):
            store.decrypt_column_key(PATH, "RSA_OAEP", broken)
    assert Vault.calls == []


def test_a_path_that_is_not_a_vault_key_url_is_a_key_error(store):
    wrapped = store.encrypt_column_key(PATH, bytes([3]) * 32)
    with pytest.raises(KeyNotDecrypted, match="not a Key Vault key URL"):
        store.decrypt_column_key("master.pem", "RSA_OAEP", wrapped)


def test_an_unwrapped_root_that_is_not_32_bytes_is_refused(store):
    wrapped = store.encrypt_column_key(PATH, bytes([3]) * 32)
    Vault.short_root = True
    with pytest.raises(KeyNotDecrypted, match="not a 32-byte column key"):
        store.decrypt_column_key(PATH, "RSA_OAEP", wrapped)
