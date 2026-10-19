"""Public RSA fixtures from Python's production key-store methods; no service calls.

Run using clients/python/.venv/bin/python. --check checks Rust's output using
Python's actual local and Key Vault providers. The fake vault performs real RSA
operations with an intentionally public fixture private key.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[3] / "python"))
from tds.encryption.backend import CryptographyBackend
from tds.encryption.keys import LocalKeyStore, master_key_metadata
from tds.encryption.keyvault import AzureKeyVaultKeyStore
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

encode = lambda b: base64.b64encode(b).decode()
backend = CryptographyBackend()
master = backend.rsa_key((HERE.parent / "encryption/master.pem").read_bytes())

class Vault:
    def __init__(self, path, credential):
        self.path = path
    def wrap_key(self, algorithm, value):
        return SimpleNamespace(encrypted_key=backend.rsa_oaep_encrypt(master, value))
    def unwrap_key(self, algorithm, value):
        return SimpleNamespace(key=backend.rsa_oaep_decrypt(master, value))
    def sign(self, algorithm, digest):
        return SimpleNamespace(signature=master.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())))
    def verify(self, algorithm, digest, signature):
        try:
            master.public_key().verify(signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
            valid = True
        except backend._invalid:
            valid = False
        return SimpleNamespace(is_valid=valid)

vault = AzureKeyVaultKeyStore(object())
vault._client = Vault
local = LocalKeyStore(HERE.parent / "encryption")
local.name = "TDS_TEST"
path = "https://Fixture.vault.azure.net/keys/MyKey/Version1"
if len(sys.argv) > 1 and sys.argv[1] == "--verify":
    data=json.loads((HERE / "key_providers.json").read_text())
    assert vault.decrypt_column_key(path,"RSA_OAEP",base64.b64decode(data["wrapped"]))==base64.b64decode(data["root"])
    assert vault.verify_master_key_metadata(path,True,base64.b64decode(data["metadata_signature"]))
    assert local.verify_master_key_metadata("master.pem",True,base64.b64decode(data["local_signature"]))
    assert data["path"]==path
    print("Python verified saved vault envelope and both metadata signatures")
elif len(sys.argv) > 1 and sys.argv[1] == "--check":
    for file in sys.argv[2:]:
        data = json.loads(Path(file).read_text())
        provider, key_path = (vault, path) if data.get("vault") else (local, "master.pem")
        assert provider.decrypt_column_key(key_path, "RSA_OAEP", base64.b64decode(data["wrapped"])) == base64.b64decode(data["root"])
        assert provider.verify_master_key_metadata(key_path, True, base64.b64decode(data["metadata_signature"]))
        assert not provider.verify_master_key_metadata(key_path, False, base64.b64decode(data["metadata_signature"]))
    print("Python decrypted Rust envelopes and verified Rust metadata signatures:", len(sys.argv) - 2)
else:
    root = bytes([3]) * 32
    wrapped = vault.encrypt_column_key(path, root)
    end = 5 + int.from_bytes(wrapped[1:3], "little") + int.from_bytes(wrapped[3:5], "little")
    output = dict(path=path, root=encode(root), wrapped=encode(wrapped), ciphertext=encode(wrapped[5+int.from_bytes(wrapped[1:3], "little"):end]),
                  body_digest=encode(hashlib.sha256(wrapped[:end]).digest()), signature=encode(wrapped[end:]),
                  metadata_digest=encode(hashlib.sha256(master_key_metadata(vault.name,path,True)).digest()),
                  metadata_signature=encode(vault.sign_master_key_metadata(path)),
                  local_signature=encode(local.sign_master_key_metadata("master.pem")))
    (HERE / "key_providers.json").write_text(json.dumps(output, indent=2) + "\n")
    print("Generated Python vault envelope and metadata signatures")
