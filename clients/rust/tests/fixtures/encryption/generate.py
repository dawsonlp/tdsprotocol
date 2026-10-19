"""Disposable, intentionally public test keys. Never use these outside tests.

Run with clients/python/.venv/bin/python. Uses the independent Python backend.
Regeneration changes the RSA fixture; assertions compare behavior, not randomness.
"""
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[3] / "python"))
from tds.encryption.backend import CryptographyBackend
from tds.encryption.cell import CellKey, _derived
from tds.encryption.keys import wrap

b = CryptographyBackend()
pem = b.generate_rsa_key(2048)
(HERE / "master.pem").write_bytes(pem)
(HERE / "master.pem").chmod(0o600)
master = b.rsa_key(pem)
serialization = b._serialization
bad_der = bytearray(master.private_bytes(serialization.Encoding.DER,
    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
bad_der[-1] ^= 1  # valid ASN.1, inconsistent CRT coefficient
encoded_bad = base64.b64encode(bad_der)
(HERE / "bad-crt.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----\n" + b"\n".join(
    encoded_bad[i:i+64] for i in range(0, len(encoded_bad), 64)) + b"\n-----END PRIVATE KEY-----\n")
roots = [hashlib.sha256(f"public disposable CEK {i}".encode()).digest() for i in range(3)]
keys = [wrap(root, "master.pem", master, b) for root in roots]
cell = CellKey(roots[0], b)
encode = lambda x: base64.b64encode(x).decode("ascii")
cases = []
for size in (0, 1, 15, 16, 17, 64, 1024, 65536):
    plaintext = bytes(i % 251 for i in range(size))
    cases.append(dict(size=size, plaintext=encode(plaintext),
                      deterministic=encode(cell.encrypt(plaintext, True)),
                      randomized=encode(cell.encrypt(plaintext, False))))
# A valid authentication tag around invalid padding, independently constructed.
iv = bytes(16)
encryptor = b._aes(_derived(roots[0], "encryption key"), iv).encryptor()
ciphertext = encryptor.update(bytes(16)) + encryptor.finalize()
tag = hmac.new(_derived(roots[0], "MAC key"), b"\x01" + iv + ciphertext + b"\x01", hashlib.sha256).digest()
(HERE / "python.json").write_text(json.dumps(dict(
    scope="Intentionally public disposable RSA/CEK fixtures, never deployment keys",
    wrapped=[encode(k) for k in keys], cases=cases,
    bad_root=encode(wrap(bytes(31), "master.pem", master, b)),
    invalid_padding=encode(b"\x01" + tag + iv + ciphertext)), indent=2) + "\n")
print(len(cases), "Python value fixtures and",len(keys),"wrapped test keys")
