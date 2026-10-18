# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography"]
# ///
"""Regenerate artificial TLS fixtures for controlled peers, not Docker credentials.

Run with `uv run tests/fixtures/generate_tls.py` from clients/rust. Tests read
the resulting PEM files directly; Python/OpenSSL/SQL Server are not test-time
dependencies. Wide fixed validity avoids coupling tests to the generation date.
The committed leaf key is public test data and protects no real service.
"""
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = Path(__file__).resolve().parent
start = datetime(2000, 1, 1, tzinfo=timezone.utc)
end = datetime(2100, 1, 1, tzinfo=timezone.utc)
authority = ec.generate_private_key(ec.SECP256R1())
server = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TDS controlled peer test CA")])
ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
      .public_key(authority.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(start).not_valid_after(end)
      .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
      .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
      .sign(authority, hashes.SHA256()))
def leaf_for(common_name, names):
    return (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(name).public_key(server.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(start).not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(authority, hashes.SHA256()))
leaf = leaf_for("localhost", [x509.DNSName("localhost"), x509.IPAddress(ip_address("127.0.0.1"))])
router = leaf_for("router.test", [x509.DNSName("router.test")])
for filename, certificate in [("test-ca.pem", ca), ("test-server.pem", leaf), ("test-router.pem", router)]:
    (HERE / filename).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
(HERE / "test-server-key.pem").write_bytes(server.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
