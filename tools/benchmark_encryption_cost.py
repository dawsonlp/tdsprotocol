"""Measure Python AE primitives or an isolated Rust probe with synthetic keys.

Run: clients/python/.venv/bin/python tools/benchmark_encryption_cost.py
Prints aggregate timings only. No SQL Server, network, or configured key store.
The default measures Python; --rust-probe runs a compiled candidate Rust probe,
not the proposed driver implementation. Python immutable
secret bytes cannot provide the proposed Rust deterministic-erasure guarantee.
"""

import argparse
import datetime
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from importlib.metadata import version
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients/python"))

from tds.encryption.backend import CryptographyBackend
from tds.encryption.cell import CellKey, _derived
from tds.encryption.keys import LocalKeyStore, RSA_OAEP, unwrap, wrap


def measure(name, operation):
    operation()
    started = time.perf_counter_ns()
    operation()
    elapsed = max(time.perf_counter_ns() - started, 1)
    count = max(3, min(100_000, int(40_000_000 / elapsed)))
    walls, cpus = [], []
    for _ in range(5):
        wall, cpu = time.perf_counter_ns(), time.process_time_ns()
        for _ in range(count):
            operation()
        cpus.append((time.process_time_ns() - cpu) / count / 1000)
        walls.append((time.perf_counter_ns() - wall) / count / 1000)
    return dict(operation=name, median_wall_us=round(statistics.median(walls), 3),
                median_cpu_us=round(statistics.median(cpus), 3),
                batch_mean_wall_range_us=[round(min(walls), 3), round(max(walls), 3)],
                operations_per_batch=count, batches=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-probe", type=Path, help="Run the compiled Rust candidate probe instead")
    arguments = parser.parse_args()
    backend = CryptographyBackend()
    pem = backend.generate_rsa_key(2048)
    master = backend.rsa_key(pem)
    raw = os.urandom(32)
    wrapped = wrap(raw, "synthetic.pem", master, backend)
    cell = CellKey(raw, backend)
    if arguments.rust_probe:
        serialization = backend._serialization
        with tempfile.TemporaryDirectory(prefix="tds-rust-ae-cost-") as directory:
            fixtures = {
                "master.der": master.private_bytes(serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
                "public.der": master.public_key().public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.PKCS1),
                "wrapped.bin": wrapped,
                "root.bin": raw,
                "working.bin": b"".join(_derived(raw, kind) for kind in ("encryption key", "MAC key", "IV key")),
            }
            for size in (64, 1024, 65536):
                plaintext = os.urandom(size)
                fixtures.update({f"plain-{size}.bin": plaintext,
                                 f"det-{size}.bin": cell.encrypt(plaintext, deterministic=True),
                                 f"random-{size}.bin": cell.encrypt(plaintext, deterministic=False)})
            for name, contents in fixtures.items():
                descriptor = os.open(Path(directory) / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(contents)
            completed = subprocess.run([str(arguments.rust_probe.resolve()), directory],
                                       check=True, capture_output=True, text=True)
            results = json.loads(completed.stdout)
        results.update(date=datetime.datetime.now().astimezone().isoformat(), machine=platform.machine(),
                       fixture_source="Synthetic Python key; three working keys checked for exact equality")
        print(json.dumps(results, indent=2))
        return
    with tempfile.TemporaryDirectory(prefix="tds-ae-cost-") as directory:
        path = Path(directory) / "synthetic.pem"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(pem)
        store = LocalKeyStore(directory, backend)
        results = [
            measure("parse_rsa_2048_private_key", lambda: backend.rsa_key(pem)),
            measure("unwrap_verify_derive_with_parsed_master", lambda: CellKey(
                unwrap(wrapped, "synthetic.pem", master, backend, store.name), backend)),
            measure("full_local_provider_unwrap_verify_derive", lambda: CellKey(
                store.decrypt_column_key("synthetic.pem", RSA_OAEP, wrapped), backend)),
        ]
        for size in (64, 1024, 65536):
            plaintext = os.urandom(size)
            ciphertext = cell.encrypt(plaintext, deterministic=True)
            assert cell.decrypt(ciphertext) == plaintext
            results.extend([
                measure(f"authenticate_decrypt_{size}_byte_value", lambda: cell.decrypt(ciphertext)),
                measure(f"encrypt_authenticate_{size}_byte_value", lambda: cell.encrypt(
                    plaintext, deterministic=True)),
            ])
    print(json.dumps(dict(
        scope="Python implementation; warm local files; synthetic RSA-2048; no SQL Server or network",
        date=datetime.datetime.now().astimezone().isoformat(), python=platform.python_version(), machine=platform.machine(),
        cryptography=version("cryptography"),
        method="Median of five batch means; wall and process CPU; calibration targets 40 ms per batch",
        caveat="No secure-erasure guarantee for Python bytes; temporary file deletion is not disk sanitization",
        results=results), indent=2))


if __name__ == "__main__":
    main()
