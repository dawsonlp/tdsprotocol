#!/usr/bin/env python3
"""Repeat the current paired Azure development slice without Azure access.

Python regenerates its production-encoder vectors in memory and checks the saved
fixture. Rust compares wire/decoding and controlled-peer behavior. Logs and exact
source hashes stay in a temporary evidence directory unless --output is given.
This is a finite runner for these cases, not a live acceptance campaign.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or Path(tempfile.mkdtemp(prefix="tds-azure-paired-"))
    output.mkdir(parents=True, exist_ok=True)
    python = ROOT / "clients/python/.venv/bin/python"
    if not python.exists():
        raise SystemExit("The repository Python development environment is required")
    files = [ROOT / "clients/rust/Cargo.toml", ROOT / "clients/rust/Cargo.lock", Path(__file__).resolve()]
    for folder in ["clients/rust/src", "clients/rust/tests", "clients/rust/examples", "clients/rust/native-sspi/src", "clients/rust/native-certstore/src", "clients/rust/native-gssapi/src"]:
        files.extend((ROOT / folder).rglob("*.rs"))
    for relative in ["tds/logins.py", "tds/login7.py", "tds/prelogin.py", "tds/tokens.py", "tds/adapters/entra.py", "tds/connection/core.py"]:
        files.append(ROOT / "clients/python" / relative)
    files.extend((ROOT / "clients/rust/tests/fixtures/azure").iterdir())
    files.extend((ROOT / "clients/python/tds/encryption").glob("*.py"))
    files.extend((ROOT / "clients/rust/tests/fixtures/encryption").glob("*"))
    files.append(ROOT / "clients/rust/native-certstore/Cargo.toml")
    files.append(ROOT / "clients/rust/native-sspi/Cargo.toml")
    files.append(ROOT / "clients/rust/native-gssapi/Cargo.toml")
    files.append(ROOT / "clients/python/tds/adapters/spnego.py")
    files.append(ROOT / "clients/python/tests/test_kerberos_azure.py")
    report = dict(started=dt.datetime.now(dt.timezone.utc).isoformat(),
                  level="paired development; no live Azure acceptance",
                  revision=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  sources={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in sorted(set(files)) if p.is_file()}, checks=[])
    commands = [
        ("python-vectors", [str(python), "clients/rust/tests/fixtures/azure/generate.py"]),
        ("python-feature-probes", [str(python), "clients/rust/tests/fixtures/azure/feature_probes.py"]),
        ("python-key-vectors",[str(python),"clients/rust/tests/fixtures/azure/key_providers.py","--verify"]),
        ("python-enclave-vectors",[str(python),"clients/rust/tests/fixtures/azure/enclave.py","--verify"]),
        ("rust-core-vectors", ["cargo", "test", "--manifest-path", "clients/rust/Cargo.toml", "--offline", "--locked", "--no-default-features", "--test", "azure_wire", "--test", "enclave_wire"]),
        ("rust-authentication", ["cargo", "test", "--manifest-path", "clients/rust/Cargo.toml", "--offline", "--locked", "--all-features", "--test", "azure_wire", "--test", "azure_login"]),
        ("rust-unsupported-features", ["cargo", "test", "--manifest-path", "clients/rust/Cargo.toml", "--offline", "--locked", "--all-features", "--test", "azure_features"]),
        ("rust-sdk-adapter", ["cargo", "test", "--manifest-path", "clients/rust/Cargo.toml", "--offline", "--locked", "--all-features", "--lib", "entra::azure::tests"]),
        ("rust-system-gssapi", ["cargo", "test", "--manifest-path", "clients/rust/Cargo.toml", "--offline", "--locked", "-p", "tds-native-gssapi"]),
        ("rust-auth-workers", ["cargo", "test", "--manifest-path", "clients/rust/Cargo.toml", "--offline", "--locked", "--all-features", "--lib", "auth::"]),
        ("rust-integrated-regressions", ["cargo", "test", "--manifest-path", "clients/rust/Cargo.toml", "--offline", "--locked", "--all-features", "--test", "authentication", "--test", "config"]),
        ("rust-key-policy",["cargo","test","--manifest-path","clients/rust/Cargo.toml","--offline","--locked","--all-features","--lib","encryption::"]),
        ("rust-key-enclave",["cargo","test","--manifest-path","clients/rust/Cargo.toml","--offline","--locked","--all-features","--test","key_providers","--test","keyvault","--test","enclave_wire","--test","enclave_connection"]),
        ("rust-cross-feature",["cargo","test","--manifest-path","clients/rust/Cargo.toml","--offline","--locked","--all-features","--test","azure_cross"]),
        ("python-read-rust-keys",[str(python),"clients/rust/tests/fixtures/azure/key_providers.py","--check",str(output/"local.json"),str(output/"vault.json")]),
        ("python-read-rust-enclave",[str(python),"clients/rust/tests/fixtures/azure/enclave.py","--check",str(output/"enclave.json")]),
    ]
    env=os.environ.copy()
    for name,file in [("TDS_KEY_PROVIDER_OUTPUT","local.json"),("TDS_VAULT_PROVIDER_OUTPUT","vault.json"),("TDS_ENCLAVE_OUTPUT","enclave.json")]:
        destination=(output/file).resolve()
        if destination.exists():
            raise SystemExit(f"Refusing to overwrite previous comparison output: {destination}")
        env[name]=str(destination)
    for name, command in commands:
        log = output / f"{name}.log"
        print(f"{name}: {log}", flush=True)
        with log.open("w") as stream:
            result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,env=env)
        counts = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", log.read_text())
        entry = dict(name=name, command=command, returncode=result.returncode)
        if counts:
            entry["passed"], entry["failed"], entry["ignored"] = map(sum, zip(*[map(int, row) for row in counts]))
        report["checks"].append(entry)
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        if result.returncode:
            print(log.read_text()[-4000:])
            raise SystemExit(result.returncode)
    report["finished"]=dt.datetime.now(dt.timezone.utc).isoformat()
    changed=[relative for relative,digest in report["sources"].items()
             if not (ROOT/relative).is_file() or hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()!=digest]
    report["source_snapshot_unchanged"]=not changed
    if changed:
        report["changed_during_checks"]=changed
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    if changed:
        raise SystemExit("Source changed during comparisons; this report is not a stable-source checkpoint")
    print(f"Paired development comparisons passed: {output / 'summary.json'}")


if __name__ == "__main__":
    main()
