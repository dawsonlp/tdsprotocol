"""Configure the VMs from inside, after terraform apply (D-62): the domain, SQL Server on Windows, the Linux runner, the
Entra identities' database users, and the Windows Rust toolchain. Then write what the tests need, both beside this
file: azure.json (endpoints and identity names, nothing secret) and secrets/ (passwords, the service principal's
secret, the runner's SSH key, the disposable CA). It is safe to run again, because each step checks whether it is
already done.

    ../../clients/python/.venv/bin/python configure.py          all steps (the certs step needs `cryptography`)
    ../../clients/python/.venv/bin/python configure.py runner   one step: files, certs, dc, users, join, sql,
                                                                sqlcert, entra, runner, wintools

Secrets go from Terraform's outputs to `az`, `ssh` and `sqlcmd` as arguments or input, never to the terminal. Only each
step's own output is printed, and no step prints a secret.
"""

import base64
import datetime as dt
import ipaddress
import json
import os
import secrets as random
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
SECRETS = HERE / "secrets"
OUTPUTS: dict = {}


def terraform_outputs() -> dict:
    out = subprocess.run(["terraform", "output", "-json"], cwd=HERE, capture_output=True, text=True, check=True).stdout
    return {k: v["value"] for k, v in json.loads(out).items()}


def group() -> str:
    return OUTPUTS["resource_group"]


def run_command(vm: str, script: str, **parameters: str) -> str:
    """Run a PowerShell script in a VM, and return what it printed. That is the script's own output, which never holds
    a secret."""
    args = ["az", "vm", "run-command", "invoke", "-g", group(), "-n", vm, "--command-id", "RunPowerShellScript",
            "--scripts", f"@{HERE / 'scripts' / script}", "-o", "json"]
    if parameters:
        args += ["--parameters", *[f"{k}={v}" for k, v in parameters.items()]]
    done = subprocess.run(args, capture_output=True, text=True)
    if done.returncode:
        raise SystemExit(f"{script} on {vm}: az failed ({done.returncode}): {done.stderr[-800:]}")
    value = json.loads(done.stdout).get("value", [])
    out = "\n".join(m.get("message", "").strip() for m in value if "StdOut" in m.get("code", ""))
    err = "\n".join(m.get("message", "").strip() for m in value if "StdErr" in m.get("code", ""))
    if err.strip():
        raise RuntimeError(f"{script} on {vm} failed:\n{out}\n{err}")
    return out


def restart(vm: str) -> None:
    subprocess.run(["az", "vm", "restart", "-g", group(), "-n", vm, "-o", "none"], check=True)
    time.sleep(60)  # let Windows finish starting its services


def ssh(o: dict, command: str, stdin: str | None = None) -> str:
    key = SECRETS / "runner_ed25519"
    done = subprocess.run(["ssh", "-i", str(key), "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
                           f"tds@{o['runner_public_ip']}", command], input=stdin, capture_output=True, text=True)
    if done.returncode:
        raise SystemExit(f"on the runner, {command!r} failed ({done.returncode}): {done.stderr[-800:]}")
    return done.stdout.strip()


def write_secret(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def step_files(o: dict, s: dict) -> None:
    SECRETS.mkdir(mode=0o700, exist_ok=True)
    write_secret(SECRETS / "secrets.json", json.dumps(s).encode())
    write_secret(SECRETS / "runner_ed25519", s["runner_ssh_key"].encode())
    public = {k: o[k] for k in ("resource_group", "azure_sql_server", "azure_sql_database", "key_vault_key_id",
                                "sql_vm_public_ip", "runner_public_ip", "domain", "tenant_id",
                                "service_principal_client_id", "service_principal_name", "runner_identity_name",
                                "deadline")}
    public["sql_vm_ca"] = "secrets/ca.pem"  # the disposable CA that signed SQL Server's certificate (step certs)
    (HERE / "azure.json").write_text(json.dumps(public, indent=2) + "\n")
    print(f"wrote azure.json and secrets/ (secrets.json, the runner's key); the resource group deletes itself at "
          f"{o['deadline']}")


def step_certs(o: dict, s: dict) -> None:
    """A disposable CA and SQL Server's certificate, so clients that verify TLS (Rust) can reach SQL Server on
    Windows: by its domain name inside the network, and by its public address from outside. Valid for two days."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    if (SECRETS / "sql.pfx").exists():
        print("certificates already made")
        return
    now = dt.datetime.now(dt.timezone.utc)
    later = now + dt.timedelta(days=2)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable TDS Azure CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(later)
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                       encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = f"tdssql.{o['domain']}"
    names = [x509.DNSName(name), x509.IPAddress(ipaddress.ip_address(o["sql_vm_public_ip"])),
             x509.IPAddress(ipaddress.ip_address("10.42.1.5"))]
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(later)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(ca_key, hashes.SHA256()))
    password = random.token_urlsafe(24)
    write_secret(SECRETS / "ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    write_secret(SECRETS / "pfx_password", password.encode())
    write_secret(SECRETS / "sql.pfx", pkcs12.serialize_key_and_certificates(
        b"tdssql", key, cert, [ca], serialization.BestAvailableEncryption(password.encode())))
    print(f"made a disposable CA and SQL Server's certificate for {name}, {o['sql_vm_public_ip']} and 10.42.1.5")


def step_dc(o: dict, s: dict) -> None:
    text = run_command("vm-tds-dc", "dc-promote.ps1", SafeModePassword=s["windows_admin_password"], Domain=o["domain"])
    print(text)
    if "restart to finish" in text:
        restart("vm-tds-dc")


def step_users(o: dict, s: dict) -> None:
    for attempt in range(12):  # after the restart, Active Directory takes a few minutes to answer
        try:
            print(run_command("vm-tds-dc", "dc-users.ps1", TestUserPassword=s["test_user_password"], Domain=o["domain"]))
            return
        except RuntimeError as e:
            if attempt == 11:
                raise SystemExit(str(e))
            print(f"  not ready yet ({str(e).splitlines()[-1][:120]}); trying again in 30 s")
            time.sleep(30)


def step_join(o: dict, s: dict) -> None:
    text = run_command("vm-tds-sql", "sql-join.ps1", AdminPassword=s["windows_admin_password"], Domain=o["domain"])
    print(text)
    if "restart to finish" in text:
        restart("vm-tds-sql")


def step_sql(o: dict, s: dict) -> None:
    print(run_command("vm-tds-sql", "sql-configure.ps1", SqlAdminPassword=s["sql_admin_password"], Domain=o["domain"]))


def step_sqlcert(o: dict, s: dict) -> None:
    print(run_command("vm-tds-sql", "sql-certificate.ps1",
                      Pfx=base64.b64encode((SECRETS / "sql.pfx").read_bytes()).decode(),
                      PfxPassword=(SECRETS / "pfx_password").read_text(),
                      Ca=base64.b64encode((SECRETS / "ca.pem").read_bytes()).decode()))


def step_entra(o: dict, s: dict) -> None:
    """Database users for the service principal and the runner's managed identity, made by the Entra admin (the
    signed-in Azure CLI user). db_owner: the tests create column master and encryption keys and tables."""
    statements = []
    for name in (o["service_principal_name"], o["runner_identity_name"]):
        quoted = name.replace("]", "]]")
        statements.append(f"IF USER_ID(N'{name}') IS NULL CREATE USER [{quoted}] FROM EXTERNAL PROVIDER; "
                          f"ALTER ROLE db_owner ADD MEMBER [{quoted}];")
    for attempt in range(6):  # a new principal can take a minute to be visible to Azure SQL
        done = subprocess.run(["sqlcmd", "-S", o["azure_sql_server"], "-d", o["azure_sql_database"],
                               "--authentication-method", "ActiveDirectoryAzCli", "-b", "-Q", " ".join(statements)],
                              capture_output=True, text=True)
        if not done.returncode:
            print(f"database users: {o['service_principal_name']}, {o['runner_identity_name']} (db_owner)")
            return
        print(f"  not yet ({done.stdout[-200:].strip()} {done.stderr[-200:].strip()}); trying again in 30 s")
        time.sleep(30)
    raise SystemExit("creating the Entra database users failed")


def step_runner(o: dict, s: dict) -> None:
    script = (HERE / "scripts" / "runner.sh").read_text()
    print(ssh(o, f"sh -s {o['domain']}", stdin=script))
    print(ssh(o, "cat > tds-ca.pem && echo 'the disposable CA is in ~/tds-ca.pem'",
              stdin=(SECRETS / "ca.pem").read_text()))


def step_wintools(o: dict, s: dict) -> None:
    """Visual C++ build tools and Rust on the SQL VM, for the certificate-store tests (tens of minutes)."""
    print(run_command("vm-tds-sql", "windows-tools.ps1"))


STEPS = {"files": step_files, "certs": step_certs, "dc": step_dc, "users": step_users, "join": step_join,
         "sql": step_sql, "sqlcert": step_sqlcert, "entra": step_entra, "runner": step_runner, "wintools": step_wintools}


def main() -> None:
    o = terraform_outputs()
    OUTPUTS.update(o)
    s = o.pop("secrets")
    for name in sys.argv[1:] or ["files", "certs", "dc", "users", "join", "users", "sql", "sqlcert", "entra",
                                 "runner", "wintools"]:
        print(f"· {name}")
        STEPS[name](o, s)


if __name__ == "__main__":
    os.chdir(HERE)
    main()
