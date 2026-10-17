"""Configure the VMs from inside, after terraform apply (D-62): the domain, SQL Server on Windows, and the Linux runner.
Then write what the tests need, both beside this file: azure.json (endpoints, nothing secret) and secrets/secrets.json
(passwords, the runner's SSH key). It is safe to run again, because each step checks whether it is already done.

    python3 configure.py            all steps
    python3 configure.py runner     one step: dc, users, join, sql, runner, files

Secrets go from Terraform's outputs to `az` and `ssh` as arguments or input, never to the terminal. Only each step's own
output is printed, and no step prints a secret.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
GROUP = "rg-tds-driver-tests"
SECRETS = HERE / "secrets"


def terraform_outputs() -> dict:
    out = subprocess.run(["terraform", "output", "-json"], cwd=HERE, capture_output=True, text=True, check=True).stdout
    return {k: v["value"] for k, v in json.loads(out).items()}


def run_command(vm: str, script: str, **parameters: str) -> str:
    """Run a PowerShell script in a VM, and return what it printed. That is the script's own output, which never holds
    a secret."""
    args = ["az", "vm", "run-command", "invoke", "-g", GROUP, "-n", vm, "--command-id", "RunPowerShellScript",
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
    subprocess.run(["az", "vm", "restart", "-g", GROUP, "-n", vm, "-o", "none"], check=True)
    time.sleep(60)  # let Windows finish starting its services


def ssh(o: dict, command: str, stdin: str | None = None) -> str:
    key = SECRETS / "runner_ed25519"
    done = subprocess.run(["ssh", "-i", str(key), "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
                           f"tds@{o['runner_public_ip']}", command], input=stdin, capture_output=True, text=True)
    if done.returncode:
        raise SystemExit(f"on the runner, {command!r} failed ({done.returncode}): {done.stderr[-800:]}")
    return done.stdout.strip()


def step_files(o: dict, s: dict) -> None:
    SECRETS.mkdir(mode=0o700, exist_ok=True)
    (SECRETS / "secrets.json").write_text(json.dumps(s))
    (SECRETS / "secrets.json").chmod(0o600)
    key = SECRETS / "runner_ed25519"
    key.write_text(s["runner_ssh_key"])
    key.chmod(0o600)
    public = {k: o[k] for k in ("azure_sql_server", "azure_sql_database", "key_vault_key_id", "sql_vm_public_ip",
                                "runner_public_ip", "domain")}
    (HERE / "azure.json").write_text(json.dumps(public, indent=2) + "\n")
    print("wrote azure.json and secrets/ (secrets.json, the runner's key)")


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


def step_runner(o: dict, s: dict) -> None:
    script = (HERE / "scripts" / "runner.sh").read_text()
    print(ssh(o, f"sh -s {o['domain']}", stdin=script))


STEPS = {"files": step_files, "dc": step_dc, "users": step_users, "join": step_join, "sql": step_sql,
         "runner": step_runner}


def main() -> None:
    o = terraform_outputs()
    s = o.pop("secrets")
    for name in sys.argv[1:] or ["files", "dc", "users", "join", "users", "sql", "runner"]:
        print(f"· {name}")
        STEPS[name](o, s)


if __name__ == "__main__":
    os.chdir(HERE)
    main()
