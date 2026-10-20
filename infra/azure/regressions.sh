#!/bin/sh
# Follow-up G: regression re-runs of authentication paths first proven on GCP, with Rust's login_probe example (it
# reads its configuration, password included, as JSON on standard input, and prints only session evidence).
#   G2  on the runner: the portable provider's explicit-credential Kerberos and Negotiate, with the domain controller
#       as KDC, TDS 7.4 and 8.0.
#   G1  on the SQL VM: the native provider's signed-in identity (run-command runs as SYSTEM, so the machine account
#       TDS\TDSSQL$), Negotiate and Kerberos against the VM's own SQL Server.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
runner=$(python3 -c "import json; print(json.load(open('$here/azure.json'))['runner_public_ip'])")
key="$here/secrets/runner_ed25519"
ssh_opts="-i $key -o StrictHostKeyChecking=accept-new -o BatchMode=yes"
probe="cd rust/clients/rust && ~/.cargo/bin/cargo run -q --locked --features system-gssapi --example login_probe"

echo "G2: portable explicit-credential Kerberos from the runner"
rsync -rlp --checksum --delete -e "ssh $ssh_opts" --exclude target "$here/../../clients/rust/" "tds@$runner:rust/clients/rust/"
for method in kerberos negotiate; do
    for version in 7.4 8.0; do
        python3 - "$here" "$method" "$version" <<'PY' | ssh $ssh_opts "tds@$runner" "$probe" 2>&1 | tail -2 | sed "s/^/  $method $version: /"
import json, sys
here, method, version = sys.argv[1:]
secrets = json.load(open(f"{here}/secrets/secrets.json"))
print(json.dumps({"host": "tdssql.tds.test", "server_name": "tdssql.tds.test",
                  "ca_file": "/home/tds/rust/infra/azure/secrets/ca.pem", "method": method, "provider": "portable",
                  "username": "tdsuser@TDS.TEST", "password": secrets["test_user_password"],
                  "kdc_url": "tcp://10.42.1.4:88", "tds_version": version}))
PY
    done
done

echo "G1: native signed-in Windows SSPI on the SQL VM"
python3 - "$here" <<'PY'
import asyncio, json, ssl, subprocess, sys
here = sys.argv[1]
sys.path.insert(0, here)
import paired
async def grant():  # the machine account's login, which the native signed-in provider logs in as under SYSTEM
    options = {"host": paired.PLACES["sql_vm_public_ip"], "port": 1433, "user": "tdsadmin",
               "password": paired.secrets()["sql_admin_password"],
               "ssl_context": ssl.create_default_context(cafile=f"{here}/{paired.PLACES['sql_vm_ca']}")}
    async with await paired.tds.connect(**options) as admin:
        async with admin.serial_channel() as channel:
            await paired.fetch(channel, "IF SUSER_ID(N'TDS\\TDSSQL$') IS NULL CREATE LOGIN [TDS\\TDSSQL$] FROM WINDOWS")
asyncio.run(grant())
done = subprocess.run(["az", "vm", "run-command", "invoke", "-g", paired.PLACES["resource_group"], "-n", "vm-tds-sql",
                       "--command-id", "RunPowerShellScript", "--scripts", f"@{here}/scripts/native-probe.ps1", "-o", "json"],
                      capture_output=True, text=True, check=True)
for m in json.loads(done.stdout)["value"]:
    if m["message"].strip():
        print(m["message"].strip()[-3000:])
PY
