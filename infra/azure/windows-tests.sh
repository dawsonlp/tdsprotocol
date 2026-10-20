#!/bin/sh
# Run the Windows certificate store's tests on the SQL VM (D-62), for Python and Rust: the runner serves both drivers
# inside the network for a few minutes, the VM fetches them, and scripts/windows-tests.ps1 runs the tests there.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
runner=$(python3 -c "import json; print(json.load(open('$here/azure.json'))['runner_public_ip'])")
key="$here/secrets/runner_ed25519"
ssh_="ssh -i $key -o StrictHostKeyChecking=accept-new -o BatchMode=yes tds@${runner}"
zip="$(mktemp -d)/tds.zip"
(cd "$here/../.." && zip -qr "$zip" clients/python clients/rust -x "*/.venv/*" "*/__pycache__/*" "*/.pytest_cache/*" "clients/rust/target/*")
$ssh_ "mkdir -p ~/share"
scp -q -i "$key" -o BatchMode=yes "$zip" "tds@${runner}:share/tds.zip"
$ssh_ "cd ~/share && (timeout 5400 python3 -m http.server 8765 >/dev/null 2>&1 &)"
python3 - "$here" <<'PY'
import json, subprocess, sys
here = sys.argv[1]
places = json.load(open(f"{here}/azure.json"))
secrets = json.load(open(f"{here}/secrets/secrets.json"))
done = subprocess.run(["az", "vm", "run-command", "invoke", "-g", places["resource_group"], "-n", "vm-tds-sql",
                       "--command-id", "RunPowerShellScript", "--scripts", f"@{here}/scripts/windows-tests.ps1",
                       "--parameters", f"SqlPassword={secrets['sql_admin_password']}", "Source=http://10.42.1.6:8765",
                       f"Domain={places['domain']}", "-o", "json"], capture_output=True, text=True)
if done.returncode:
    sys.exit(f"az failed: {done.stderr[-800:]}")
for m in json.loads(done.stdout)["value"]:
    if m.get("message", "").strip():
        print(f"[{m['code'].split('/')[1]}]", m["message"].strip()[-4000:])
PY
