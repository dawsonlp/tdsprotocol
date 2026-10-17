#!/bin/sh
# Run the Windows certificate store's test on the SQL VM (D-62): the runner serves the driver inside the network for
# a few minutes, the VM fetches it, and scripts/windows-tests.ps1 runs the test there.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
runner=$(python3 -c "import json; print(json.load(open('$here/azure.json'))['runner_public_ip'])")
key="$here/secrets/runner_ed25519"
ssh_="ssh -i $key -o StrictHostKeyChecking=accept-new -o BatchMode=yes tds@${runner}"
zip="$(mktemp -d)/tds.zip"
(cd "$here/../../clients/python" && zip -qr "$zip" . -x ".venv/*" "*/__pycache__/*" ".pytest_cache/*")
$ssh_ "mkdir -p ~/share"
scp -q -i "$key" -o BatchMode=yes "$zip" "tds@${runner}:share/tds.zip"
$ssh_ "cd ~/share && (timeout 900 python3 -m http.server 8765 >/dev/null 2>&1 &)"
python3 - "$here" <<'PY'
import json, subprocess, sys
here = sys.argv[1]
secrets = json.load(open(f"{here}/secrets/secrets.json"))
done = subprocess.run(["az", "vm", "run-command", "invoke", "-g", "rg-tds-driver-tests", "-n", "vm-tds-sql",
                       "--command-id", "RunPowerShellScript", "--scripts", f"@{here}/scripts/windows-tests.ps1",
                       "--parameters", f"SqlPassword={secrets['sql_admin_password']}", "Source=http://10.42.1.6:8765",
                       "-o", "json"], capture_output=True, text=True)
if done.returncode:
    sys.exit(f"az failed: {done.stderr[-800:]}")
for m in json.loads(done.stdout)["value"]:
    if m.get("message", "").strip():
        print(f"[{m['code'].split('/')[1]}]", m["message"].strip()[-4000:])
PY
