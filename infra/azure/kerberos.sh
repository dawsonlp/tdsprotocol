#!/bin/sh
# Run the Kerberos tests on the runner (D-62): copy the driver there, take a ticket for the domain's test user (its
# password goes in on standard input, never on a command line), and run tests/test_kerberos_azure.py.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
runner=$(python3 -c "import json; print(json.load(open('$here/azure.json'))['runner_public_ip'])")
domain=$(python3 -c "import json; print(json.load(open('$here/azure.json'))['domain'])")
key="$here/secrets/runner_ed25519"
ssh_="ssh -i $key -o StrictHostKeyChecking=accept-new -o BatchMode=yes tds@$runner"
rsync -a --delete -e "ssh -i $key -o StrictHostKeyChecking=accept-new -o BatchMode=yes" \
    --exclude .venv --exclude __pycache__ --exclude .pytest_cache "$here/../../clients/python/" "tds@$runner:tds/"
python3 -c "import json; print(json.load(open('$here/secrets/secrets.json'))['test_user_password'])" \
    | $ssh_ "kinit tdsuser@$(echo $domain | tr a-z A-Z) >/dev/null && klist | head -3"
$ssh_ "cd tds && ~/.local/bin/uv sync -q --extra kerberos && TDS_KERBEROS_HOST=tdssql.$domain ~/.local/bin/uv run -q pytest -q -p no:cacheprovider tests/test_kerberos_azure.py"
