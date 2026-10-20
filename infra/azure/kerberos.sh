#!/bin/sh
# On the runner (D-62): Kerberos and managed-identity logins, for Python and Rust. Copies the drivers there, takes a
# ticket for the domain's test user (its password goes in on standard input, never on a command line), runs Python's
# tests/test_kerberos_azure.py and paired.py identity, then Rust's runner_ tests, and finally checks that with an
# expired ticket and without one Rust refuses, with GSSAPI's status, instead of falling back to NTLM. Only azure.json, paired.py and the public CA go to the runner.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
repo="$here/../.."
runner=$(python3 -c "import json; print(json.load(open('$here/azure.json'))['runner_public_ip'])")
domain=$(python3 -c "import json; print(json.load(open('$here/azure.json'))['domain'])")
key="$here/secrets/runner_ed25519"
ssh_opts="-i $key -o StrictHostKeyChecking=accept-new -o BatchMode=yes"
ssh_="ssh $ssh_opts tds@$runner"
$ssh_ "mkdir -p rust/clients/rust rust/infra/azure/secrets"
rsync -a --delete -e "ssh $ssh_opts" --exclude .venv --exclude __pycache__ --exclude .pytest_cache \
    "$repo/clients/python/" "tds@$runner:tds/"
# Not -a: copied files must look newer than the runner's last build, or Cargo
# keeps a stale library. --checksum leaves unchanged files untouched.
rsync -rlp --checksum --delete -e "ssh $ssh_opts" --exclude target "$repo/clients/rust/" "tds@$runner:rust/clients/rust/"
scp -q $ssh_opts "$here/azure.json" "$here/paired.py" "tds@$runner:rust/infra/azure/"
scp -q $ssh_opts "$here/secrets/ca.pem" "tds@$runner:rust/infra/azure/secrets/ca.pem"
python3 -c "import json; print(json.load(open('$here/secrets/secrets.json'))['test_user_password'])" \
    | $ssh_ "kinit tdsuser@$(echo $domain | tr a-z A-Z) >/dev/null && klist | head -3"
$ssh_ "cd tds && ~/.local/bin/uv sync -q --extra kerberos && TDS_KERBEROS_HOST=tdssql.$domain ~/.local/bin/uv run -q pytest -q -p no:cacheprovider tests/test_kerberos_azure.py"
$ssh_ "cd tds && ~/.local/bin/uv run -q python ~/rust/infra/azure/paired.py identity"
cargo="cd rust/clients/rust && ~/.cargo/bin/cargo test --locked --features azure-keyvault,system-gssapi --test azure_live --"
$ssh_ "$cargo --ignored --test-threads=1 --nocapture runner_"
# An expired ticket: one minute long, then wait it out. Then no ticket at all.
python3 -c "import json; print(json.load(open('$here/secrets/secrets.json'))['test_user_password'])" \
    | $ssh_ "kinit -l 1m tdsuser@$(echo $domain | tr a-z A-Z) >/dev/null && klist | sed -n 5p"
sleep 75
$ssh_ "export TDS_EXPECT_TICKET=expired && $cargo --ignored --nocapture runner_without_a_usable_ticket"
$ssh_ "kdestroy && export TDS_EXPECT_TICKET=absent && $cargo --ignored --nocapture runner_without_a_usable_ticket"
