# Azure test infrastructure (D-62)

This is the infrastructure that M17 and M18 were tested against, extended for the Rust Azure campaign. It is
described so that it can be created again and deleted afterward. Everything is in one resource group,
`rg-tds-rust-azure` by default (`resource_group_name`), which is created and deleted whole. The previous campaign's
group was `rg-tds-driver-tests`.

| Part | Region | For |
|---|---|---|
| Azure SQL logical server and a serverless database with a VBS enclave; Entra admin: the person who runs it; connection policy Redirect; firewall open to this machine and the runner | East US (`sql_location`: Azure can refuse to provision Azure SQL in a region for a given subscription) | Entra ID logins, routing, the Azure-only features, Always Encrypted with enclaves |
| Key Vault with an RSA key | East US 2 | Always Encrypted's Key Vault key store |
| A Windows Server domain controller (`tds.test`) | East US 2 | Kerberos |
| SQL Server 2022 Developer on Windows, joined to the domain, with the Browser running and a certificate from a disposable CA | East US 2 | NTLM, Kerberos, the Browser, the Windows certificate store |
| An Ubuntu runner (B2ms) with a system-assigned managed identity | East US 2 | Kerberos tests inside the domain, managed-identity logins, building Rust |
| A service principal (an app registration in the tenant) | Entra | Service-principal logins, the .NET tie-breaker |
| A budget and a Logic App | East US 2 | Alerts at 50/80/100% of `budget_amount`; deletes the resource group `lifetime_hours` after creation |

The network accepts connections from one address only: SQL Server's port and the Browser's port on the SQL VM, and
SSH on the runner. The VMs shut down each night at 05:00 UTC. While deployed it costs roughly $6–10 a day. The
previous campaign's 55 minutes cost $0.58.

**Limits.** Azure budgets only alert. The hard stop is the Logic App, which deletes the whole resource group at the
`deadline` output, even if `terraform destroy` never runs. The service principal is outside the group: its secret
expires at the same deadline, and `terraform destroy` deletes it. A deleted Key Vault stays soft-deleted for 7 days
(`terraform destroy` purges it; the Logic App's deletion does not).

## Creating it

```sh
cd infra/azure
terraform init
terraform apply -var subscription_id=$(az account show --query id -o tsv) \
  -var client_ip=$(curl -s https://api.ipify.org) -var admin_login=$(az account show --query user.name -o tsv) \
  -var alert_email=$(az account show --query user.name -o tsv)
../../clients/python/.venv/bin/python configure.py   # domain, SQL Server, certificate, Entra users, runner, Windows Rust
```

`configure.py` writes `azure.json` (endpoints and identity names) and `secrets/` (passwords, the service principal's
secret, the runner's key, the disposable CA). Neither is committed. `wintools` installs the Visual C++ build tools
and Rust on the SQL VM and takes tens of minutes.

## Testing, in order

On this machine (Python's Key Vault test also needs the local Docker SQL Server):

```sh
(cd ../../clients/python && .venv/bin/python -m pytest -m azure)           # Python's baseline
../../clients/python/.venv/bin/python paired.py principal                   # Python as the service principal
../../clients/python/.venv/bin/python paired.py write                       # Python's Key Vault and enclave tables
(cd ../../clients/rust && TDS_AZURE_PAIRED=1 cargo test --all-features --test azure_live -- --ignored \
   --test-threads=1 --nocapture mac_)    # Rust: Entra, SQL, pools, features, NTLM, Browser, vault, enclave, Part B
../../clients/python/.venv/bin/python paired.py read                        # Python reads Rust's
dotnet/run.sh                                                               # SqlClient reads both: the tie-breaker
./kerberos.sh        # on the runner: Kerberos and managed identity for both clients; no-ticket refusal for Rust
./windows-tests.sh   # on the SQL VM: the certificate store for both clients
```

## Deleting it

```sh
terraform destroy -var subscription_id=… -var client_ip=… -var admin_login=… -var alert_email=…
az group show -n rg-tds-rust-azure                    # deleted: "ResourceGroupNotFound"
az keyvault list-deleted --query "[?contains(name,'kv-tds')]"   # empty: purged
az ad app list --display-name tds-rust-azure --query "[].displayName"   # empty
rm -rf azure.json secrets terraform.tfstate terraform.tfstate.backup   # secrets, not needed after destroy
```

`configure.py` and the scripts never print a secret. Passwords go from Terraform's outputs to `az`, `ssh` and
`sqlcmd` as arguments or input. The Terraform state also holds them; it stays on the machine that ran Terraform and
is not committed (`.gitignore`). Delete it after `terraform destroy`.
