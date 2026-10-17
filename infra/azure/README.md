# Azure test infrastructure (D-62)

This is the infrastructure that M17 and M18 were tested against. It is described so that it can be created again and
deleted afterward. It is one resource group, `rg-tds-driver-tests`, in the subscription that you choose.

| Part | Region | For |
|---|---|---|
| Azure SQL logical server and a serverless database with a VBS enclave; Entra admin: the person who runs it; connection policy Redirect; firewall open to one address | East US (set by `sql_location`, because Azure can refuse to provision Azure SQL in a region for a given subscription) | Entra ID logins, routing, the Azure-only features, Always Encrypted with enclaves |
| Key Vault with an RSA key | East US 2 | Always Encrypted's Key Vault key store |
| A Windows Server domain controller (`tds.test`) | East US 2 | Kerberos |
| SQL Server 2022 Developer on Windows, joined to the domain, with the Browser running | East US 2 | NTLM, Kerberos, the Browser, the Windows certificate store |
| A small Ubuntu VM in the network | East US 2 | running the Kerberos tests inside the domain |

The network accepts connections from one address only: to SQL Server's port and the Browser's port on the SQL VM, and
to SSH on the runner. The VMs shut down each night at 05:00 UTC. While the infrastructure is deployed, it costs about
$5–8 a day.

## Creating it, testing, deleting it

```sh
cd infra/azure
terraform init
terraform apply -var subscription_id=$(az account show --query id -o tsv) \
  -var client_ip=$(curl -s https://api.ipify.org) -var admin_login=$(az account show --query user.name -o tsv)
python3 configure.py        # the domain, SQL Server, the runner; writes azure.json and secrets/
cd ../../clients/python
.venv/bin/python -m pytest -m azure          # from this machine: Entra ID, routing, NTLM, the Browser, Key Vault, enclaves
../../infra/azure/kerberos.sh                # Kerberos, on the runner
../../infra/azure/windows-tests.sh           # the Windows certificate store, on the SQL VM
cd ../../infra/azure
terraform destroy -var subscription_id=… -var client_ip=… -var admin_login=…
az group show -n rg-tds-driver-tests         # deleted: "ResourceGroupNotFound"
rm -rf azure.json secrets terraform.tfstate terraform.tfstate.backup   # files written by configure.py and Terraform: secrets, not needed after destroy
```

`configure.py` and the scripts never print a secret. Passwords are passed from Terraform's outputs to `az` and `ssh`
as arguments or input. The Terraform state also holds them. It stays on the machine that ran Terraform and is not
committed (`.gitignore`). Delete it after `terraform destroy`.
