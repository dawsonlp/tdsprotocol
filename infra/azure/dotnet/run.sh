#!/bin/sh
# The Microsoft client tie-breaker (D-62): SqlClient in Microsoft's .NET SDK image reads Python's and Rust's Key Vault
# and enclave tables in Azure SQL, signed in as the campaign's service principal. Run after paired.py write and Rust's
# paired test. Nothing is installed on this machine; NuGet packages are cached in the docker volume tds-nuget.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
eval "$(python3 - "$here/.." <<'PY'
import json, shlex, sys
here = sys.argv[1]
places = json.load(open(f"{here}/azure.json"))
secret = json.load(open(f"{here}/secrets/secrets.json"))["service_principal_secret"]
for name, value in [("AZURE_TENANT_ID", places["tenant_id"]), ("AZURE_CLIENT_ID", places["service_principal_client_id"]),
                    ("AZURE_CLIENT_SECRET", secret), ("TDS_AZURE_SQL_SERVER", places["azure_sql_server"]),
                    ("TDS_AZURE_SQL_DATABASE", places["azure_sql_database"])]:
    print(f"export {name}={shlex.quote(value)}")
PY
)"
exec docker run --rm -e AZURE_TENANT_ID -e AZURE_CLIENT_ID -e AZURE_CLIENT_SECRET -e TDS_AZURE_SQL_SERVER \
    -e TDS_AZURE_SQL_DATABASE -v "$here":/src:ro -v tds-nuget:/root/.nuget/packages mcr.microsoft.com/dotnet/sdk:10.0 \
    sh -c 'cp -r /src /work && cd /work && dotnet build -c Release -o /tmp/out -nologo -v q >/tmp/build.log 2>&1 \
           || { cat /tmp/build.log >&2; exit 1; } && dotnet /tmp/out/AzureCheck.dll'
