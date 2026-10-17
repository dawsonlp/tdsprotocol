#!/bin/sh
# Runs AeCheck (Always Encrypted pass 2, D-61) with Microsoft's .NET SDK image, in the SQL Server container's network,
# and trusts the test certificate authority. TDS_PASSWORD must be set in the environment.
# Usage: run.sh <keys directory> < cases.json
# Nothing is installed on the host. NuGet packages are cached in the docker volume tds-nuget.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
ca="$here/../../../../docker/macos/tls/test-ca.pem"
exec docker run --rm -i --network container:mssql-2025 -e TDS_PASSWORD \
    -v "$here":/src:ro -v "$1":/keys:ro -v "$ca":/usr/local/share/ca-certificates/tds-test-ca.crt:ro \
    -v tds-nuget:/root/.nuget/packages mcr.microsoft.com/dotnet/sdk:10.0 \
    sh -c 'update-ca-certificates >/dev/null 2>&1 && cp -r /src /work && cd /work &&
           dotnet build -c Release -o /tmp/out -nologo -v q >/tmp/build.log 2>&1 || { cat /tmp/build.log >&2; exit 1; } &&
           dotnet /tmp/out/AeCheck.dll'
