#!/bin/sh
# Builds TdsTestTypes.dll with Microsoft's .NET SDK image. Nothing is installed on the host.
set -e
cd "$(dirname "$0")"
docker run --rm -v "$PWD":/src -w /src mcr.microsoft.com/dotnet/sdk:10.0 \
    sh -c 'dotnet build -c Release -o /tmp/out -nologo -v q && cp /tmp/out/TdsTestTypes.dll . && rm -rf bin obj'
