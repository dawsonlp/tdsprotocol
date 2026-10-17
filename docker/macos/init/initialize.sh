#!/bin/bash
# Compose starts this after the container starts. Wait for master, then prepare
# the test database. Health checks wait for tds_test, so up --wait includes setup.
set -eu
export SQLCMDPASSWORD="${MSSQL_SA_PASSWORD:?MSSQL_SA_PASSWORD must be set}"
sqlcmd=/opt/mssql-tools18/bin/sqlcmd
remaining=60

# Do not launch sqlcmd while SQL Server initializes its security subsystem.
# A Rosetta first-start SQLPAL crash was observed with an early sqlcmd.
until (: > /dev/tcp/127.0.0.1/1433) 2>/dev/null &&
      "$sqlcmd" -C -S localhost -U sa -d master -l 1 -b -Q 'SELECT 1' -o /dev/null 2>/dev/null; do
    remaining=$((remaining - 1))
    if [ "$remaining" -eq 0 ]; then
        echo 'SQL Server did not become ready for test database initialization.' >&2
        exit 1
    fi
    sleep 1
done

"$sqlcmd" -C -S localhost -U sa -d master -l 5 -t 30 -b -i /etc/tds-test-init/tds_test.sql
