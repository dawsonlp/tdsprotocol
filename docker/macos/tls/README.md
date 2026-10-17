# The test container's TLS certificate

The SQL Server 2025 test container presents a certificate signed by a **test certificate authority** that exists only on
the machine where it was generated. The tests trust that authority, and nothing else: they verify the certificate, as production clients do,
rather than accepting any certificate (D-10). TDS 8.0 also needs it, because SQL Server closes a TLS-first connection when no
certificate is configured.

## Set it up

From the repository root:

```sh
docker/macos/tls/make-test-certificates.sh                      # writes test-ca.pem/.key, server.pem/.key here
docker compose -f docker/macos/compose.sqlserver-2025.yaml up -d --wait  # recreates the container with them mounted
```

Use Docker Compose 2.30 or later. The [post-start hook](https://docs.docker.com/compose/how-tos/lifecycle/) runs `../init/initialize.sh`, which waits for SQL Server and applies `../init/tds_test.sql`. It creates `tds_test` only when missing. The health check connects to `tds_test`, so `up --wait` includes database readiness. Initialization does not drop an existing database or seed test tables; each scenario owns its own tables. Use Compose to start or recreate the test service so its initialization hook runs.

Run the script again to replace the certificates (they are valid for ten years), then run `docker restart mssql-2025`.

## What each piece does

| File | What it is | Where it goes |
|---|---|---|
| `make-test-certificates.sh` | creates the authority and the server's certificate with OpenSSL | — |
| `test-ca.pem` | the test authority's certificate | the tests' `ssl_context` (`tests/conftest.py`), and `uv run tds --ca-file` |
| `test-ca.key` | the authority's private key, used only by the script to sign | stays here, mode 0600; never mounted |
| `server.pem`, `server.key` | the server's certificate (CN `localhost`; also `127.0.0.1` and `mssql-2025`) and key | mounted read-only at `/etc/mssql-tls/` |
| `mssql.conf` | SQL Server's settings: `[network] tlscert`, `tlskey`, `forceencryption = 0` | mounted read-only at `/var/opt/mssql/mssql.conf` |

The keys and certificates are generated, and never committed (`.gitignore`).

## Requirements met, and problems found during setup

- **SQL Server's requirements** (Microsoft, "Encrypt connections to SQL Server on Linux"): server authentication key
  usage, key encipherment, SHA-256 or stronger, and a name matching the host the client connects to.
- **Python 3.13 and later verify strictly** (`VERIFY_X509_STRICT`). The certificate must identify its authority's key
  (Authority Key Identifier). Without it, verification fails with "Missing Authority Key Identifier".
- **The key must be readable by the `mssql` user,** which SQL Server runs as. When the key is mounted under
  `/etc/ssl/private`, a directory that this user cannot open in the image, SQL Server stops with error 49940 ("Unable to
  open one or more of the user-specified certificate file(s)"). For this reason the files are mounted at
  `/etc/mssql-tls/`, and the key has mode 0644. This is acceptable because it is a test key.
- **Check it** with `uv run tds --ca-file ../../docker/macos/tls/test-ca.pem --tds-version 8.0` (from `clients/python`).
  The outline shows `⇄ secure · TLSv1.3 · … · ALPN tds/8.0` before the hello.
