"""The live server for tests marked `live`, the SQL Server 2025 container in docker/macos.

Tests skip if it isn't running.
"""

import os
import socket
from pathlib import Path

import pytest

HOST, PORT = "127.0.0.1", 14325
DAC_PORT = 14345  # the dedicated administrator connection, forwarded by compose.sqlserver-2025.yaml
REPO = Path(__file__).resolve().parents[2].parent  # the repository, when the client is inside it (not copied alone)
TEST_CA = REPO / "docker" / "macos" / "tls" / "test-ca.pem"  # D-10: tests trust only this


def trust_test_authority():
    """An ssl.SSLContext that trusts the test container's certificate authority, and nothing else."""
    import ssl

    if not TEST_CA.exists():
        pytest.skip(f"no test certificate authority: run docker/macos/tls/make-test-certificates.sh ({TEST_CA})")
    return ssl.create_default_context(cafile=TEST_CA)


class Secret(str):
    """A string whose printed form is masked, so failure reports (which print fixture values) can't show it."""

    def __repr__(self) -> str:
        return "'•••• (hidden)'"

    __str__ = __repr__  # str(secret) is masked too. The value itself is still the string.


ENV_FILE = REPO / "docker" / "macos" / ".env"


def _password() -> str | None:
    if os.environ.get("MSSQL_SA_PASSWORD"):
        return os.environ["MSSQL_SA_PASSWORD"]
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith("MSSQL_SA_PASSWORD="):
                return line.split("=", 1)[1]
    return None


@pytest.fixture
def server() -> dict:
    password = _password()
    if not password:
        pytest.skip(f"no password: set MSSQL_SA_PASSWORD or create {ENV_FILE}")
    try:
        socket.create_connection((HOST, PORT), timeout=1).close()
    except OSError:
        pytest.skip(f"SQL Server isn't listening on {HOST}:{PORT}: docker compose -f docker/macos/compose.sqlserver-2025.yaml up -d")
    return {"host": HOST, "port": PORT, "user": "sa", "password": Secret(password), "ssl_context": trust_test_authority()}


async def fetch(channel, sql):
    """Run SQL or a request on a serial channel, and read its whole response into memory.

    Raises ServerError if the response reports errors.
    """
    import tds

    async with await channel.exchange(tds.Batch(sql) if isinstance(sql, str) else sql) as response:
        return await response.fetch()
