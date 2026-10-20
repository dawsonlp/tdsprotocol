"""Python's half of the paired Azure checks (D-62), against the same Azure SQL database as Rust's tests/azure_live.rs.

    ../../clients/python/.venv/bin/python paired.py write        Python's Key Vault and enclave tables
    ../../clients/python/.venv/bin/python paired.py read         read Rust's tables (after Rust's paired test)
    ../../clients/python/.venv/bin/python paired.py principal    service-principal logins, both flows
    python paired.py identity                                    managed-identity logins (on the runner)
    ../../clients/python/.venv/bin/python paired.py recovery     the server ends a session; it is recovered

The order is: write, Rust's mac_key_vault_and_enclave_values_round_trip_and_read_python_values with
TDS_AZURE_PAIRED=1, then read. Both clients use the same Key Vault key, values and expected rows; each creates its own
master key, column key and tables (python_* here, rust_* in Rust). Nothing secret is printed.
"""

import asyncio
import json
import ssl
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "clients" / "python"))
import tds  # noqa: E402
from tds.adapters.entra import fetch as entra_fetch, token as entra_token  # noqa: E402

PLACES = json.loads((HERE / "azure.json").read_text())
VAULT_VALUE = "kept in a vault"
STAFF = [("Ada", 41000), ("Alan", 52000), ("Grace", 61000)]
TEXT = tds.types.nvarchar(tds.types.MAX)


def secrets() -> dict:
    return json.loads((HERE / "secrets" / "secrets.json").read_text())


def azure_sql(login) -> dict:
    import certifi
    return {"host": PLACES["azure_sql_server"], "port": 1433, "database": PLACES["azure_sql_database"],
            "ssl_context": ssl.create_default_context(cafile=certifi.where()), "login": login}


async def fetch(channel, sql):
    async with await channel.exchange(tds.Batch(sql) if isinstance(sql, str) else sql) as response:
        return await response.fetch()


def executesql(statement, declarations, *params):
    return tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, statement),
                    tds.Param("@params", TEXT, declarations), *params)


def cli():
    from azure.identity import AzureCliCredential
    return AzureCliCredential()


def store():
    from tds.encryption.keyvault import AzureKeyVaultKeyStore
    return AzureKeyVaultKeyStore(cli())


async def write() -> None:
    from tds.encryption import Encryption
    vault, path = store(), PLACES["key_vault_key_id"]
    signature, wrapped = vault.sign_master_key_metadata(path), vault.encrypt_column_key(path)
    login = tds.EntraToken(entra_token(cli()))
    async with await tds.connect(**azure_sql(login)) as admin:
        async with admin.serial_channel() as channel:
            await fetch(channel, "DROP TABLE IF EXISTS dbo.python_akv; DROP TABLE IF EXISTS dbo.python_enclave; "
                                 "IF EXISTS (SELECT 1 FROM sys.column_encryption_keys WHERE name = 'python_cek') "
                                 "DROP COLUMN ENCRYPTION KEY python_cek; "
                                 "IF EXISTS (SELECT 1 FROM sys.column_master_keys WHERE name = 'python_cmk') "
                                 "DROP COLUMN MASTER KEY python_cmk")
            await fetch(channel, f"CREATE COLUMN MASTER KEY python_cmk WITH (KEY_STORE_PROVIDER_NAME = N'{vault.name}', "
                                 f"KEY_PATH = N'{path}', ENCLAVE_COMPUTATIONS (SIGNATURE = 0x{signature.hex()}))")
            await fetch(channel, "CREATE COLUMN ENCRYPTION KEY python_cek WITH VALUES (COLUMN_MASTER_KEY = python_cmk, "
                                 f"ALGORITHM = 'RSA_OAEP', ENCRYPTED_VALUE = 0x{wrapped.hex()})")
            await fetch(channel, "CREATE TABLE dbo.python_akv (v nvarchar(50) COLLATE Latin1_General_BIN2 ENCRYPTED WITH "
                                 "(COLUMN_ENCRYPTION_KEY = python_cek, ENCRYPTION_TYPE = DETERMINISTIC, "
                                 "ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256')); "
                                 "CREATE TABLE dbo.python_enclave (id int, name nvarchar(50) COLLATE Latin1_General_BIN2 "
                                 "ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = python_cek, ENCRYPTION_TYPE = RANDOMIZED, "
                                 "ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'), salary int ENCRYPTED WITH "
                                 "(COLUMN_ENCRYPTION_KEY = python_cek, ENCRYPTION_TYPE = RANDOMIZED, "
                                 "ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'))")
    encryption = Encryption([store()], enclave_attestation="none")
    async with await encryption.connect(**azure_sql(login)) as connection:
        async with connection.serial_channel() as channel:
            await fetch(channel, executesql("INSERT dbo.python_akv VALUES (@v)", "@v nvarchar(50)",
                                            tds.Param("@v", tds.types.nvarchar(50), VAULT_VALUE)))
            for i, (name, salary) in enumerate(STAFF):
                await fetch(channel, executesql("INSERT dbo.python_enclave VALUES (@id, @name, @salary)",
                                                "@id int, @name nvarchar(50), @salary int",
                                                tds.Param("@id", tds.types.int, i),
                                                tds.Param("@name", tds.types.nvarchar(50), name),
                                                tds.Param("@salary", tds.types.int, salary)))
    print("PAIRED python wrote python_akv and python_enclave")


async def read() -> None:
    from tds.encryption import Encryption
    login = tds.EntraToken(entra_token(cli()))
    encryption = Encryption([store()], enclave_attestation="none")
    async with await encryption.connect(**azure_sql(login)) as connection:
        async with connection.serial_channel() as channel:
            value = (await fetch(channel, "SELECT v FROM dbo.rust_akv")).result_sets[0].rows
            like = (await fetch(channel, executesql("SELECT name FROM dbo.rust_enclave WHERE name LIKE @p ORDER BY id",
                                                    "@p nvarchar(50)", tds.Param("@p", tds.types.nvarchar(50), "A%"))
                     )).result_sets[0].rows
            more = (await fetch(channel, executesql("SELECT name FROM dbo.rust_enclave WHERE salary > @s ORDER BY id",
                                                    "@s int", tds.Param("@s", tds.types.int, 50000)))).result_sets[0].rows
    assert value == ((VAULT_VALUE,),), value
    assert like == (("Ada",), ("Alan",)) and more == (("Alan",), ("Grace",)), (like, more)
    print("PAIRED python read rust_akv and rust_enclave: value, LIKE 'A%' = Ada, Alan; salary > 50000 = Alan, Grace")


async def logins(credential, expected_user: str, label: str) -> None:
    for login in (tds.EntraToken(entra_token(credential)), tds.EntraLogin(entra_fetch(credential))):
        async with await tds.connect(**azure_sql(login)) as connection:
            async with connection.serial_channel() as channel:
                name, user = (await fetch(channel, "SELECT SUSER_SNAME(), USER_NAME()")).result_sets[0].rows[0]
        assert user == expected_user, (user, expected_user)
        print(f"PAIRED python {label} {type(login).__name__}: login={name} user={user}")


async def recovery() -> None:
    """Follow-up B: KILL ends the session from an admin connection; explicit recovery asks the token source again
    and the server rebuilds the session's SET options. Paired with Rust's mac_recovery_after_the_server_ends_the_session."""
    admin_login = tds.EntraToken(entra_token(cli()))
    for deferred in (False, True):
        calls = []
        inner_token, inner_fetch = entra_token(cli()), entra_fetch(cli())
        def counted_token():
            calls.append("token")
            return inner_token()
        def counted_fetch(spn, sts):
            calls.append(spn)
            return inner_fetch(spn, sts)
        login = tds.EntraLogin(counted_fetch) if deferred else tds.EntraToken(counted_token)
        async with await tds.connect(**azure_sql(admin_login)) as admin, await tds.connect(**azure_sql(login)) as c:
            async with c.serial_channel() as channel:
                await fetch(channel, "SET DATEFIRST 3; SET TEXTSIZE 100")
                spid = (await fetch(channel, "SELECT CAST(@@SPID AS int)")).result_sets[0].rows[0][0]
            before = len(calls)
            async with admin.serial_channel() as channel:
                await fetch(channel, f"KILL {spid}")
            for _ in range(100):
                if not c.alive:
                    break
                await asyncio.sleep(0.1)
            await c.recover()
            async with c.serial_channel() as channel:
                state = (await fetch(channel, "SELECT CAST(@@DATEFIRST AS int), CAST(@@TEXTSIZE AS int)")).result_sets[0].rows[0]
            assert state == (3, 100), state
            print(f"PAIRED python recovery deferred={deferred}: recovered; recoveries={c.recoveries} "
                  f"new token calls={len(calls) - before} state={state} old spid={spid}")


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "write":
        asyncio.run(write())
    elif mode == "read":
        asyncio.run(read())
    elif mode == "principal":
        from azure.identity import ClientSecretCredential
        credential = ClientSecretCredential(PLACES["tenant_id"], PLACES["service_principal_client_id"],
                                            secrets()["service_principal_secret"])
        asyncio.run(logins(credential, PLACES["service_principal_name"], "service principal"))
    elif mode == "recovery":
        asyncio.run(recovery())
    elif mode == "identity":
        from azure.identity import ManagedIdentityCredential
        asyncio.run(logins(ManagedIdentityCredential(), PLACES["runner_identity_name"], "managed identity"))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
