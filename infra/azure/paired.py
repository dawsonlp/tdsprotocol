"""Python's half of the paired Azure checks (D-62), against the same Azure SQL database as Rust's tests/azure_live.rs.

    ../../clients/python/.venv/bin/python paired.py write        Python's Key Vault and enclave tables
    ../../clients/python/.venv/bin/python paired.py read         read Rust's tables (after Rust's paired test)
    ../../clients/python/.venv/bin/python paired.py principal    service-principal logins, both flows
    python paired.py identity                                    managed-identity logins (on the runner)
    ../../clients/python/.venv/bin/python paired.py recovery     the server ends a session; it is recovered
    ../../clients/python/.venv/bin/python paired.py rotation     Windows password rotation, explicit connections
    python paired.py kdc-deadline < password                     on the runner: an unreachable KDC meets the deadline
    ../../clients/python/.venv/bin/python paired.py review       evidence for PY-AZ-02, 03 and 04 (no changes made)

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
CLEANUP = ("DECLARE @i int = 0, @k nvarchar(max); WHILE SUSER_ID(N\'{login}\') IS NOT NULL AND @i < 10 BEGIN SET @k = N\'\'; SELECT @k += N\'BEGIN TRY KILL \' + CAST(session_id AS nvarchar) + N\' END TRY BEGIN CATCH END CATCH;\' FROM sys.dm_exec_sessions WHERE login_name = N\'{login}\'; EXEC (@k); BEGIN TRY DROP LOGIN [{login}] END TRY BEGIN CATCH WAITFOR DELAY \'00:00:01\' END CATCH; SET @i += 1; END")  # end the login's sessions (each may already be gone), then drop it


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


def rotation_account(vm: str, action: str, scope: str, name: str, password: str = "") -> None:
    """scripts/rotation.ps1 on a VM: a throwaway account. The password goes to az as a parameter."""
    import subprocess
    done = subprocess.run(["az", "vm", "run-command", "invoke", "-g", PLACES["resource_group"], "-n", vm,
                           "--command-id", "RunPowerShellScript", "--scripts", f"@{HERE / 'scripts' / 'rotation.ps1'}",
                           "-o", "json", "--parameters", f"Action={action}", f"Scope={scope}", f"Name={name}",
                           f"Password={password}"],
                          capture_output=True, text=True, check=True)
    messages = json.loads(done.stdout)["value"]
    assert not any("StdErr" in m["code"] and m["message"].strip() for m in messages), done.stdout
    assert any(f"{action} done" in m["message"] for m in messages), done.stdout


async def rotation() -> None:
    """Follow-up C, Python's explicit connections: the new password logs in after a rotation; whether the old one is
    still accepted is recorded (a domain account's previous password stays usable for NTLM for a while)."""
    import secrets as random
    from tds.adapters.spnego import Spnego
    def windows(user, password):
        context = ssl.create_default_context(cafile=str(HERE / PLACES["sql_vm_ca"]))
        return {"host": PLACES["sql_vm_public_ip"], "port": 1433, "ssl_context": context,
                "login": tds.WindowsLogin(Spnego(user, password, "ntlm"))}
    admin_options = {"host": PLACES["sql_vm_public_ip"], "port": 1433, "user": "tdsadmin",
                     "password": secrets()["sql_admin_password"],
                     "ssl_context": ssl.create_default_context(cafile=str(HERE / PLACES["sql_vm_ca"]))}
    async def who(options):
        async with await tds.connect(**options) as c:
            async with c.serial_channel() as channel:
                return (await fetch(channel, "SELECT SUSER_SNAME()")).result_sets[0].rows[0][0]
    for scope, vm, prefix in (("local", "vm-tds-sql", "TDSSQL"), ("domain", "vm-tds-dc", "TDS")):
        first, second = (f"Tds-{random.token_hex(9)}-Rr7!" for _ in range(2))
        name = f"tdsrot-{random.token_hex(4)}"  # new each run: a reused name can map to a stale SID
        login = f"{prefix}\\{name}"
        rotation_account(vm, "create", scope, name, first)
        async with await tds.connect(**admin_options) as admin:
            async with admin.serial_channel() as channel:
                await fetch(channel, f"IF SUSER_ID(N'{login}') IS NULL CREATE LOGIN [{login}] FROM WINDOWS")
        assert (await who(windows(login, first))).upper() == login.upper()
        rotation_account(vm, "set", scope, name, second)
        try:
            await who(windows(login, first))
            old = "still accepted right after the change"
        except tds.LoginRejected as e:
            assert "18452" in str(e), e
            old = "refused (18452)"
        assert (await who(windows(login, second))).upper() == login.upper()
        async with await tds.connect(**admin_options) as admin:
            async with admin.serial_channel() as channel:
                await fetch(channel, CLEANUP.format(login=login))
        rotation_account(vm, "remove", scope, name)
        print(f"PAIRED python rotation {scope}: old password {old}; new password logs in")


async def kdc_deadline() -> None:
    """Follow-up D, on the runner: the GCP failure again. A Kerberos config whose KDC never answers (an unused address
    in the lab's subnet), an empty ticket cache and an explicit password make gssapi wait on the KDC. The opening must
    return at its 1.5 s deadline while the event loop keeps running. The password arrives on standard input."""
    import os
    import tempfile
    import time
    from tds.adapters.spnego import Spnego
    password = sys.stdin.readline().strip()
    realm = PLACES["domain"].upper()
    scratch = tempfile.mkdtemp(prefix="tds-kdc-")
    config = os.path.join(scratch, "krb5.conf")
    with open(config, "w") as f:
        f.write(f"[libdefaults]\n  default_realm = {realm}\n  dns_lookup_kdc = false\n  rdns = false\n"
                f"[realms]\n  {realm} = {{\n    kdc = 10.42.1.250\n  }}\n")
    os.environ["KRB5_CONFIG"], os.environ["KRB5CCNAME"] = config, f"FILE:{os.path.join(scratch, 'empty-cache')}"
    ticks = 0

    async def heartbeat():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    beat = asyncio.create_task(heartbeat())
    started = time.monotonic()
    try:
        await tds.connect(f"tdssql.{PLACES['domain']}", 1433, timeout=1.5,
                          ssl_context=ssl.create_default_context(cafile=str(HERE / PLACES["sql_vm_ca"])),
                          login=tds.WindowsLogin(Spnego(f"tdsuser@{realm}", password, "kerberos")))
        outcome = "connected (unexpected)"
    except tds.ConnectError as e:
        outcome = str(e).splitlines()[0]
    elapsed = time.monotonic() - started
    beat.cancel()
    print(f"PAIRED python kdc-deadline: returned after {elapsed:.2f} s with the event loop ticking {ticks} times: {outcome}")
    assert elapsed < 2.5 and ticks > 50, (elapsed, ticks)


async def review() -> None:
    """Live evidence for the Python Azure review backlog; it changes nothing.

    PY-AZ-02: real refusal texts (wrong service principal secret, managed identity off-VM, a vault key that forbids
    unwrap), checked for the secret and for anything token-like. PY-AZ-03: the event loop's longest stall during a
    login through a synchronous credential, and through the asynchronous one. PY-AZ-04: enclave queries over two
    connections from one Encryption context, and concurrently on one MARS connection."""
    import re
    import subprocess
    import time
    from azure.identity import AzureCliCredential, ClientSecretCredential, ManagedIdentityCredential
    from azure.identity.aio import AzureCliCredential as AsyncCliCredential
    from tds.encryption import Encryption
    from tds.encryption.keyvault import AzureKeyVaultKeyStore

    canary = "wrong-secret-canary-7f3a"
    def leaks(text: str) -> list[str]:
        return [name for name, found in (("secret", canary in text), ("jwt", re.search(r"eyJ[\w-]{10,}\.", text)))
                if found]
    refusals = {
        "service principal, wrong secret": ClientSecretCredential(PLACES["tenant_id"], PLACES["service_principal_client_id"], canary),
        "managed identity off the VM": ManagedIdentityCredential(),
    }
    for label, credential in refusals.items():
        try:
            await tds.connect(**azure_sql(tds.EntraToken(entra_token(credential))), timeout=30)
            print(f"REVIEW PY-AZ-02 {label}: unexpectedly connected")
        except Exception as e:
            text = str(e)
            print(f"REVIEW PY-AZ-02 {label}: {type(e).__name__}, {len(text)} chars, leaks={leaks(text)}: {text[:240]!r}")
    vault = PLACES["key_vault_key_id"].split("/keys/")[0]
    name = f"tds-sign-only-{int(time.time())}"
    vault_name = vault.removeprefix("https://").split(".")[0]
    subprocess.run(["az", "keyvault", "key", "create", "--vault-name", vault_name, "--name", name, "--kty", "RSA",
                    "--size", "2048", "--ops", "sign", "verify", "-o", "none"], check=True)
    try:
        store = AzureKeyVaultKeyStore(cli())
        envelope = store.encrypt_column_key(PLACES["key_vault_key_id"])  # a valid envelope from the campaign key
        try:
            store.decrypt_column_key(f"{vault}/keys/{name}", "RSA_OAEP", envelope)
        except Exception as e:
            text = str(e)
            print(f"REVIEW PY-AZ-02 vault key without unwrap: {type(e).__name__}, leaks={leaks(text)}: {text[:240]!r}")
    finally:
        subprocess.run(["az", "keyvault", "key", "delete", "--vault-name", vault_name, "--name", name, "-o", "none"])
        subprocess.run(["az", "keyvault", "key", "purge", "--vault-name", vault_name, "--name", name],
                       capture_output=True)

    for label, credential in (("synchronous", AzureCliCredential()), ("asynchronous", AsyncCliCredential())):
        gaps, last = [], time.monotonic()
        async def heartbeat():
            nonlocal last
            while True:
                await asyncio.sleep(0.01)
                now = time.monotonic(); gaps.append(now - last); last = now
        beat = asyncio.create_task(heartbeat())
        async with await tds.connect(**azure_sql(tds.EntraToken(entra_token(credential)))):
            pass
        beat.cancel()
        if hasattr(credential, "close") and asyncio.iscoroutinefunction(credential.close):
            await credential.close()
        print(f"REVIEW PY-AZ-03 {label} Azure CLI credential: longest event-loop stall {max(gaps):.3f} s during the login")

    login = tds.EntraToken(entra_token(cli()))
    encryption = Encryption([store], enclave_attestation="none")
    like = executesql("SELECT name FROM dbo.python_enclave WHERE name LIKE @p ORDER BY id", "@p nvarchar(50)",
                      tds.Param("@p", tds.types.nvarchar(50), "A%"))
    for round_ in (1, 2):
        async with await encryption.connect(**azure_sql(login)) as connection:
            async with connection.serial_channel() as channel:
                rows = (await fetch(channel, like)).result_sets[0].rows
        print(f"REVIEW PY-AZ-04 connection {round_} from one Encryption context: {rows}")
    async with await encryption.connect(**azure_sql(login), mars=True) as connection:
        async def one():
            async with connection.serial_channel() as channel:
                return (await fetch(channel, like)).result_sets[0].rows
        results = await asyncio.gather(*(one() for _ in range(4)), return_exceptions=True)
    print(f"REVIEW PY-AZ-04 four concurrent MARS channels on one connection: {results}")


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
    elif mode == "review":
        asyncio.run(review())
    elif mode == "kdc-deadline":
        asyncio.run(kdc_deadline())
    elif mode == "rotation":
        asyncio.run(rotation())
    elif mode == "recovery":
        asyncio.run(recovery())
    elif mode == "identity":
        from azure.identity import ManagedIdentityCredential
        asyncio.run(logins(ManagedIdentityCredential(), PLACES["runner_identity_name"], "managed identity"))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
