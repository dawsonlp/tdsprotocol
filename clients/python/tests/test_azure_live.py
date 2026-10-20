"""M17 and M18 against the Azure test infrastructure (D-62).

The tests cover Entra ID logins and routing on Azure SQL, Windows logins (NTLM) and the Browser on SQL Server on
Windows, Azure Key Vault as an Always Encrypted key store, and the Azure-only login features. Kerberos runs from the
Linux runner inside the network (test_kerberos_azure.py).

The tests need infra/azure to be deployed (terraform apply, then configure.py), and are skipped otherwise. Its
azure.json says where everything is, and secrets/ holds the passwords. Entra ID logins use the user signed in to the
Azure CLI, who is Azure SQL's Entra admin.
"""

import asyncio
import json
import ssl
from pathlib import Path

import pytest

import tds
from conftest import fetch
from tds import Feature, browser
from tds.adapters.entra import fetch as entra_fetch, token as entra_token
from tds.adapters.spnego import Spnego

pytestmark = pytest.mark.azure
INFRA = Path(__file__).resolve().parents[2].parent / "infra" / "azure"


@pytest.fixture(scope="module")
def azure():
    if not (INFRA / "azure.json").exists():
        pytest.skip("the Azure test infrastructure isn't up: infra/azure (terraform apply, then configure.py)")
    places = json.loads((INFRA / "azure.json").read_text())
    secrets = json.loads((INFRA / "secrets" / "secrets.json").read_text())
    return places, secrets


@pytest.fixture(scope="module")
def credential():
    from azure.identity import AzureCliCredential
    return AzureCliCredential()


def run(coroutine):
    return asyncio.run(coroutine)


def public_ca() -> ssl.SSLContext:
    """Azure SQL's certificate chains to a public authority. The authorities are the system's, or certifi's where
    Python has none."""
    import certifi
    return ssl.create_default_context(cafile=certifi.where())


def unverified() -> ssl.SSLContext:
    """SQL Server on the Windows VM presents its own self-signed certificate. Under 7.4, a context that doesn't verify
    is allowed (D-10). The tests use it for that server only."""
    context = ssl.create_default_context()
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    return context


def azure_sql(places, **options) -> dict:
    return {"host": places["azure_sql_server"], "port": 1433, "database": places["azure_sql_database"],
            "ssl_context": public_ca(), **options}


async def who(connection) -> tuple:
    async with connection.serial_channel() as channel:
        return (await fetch(channel, "SELECT SUSER_SNAME(), DB_NAME()")).result_sets[0].rows[0]


# --------------------------------------------------------------------------- Entra ID logins and routing on Azure SQL

def test_an_entra_token_up_front(azure, credential):
    places, _ = azure
    shown = []

    async def go():
        async with await tds.connect(**azure_sql(places), login=tds.EntraToken(entra_token(credential)),
                                     observe=lambda e: shown.append(e.text)) as connection:
            return await who(connection), connection.routed_from

    (name, database), routed_from = run(go())
    assert "@" in name and database == places["azure_sql_database"]
    assert routed_from is not None  # connection policy Redirect: the gateway routes every connection (D-11)
    assert any(t.startswith("routed · to ") for t in shown)


def test_an_entra_token_fetched_mid_login(azure, credential):
    places, _ = azure
    shown = []

    async def go():
        async with await tds.connect(**azure_sql(places), login=tds.EntraLogin(entra_fetch(credential)),
                                     observe=lambda e: shown.append(e.text)) as connection:
            return await who(connection)

    name, _ = run(go())
    assert "@" in name
    asked = [t for t in shown if "the server asks for a token for" in t]
    assert asked and "https://database.windows.net/" in asked[0]


def test_a_sql_login_on_azure_sql(azure):
    places, secrets = azure

    async def go():
        async with await tds.connect(**azure_sql(places), user="tdsadmin",
                                     password=secrets["sql_admin_password"]) as connection:
            return await who(connection)

    assert run(go())[0] == "tdsadmin"


def test_the_azure_only_features(azure, credential):
    """PY-AZ-06: each unimplemented Azure feature, requested alone, warns; one the server enables refuses the login
    before any SQL. Both campaigns saw AZURE_SQL_SUPPORT, AZURE_DNS_CACHING and GLOBAL_TRANSACTIONS enabled."""
    places, _ = azure
    asked = [Feature.AZURE_SQL_SUPPORT, Feature.AZURE_DNS_CACHING, Feature.ENHANCED_ROUTING, Feature.GLOBAL_TRANSACTIONS]
    outcomes = {}
    for feature in asked:
        async def go():
            async with await tds.connect(**azure_sql(places), login=tds.EntraToken(entra_token(credential)),
                                         features=[*tds.DEFAULT_FEATURES, feature]) as connection:
                return connection.features.get(feature)
        with pytest.warns(tds.UnsupportedFeatureWarning):
            try:
                outcomes[feature.name] = f"allowed ({run(go())!r})"
            except tds.UnsupportedFeatureEnabled as e:
                assert e.feature == feature
                outcomes[feature.name] = "refused: enabled"
    print("outcomes:", outcomes)  # recorded on Connect › Edge cases
    assert any(v.startswith("refused") for v in outcomes.values())


# --------------------------------------------------------------------------- Windows logins (NTLM) and the Browser

def windows_sql(places, **options) -> dict:
    return {"host": places["sql_vm_public_ip"], "port": 1433, "ssl_context": unverified(), **options}


def test_ntlm_with_a_local_windows_account(azure):
    places, secrets = azure
    provider = Spnego("tdssql\\tdsadmin", secrets["windows_admin_password"], "ntlm")

    async def go():
        async with await tds.connect(**windows_sql(places), login=tds.WindowsLogin(provider)) as connection:
            return await who(connection)

    assert run(go())[0].upper() == "TDSSQL\\TDSADMIN"


def test_ntlm_with_a_domain_account(azure):
    places, secrets = azure
    provider = Spnego("TDS\\tdsuser", secrets["test_user_password"], "ntlm")

    async def go():
        async with await tds.connect(**windows_sql(places), login=tds.WindowsLogin(provider)) as connection:
            return await who(connection)

    assert run(go())[0].upper() == "TDS\\TDSUSER"


def test_a_wrong_windows_password_is_refused(azure):
    places, _ = azure
    provider = Spnego("tdssql\\tdsadmin", "not the password", "ntlm")
    with pytest.raises(tds.LoginRejected, match="Msg 18452(.|\\n)*untrusted domain(.|\\n)*for a wrong password"):
        run(tds.connect(**windows_sql(places), login=tds.WindowsLogin(provider)))


def test_the_browser(azure):
    places, _ = azure

    async def go():
        default = await browser.instance(places["sql_vm_public_ip"], "MSSQLSERVER", timeout_ms=3000)
        every = await browser.machine(places["sql_vm_public_ip"], timeout_ms=3000)
        return default, every

    default, every = run(go())
    assert default.tcp_port == 1433 and default.server_name.upper() == "TDSSQL"
    assert [i.instance_name for i in every] == ["MSSQLSERVER"]


# --------------------------------------------------------------------------- Azure Key Vault as an Always Encrypted key store

def test_always_encrypted_with_a_key_vault_master_key(azure, credential, server):
    """The master key is the Key Vault key, and the database is in the local container. SQL Server never has a key."""
    from tds.encryption import Encryption
    from tds.encryption.keyvault import AzureKeyVaultKeyStore

    places, _ = azure
    store = AzureKeyVaultKeyStore(credential)
    key_url = places["key_vault_key_id"]
    wrapped = store.encrypt_column_key(key_url)

    async def go():
        async with await tds.connect(**server) as admin:
            async with admin.serial_channel() as channel:
                await fetch(channel, "IF DB_ID('tds_akv') IS NOT NULL BEGIN ALTER DATABASE tds_akv SET SINGLE_USER WITH "
                                     "ROLLBACK IMMEDIATE; DROP DATABASE tds_akv END; CREATE DATABASE tds_akv")
                await fetch(channel, f"USE tds_akv; CREATE COLUMN MASTER KEY akv WITH (KEY_STORE_PROVIDER_NAME = "
                                     f"N'AZURE_KEY_VAULT', KEY_PATH = N'{key_url}')")
                await fetch(channel, f"USE tds_akv; CREATE COLUMN ENCRYPTION KEY cek WITH VALUES (COLUMN_MASTER_KEY = akv, "
                                     f"ALGORITHM = 'RSA_OAEP', ENCRYPTED_VALUE = 0x{wrapped.hex()})")
        async with await Encryption([store]).connect(**{**server, "database": "tds_akv"}) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE dbo.t (v nvarchar(20) COLLATE Latin1_General_BIN2 ENCRYPTED WITH "
                                     "(COLUMN_ENCRYPTION_KEY = cek, ENCRYPTION_TYPE = DETERMINISTIC, "
                                     "ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'))")
                text = tds.types.nvarchar(tds.types.MAX)
                await fetch(channel, tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", text, "INSERT dbo.t VALUES (@v)"),
                                              tds.Param("@params", text, "@v nvarchar(20)"),
                                              tds.Param("@v", tds.types.nvarchar(20), "kept in a vault")))
                return (await fetch(channel, "SELECT v FROM dbo.t")).result_sets[0].rows

    assert run(go()) == (("kept in a vault",),)


# --------------------------------------------------------------------------- Always Encrypted with a VBS enclave (M18)

def test_always_encrypted_with_an_enclave(azure, credential, tmp_path):
    """LIKE and ranges on a randomized column. The server runs them inside its VBS enclave, which gets the column key
    in an enclave package. There is no attestation, as Azure SQL Database offers none."""
    from tds.encryption import Encryption, LocalKeyStore

    places, _ = azure
    store = LocalKeyStore(tmp_path)
    store.create_master_key("enclave.pem")
    signature = store.sign_master_key_metadata("enclave.pem")
    wrapped = store.encrypt_column_key("enclave.pem")
    entra = tds.EntraToken(entra_token(credential))
    text = tds.types.nvarchar(tds.types.MAX)

    def executesql(statement, declarations, *params):
        return tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", text, statement),
                        tds.Param("@params", text, declarations), *params)

    async def go():
        async with await tds.connect(**azure_sql(places), login=entra) as admin:
            async with admin.serial_channel() as channel:
                await fetch(channel, "DROP TABLE IF EXISTS dbo.secrets; "
                                     "IF EXISTS (SELECT 1 FROM sys.column_encryption_keys WHERE name = 'tds_enclave_cek') "
                                     "DROP COLUMN ENCRYPTION KEY tds_enclave_cek; "
                                     "IF EXISTS (SELECT 1 FROM sys.column_master_keys WHERE name = 'tds_enclave_cmk') "
                                     "DROP COLUMN MASTER KEY tds_enclave_cmk")
                await fetch(channel, "CREATE COLUMN MASTER KEY tds_enclave_cmk WITH (KEY_STORE_PROVIDER_NAME = "
                                     f"N'{store.name}', KEY_PATH = N'enclave.pem', ENCLAVE_COMPUTATIONS "
                                     f"(SIGNATURE = 0x{signature.hex()}))")
                await fetch(channel, "CREATE COLUMN ENCRYPTION KEY tds_enclave_cek WITH VALUES (COLUMN_MASTER_KEY = "
                                     f"tds_enclave_cmk, ALGORITHM = 'RSA_OAEP', ENCRYPTED_VALUE = 0x{wrapped.hex()})")
                await fetch(channel, "CREATE TABLE dbo.secrets (id int, name nvarchar(50) COLLATE Latin1_General_BIN2 "
                                     "ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = tds_enclave_cek, ENCRYPTION_TYPE = RANDOMIZED, "
                                     "ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'), salary int ENCRYPTED WITH "
                                     "(COLUMN_ENCRYPTION_KEY = tds_enclave_cek, ENCRYPTION_TYPE = RANDOMIZED, "
                                     "ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'))")
        encryption = Encryption([store], enclave_attestation="none")
        async with await encryption.connect(**azure_sql(places), login=entra) as connection:
            async with connection.serial_channel() as channel:
                for i, (name, salary) in enumerate([("Ada", 41000), ("Alan", 52000), ("Grace", 61000)]):
                    await fetch(channel, executesql("INSERT dbo.secrets VALUES (@id, @name, @salary)",
                                                    "@id int, @name nvarchar(50), @salary int",
                                                    tds.Param("@id", tds.types.int, i),
                                                    tds.Param("@name", tds.types.nvarchar(50), name),
                                                    tds.Param("@salary", tds.types.int, salary)))
                like = (await fetch(channel, executesql("SELECT name FROM dbo.secrets WHERE name LIKE @p ORDER BY id",
                                                        "@p nvarchar(50)",
                                                        tds.Param("@p", tds.types.nvarchar(50), "A%")))).result_sets[0].rows
                more = (await fetch(channel, executesql("SELECT name FROM dbo.secrets WHERE salary > @s ORDER BY id",
                                                        "@s int", tds.Param("@s", tds.types.int, 50000)))).result_sets[0].rows
                return connection.connection._core.negotiated.get("enclave_type"), like, more

    enclave_type, like, more = run(go())
    assert enclave_type == "VBS"
    assert like == (("Ada",), ("Alan",)) and more == (("Alan",), ("Grace",))
