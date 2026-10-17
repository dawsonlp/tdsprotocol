"""The Windows certificate store as an Always Encrypted key store (M17, D-60), on Windows.

infra/azure/windows-tests.sh runs these tests on the Azure SQL VM, against that VM's own SQL Server, with a certificate
made in its LocalMachine/My store whose key can't be exported. They are skipped anywhere else.
"""

import asyncio
import os
import sys

import pytest

import tds
from conftest import fetch

pytestmark = pytest.mark.azure
THUMBPRINT = os.environ.get("TDS_CERT_THUMBPRINT")


@pytest.fixture
def windows():
    if sys.platform != "win32" or not THUMBPRINT:
        pytest.skip("the Windows certificate store runs on the Azure SQL VM: infra/azure/windows-tests.sh")
    import ssl
    context = ssl.create_default_context()
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE  # the VM's own certificate (D-10: 7.4)
    return {"host": "localhost", "port": 1433, "user": "tdsadmin", "password": os.environ["TDS_SQL_PASSWORD"],
            "ssl_context": context}


def test_always_encrypted_with_a_certificate_store_master_key(windows):
    from tds.encryption import Encryption
    from tds.encryption.certstore import WindowsCertificateStore

    store = WindowsCertificateStore()
    path = f"LocalMachine/My/{THUMBPRINT}"
    wrapped = store.encrypt_column_key(path)
    assert len(store.decrypt_column_key(path, "RSA_OAEP", wrapped)) == 32  # the private key, by CNG
    signature = store.sign_master_key_metadata(path)
    assert store.verify_master_key_metadata(path, True, signature)

    async def go():
        async with await tds.connect(**windows) as admin:
            async with admin.serial_channel() as channel:
                await fetch(channel, "IF DB_ID('tds_certstore') IS NOT NULL BEGIN ALTER DATABASE tds_certstore SET "
                                     "SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE tds_certstore END; "
                                     "CREATE DATABASE tds_certstore")
                await fetch(channel, f"USE tds_certstore; CREATE COLUMN MASTER KEY cmk WITH (KEY_STORE_PROVIDER_NAME = "
                                     f"N'{store.name}', KEY_PATH = N'{path}')")
                await fetch(channel, f"USE tds_certstore; CREATE COLUMN ENCRYPTION KEY cek WITH VALUES "
                                     f"(COLUMN_MASTER_KEY = cmk, ALGORITHM = 'RSA_OAEP', ENCRYPTED_VALUE = 0x{wrapped.hex()})")
        async with await Encryption([store]).connect(**{**windows, "database": "tds_certstore"}) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE dbo.t (v int ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = cek, "
                                     "ENCRYPTION_TYPE = RANDOMIZED, ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'))")
                text = tds.types.nvarchar(tds.types.MAX)
                await fetch(channel, tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", text, "INSERT dbo.t VALUES (@v)"),
                                              tds.Param("@params", text, "@v int"), tds.Param("@v", tds.types.int, 41000)))
                return (await fetch(channel, "SELECT v FROM dbo.t")).result_sets[0].rows

    assert asyncio.run(go()) == ((41000,),)
