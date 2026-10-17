"""Always Encrypted (M15, D-60) against the live SQL Server 2025, pass 1 (D-61).

What the driver writes, it reads back exactly. The server holds a master key named for a local key store, and a column
key encrypted by that master key. The key files are in a temporary directory for the test session. SQL Server never
sees a key it can use, or a plaintext.
"""

import asyncio
import datetime as dt
import os
import tempfile
import uuid
from decimal import Decimal

import pytest

import tds
from conftest import fetch
from tds import Feature, types
from tds.encryption import Encryption, EncryptionNotAgreed, LocalKeyStore
from tds.types import EncryptedValue, NotDecrypted, SqlDateTime, SqlDateTimeOffset, SqlDateTime2, SqlTime

pytestmark = pytest.mark.live

DATABASE = "tds_encryption"
TEXT = types.nvarchar(types.MAX)
_keys: dict = {}


def store() -> LocalKeyStore:
    """The session's key store: two master keys, each encrypting a column key."""
    if not _keys:
        keys = LocalKeyStore(tempfile.mkdtemp(prefix="tds-keys-"))
        keys.create_master_key("cmk.pem")
        keys.create_master_key("cmk2.pem")
        _keys.update(store=keys, wrapped=keys.encrypt_column_key("cmk.pem"), wrapped2=keys.encrypt_column_key("cmk2.pem"))
    return _keys["store"]


def run(coroutine):
    return asyncio.run(coroutine)


@pytest.fixture
def ae(server):
    """A fresh database with the session's keys, and an Encryption that holds the key store."""
    keys = store()

    async def go():
        async with await tds.connect(**server) as admin:
            async with admin.serial_channel() as channel:
                await fetch(channel, f"IF DB_ID('{DATABASE}') IS NOT NULL BEGIN ALTER DATABASE {DATABASE} SET "
                                     f"SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE {DATABASE} END; "
                                     f"CREATE DATABASE {DATABASE}")
                await fetch(channel, f"USE {DATABASE}; CREATE COLUMN MASTER KEY cmk WITH "
                                     f"(KEY_STORE_PROVIDER_NAME = N'{keys.name}', KEY_PATH = N'cmk.pem')")
                await fetch(channel, f"USE {DATABASE}; CREATE COLUMN ENCRYPTION KEY cek WITH VALUES "
                                     f"(COLUMN_MASTER_KEY = cmk, ALGORITHM = 'RSA_OAEP', "
                                     f"ENCRYPTED_VALUE = 0x{_keys['wrapped'].hex()})")
                await fetch(channel, f"USE {DATABASE}; CREATE COLUMN MASTER KEY cmk2 WITH "
                                     f"(KEY_STORE_PROVIDER_NAME = N'{keys.name}', KEY_PATH = N'cmk2.pem')")
                await fetch(channel, f"USE {DATABASE}; CREATE COLUMN ENCRYPTION KEY cek2 WITH VALUES "
                                     f"(COLUMN_MASTER_KEY = cmk2, ALGORITHM = 'RSA_OAEP', "
                                     f"ENCRYPTED_VALUE = 0x{_keys['wrapped2'].hex()})")

    run(go())
    return {**server, "database": DATABASE}, Encryption([keys])


def encrypted(column: str, sql_type: str, kind: str, collation: str = "", key: str = "cek") -> str:
    return (f"{column} {sql_type} {collation} ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = {key}, ENCRYPTION_TYPE = {kind}, "
            "ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256')")


def executesql(statement: str, declarations: str, *params) -> tds.Call:
    return tds.Call(tds.Builtin.SP_EXECUTESQL, tds.Param("@stmt", TEXT, statement),
                    tds.Param("@params", TEXT, declarations), *params)


BIN2 = "COLLATE Latin1_General_BIN2"  # deterministic encryption of text needs a binary collation
TYPES = [  # (declared, the driver's type, collation, values: each read back as given)
    ("tinyint", types.tinyint, "", [0, 255]),
    ("smallint", types.smallint, "", [-32768, 32767]),
    ("int", types.int, "", [-(2 ** 31), 2 ** 31 - 1]),
    ("bigint", types.bigint, "", [-(2 ** 63), 2 ** 63 - 1]),
    ("bit", types.bit, "", [False, True]),
    ("real", types.real, "", [1.5, -3.4028234663852886e38]),
    ("float", types.float, "", [-2.2250738585072014e-308, 1.7976931348623157e308]),
    ("decimal(38, 10)", types.decimal(38, 10), "", [Decimal("-9999999999999999999999999999.9999999999"), Decimal("0.0000000001")]),
    ("numeric(5, 2)", types.numeric(5, 2), "", [Decimal("-999.99"), Decimal("0.00")]),
    ("money", types.money, "", [Decimal("-922337203685477.5808"), Decimal("922337203685477.5807")]),
    ("smallmoney", types.smallmoney, "", [Decimal("-214748.3648"), Decimal("214748.3647")]),
    ("date", types.date, "", [dt.date(1, 1, 1), dt.date(9999, 12, 31)]),
    ("time(0)", types.time(0), "", [SqlTime(0), SqlTime(863990000000)]),
    ("time(7)", types.time(7), "", [SqlTime(1), SqlTime(863999999999)]),
    ("datetime2(3)", types.datetime2(3), "", [SqlDateTime2(dt.date(1, 1, 1), 0), SqlDateTime2(dt.date(9999, 12, 31), 863999990000)]),
    ("datetimeoffset(7)", types.datetimeoffset(7), "", [SqlDateTimeOffset(dt.date(2026, 10, 17), 123456789, -840),
                                                         SqlDateTimeOffset(dt.date(2000, 1, 1), 0, 840)]),
    ("datetime", types.datetime, "", [SqlDateTime(-53690, 0), SqlDateTime(2958463, 25919999)]),
    ("smalldatetime", types.smalldatetime, "", [dt.datetime(1900, 1, 1), dt.datetime(2079, 6, 6, 23, 59)]),
    ("uniqueidentifier", types.uniqueidentifier, "", [uuid.UUID(int=0), uuid.UUID("f81d4fae-7dec-11d0-a765-00a0c91e6bf6")]),
    ("char(10)", types.char(10), BIN2, ["café      ", "          "]),
    ("varchar(20)", types.varchar(20), BIN2, ["", "naïve résumé"]),
    ("varchar(max)", types.varchar(types.MAX), BIN2, ["x" * 9000, "é"]),
    ("nchar(5)", types.nchar(5), BIN2, ["日本語  ", "     "]),
    ("nvarchar(30)", types.nvarchar(30), BIN2, ["", "𝄞 and \ud800 alone"]),
    ("nvarchar(max)", types.nvarchar(types.MAX), BIN2, ["界" * 5000, ""]),
    ("binary(4)", types.binary(4), "", [b"\x00\x00\x00\x00", b"\x01\x02\x03\x04"]),
    ("varbinary(10)", types.varbinary(10), "", [b"", b"\xff" * 10]),
    ("varbinary(max)", types.varbinary(types.MAX), "", [bytes(range(256)) * 40, b"\x00"]),
]


@pytest.mark.parametrize("declared, sql_type, collation, values", TYPES, ids=[t[0] for t in TYPES])
def test_every_type_reads_back_exactly(ae, declared, sql_type, collation, values):
    options, encryption = ae

    async def go():
        async with await encryption.connect(**options) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, f"CREATE TABLE dbo.t (id int, {encrypted('d', declared, 'DETERMINISTIC', collation)}, "
                                     f"{encrypted('r', declared, 'RANDOMIZED', collation)})")
                for i, value in enumerate([*values, None]):
                    await fetch(channel, executesql("INSERT dbo.t VALUES (@id, @d, @r)",
                                                    f"@id int, @d {declared}, @r {declared}",
                                                    tds.Param("@id", types.int, i), tds.Param("@d", sql_type, value),
                                                    tds.Param("@r", sql_type, value)))
                rows = (await fetch(channel, "SELECT d, r FROM dbo.t ORDER BY id")).result_sets[0].rows
                found = [(await fetch(channel, executesql("SELECT id FROM dbo.t WHERE d = @d", f"@d {declared}",
                                                          tds.Param("@d", sql_type, value)))).result_sets[0].rows
                         for value in values]
                return rows, found

    rows, found = run(go())
    assert rows == tuple((v, v) for v in [*values, None])
    assert found == [((i,),) for i in range(len(values))]  # a deterministic column finds its row


@pytest.mark.parametrize("declared, sql_type, collation, values", TYPES, ids=[t[0] for t in TYPES])
def test_every_type_bulk_loads_and_reads_back_exactly(ae, declared, sql_type, collation, values):
    options, encryption = ae

    async def go():
        async with await encryption.connect(**options) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, f"CREATE TABLE dbo.t (id int NOT NULL, {encrypted('d', declared, 'DETERMINISTIC', collation)}, "
                                     f"{encrypted('r', declared, 'RANDOMIZED', collation)})")
                columns = (await fetch(channel, "SELECT TOP 0 id, d, r FROM dbo.t")).result_sets[0].columns
                ciphertext = columns[1].type.cipher  # the statement names an encrypted column by its ciphertext's type
                await fetch(channel, tds.BulkInsert(f"INSERT BULK dbo.t (id int NOT NULL, d {ciphertext}, r {ciphertext})"))
                await fetch(channel, tds.BulkRows(columns, [(i, v, v) for i, v in enumerate([*values, None])]))
                rows = (await fetch(channel, "SELECT d, r FROM dbo.t ORDER BY id")).result_sets[0].rows
                found = [(await fetch(channel, executesql("SELECT id FROM dbo.t WHERE d = @d", f"@d {declared}",
                                                          tds.Param("@d", sql_type, value)))).result_sets[0].rows
                         for value in values]
                return rows, found

    rows, found = run(go())
    assert rows == tuple((v, v) for v in [*values, None])
    assert found == [((i,),) for i in range(len(values))]


def test_bulk_rows_from_a_source_are_encrypted_as_they_are_sent(ae):
    options, encryption = ae

    async def rows():
        for i in range(3000):
            yield (i, f"secret {i}")

    async def go():
        async with await encryption.connect(**options) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, f"CREATE TABLE dbo.t (id int NOT NULL, {encrypted('s', 'nvarchar(20)', 'RANDOMIZED', BIN2)})")
                columns = (await fetch(channel, "SELECT TOP 0 id, s FROM dbo.t")).result_sets[0].columns
                await fetch(channel, tds.BulkInsert(f"INSERT BULK dbo.t (id int NOT NULL, s {columns[1].type.cipher})"))
                await fetch(channel, tds.BulkRows(columns, rows()))
                return (await fetch(channel, "SELECT COUNT(*), MAX(id) FROM dbo.t")).result_sets[0].rows, \
                    (await fetch(channel, "SELECT s FROM dbo.t WHERE id = 2999")).result_sets[0].rows

    assert run(go()) == (((3000, 2999),), (("secret 2999",),))


def test_a_column_re_encrypted_with_another_key_is_described_again(ae):
    options, encryption = ae
    shown = []

    async def go():
        insert = executesql("INSERT dbo.t VALUES (@v)", "@v int", tds.Param("@v", types.int, 1))
        async with await encryption.connect(**options, observe=lambda e: shown.append(e.text)) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, f"CREATE TABLE dbo.t ({encrypted('v', 'int', 'RANDOMIZED')})")
                await fetch(channel, insert)  # described, and the answer kept
                await fetch(channel, f"DROP TABLE dbo.t; CREATE TABLE dbo.t ({encrypted('v', 'int', 'RANDOMIZED', key='cek2')})")
                await fetch(channel, insert)  # refused (206), described again, sent once more
                await fetch(channel, insert)  # the new answer, kept
                return (await fetch(channel, "SELECT v FROM dbo.t")).result_sets[0].rows

    assert run(go()) == ((1,), (1,))
    refused = [t for t in shown if t.startswith("the server refused")]
    assert len(refused) == 1 and "(error 206: Operand type clash" in refused[0]
    assert sum("sp_describe_parameter_encryption" in t for t in shown if t.startswith("→")) == 2


def test_a_refusal_of_a_new_describing_isnt_retried(ae):
    options, encryption = ae
    shown = []

    async def go():
        async with await encryption.connect(**options, observe=lambda e: shown.append(e.text)) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, f"CREATE TABLE dbo.t ({encrypted('v', 'int', 'RANDOMIZED')})")
                for _ in range(2):  # a randomized column can't be compared: refused while describing, each time
                    with pytest.raises(tds.ServerError, match="33277"):
                        await fetch(channel, executesql("SELECT 1 FROM dbo.t WHERE v = @v", "@v int",
                                                        tds.Param("@v", types.int, 5)))

    run(go())
    assert not [t for t in shown if t.startswith("the server refused")]


def test_an_output_parameter_and_a_procedures_positional_parameters(ae):
    options, encryption = ae

    async def go():
        async with await encryption.connect(**options) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, f"CREATE TABLE dbo.people (ssn char(11) {BIN2}, {encrypted('salary', 'int', 'RANDOMIZED')}); "
                                     "EXEC('CREATE PROCEDURE dbo.salary_of @ssn char(11), @salary int OUTPUT AS "
                                     "SELECT @salary = salary FROM dbo.people WHERE ssn = @ssn')")
                await fetch(channel, executesql("INSERT dbo.people VALUES (@ssn, @salary)", "@ssn char(11), @salary int",
                                                tds.Param("@ssn", types.char(11), "123-45-6789"),
                                                tds.Param("@salary", types.int, 41000)))
                named = await (await fetch(channel, tds.Call("dbo.salary_of", tds.Param("@ssn", types.char(11), "123-45-6789"),
                                                             tds.Param("@salary", types.int, None, output=True)))).returns()
                positional = await (await fetch(channel, tds.Call("dbo.salary_of", tds.Param("", types.char(11), "123-45-6789"),
                                                                  tds.Param("", types.int, 7, output=True)))).returns()
                return named[0].outputs["@salary"].value, positional[0].outputs[1].value  # ordinals from 0

    assert run(go()) == (41000, 41000)


def test_without_the_package_values_arrive_as_ciphertext(ae, server):
    options, encryption = ae

    async def go():
        async with await encryption.connect(**options) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, f"CREATE TABLE dbo.t ({encrypted('v', 'int', 'RANDOMIZED')})")
                await fetch(channel, executesql("INSERT dbo.t VALUES (@v)", "@v int", tds.Param("@v", types.int, 5)))
        async with await tds.connect(**options, features=[*tds.DEFAULT_FEATURES, Feature.COLUMN_ENCRYPTION]) as plain:
            async with plain.serial_channel() as channel:
                with_feature = (await fetch(channel, "SELECT v FROM dbo.t")).result_sets[0]
        async with await tds.connect(**options) as plain:
            async with plain.serial_channel() as channel:
                without = (await fetch(channel, "SELECT v FROM dbo.t")).result_sets[0]
        return with_feature, without

    with_feature, without = run(go())
    assert str(with_feature.columns[0].type) == "int encrypted randomized"
    assert isinstance(with_feature.rows[0][0], EncryptedValue)
    assert str(without.columns[0].type).startswith("varbinary") and isinstance(without.rows[0][0], bytes)


def test_a_key_that_cant_be_decrypted_is_said_in_the_value(ae, server):
    options, encryption = ae

    async def go():
        async with await encryption.connect(**options) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, f"CREATE TABLE dbo.t ({encrypted('v', 'int', 'RANDOMIZED')})")
                await fetch(channel, executesql("INSERT dbo.t VALUES (@v)", "@v int", tds.Param("@v", types.int, 5)))
        stranger = LocalKeyStore(tempfile.mkdtemp(prefix="tds-other-"))
        stranger.create_master_key("cmk.pem")  # same name, another key
        async with await Encryption([stranger]).connect(**options) as connection:
            async with connection.serial_channel() as channel:
                wrong = (await fetch(channel, "SELECT v FROM dbo.t")).result_sets[0].rows[0][0]
        async with await Encryption([]).connect(**options) as connection:
            async with connection.serial_channel() as channel:
                none = (await fetch(channel, "SELECT v FROM dbo.t")).result_sets[0].rows[0][0]
        return wrong, none

    wrong, none = run(go())
    assert isinstance(wrong, NotDecrypted) and "signature doesn't verify" in wrong.reason
    assert isinstance(none, NotDecrypted) and "TDS_LOCAL_KEYS “cmk.pem”: no key store of that name here" in none.reason


def test_the_servers_refusal_reaches_the_application(ae):
    options, encryption = ae

    async def go():
        async with await encryption.connect(**options) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, f"CREATE TABLE dbo.t ({encrypted('salary', 'int', 'RANDOMIZED')})")
                with pytest.raises(tds.ServerError) as refused:  # a randomized column can't be compared
                    await fetch(channel, executesql("SELECT 1 FROM dbo.t WHERE salary > @s", "@s int",
                                                    tds.Param("@s", types.int, 5)))
                return refused.value

    refused = run(go())
    assert refused.errors[0].number == 33277 and "sp_describe_parameter_encryption" in str(refused)


def test_wrapping_needs_the_feature(server):
    async def go():
        async with await tds.connect(**server) as connection:
            Encryption([]).wrap(connection)

    with pytest.raises(EncryptionNotAgreed, match="didn't ask for column encryption"):
        run(go())


def test_bulk_load_of_plain_columns_on_an_encrypting_connection(ae):
    options, encryption = ae  # with column encryption agreed, bulk data carries an (empty) key table

    async def go():
        async with await encryption.connect(**options) as connection:
            async with connection.serial_channel() as channel:
                await fetch(channel, "CREATE TABLE dbo.plain (n int NOT NULL)")
                columns = (await fetch(channel, "SELECT TOP 0 n FROM dbo.plain")).result_sets[0].columns
                await fetch(channel, tds.BulkInsert("INSERT BULK dbo.plain (n int NOT NULL)"))
                await fetch(channel, tds.BulkRows(columns, [(1,), (2,)]))
                return (await fetch(channel, "SELECT COUNT(*) FROM dbo.plain")).result_sets[0].rows

    assert run(go()) == ((2,),)


def test_a_pool_lends_encrypting_connections(ae):
    options, encryption = ae

    async def go():
        async with encryption.pool(options.pop("host"), options.pop("port"), size=2, **options) as pool:
            async with pool.connection() as connection:
                async with connection.serial_channel() as channel:
                    await fetch(channel, f"CREATE TABLE dbo.t ({encrypted('v', 'int', 'DETERMINISTIC')})")
                    await fetch(channel, executesql("INSERT dbo.t VALUES (@v)", "@v int", tds.Param("@v", types.int, 9)))
                    return (await fetch(channel, "SELECT v FROM dbo.t")).result_sets[0].rows

    assert run(go()) == ((9,),)
