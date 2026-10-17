"""Always Encrypted (M15, D-60) against constructed bytes.

The core's wire elements are read from bytes written out field by field. tds.encryption's parts are tested one at a
time: a value's encryption, column keys, and normalization.
"""

import datetime as dt
import tempfile
from decimal import Decimal

import pytest

import tds
from tds import types
from tds.encryption import DecryptionFailed, Encryption, KeyNotDecrypted, LocalKeyStore
from tds.encryption.cell import CellKey
from tds.encryption.keys import unwrap
from tds.encryption.normalize import denormalize, normalize
from tds.requests import CipherInfo, Context
from tds.tokens import TOKENS
from tds.types import Encrypted, EncryptedValue, EncryptionType, NotDecrypted, SqlTime, ValueRefused


def utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


# --------------------------------------------------------------------------- the core: reading (MS-TDS §2.2.7.4, §2.2.5.7)

KEY_TABLE = (bytes.fromhex("01 00")  # one column key
             + bytes.fromhex("06 00 00 00  01 00 00 00  01 00 00 00") + bytes(range(0x11, 0x19))  # database, key, version, metadata version
             + bytes.fromhex("01")  # one encrypted value of it
             + bytes.fromhex("03 00 AA BB CC")  # its ciphertext
             + bytes([14]) + utf16("TDS_LOCAL_KEYS") + bytes.fromhex("07 00") + utf16("cmk.pem") + bytes([8]) + utf16("RSA_OAEP"))
SALARY = (bytes.fromhex("00 00 00 00  01 08")  # user type; flags: nullable, encrypted
          + bytes.fromhex("A5 41 00")  # the ciphertext's type: varbinary(65)
          + bytes.fromhex("00 00  00 00 00 00  26 04  02  02  01")  # key 0; user type; int; AEAD…SHA256; randomized; version 1
          + bytes([6]) + utf16("salary"))
COLMETADATA = bytes.fromhex("81 01 00") + KEY_TABLE + SALARY
ROW = bytes.fromhex("D1 03 00 01 02 03")


def test_an_encrypted_column_is_read_with_its_key():
    columns, row = TOKENS.decode(COLMETADATA + ROW, context={"column_encryption": 1})
    salary = columns.columns[0].type
    assert isinstance(salary, Encrypted) and str(salary) == "int encrypted randomized"
    assert (salary.cipher, salary.base, salary.algorithm_label) == (types.varbinary(65), types.int, "AEAD_AES_256_CBC_HMAC_SHA256")
    assert (salary.key.database_id, salary.key.key_id, salary.key.metadata_version) == (6, 1, bytes(range(0x11, 0x19)))
    value = salary.key.values[0]
    assert (value.encrypted, value.key_store, value.key_path, value.algorithm) == (b"\xaa\xbb\xcc", "TDS_LOCAL_KEYS", "cmk.pem", "RSA_OAEP")
    assert row["values"] == [EncryptedValue(b"\x01\x02\x03")]  # no hook: the ciphertext, as sent


def test_the_key_table_is_there_only_once_the_feature_is_agreed():
    plain = TOKENS.decode(bytes.fromhex("81 01 00 00 00 00 00 00 00 26 04") + bytes([1]) + utf16("n"))[0]
    assert plain.get("key_table") is None and plain.columns[0].type == types.int
    agreed = TOKENS.decode(bytes.fromhex("81 01 00 00 00 00 00 00 00 00 00 26 04") + bytes([1]) + utf16("n"),
                           context={"column_encryption": 1})[0]
    assert agreed.key_table.count == 0 and agreed.columns[0].type == types.int


def test_the_hook_decrypts_and_a_failure_is_said_in_the_value():
    def decrypt(encrypted, ciphertext):
        if ciphertext == b"\x01\x02\x03":
            return 41000
        raise ValueError("its authentication tag doesn't match")

    columns, good, bad = TOKENS.decode(COLMETADATA + ROW + bytes.fromhex("D1 02 00 09 09"),
                                       context={"column_encryption": 1, "decrypt": decrypt})
    assert good["values"] == [41000]
    assert bad["values"] == [NotDecrypted(b"\x09\x09", "its authentication tag doesn't match")]


def test_an_encrypted_output_parameter():
    body = (bytes.fromhex("AC 01 00") + bytes([2]) + utf16("@s") + bytes.fromhex("01  00 00 00 00  00 08")
            + bytes.fromhex("A5 41 00")  # varbinary(65)
            + bytes.fromhex("00 00 00 00  26 04  02  01  01")  # no ordinal: user type, int, algorithm, deterministic, version
            + bytes.fromhex("02 00 07 07"))
    [returned] = TOKENS.decode(body, context={"column_encryption": 1})
    assert str(returned.type) == "int encrypted deterministic" and returned.type.parameter == "@s"
    assert returned.value == EncryptedValue(b"\x07\x07")


# --------------------------------------------------------------------------- the core: writing (MS-TDS §2.2.6.6, §2.2.6.7)

def test_an_encrypted_parameter_carries_its_cipher_info():
    cipher = CipherInfo(types.int, EncryptionType.RANDOMIZED, 6, 1, 1, bytes(range(0x11, 0x19)))
    call = tds.Call("p", tds.Param("@s", types.varbinary(3), b"\x01\x02\x03", cipher=cipher))
    body, _ = call.encode(Context(0, 1, b""), False)[:2]
    expected = (bytes([2]) + utf16("@s")  # the name
                + bytes.fromhex("08")  # status: encrypted
                + bytes.fromhex("A5 03 00  03 00 01 02 03")  # varbinary(3), the ciphertext
                + bytes.fromhex("26 04  02  02") + bytes.fromhex("06 00 00 00  01 00 00 00  01 00 00 00")
                + bytes(range(0x11, 0x19)) + bytes.fromhex("01"))
    assert body.endswith(expected)


def test_bulk_data_carries_an_empty_key_table_once_the_feature_is_agreed():
    column = TOKENS.decode(bytes.fromhex("81 01 00 00 00 00 00 08 00 26 04") + bytes([1]) + utf16("n"))[0].columns[0]
    rows = tds.BulkRows([column], [(1,)])
    plain = rows.encode(Context(0, 1, b""), False)[0]
    agreed = rows.encode(Context(0, 1, b"", column_encryption=True), False)[0]
    assert plain.startswith(bytes.fromhex("81 01 00 00 00 00 00"))
    assert agreed.startswith(bytes.fromhex("81 01 00 00 00 00 00 00 00"))  # count, then a key table of 0 keys


def test_bulk_data_for_an_encrypted_column_carries_its_key_and_crypto_metadata():
    columns = TOKENS.decode(COLMETADATA, context={"column_encryption": 1})[0].columns
    body = tds.BulkRows(columns, [(b"\x01\x02\x03",)]).encode(Context(0, 1, b"", column_encryption=True), False)[0]
    assert body == (bytes.fromhex("81 01 00")  # COLMETADATA, 1 column
                    + bytes.fromhex("01 00  06 00 00 00  01 00 00 00  01 00 00 00") + bytes(range(0x11, 0x19))
                    + bytes.fromhex("00")  # the key's ids, and none of its encrypted values (as SqlClient sends it)
                    + SALARY  # the column as the server described it: varbinary(65), then its crypto metadata
                    + bytes.fromhex("D1 03 00 01 02 03")  # the row: its ciphertext
                    + bytes.fromhex("FD") + bytes(12))  # DONE


def test_bulk_data_for_an_encrypted_column_takes_ciphertext():
    columns = TOKENS.decode(COLMETADATA, context={"column_encryption": 1})[0].columns
    with pytest.raises(ValueRefused, match="the column is encrypted: its value is sent as ciphertext, which "
                                           "tds.encryption makes from int values"):
        tds.BulkRows(columns, [(41000,)]).encode(Context(0, 1, b"", column_encryption=True), False)
    with pytest.raises(ValueRefused, match="this connection's login didn't agree column encryption"):
        tds.BulkRows(columns, [(b"",)]).encode(Context(0, 1, b""), False)


def test_once_enclaves_are_agreed_every_request_carries_a_package():
    enclaves = Context(0, 1, b"", column_encryption=2)
    batch = tds.Batch("SELECT 1", enclave_package=b"\xe1\xe2").encode(enclaves, False)[0]
    assert batch.endswith(bytes.fromhex("02 00 E1 E2") + utf16("SELECT 1"))  # a u16 length, as SqlClient writes it
    assert tds.Batch("SELECT 1").encode(enclaves, False)[0].endswith(bytes.fromhex("00 00") + utf16("SELECT 1"))
    call = tds.Call("p", enclave_package=b"\xe1").encode(enclaves, False)[0]
    assert call.endswith(bytes([1, 0]) + utf16("p") + bytes.fromhex("00 00  01 00 E1"))
    without = tds.Batch("SELECT 1", enclave_package=b"\xe1").encode(Context(0, 1, b"", column_encryption=1), False)[0]
    assert without.endswith(utf16("SELECT 1")) and b"\xe1" not in without  # version 1: no field at all


# --------------------------------------------------------------------------- tds.encryption: a value's encryption

KEY = bytes(range(32))


def test_deterministic_encryption_repeats_and_randomized_doesnt():
    cell = CellKey(KEY, LocalKeyStore(tempfile.mkdtemp()).backend)
    assert cell.encrypt(b"same", True) == cell.encrypt(b"same", True)
    assert cell.encrypt(b"same", False) != cell.encrypt(b"same", False)
    value = cell.encrypt(b"sixteen bytes!!!", False)
    assert value[0] == 1 and len(value) == 1 + 32 + 16 + 32  # version, tag, iv, two blocks (padding adds one)
    assert cell.decrypt(value) == b"sixteen bytes!!!"


def test_a_changed_value_isnt_decrypted():
    cell = CellKey(KEY, LocalKeyStore(tempfile.mkdtemp()).backend)
    value = bytearray(cell.encrypt(b"41000", False))
    value[-1] ^= 1
    with pytest.raises(DecryptionFailed, match="authentication tag doesn't match"):
        cell.decrypt(bytes(value))
    with pytest.raises(DecryptionFailed, match="version is 0x02"):
        cell.decrypt(b"\x02" + bytes(value[1:]))
    with pytest.raises(DecryptionFailed, match="is 10 bytes: an encrypted value is at least 65"):
        cell.decrypt(bytes(10))


# --------------------------------------------------------------------------- tds.encryption: keys

def test_a_column_key_round_trips_through_its_master_key():
    store = LocalKeyStore(tempfile.mkdtemp())
    store.create_master_key("cmk.pem")
    wrapped = store.encrypt_column_key("cmk.pem", KEY)
    assert wrapped[0] == 1 and wrapped[1:3] == len(utf16("cmk.pem")).to_bytes(2, "little")
    assert wrapped[5 : 5 + 14] == utf16("cmk.pem") and len(wrapped) == 5 + 14 + 256 + 256  # 2048-bit key
    assert store.decrypt_column_key("cmk.pem", "RSA_OAEP", wrapped) == KEY


def test_another_master_keys_column_key_is_refused_by_its_signature():
    ours, theirs = LocalKeyStore(tempfile.mkdtemp()), LocalKeyStore(tempfile.mkdtemp())
    ours.create_master_key("cmk.pem")
    theirs.create_master_key("cmk.pem")
    with pytest.raises(KeyNotDecrypted, match="signature doesn't verify"):
        ours.decrypt_column_key("cmk.pem", "RSA_OAEP", theirs.encrypt_column_key("cmk.pem"))


def test_the_key_store_keeps_to_its_directory_and_its_keys():
    store = LocalKeyStore(tempfile.mkdtemp())
    with pytest.raises(KeyNotDecrypted, match="leads outside"):
        store.decrypt_column_key("../elsewhere.pem", "RSA_OAEP", b"")
    with pytest.raises(KeyNotDecrypted, match="no master key “missing.pem”"):
        store.decrypt_column_key("missing.pem", "RSA_OAEP", b"")
    store.create_master_key("cmk.pem")
    with pytest.raises(FileExistsError, match="replacing a master key loses every column key"):
        store.create_master_key("cmk.pem")


def test_a_column_key_no_store_here_holds():
    from tds.types import ColumnKey, MasterKeyValue

    key = ColumnKey(6, 1, 1, bytes(8), (MasterKeyValue(b"", "AZURE_KEY_VAULT", "https://vault/keys/k", "RSA_OAEP"),))
    with pytest.raises(KeyNotDecrypted, match="AZURE_KEY_VAULT “https://vault/keys/k”: no key store of that name here"):
        Encryption([]).cell_key(key)


# --------------------------------------------------------------------------- tds.encryption: normalization, version 1

@pytest.mark.parametrize("sql_type, value, plaintext", [
    (types.tinyint, 200, "C8 00 00 00 00 00 00 00"),  # every integer as a bigint
    (types.int, -2, "FE FF FF FF FF FF FF FF"),
    (types.bit, True, "01 00 00 00 00 00 00 00"),
    (types.smallmoney, Decimal("-1.5"), "FF FF FF FF 68 C5 FF FF"),  # smallmoney as money
    (types.decimal(10, 2), Decimal("-123.45"), "00 39 30" + " 00" * 14),  # sign, then 16 bytes of digits
    (types.time(0), SqlTime(10_000_000), "80 96 98 00 00"),  # at scale 7, whatever the column's
    (types.date, dt.date(1, 1, 2), "01 00 00"),
    (types.nchar(5), "ab", "61 00 62 00"),  # unpadded
    (types.binary(4), b"\x01", "01"),
])
def test_each_types_plaintext(sql_type, value, plaintext):
    assert normalize(sql_type, value) == bytes.fromhex(plaintext)


def test_fixed_length_values_are_padded_when_read():
    assert denormalize(types.nchar(5), bytes.fromhex("61 00 62 00")) == "ab   "
    assert denormalize(types.binary(4), b"\x01") == b"\x01\x00\x00\x00"
    assert denormalize(types.decimal(10, 2), bytes.fromhex("00 39 30" + " 00" * 14)) == Decimal("-123.45")


def test_what_cant_be_encrypted_and_what_doesnt_fit():
    with pytest.raises(ValueRefused, match="Always Encrypted can't encrypt xml"):
        normalize(types.xml, "<a/>")
    with pytest.raises(ValueRefused):
        normalize(types.tinyint, 256)
    with pytest.raises(ValueRefused, match="4 bytes of int plaintext don't match normalization version 1"):
        denormalize(types.int, bytes(4))


# --------------------------------------------------------------------------- tds.encryption: enclaves, without attestation

def test_an_enclave_session_and_package():
    import hashlib
    import struct

    from tds.encryption import enclave
    from tds.encryption.backend import CryptographyBackend

    backend = CryptographyBackend()
    parameters, client_key = enclave.attestation_parameters(backend)
    protocol, input_length, blob_length = struct.unpack_from("<III", parameters)
    assert (protocol, input_length, blob_length, parameters[12:16]) == (2, 0, 104, b"ECK3")  # None; no input; P-384

    server_key, x, y = backend.ecdh_p384()  # the enclave's side
    blob = b"ECK3" + (48).to_bytes(4, "little") + x + y
    handle = bytes(range(8))
    info = struct.pack("<II", 0, 8 + 8 + len(blob) + 4) + handle + struct.pack("<II", len(blob), 4) + blob + b"SIGN"
    session = enclave.session(info, client_key, backend)
    shared = backend.ecdh_shared(server_key, parameters[20:68], parameters[68:116])  # after the blob's 8-byte header
    enclave_key = CellKey(hashlib.sha256(shared).digest(), backend)  # what the enclave derives

    package = session.package("SELECT 1", [(6, bytes(range(8)), 1, KEY)])
    assert package[:8] == handle
    body = enclave_key.decrypt(package[8:])
    assert struct.unpack_from("<q", body, 16)[0] == 1  # the session's first package
    assert body[24:56] == hashlib.sha256("SELECT 1".encode("utf-16-le")).digest()
    assert body[56:] == struct.pack("<I", 6) + bytes(range(8)) + struct.pack("<H", 1) + KEY
    assert struct.unpack_from("<q", enclave_key.decrypt(session.package("SELECT 1", [])[8:]), 16)[0] == 2


def test_a_master_key_signs_whether_its_keys_may_go_to_an_enclave():
    store = LocalKeyStore(tempfile.mkdtemp())
    store.create_master_key("cmk.pem")
    signature = store.sign_master_key_metadata("cmk.pem")
    assert store.verify_master_key_metadata("cmk.pem", True, signature)
    assert not store.verify_master_key_metadata("cmk.pem", False, signature)  # signed for enclaves, not without
