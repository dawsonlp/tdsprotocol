# Always Encrypted (reference)

**Where this sits:** across the protocol. It has a login feature, a key table and crypto metadata in every result's column descriptions, encrypted parameters in calls, and, outside TDS, the keys and the cryptography.
**Use this page to** read or build Always Encrypted's wire elements, encrypt and decrypt values as SQL Server's drivers do, and know what the server allows.

## Purpose

Always Encrypted keeps chosen columns encrypted everywhere except in the client. The server stores and returns ciphertext, and never holds a key that could decrypt it. Only a client with access to the master key can read or write those columns.

Part of it is TDS. MS-TDS defines how encrypted values and their metadata travel. Most of it isn't TDS. The keys, the encryption, and how a value becomes plaintext come from Microsoft's documentation and drivers. The driver splits it the same way (D-60):
- **the core** reads and writes every wire element, and shows encrypted values as ciphertext;
- **`tds.encryption`** holds the keys and the cryptography, and describes a call's parameters before encrypting them.

## Shape

### On the wire

| Element | Where | Layout |
|---|---|---|
| **The login feature** | LOGIN7's feature list, `04` | version: `01` without enclaves; `02`, `03` with them. The acknowledgement repeats the version and, with enclaves, names the enclave type |
| **The key table** | after the column count in every COLMETADATA once the feature is agreed, and in bulk data the client sends. It may be empty. The client's key table gives each key's ids, without its encrypted values | count (u16), then each column key (below) |
| **A column key** (EK_INFO) | in the key table | database id (u32) · key id (u32) · key version (u32) · metadata version (8 bytes) · count (u8) · each encrypted value of the key: the encrypted key (u16 length, bytes), key store name (short text), key path (long text), algorithm (short text) |
| **Crypto metadata** | a column whose flags have `0x0800`, after its TYPE_INFO and before its name | key ordinal in the key table (u16) · user type (u32) · the plaintext's TYPE_INFO · algorithm (u8: `02` AEAD_AES_256_CBC_HMAC_SHA256; `00`: the name follows, as short text) · encryption type (u8: `01` deterministic, `02` randomized) · normalization version (u8: `01`) |
| **An encrypted column's values** | rows | the TYPE_INFO before the crypto metadata is the ciphertext's, `varbinary(n)` or `varbinary(max)`; each value is ciphertext |
| **An encrypted output parameter** | RETURNVALUE, flags `0x0800` | crypto metadata as above, without the key ordinal; then the ciphertext |
| **An encrypted parameter** | an RPC parameter, status `0x08` | TYPE_INFO `varbinary`, the ciphertext, then its cipher info: the plaintext's TYPE_INFO · algorithm · [algorithm name] · encryption type · database id · key id · key version · metadata version · normalization version |
| **The enclave package** | RPC: after each call's options; SQL batch: after the headers | u16 length (MS-TDS says u32: Edge cases), then bytes for the server's enclave, which the server doesn't read. Once enclaves are agreed, it is in every batch and call, and is empty when there's nothing to send |
| **The enclave's type** | the feature's acknowledgement, version 2 | its length in characters (u8), then UTF-16LE: `02 03 'V' 'B' 'S'` |

### Off the wire

**Keys.** A *master key* stays in a key store that the client can reach: Azure Key Vault (`AZURE_KEY_VAULT`; the path is the key's URL), the Windows certificate store (`MSSQL_CERTIFICATE_STORE`; the path is `LocalMachine/My/<thumbprint>`), or the driver's own local key store of RSA key files (`TDS_LOCAL_KEYS`). The driver has all three: `AzureKeyVaultKeyStore`, `WindowsCertificateStore` (Windows only; the private key stays in the store, used through Windows' CNG) and `LocalKeyStore`. The database holds each *column key* only in a form encrypted by a master key, together with the key store's name and the key's path. It sends these in the key table or in `sp_describe_parameter_encryption`'s answer. The client asks the key store to decrypt it. An encrypted column key, as SQL Server's tools write it:

| Bytes | Field |
|---|---|
| 1 | version, `01` |
| 2 | key path length, in bytes |
| 2 | ciphertext length |
| *n* | key path, UTF-16LE |
| *k* | the column key, RSA-OAEP with SHA-1, *k* the master key's size |
| *k* | signature: RSA PKCS#1 v1.5 with SHA-256, over everything before it |

**A value** (AEAD_AES_256_CBC_HMAC_SHA256). Three keys are derived from the 32-byte column key, each HMAC-SHA-256 keyed with it over a label in UTF-16LE (“Microsoft SQL Server cell encryption key with encryption algorithm:AEAD_AES_256_CBC_HMAC_SHA256 and key length:256”, then *cell MAC key*, then *cell IV key*). Then:

| | Randomized | Deterministic |
|---|---|---|
| iv | 16 random bytes | HMAC-SHA-256(IV key, plaintext), its first 16 bytes |
| ciphertext | AES-256-CBC(encryption key, iv, plaintext), PKCS#7 padding | the same |
| tag | HMAC-SHA-256(MAC key, `01` + iv + ciphertext + `01`) | the same |
| the value | `01` + tag (32 bytes) + iv (16 bytes) + ciphertext | the same |

The same plaintext always gives the same deterministic ciphertext, so the server can test equality on it, and only equality. Decryption checks the tag first, and releases nothing unless the tag matches.

**Plaintext** (normalization version 1). Each type's value as TDS lays it out, without its length, in the type's widest form:

| Type | Plaintext |
|---|---|
| bit, tinyint, smallint, int, bigint | 8 bytes, as a bigint |
| real, float | 4 or 8 bytes |
| smallmoney, money | 8 bytes, as money |
| decimal(p, s), numeric(p, s) | 17 bytes: sign (`01` positive), then 16 bytes of digits |
| date | 3 bytes |
| time(n), datetime2(n), datetimeoffset(n) | at scale 7, whatever *n* is: 5, 8 and 10 bytes |
| smalldatetime, datetime, uniqueidentifier | as TDS sends them |
| char, varchar, nchar, nvarchar | the text in the column's encoding, unpadded |
| binary, varbinary | the bytes, unpadded |

When read back, `char(n)`, `nchar(n)` and `binary(n)` are padded to their length, as their unencrypted columns are. Other types can't be encrypted.

**Which parameters to encrypt.** `sp_describe_parameter_encryption(@tsql, @params)`, an ordinary stored procedure, answers with two result sets:
1. the column keys involved: key ordinal, database id, key id, version, metadata version, encrypted value, key store name, key path, algorithm (one row for each master key that encrypts it);
2. each parameter: its name, algorithm, encryption type (`0`: plaintext), key ordinal and normalization version.

### Enclaves

With a **secure enclave**, the server can compute on encrypted values (LIKE, ranges, in-place encryption) inside memory it can't read itself. The client sends the enclave the column keys a statement needs, encrypted with a key only they share. MS-TDS carries the bytes without describing them. The protocol is SqlClient's. The driver runs it without attestation, which Azure SQL Database's VBS enclaves offer (`Encryption(…, enclave_attestation="none")`). Without attestation, the client trusts the server to run a real enclave.

1. The login asks for column encryption version 2; the server acknowledges 2 and names its enclave (`VBS`).
2. Describing a statement sends a third parameter, by position, as `varbinary(n)`: the attestation protocol (u32 `2`, none), an empty input (u32 `0`), and the client's ECDH P-384 public key (u32 length, then a 104-byte blob: `ECK3`, u32 48, x, y).
3. The answer's third result set is the enclave's attestation info: an empty trusted-module part (u32 0), the size of what follows, the session's handle (8 bytes), the enclave's public key's and signature's sizes, its public key (the same blob), and the signature. The session key is SHA-256 of the ECDH shared secret.
4. The first result set marks the column keys the enclave asks for (`is_requested_by_enclave`), each with its master key's signature over its metadata (the key store's name, the key path and `true`, lowercased, UTF-16LE, signed RSA PKCS#1 v1.5 with SHA-256). The client sends a key only if that signature verifies. Otherwise, a server could ask for any key.
5. The call carries the enclave package: the session handle, then, encrypted with the session key as a column key (randomized): a GUID, the session's counter (i64, one more each time), SHA-256 of the statement (UTF-16LE), and each key: database id (u32), metadata version (8 bytes), key id (u16), the key.

A master key allows enclave computations when it is created with its signature: `CREATE COLUMN MASTER KEY … WITH (…, ENCLAVE_COMPUTATIONS (SIGNATURE = 0x…))`. Each key store can make the signature (`sign_master_key_metadata`).

## Rules

- **`tds.encryption` asks for the feature, and the core reads what it changes.** `Encryption(key_stores).connect(…)` or `.pool(…)` opens connections whose login asks for column encryption; `.wrap(connection)` takes one opened that way, and refuses one that wasn't, saying why.
- **A call with parameters is described first,** in its own exchange on the same serial channel: `sp_describe_parameter_encryption` with the call's statement (a procedure call is described as `EXEC procedure @a = @a, …`, positional parameters as `@p1`, `@p2`, … in place). Each parameter it names is normalized, encrypted and sent as `varbinary` with its cipher info. The answer is kept for the next time the same statement is sent. If the server refuses a call encrypted by a kept answer before running it (error 206, "Operand type clash", or 33514), the column's key has changed. The call is then described again, encrypted again and sent once more. The refused call ran nothing, so nothing runs twice, and the connection's observer sees it happen (`⚿ the server refused …`). Observed: a master key rotation (the column key gets a value under a new master key) changes nothing that a call needs. A call to a column re-encrypted with another column key is refused with error 206, then succeeds when sent again. SqlClient retries the same way, but only on 33514.
- **Values are decrypted as they are read,** by a hook the core is given for each exchange (`SerialChannel.exchange(request, decrypt=…)`), so every way of reading a response works unchanged. An output parameter's column key is the one named when its call was described.
- **Bulk load into encrypted columns:** take the columns from `SELECT TOP 0 …` on an encrypting connection, as for any bulk load (D-50). The statement names each encrypted column by its ciphertext's type, as those columns give it (`column.type.cipher`, such as `varbinary(81)` for an encrypted `int`). `tds.encryption` encrypts each encrypted column's values as the rows are sent, including rows from a source. The bulk data describes them as the server did. Its key table holds only the column keys' ids, not their encrypted values, as SqlClient's does. Each encrypted column carries its crypto metadata.

        columns = (await fetch(channel, "SELECT TOP 0 id, ssn FROM dbo.people")).result_sets[0].columns
        await fetch(channel, tds.BulkInsert(f"INSERT BULK dbo.people (id int, ssn {columns[1].type.cipher})"))
        await fetch(channel, tds.BulkRows(columns, [(1, "123-45-6789"), …]))
- **An enclave session is kept within one connection lease,** and created again if the server refuses one (error 33195): the call is described again, with attestation parameters, and sent once more. Database/collation changes, reset, recovery, return and close clear its session and statement descriptions.
- **Column and local master keys follow explicit retention policies (D-66),** within one physical connection and exclusive pool lease. Transaction is the default; see Key retention below.
- **Without `tds.encryption`, encrypted values are shown as they arrive:** `EncryptedValue(ciphertext)`, with the column's type saying what it holds (`int encrypted randomized`). A value `tds.encryption` can't decrypt is `NotDecrypted(ciphertext, reason)`, and the rest of the response is still read.
- **An encrypted large value is read whole,** never streamed: nothing may be released before its tag is checked.
- **Only what can't be encrypted is refused before sending:** a value that doesn't fit its type (D-48), a type Always Encrypted can't encrypt, an algorithm the driver doesn't have. The server judges everything else. For example, comparing a randomized column is error 33277, raised by the describing call.

## Key retention

Python accepts `Encryption(stores, policies=Policies(...))`. Both `master` and
`column` default to `Policy.transaction()`, with bounded capacities of 8 and 32
entries (configurable from 1 to 4096).

| Policy | Reuse boundary | Cleanup |
|---|---|---|
| `Policy.transaction()` | One server-announced outer transaction; exchange scope outside a transaction | Outer commit/rollback/end, including server rollback; nested commit/savepoint does not end it |
| `Policy.exchange()` | Parameter preparation, streamed input production and response decoding for one application request | Terminal response message, failed preparation/send, or cancel/drain |
| `Policy.time(seconds)` | Across transactions/autocommit within the same physical connection and lease | Fixed age measured from acquisition start, including idle expiry; hits do not extend it |

Expiry/eviction reloads a needed key; a long transaction does not fail merely
because a key expired. An age shorter than acquisition is refused, rather than
retried forever. Event-loop scheduling bounds idle timer precision. Runtime
task cancellation at orderly shutdown (such as `asyncio.run`) revokes banks used
in that runtime. Closing/abandoning an event loop without cancelling its tasks is
outside that guarantee; close the connection or bank explicitly. Standalone
synchronous banks must also be closed explicitly.

An exchange can choose `channel.exchange(request, policies=Policies(...))`. It
cannot borrow keys retained under a broader policy. It does not retroactively erase
entries retained by earlier exchanges; `set_policies` clears those entries. Each setting controls its
own key class: retaining a column key avoids a new unwrap even when its master
has already been released. Changing lease defaults with
`connection.keys.set_policies(...)` requires no active exchange and clears all
retained keys. Changes to `Encryption.policies` configure newly wrapped leases.

Every policy is cleared/revoked at connection close, pool return, physical failure
and recovery. A new borrower never inherits keys or descriptions. Deferred pool
reset is completed with an empty batch before describing/encrypting the next
application request, restoring its login database/collation first. A database or
collation change invalidates old guards and descriptions. Old readers pin their
transaction generation; they may reload exchange-local keys after that generation
ends, but cannot join a later transaction with a reused descriptor.

Master retention controls loaded `LocalKeyStore` RSA objects. Opaque custom,
Windows certificate and vault providers retain control over private-key operations
and any provider-internal cache. Enclave session keys have separate lease-local
ownership and are not governed by the column-key policy. Owned CellKey root,
AES, MAC and IV buffers are overwritten on release. Python immutable temporary
copies and backend-native memory are outside that guarantee.

`connection.key_statistics` reports local master loads, successful unwraps, hits,
evictions, expirations and live entry counts; inspection never triggers expiry.
Unscoped `Encryption.cell_key(key)` is uncached and caller-owned (call `close()`);
standalone controlled use is `with encryption.key_session() as bank:` followed by
`with bank.exchange() as exchange:`. Only server-driven connection wrappers supply
automatic transaction and pool lifecycle events. [Design and test evidence](../experiments/python-encryption-retention.md)
record the Python implementation; Rust's SQL integration remains separate work.

## Example

Insert into, and read from, a table with an encrypted column:

```python
encryption = Encryption([LocalKeyStore("keys")])
async with await encryption.connect(host, port, user=…, password=…, database=…) as connection:
    async with connection.serial_channel() as channel:
        await channel.exchange(tds.Call(tds.Builtin.SP_EXECUTESQL,
            tds.Param("@stmt", types.nvarchar(types.MAX), "INSERT dbo.people VALUES (@ssn, @salary)"),
            tds.Param("@params", types.nvarchar(types.MAX), "@ssn char(11), @salary int"),
            tds.Param("@ssn", types.char(11), "123-45-6789"), tds.Param("@salary", types.int, 41000)))
```

On the wire, this is two exchanges: the describing call, then the insert, whose `@salary` is `varbinary` ciphertext with status `08` and its cipher info. A SELECT's COLMETADATA then reads, for an encrypted `salary` column:

| Bytes | Meaning |
|---|---|
| `81 01 00` | COLMETADATA, 1 column |
| `01 00` | the key table: 1 column key |
| `06 00 00 00  01 00 00 00  01 00 00 00  …8 bytes…` | database 6, key 1, version 1, metadata version |
| `01  03 00 AA BB CC  0E …  07 00 …  08 …` | 1 encrypted value of it: the encrypted key, then `TDS_LOCAL_KEYS`, `cmk.pem`, `RSA_OAEP` |
| `00 00 00 00  01 08` | user type; flags: nullable, encrypted |
| `A5 41 00` | the ciphertext's type: `varbinary(65)` |
| `00 00  00 00 00 00  26 04  02  02  01` | key 0; user type; plaintext `int`; AEAD_AES_256_CBC_HMAC_SHA256; randomized; version 1 |
| `06 …` | the name, `salary` |

## Edge cases

**Where SQL Server differs from MS-TDS.** Observed from SQL Server 2025 (17.0.5015).
- **MS-TDS numbers the algorithm two ways.** Its RPC section says `01` is AEAD_AES_256_CBC_HMAC_SHA512; its COLMETADATA section says `02` is AEAD_AES_256_CBC_HMAC_SHA256. SQL Server uses `02` in both, and in `sp_describe_parameter_encryption`'s answer.

- **The enclave package's length is a u16,** where MS-TDS says L_VARBYTE, a u32. SqlClient writes a u16, and SQL Server reads a u16: a batch and a call with an empty two-byte package succeed (observed, Azure SQL Database). Once enclaves are agreed, every batch and call carries the field.

**What MS-TDS doesn't state.** Observed from SQL Server 2025 (17.0.5015), or from Microsoft's SqlClient where marked.
- **The encryption, the column key's layout and the plaintext's layout** aren't in MS-TDS. This page takes them from Microsoft's documentation and SqlClient (MIT-licensed; what was used is in [THIRD-PARTY-NOTICES.md](../../../THIRD-PARTY-NOTICES.md)), and the driver is checked against SqlClient itself (D-61).
- **The client's bulk data carries a key table too,** once the feature is agreed: empty when no column is encrypted (SqlClient; confirmed live).
- **Without the login feature, encrypted columns arrive as `varbinary` ciphertext,** with no metadata.
- **The server accepts any key store name and any encrypted column key:** it never decrypts one. So the tests run against the local container, with a key store of RSA files.
- **A table type can't have encrypted columns:** `CREATE TYPE … AS TABLE` refuses `ENCRYPTED WITH`. So no table-valued parameter carries encrypted values.
- **How the statement names an encrypted column for bulk load:** by its ciphertext's type, exactly as the server reports it, `varbinary(81)` for an encrypted `int` (observed: SqlClient's SqlBulkCopy sends `insert bulk [dbo].[b] ([v] VarBinary(81))`, recorded with an Extended Events session). The server refuses any other declaration: the plain type, a `varbinary` of another length, `ENCRYPTED WITH`, or `ALLOW_ENCRYPTED_VALUE_MODIFICATIONS` (errors 518, 102).
- **Describing with enclaves:** the attestation parameters go third, by position, as `varbinary(n)`. As `varbinary(max)`, the server refuses them (error 214, “Procedure expects parameter 'enclave_identity_attestation_securechannel_input' of type 'unsupported protocol type'”). Azure SQL Database, observed.
- **Enclaves without attestation work on Azure SQL Database's VBS enclaves:** LIKE and range comparisons on randomized columns returned the right rows (observed).
- **Where SqlClient differs from the driver** (D-61's pass 2): SqlClient decodes and encodes UTF-16 with replacement, so an unpaired surrogate, which the driver keeps (D-48), becomes U+FFFD in SqlClient, and a deterministic lookup for such a value finds nothing written by the other. SqlClient also can't send a `time(0)` parameter to an encrypted column: it treats a Scale of 0 as "unset", so it sends `time(7)`, which the server refuses.

---

**Source:** MS-TDS §2.2.5.7, §2.2.6.4, §2.2.6.6, §2.2.6.7, §2.2.7.4, §2.2.7.11, §2.2.7.19; SqlClient (SqlAeadAes256CbcHmac256Algorithm, EncryptedColumnEncryptionKeyParameters, TdsParser)
