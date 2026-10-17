/* Reference: Always Encrypted. */
(function () {
  const { L, D, table, source } = window.TDS;

  window.TDS.page({
    id: 'ref/always-encrypted', group: 'Reference', kind: 'reference',
    title: 'Always Encrypted',
    where: 'Across the protocol. It has a login feature, a key table and crypto metadata in every result’s column descriptions, encrypted parameters in calls, and, outside TDS, the keys and the cryptography.',
    outcome: 'read or build Always Encrypted’s wire elements, encrypt and decrypt values as SQL Server’s drivers do, and know what the server allows.',
    body: () => `
      <h2>Purpose</h2>
      <p>Always Encrypted keeps chosen columns encrypted everywhere except in the client. The server stores and returns ciphertext, and never holds a key that could decrypt it. Only a client with access to the master key can read or write those columns.</p>
      <p>Part of it is TDS. MS-TDS defines how encrypted values and their metadata travel. Most of it isn’t TDS. The keys, the encryption, and how a value becomes plaintext come from Microsoft’s documentation and drivers. The driver splits it the same way (${D(60)}):</p>
      <ul>
        <li><b>the core</b> reads and writes every wire element, and shows encrypted values as ciphertext;</li>
        <li><b><code>tds.encryption</code></b> holds the keys and the cryptography, and describes a call’s parameters before encrypting them.</li>
      </ul>

      <h2>Shape</h2>
      <h3>On the wire</h3>
      ${table(['Element', 'Where', 'Layout'], [
        ['<b>The login feature</b>', 'LOGIN7’s feature list, <code>04</code>', 'version: <code>01</code> without enclaves; <code>02</code>, <code>03</code> with them. The acknowledgement repeats the version and, with enclaves, names the enclave type'],
        ['<b>The key table</b>', 'after the column count in every COLMETADATA once the feature is agreed, and in bulk data the client sends. It may be empty. The client’s key table gives each key’s ids, without its encrypted values', 'count (u16), then each column key (below)'],
        ['<b>A column key</b> (EK_INFO)', 'in the key table', 'database id (u32) · key id (u32) · key version (u32) · metadata version (8 bytes) · count (u8) · each encrypted value of the key: the encrypted key (u16 length, bytes), key store name (short text), key path (long text), algorithm (short text)'],
        ['<b>Crypto metadata</b>', 'a column whose flags have <code>0x0800</code>, after its TYPE_INFO and before its name', 'key ordinal in the key table (u16) · user type (u32) · the plaintext’s TYPE_INFO · algorithm (u8: <code>02</code> AEAD_AES_256_CBC_HMAC_SHA256; <code>00</code>: the name follows, as short text) · encryption type (u8: <code>01</code> deterministic, <code>02</code> randomized) · normalization version (u8: <code>01</code>)'],
        ['<b>An encrypted column’s values</b>', 'rows', 'the TYPE_INFO before the crypto metadata is the ciphertext’s, <code>varbinary(n)</code> or <code>varbinary(max)</code>; each value is ciphertext'],
        ['<b>An encrypted output parameter</b>', 'RETURNVALUE, flags <code>0x0800</code>', 'crypto metadata as above, without the key ordinal; then the ciphertext'],
        ['<b>An encrypted parameter</b>', 'an RPC parameter, status <code>0x08</code>', 'TYPE_INFO <code>varbinary</code>, the ciphertext, then its cipher info: the plaintext’s TYPE_INFO · algorithm · [algorithm name] · encryption type · database id · key id · key version · metadata version · normalization version'],
        ['<b>The enclave package</b>', 'RPC: after each call’s options; SQL batch: after the headers', 'u16 length (MS-TDS says u32: Edge cases), then bytes for the server’s enclave, which the server doesn’t read. Once enclaves are agreed, it is in every batch and call, and is empty when there’s nothing to send'],
        ['<b>The enclave’s type</b>', 'the feature’s acknowledgement, version 2', 'its length in characters (u8), then UTF-16LE: <code>02 03 \'V\' \'B\' \'S\'</code>'],
      ], 'compact')}

      <h3>Off the wire</h3>
      <p><b>Keys.</b> A <i>master key</i> stays in a key store that the client can reach: Azure Key Vault (<code>AZURE_KEY_VAULT</code>; the path is the key’s URL), the Windows certificate store (<code>MSSQL_CERTIFICATE_STORE</code>; the path is <code>LocalMachine/My/&lt;thumbprint&gt;</code>), or the driver’s own local key store of RSA key files (<code>TDS_LOCAL_KEYS</code>). The driver has all three: <code>AzureKeyVaultKeyStore</code>, <code>WindowsCertificateStore</code> (Windows only; the private key stays in the store, used through Windows’ CNG) and <code>LocalKeyStore</code>. The database holds each <i>column key</i> only in a form encrypted by a master key, together with the key store’s name and the key’s path. It sends these in the key table or in <code>sp_describe_parameter_encryption</code>’s answer. The client asks the key store to decrypt it. An encrypted column key, as SQL Server’s tools write it:</p>
      ${table(['Bytes', 'Field'], [
        ['1', 'version, <code>01</code>'], ['2', 'key path length, in bytes'], ['2', 'ciphertext length'],
        ['<i>n</i>', 'key path, UTF-16LE'], ['<i>k</i>', 'the column key, RSA-OAEP with SHA-1, <i>k</i> the master key’s size'],
        ['<i>k</i>', 'signature: RSA PKCS#1 v1.5 with SHA-256, over everything before it'],
      ], 'compact')}
      <p><b>A value</b> (AEAD_AES_256_CBC_HMAC_SHA256). Three keys are derived from the 32-byte column key, each HMAC-SHA-256 keyed with it over a label in UTF-16LE (“Microsoft SQL Server cell encryption key with encryption algorithm:AEAD_AES_256_CBC_HMAC_SHA256 and key length:256”, then <i>cell MAC key</i>, then <i>cell IV key</i>). Then:</p>
      ${table(['', 'Randomized', 'Deterministic'], [
        ['iv', '16 random bytes', 'HMAC-SHA-256(IV key, plaintext), its first 16 bytes'],
        ['ciphertext', 'AES-256-CBC(encryption key, iv, plaintext), PKCS#7 padding', 'the same'],
        ['tag', 'HMAC-SHA-256(MAC key, <code>01</code> + iv + ciphertext + <code>01</code>)', 'the same'],
        ['the value', '<code>01</code> + tag (32 bytes) + iv (16 bytes) + ciphertext', 'the same'],
      ], 'compact')}
      <p>The same plaintext always gives the same deterministic ciphertext, so the server can test equality on it, and only equality. Decryption checks the tag first, and releases nothing unless the tag matches.</p>
      <p><b>Plaintext</b> (normalization version 1). Each type’s value as TDS lays it out, without its length, in the type’s widest form:</p>
      ${table(['Type', 'Plaintext'], [
        ['bit, tinyint, smallint, int, bigint', '8 bytes, as a bigint'], ['real, float', '4 or 8 bytes'],
        ['smallmoney, money', '8 bytes, as money'], ['decimal(p, s), numeric(p, s)', '17 bytes: sign (<code>01</code> positive), then 16 bytes of digits'],
        ['date', '3 bytes'], ['time(n), datetime2(n), datetimeoffset(n)', 'at scale 7, whatever <i>n</i> is: 5, 8 and 10 bytes'],
        ['smalldatetime, datetime, uniqueidentifier', 'as TDS sends them'],
        ['char, varchar, nchar, nvarchar', 'the text in the column’s encoding, unpadded'], ['binary, varbinary', 'the bytes, unpadded'],
      ], 'compact')}
      <p>When read back, <code>char(n)</code>, <code>nchar(n)</code> and <code>binary(n)</code> are padded to their length, as their unencrypted columns are. Other types can’t be encrypted.</p>
      <p><b>Which parameters to encrypt.</b> <code>sp_describe_parameter_encryption(@tsql, @params)</code>, an ordinary stored procedure, answers with two result sets:</p>
      <ol>
        <li>the column keys involved: key ordinal, database id, key id, version, metadata version, encrypted value, key store name, key path, algorithm (one row for each master key that encrypts it);</li>
        <li>each parameter: its name, algorithm, encryption type (<code>0</code>: plaintext), key ordinal and normalization version.</li>
      </ol>

      <h3 id="enclaves">Enclaves</h3>
      <p>With a <b>secure enclave</b>, the server can compute on encrypted values (LIKE, ranges, in-place encryption) inside memory it can’t read itself. The client sends the enclave the column keys a statement needs, encrypted with a key only they share. MS-TDS carries the bytes without describing them. The protocol is SqlClient’s. The driver runs it without attestation, which Azure SQL Database’s VBS enclaves offer (<code>Encryption(…, enclave_attestation="none")</code>). Without attestation, the client trusts the server to run a real enclave.</p>
      <ol>
        <li>The login asks for column encryption version 2; the server acknowledges 2 and names its enclave (<code>VBS</code>).</li>
        <li>Describing a statement sends a third parameter, by position, as <code>varbinary(n)</code>: the attestation protocol (u32 <code>2</code>, none), an empty input (u32 <code>0</code>), and the client’s ECDH P-384 public key (u32 length, then a 104-byte blob: <code>ECK3</code>, u32 48, x, y).</li>
        <li>The answer’s third result set is the enclave’s attestation info: an empty trusted-module part (u32 0), the size of what follows, the session’s handle (8 bytes), the enclave’s public key’s and signature’s sizes, its public key (the same blob), and the signature. The session key is SHA-256 of the ECDH shared secret.</li>
        <li>The first result set marks the column keys the enclave asks for (<code>is_requested_by_enclave</code>), each with its master key’s signature over its metadata (the key store’s name, the key path and <code>true</code>, lowercased, UTF-16LE, signed RSA PKCS#1 v1.5 with SHA-256). The client sends a key only if that signature verifies. Otherwise, a server could ask for any key.</li>
        <li>The call carries the enclave package: the session handle, then, encrypted with the session key as a column key (randomized): a GUID, the session’s counter (i64, one more each time), SHA-256 of the statement (UTF-16LE), and each key: database id (u32), metadata version (8 bytes), key id (u16), the key.</li>
      </ol>
      <p>A master key allows enclave computations when it is created with its signature: <code>CREATE COLUMN MASTER KEY … WITH (…, ENCLAVE_COMPUTATIONS (SIGNATURE = 0x…))</code>. Each key store can make the signature (<code>sign_master_key_metadata</code>).</p>

      <h2>Rules</h2>
      <ul>
        <li><b><code>tds.encryption</code> asks for the feature, and the core reads what it changes.</b> <code>Encryption(key_stores).connect(…)</code> or <code>.pool(…)</code> opens connections whose login asks for column encryption; <code>.wrap(connection)</code> takes one opened that way, and refuses one that wasn’t, saying why.</li>
        <li><b>A call with parameters is described first,</b> in its own exchange on the same serial channel: <code>sp_describe_parameter_encryption</code> with the call’s statement (a procedure call is described as <code>EXEC procedure @a = @a, …</code>, positional parameters as <code>@p1</code>, <code>@p2</code>, … in place). Each parameter it names is normalized, encrypted and sent as <code>varbinary</code> with its cipher info. The answer is kept for the next time the same statement is sent. If the server refuses a call encrypted by a kept answer before running it (error 206, “Operand type clash”, or 33514), the column’s key has changed. The call is then described again, encrypted again and sent once more. The refused call ran nothing, so nothing runs twice, and the connection’s observer sees it happen (<code>⚿ the server refused …</code>). Observed: a master key rotation (the column key gets a value under a new master key) changes nothing that a call needs. A call to a column re-encrypted with another column key is refused with error 206, then succeeds when sent again. SqlClient retries the same way, but only on 33514.</li>
        <li><b>Values are decrypted as they are read,</b> by a hook the core is given for each exchange (<code>SerialChannel.exchange(request, decrypt=…)</code>), so every way of reading a response works unchanged. An output parameter’s column key is the one named when its call was described.</li>
        <li><b>Bulk load into encrypted columns:</b> take the columns from <code>SELECT TOP 0 …</code> on an encrypting connection, as for any bulk load (${D(50)}). The statement names each encrypted column by its ciphertext’s type, as those columns give it (<code>column.type.cipher</code>, such as <code>varbinary(81)</code> for an encrypted <code>int</code>). <code>tds.encryption</code> encrypts each encrypted column’s values as the rows are sent, including rows from a source. The bulk data describes them as the server did. Its key table holds only the column keys’ ids, not their encrypted values, as SqlClient’s does. Each encrypted column carries its crypto metadata.
          <pre>columns = (await fetch(channel, "SELECT TOP 0 id, ssn FROM dbo.people")).result_sets[0].columns
await fetch(channel, tds.BulkInsert(f"INSERT BULK dbo.people (id int, ssn {columns[1].type.cipher})"))
await fetch(channel, tds.BulkRows(columns, [(1, "123-45-6789"), …]))</pre></li>
        <li><b>An enclave session is kept for the server</b> by the <code>Encryption</code>, and created again if the server refuses one (error 33195): the call is described again, with attestation parameters, and sent once more.</li>
        <li><b>Column keys, once decrypted, are kept</b> by the <code>Encryption</code>, for every connection it serves.</li>
        <li><b>Without <code>tds.encryption</code>, encrypted values are shown as they arrive:</b> <code>EncryptedValue(ciphertext)</code>, with the column’s type saying what it holds (<code>int encrypted randomized</code>). A value <code>tds.encryption</code> can’t decrypt is <code>NotDecrypted(ciphertext, reason)</code>, and the rest of the response is still read.</li>
        <li><b>An encrypted large value is read whole,</b> never streamed: nothing may be released before its tag is checked.</li>
        <li><b>Only what can’t be encrypted is refused before sending:</b> a value that doesn’t fit its type (${D(48)}), a type Always Encrypted can’t encrypt, an algorithm the driver doesn’t have. The server judges everything else. For example, comparing a randomized column is error 33277, raised by the describing call.</li>
      </ul>

      <h2>Example</h2>
      <p>Insert into, and read from, a table with an encrypted column:</p>
      <pre>encryption = Encryption([LocalKeyStore("keys")])
async with await encryption.connect(host, port, user=…, password=…, database=…) as connection:
    async with connection.serial_channel() as channel:
        await channel.exchange(tds.Call(tds.Builtin.SP_EXECUTESQL,
            tds.Param("@stmt", types.nvarchar(types.MAX), "INSERT dbo.people VALUES (@ssn, @salary)"),
            tds.Param("@params", types.nvarchar(types.MAX), "@ssn char(11), @salary int"),
            tds.Param("@ssn", types.char(11), "123-45-6789"), tds.Param("@salary", types.int, 41000)))</pre>
      <p>On the wire, this is two exchanges: the describing call, then the insert, whose <code>@salary</code> is <code>varbinary</code> ciphertext with status <code>08</code> and its cipher info. A SELECT’s COLMETADATA then reads, for an encrypted <code>salary</code> column:</p>
      ${table(['Bytes', 'Meaning'], [
        ['<code>81 01 00</code>', 'COLMETADATA, 1 column'], ['<code>01 00</code>', 'the key table: 1 column key'],
        ['<code>06 00 00 00  01 00 00 00  01 00 00 00  …8 bytes…</code>', 'database 6, key 1, version 1, metadata version'],
        ['<code>01  03 00 AA BB CC  0E …  07 00 …  08 …</code>', '1 encrypted value of it: the encrypted key, then <code>TDS_LOCAL_KEYS</code>, <code>cmk.pem</code>, <code>RSA_OAEP</code>'],
        ['<code>00 00 00 00  01 08</code>', 'user type; flags: nullable, encrypted'], ['<code>A5 41 00</code>', 'the ciphertext’s type: <code>varbinary(65)</code>'],
        ['<code>00 00  00 00 00 00  26 04  02  02  01</code>', 'key 0; user type; plaintext <code>int</code>; AEAD_AES_256_CBC_HMAC_SHA256; randomized; version 1'],
        ['<code>06 …</code>', 'the name, <code>salary</code>'],
      ], 'compact')}

      <h2>Edge cases</h2>
      <p><b>Where SQL Server differs from MS-TDS.</b> Observed from SQL Server 2025 (17.0.5015).</p>
      <ul>
        <li><b>MS-TDS numbers the algorithm two ways.</b> Its RPC section says <code>01</code> is AEAD_AES_256_CBC_HMAC_SHA512; its COLMETADATA section says <code>02</code> is AEAD_AES_256_CBC_HMAC_SHA256. SQL Server uses <code>02</code> in both, and in <code>sp_describe_parameter_encryption</code>’s answer.</li>
        <li><b>The enclave package’s length is a u16,</b> where MS-TDS says L_VARBYTE, a u32. SqlClient writes a u16, and SQL Server reads a u16: a batch and a call with an empty two-byte package succeed (observed, Azure SQL Database). Once enclaves are agreed, every batch and call carries the field.</li>
      </ul>
      <p><b>What MS-TDS doesn’t state.</b> Observed from SQL Server 2025 (17.0.5015), or from Microsoft’s SqlClient where marked.</p>
      <ul>
        <li><b>The encryption, the column key’s layout and the plaintext’s layout</b> aren’t in MS-TDS. This page takes them from Microsoft’s documentation and SqlClient (MIT-licensed; what was used is listed in the repository’s <code>THIRD-PARTY-NOTICES.md</code>), and the driver is checked against SqlClient itself (${D(61)}).</li>
        <li><b>The client’s bulk data carries a key table too,</b> once the feature is agreed: empty when no column is encrypted (SqlClient; confirmed live).</li>
        <li><b>Without the login feature, encrypted columns arrive as <code>varbinary</code> ciphertext,</b> with no metadata.</li>
        <li><b>The server accepts any key store name and any encrypted column key:</b> it never decrypts one. So the tests run against the local container, with a key store of RSA files.</li>
        <li><b>A table type can’t have encrypted columns:</b> <code>CREATE TYPE … AS TABLE</code> refuses <code>ENCRYPTED WITH</code>. So no table-valued parameter carries encrypted values.</li>
        <li><b>How the statement names an encrypted column for bulk load:</b> by its ciphertext’s type, exactly as the server reports it, <code>varbinary(81)</code> for an encrypted <code>int</code> (observed: SqlClient’s SqlBulkCopy sends <code>insert bulk [dbo].[b] ([v] VarBinary(81))</code>, recorded with an Extended Events session). The server refuses any other declaration: the plain type, a <code>varbinary</code> of another length, <code>ENCRYPTED WITH</code>, or <code>ALLOW_ENCRYPTED_VALUE_MODIFICATIONS</code> (errors 518, 102).</li>
        <li><b>Describing with enclaves:</b> the attestation parameters go third, by position, as <code>varbinary(n)</code>. As <code>varbinary(max)</code>, the server refuses them (error 214, “Procedure expects parameter ‘enclave_identity_attestation_securechannel_input’ of type ‘unsupported protocol type’”). Azure SQL Database, observed.</li>
        <li><b>Enclaves without attestation work on Azure SQL Database’s VBS enclaves:</b> LIKE and range comparisons on randomized columns returned the right rows (observed).</li>
        <li><b>Where SqlClient differs from the driver</b> (${D(61)}’s pass 2): SqlClient decodes and encodes UTF-16 with replacement, so an unpaired surrogate, which the driver keeps (${D(48)}), becomes U+FFFD in SqlClient, and a deterministic lookup for such a value finds nothing written by the other. SqlClient also can’t send a <code>time(0)</code> parameter to an encrypted column: it treats a Scale of 0 as “unset”, so it sends <code>time(7)</code>, which the server refuses.</li>
      </ul>

      ${source('§2.2.5.7, §2.2.6.4, §2.2.6.6, §2.2.6.7, §2.2.7.4, §2.2.7.11, §2.2.7.19; SqlClient (SqlAeadAes256CbcHmac256Algorithm, EncryptedColumnEncryptionKeyParameters, TdsParser)')}`,
  });
})();
