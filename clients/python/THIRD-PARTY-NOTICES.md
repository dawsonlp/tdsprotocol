# Third-party notices

## Microsoft SqlClient

[Microsoft.Data.SqlClient](https://github.com/dotnet/SqlClient), Microsoft's .NET driver for SQL Server, helped this project in two ways. No SqlClient code is copied into this repository.

**1. As a reference, for Always Encrypted only.** MS-TDS carries Always Encrypted's bytes but does not define what is inside them. For the parts listed below, this project's authors read SqlClient's source and wrote the Python code independently to produce the same bytes. Each module says where it follows SqlClient, in its header or beside the code.

| What MS-TDS leaves out | Module, in `clients/python/` | SqlClient source read |
|---|---|---|
| Encrypting a value: AEAD_AES_256_CBC_HMAC_SHA256, its derived keys and its layout | `tds/encryption/cell.py` | SqlAeadAes256CbcHmac256Algorithm, SqlAeadAes256CbcHmac256EncryptionKey |
| An encrypted column key's layout, and the signature over a master key's metadata | `tds/encryption/keys.py` | EncryptedColumnEncryptionKeyParameters, ColumnMasterKeyMetadata |
| How each type's plaintext is laid out before encryption (normalization version 1) | `tds/encryption/normalize.py` | TdsParser (SerializeUnencryptedValue, DeserializeUnencryptedValue) |
| The secure-enclave session and the enclave package, without attestation | `tds/encryption/enclave.py` | NoneAttestationEnclaveProvider, EnclaveDelegate, AlwaysEncryptedKeyConverter, ColumnEncryptionKeyInfo, EnclaveSessionCache, SqlConnectionAttestationProtocol, TdsEnums |
| The Azure Key Vault and Windows certificate store key stores: key paths, and the column-key format each writes | `tds/encryption/keyvault.py`, `tds/encryption/certstore.py` | SqlColumnEncryptionAzureKeyVaultProvider, AzureSqlKeyCryptographer, SqlColumnEncryptionCertificateStoreProvider |
| How the parameter-describing call is made, which errors mean "describe again", and the bulk-load key table | `tds/encryption/context.py`, `tds/requests.py` | SqlCommand, SqlBulkCopy, TdsParser |

Where SqlClient's behavior differs from MS-TDS, the design documents say so and record what SQL Server actually accepted. For example, the enclave package's length is two bytes, where MS-TDS says four (the Always Encrypted reference's Edge cases, `docs/design/3-reference/always-encrypted.md`).

The rest of the client was built from MS-TDS, MC-SQLR and MC-SMP, and from SQL Server's observed behavior: packets, PRELOGIN, LOGIN7, tokens, data types, requests, MARS, routing, session recovery and logins. For the logins, SqlClient's protocol constants were also used to cross-check MS-TDS. Where MS-TDS does not say what to send, two login details follow SqlClient's behavior. One is the server name a routed login sends: Azure SQL refused ours, and SqlClient showed what it expects. The other is the workflow byte of an Entra ID login whose token is fetched during the login.

**2. As an independent check, in tests.** `clients/python/tests/dotnet/` runs the published Microsoft.Data.SqlClient package (7.1.1, from NuGet, in Microsoft's .NET SDK container). It reads every encrypted value this client writes, and this client reads every value SqlClient writes (D-61). The package is downloaded when the test runs and is not stored here. While bulk load into encrypted columns was being built, the statement that SqlClient's SqlBulkCopy sends was also recorded.

SqlClient's license:

```
MIT License

Copyright (c) .NET Foundation. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE
```
