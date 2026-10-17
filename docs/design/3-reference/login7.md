# LOGIN7 (log in)

**Where this sits:** the *log in* step of the connect conversation. Its body is a **structure**. Its packet type is `10`.
**Use this page to** read or build a login message.

## Purpose

The client says who it is, how to authenticate it, and how it wants the session set up: database, language, packet size and options.

## Shape

The body has four parts, in this order:

```
fixed part        36 bytes of always-present fields
pointer table     (offset, length) pairs that point into the data part
data part         UTF-16LE strings and blobs, packed back to back
feature list      optional (7.4): (feature, length, data) entries, then FF
```

**Fixed part**

| At | Field | Size | Meaning | MS-TDS name |
|----|-------|------|---------|-------------|
| 00 | length | u32 | Whole body | Length |
| 04 | TDS version | u32 | `04 00 00 74` = 7.4 | TDSVersion |
| 08 | packet size | u32 | Requested packet size | PacketSize |
| 0C | client library version | u32 | Informational | ClientProgVer |
| 10 | client process id | u32 | Informational | ClientPID |
| 14 | connection id | u32 | 0 | ConnectionID |
| 18 | option flags 1 | u8 | below | OptionFlags1 |
| 19 | option flags 2 | u8 | below | OptionFlags2 |
| 1A | type flags | u8 | below | TypeFlags |
| 1B | option flags 3 | u8 | below | OptionFlags3 |
| 1C | time zone | i32 | Unused, 0 | ClientTimeZone |
| 20 | locale | u32 | Client's locale id; ignored by servers | ClientLCID |

**Pointer table.** Offsets count from the start of the body. Lengths are in characters, except where marked.

| At | Points to | MS-TDS name |
|----|-----------|-------------|
| 24 | host name | ibHostName / cchHostName |
| 28 | user name | ibUserName / cchUserName |
| 2C | password (scrambled, see Rules) | ibPassword / cchPassword |
| 30 | application name | ibAppName / cchAppName |
| 34 | server name | ibServerName / cchServerName |
| 38 | extension → feature list (length in **bytes**) | ibExtension / cbExtension |
| 3C | client library name | ibCltIntName / cchCltIntName |
| 40 | language | ibLanguage / cchLanguage |
| 44 | database | ibDatabase / cchDatabase |
| 48 | *client id: 6 bytes inline (a MAC address), not a pointer* | ClientID |
| 4E | Windows auth data (length in **bytes**) | ibSSPI / cbSSPI |
| 52 | database file to attach | ibAtchDBFile / cchAtchDBFile |
| 56 | new password (scrambled) | ibChangePassword / cchChangePassword |
| 5A | *large Windows auth length: u32 inline* | cbSSPILong |

The data part begins at `5E`.

**Flags.** The first bit listed in each flag set is the lowest bit.

| Set | Bits (low → high) |
|-----|-------------------|
| option flags 1 | byte order (0 = little-endian) · character set (0 = ASCII) · float format, 2 bits (0 = IEEE 754) · bulk-load support (1 = off) · **report database changes** · **initial database must succeed** · **report language changes** |
| option flags 2 | **initial language must succeed** · ODBC client · 2 reserved bits · user type, 3 bits (0 = normal) · Windows (integrated) auth |
| type flags | SQL dialect, 4 bits (0 = default) · OLE DB client · **read-only intent** · 2 reserved bits |
| option flags 3 | change password · binary XML · user instance · unknown-collation handling · **feature list present** · 3 reserved bits |

**The ODBC flag** (fODBC, option flags 2) chooses the settings a session starts with. When it is set, the server starts the session with ODBC's defaults: ANSI_NULLS, ANSI_PADDING, ANSI_WARNINGS, CONCAT_NULL_YIELDS_NULL and QUOTED_IDENTIFIER on, no implicit transactions, and unlimited TEXTSIZE. When it is clear, the server's own defaults apply: those options are off, and TEXTSIZE is 4,096 bytes. The driver sets it, as ODBC, .NET and JDBC clients do, unless `connect(odbc=False)` clears it (D-9).

**Who the client is** (D-9). Administrators see these in `sys.dm_exec_sessions`:
- *client process id*: the real one (`host_process_id`);
- *host name*: this machine's name, or the value of `connect(host_name=…)` (`host_name`);
- *application name*: `tds (python)`, or the value of `connect(app_name=…)` (`program_name`);
- *client library name*: `tds` (`client_interface_name`).

*Language* is empty unless `connect(language=…)` sets it. When it is empty, the session starts in the login's default language. *Read-only intent* is set by `connect(read_only_intent=True)`. It is a hint that an availability group uses for routing, and it doesn't prevent writes. *Server name* is the host the driver connects to. After routing, it is the host the application asked for. MS-TDS doesn't say which name to send; this is to be confirmed on Azure (M17).

**How the login carries each way of logging in** ([Conversations](conversations.md#what-each-way-of-logging-in-needs--built-d-54-d-55), D-55):
- *SQL Server login:* user name and password. To change an expired password, set *change password* in option flags 3, and put the new password at entry `56`, scrambled in the same way as the password.
- *Windows login:* *Windows (integrated) auth* set in option flags 2, no user name or password, and the security library's first token at entry `4E`, with its length in bytes. If the token is over 65,535 bytes, its length goes in the u32 at `5A`.
- *Entra ID:* no user name or password, and the federated authentication feature (`02`) in the feature list. The feature's first byte is the library number shifted left by one bit. Bit 0 is set when the FEDAUTHREQUIRED value in the hello reply was 1:
  - token sent with the login (library `01`): the first byte is followed by the token's length (u32), the token in UTF-16LE, and the nonce from the hello reply, if the server sent one;
  - token fetched during the login (library `02`, MS-TDS's “ADAL”): the first byte is followed by a workflow byte: `01` password, `02` integrated, or `03` for everything else, as Microsoft's drivers send it.

These values are credentials. Observability shows only their length, and captures replace them with zeros (D-12).

**Feature list (7.4).** To send one:
1. Set *feature list present* in option flags 3.
2. Point the *extension* entry at a 4-byte offset inside the data part.
3. That offset points to the list itself.

| Entry field | Size |
|-------------|------|
| feature | u8 (table below) |
| length | u32 |
| data | *length* bytes |

The list ends with a single `FF`.

| Feature | Value | Feature | Value |
|---------|-------|---------|-------|
| session recovery | `01` | UTF-8 support | `0A` |
| federated auth | `02` | Azure DNS caching | `0B` |
| column encryption | `04` | JSON support | `0D` |
| global transactions | `05` | vector support | `0E` |
| Azure SQL support | `08` | enhanced routing | `0F` |
| data classification | `09` | user agent | `10` |

**The driver sends five by default** (D-8): JSON support (version 1), vector support (version 2: float32 and float16), UTF-8 support (version 1), data classification (version 2, with ranks) and session recovery (no data; a recovery login sends the session instead, [Connect › Session recovery](connect.md#session-recovery)). `connect(features=…)` chooses others. For example, `tds.encryption` asks for column encryption ([Always Encrypted](always-encrypted.md)). [Connect › Options](connect.md#options) lists the features, what each one changes, and which ones can't be requested yet. The list goes after the data part, and its length is counted in the login's total length. Observed: SQL Server 2025 (17.0.5015) accepts JSON support 1, vector support **1** (float32 only), UTF-8 support, data classification 2 and session recovery.

## Rules

- **Empty strings:** set the length to 0, and the offset is ignored. The exception is host name, whose offset must point at the start of the data part even if every string is empty.
- **Limits:** each string is at most 128 characters (the attach-file name may be up to 260). The extension block is at most 255 bytes. The whole login is at most 128 KB − 1.
- **User name and database** are treated as bracket-quoted identifiers, so they must be valid as `[name]`.
- **Password scrambling:** for each byte of the UTF-16LE password, swap its two 4-bit halves, then XOR the result with `A5`. For example, `a` (`61 00`) becomes `B3 A5`. This only obscures the password. TLS is what protects it.
- **Version:** the server uses the lower of its own highest version and the version the client sends. The driver sends 7.4 and checks the version in the reply. See [Login Response](login-response.md).

## Example

[Worked Example §4](../2-example-login.md#4--log-in--who-the-client-is-and-what-it-wants) shows a full 136-byte login, every field annotated.

## Edge cases

- In 8.0 the TDS version field is ignored, because the version was agreed in the TLS handshake (ALPN `tds/8.0`).
- Entry `38` is called "unused" in older versions. In 7.4 it is the extension pointer, used only when *feature list present* is set.

---

**Source:** MS-TDS §2.2.6.4
