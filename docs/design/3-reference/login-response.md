# Login Response

**Where this sits:** the server's answer to *log in*. Its body is a **token stream**. Its packet type is `04`.
**Use this page to** read a login reply and decide whether the login succeeded, failed or was redirected.

## Purpose

The server either accepts the login and describes the new session, rejects the login and says why, or redirects the client to another server.

## Shape

A sequence of tokens, each a 1-byte tag followed by its fields. A login reply contains:

```
( ENVCHANGE | INFO | ERROR )*   LOGINACK?   FEATUREEXTACK?   ENVCHANGE(routing)?   DONE
```

The order shown is typical, but only two positions are fixed: `DONE` comes last, and a routing `ENVCHANGE` comes after `LOGINACK`.

### Text and byte fields

| Shape | Layout | MS-TDS name |
|-------|--------|-------------|
| short text | u8 character count, then UTF-16LE | B_VARCHAR |
| long text | u16 character count, then UTF-16LE | US_VARCHAR |
| short bytes | u8 byte count, then bytes | B_VARBYTE |

### `E3` ENVCHANGE — a session setting changed

| Field | Size |
|-------|------|
| length | u16: bytes that follow |
| kind | u8 |
| new value, old value | depends on kind (below) |

| Kind | Setting | New / old values |
|------|---------|------------------|
| 1 | database | short text / short text |
| 2 | language | short text / short text |
| 4 | packet size | short text / short text (a decimal number written as text, such as `"4096"`) |
| 7 | collation | short bytes (5 bytes) / short bytes |
| 13 | mirroring partner | short text / empty. The new value is database mirroring's partner server. The driver keeps it as `connection.session.mirroring_partner` and never connects to it on its own (D-58) |
| 20 | **routing** | u16 length, protocol u8 (`0` = TCP), port u16, server as long text / `00 00` |
| 21 | **routing to a database** | as 20, followed by the database name as long text / `00 00` |

Other kinds (transactions, reset, user instance) don't occur in a login reply.

### `AB` INFO and `AA` ERROR — a message from the server

The two tokens share one layout. INFO is informational; ERROR is a failure.

| Field | Size |
|-------|------|
| length | u16 |
| number | i32 |
| state | u8 |
| class | u8 (severity: below 10 is informational) |
| message | long text |
| server name | short text |
| procedure | short text |
| line | i32 |

### `AD` LOGINACK — the login is accepted

| Field | Size | Meaning |
|-------|------|---------|
| length | u16 | |
| interface | u8 | `1` = T-SQL |
| TDS version | 4 bytes | `74 00 00 04` = 7.4 |
| server program | short text | for example, "Microsoft SQL Server" |
| server version | 4 bytes | major, minor, build (2 bytes) |

### `AE` FEATUREEXTACK — the server accepts requested features

Entries of feature (u8), length (u32) and data, ending with `FF`. There is **no overall length**. The reader finds the end by walking the entries. The client keeps the accepted features as `connection.features`. SQL Server 2025 was observed to return JSON support `01` and vector support `01`.

### `FD` DONE — end of the reply

| Field | Size | Meaning |
|-------|------|---------|
| status | u16 | `00` final · `01` more follows · `02` error · `10` row count valid · `20` cancel acknowledged · `100` severe error |
| current command | u16 | |
| row count | u64 | |

## Rules

- **Success means a LOGINACK is present.** If there's no LOGINACK, the login failed, and the ERROR tokens say why. The client then closes the connection.
- **Version check (agreed):**
  - On a 7.4 connection, LOGINACK must report 7.4.
  - Anything lower is a failure, and the error must name the version the server sent.
- **Apply every ENVCHANGE** to the session state. The new packet size takes effect from the **next** message.
- **Routing:**
  - If a routing ENVCHANGE follows LOGINACK, read the rest of the reply up to DONE.
  - Then discard everything else in this reply, close the connection, and connect to the named server instead. If the routing names a database, use that database on the new server.
  - The driver does this once, automatically, unless `connect(follow_routing=False)` turns it off (D-11).

## Example

[Worked Example §5](../2-example-login.md#5--login-reply--the-server-accepts-and-describes-the-session) is a successful reply of eight tokens: four ENVCHANGEs, two INFOs, a LOGINACK and a DONE.

## Edge cases

- The server program name may end with `00 00` characters (MS-TDS's own sample does). Trim them.
- In 8.0, LOGINACK reports 7.4 (`74 00 00 04`); version 8.0 itself was agreed by ALPN during the TLS handshake. Observed from SQL Server 2025 (17.0.5015).

---

**Source:** MS-TDS §2.2.7.6, §2.2.7.9–§2.2.7.11, §2.2.7.13–§2.2.7.14, §3.2.5.4, §3.2.5.10
