# Connect (procedure)

**Where this sits:** the first conversation on every connection. It ends either in **ready** or in **closed**.
**Use this page to** follow, implement or debug the steps from opening a TCP connection to being ready for requests.

## Purpose

This procedure turns a TCP connection into an authenticated, encrypted session whose state the client knows. This page covers SQL Server login; the other three ways to log in are listed in [Conversations](conversations.md). The connection manager runs this procedure. Client code sees only the result: a ready connection on which to open serial channels ([The Client §3](../A-the-client.md#3--connections-and-serial-channels--agreed-d-17d-23-d-36)).

## Shape

```
                     ┌──────── 8.0 ────────┐
open TCP ──► start ──┤                     ├──► hello ──► (7.4: secure) ──► log in ──► ready
                     └─► secure (TLS) ─────┘                                  │
                                                                              ├──► routed ──► closed
any step fails ──────────────────────────────────────────────────────────────► closed
```

| Step | Client sends | Client expects | Next step if all is well | Otherwise → closed, because… |
|------|--------------|----------------|--------------------------|------------------------------|
| **secure** (8.0, first) | TLS handshake on raw TCP, offering ALPN `tds/8.0` | TLS completes; certificate valid | hello | TLS failed or certificate rejected |
| **hello** | [PRELOGIN](prelogin.md) | PRELOGIN reply (type `04`) | 7.4 with encryption agreed: secure · 8.0: log in | malformed reply; instance mismatch; encryption outcome not acceptable (D-10) |
| **secure** (7.4) | TLS handshake records inside type `12` packets, repeated until done | TLS records inside type `12` packets | log in | TLS failed or certificate rejected |
| **log in** | [LOGIN7](login7.md) | [login response](login-response.md) | ready, or routed if the reply routes | no LOGINACK (server sent ERROR); version not 7.4; malformed reply |
| **ready** | — | — | requests may begin | — |
| **routed** | — | — | closed; reconnect to the named server (D-11) | — |

## Rules

- **One timer covers the whole procedure.** The connection timer (default 15 s) runs from *open TCP* until the client reaches ready or closed.
- **Fail closed.** If any message is malformed or not expected at the current step, close the connection, enter *closed*, and report the step, what was expected and what arrived.
- **Session state** is built only from the login reply's announcements, starting from these defaults: packet size 4096, nothing else known.
- **Packet size** switches to the announced value after the login reply, before the first request.
- **The client chooses 8.0, and nothing falls back** (D-10). `tds_version="8.0"` (or `strict=True`) starts with TLS. If that fails, the connection fails, saying why and what the options are. It never retries as 7.4, because that would silently lose the protection 8.0 gives.
- **Under 7.4, the whole connection is encrypted, or the connection fails** (D-10). A server that offers only login encryption, or none, is refused with an explanation.
- **The server's certificate is verified** with Python's `ssl.SSLContext` (D-10): by default against the system's trusted authorities and the host name connected to. A certificate naming another host is checked against `server_hostname`. Under 8.0, a context that doesn't verify is refused: TLS that accepts any certificate can't prevent a man-in-the-middle attack.

## Session recovery

**When a connection breaks, a new one can continue its session** (D-57). The login asks for session recovery (it is among the default features), and the server then reports the session's state as it changes. To recover, the driver opens a new connection whose login carries that state, and the server rebuilds the session from it.

| When | The client sends | The server sends |
|---|---|---|
| the first login | the session recovery feature, with no data | its acknowledgement, holding the session's initial states |
| each response | — | a SESSIONSTATE token for each change: a sequence number, whether the session can be recovered, and the states that changed |
| a recovery login | the session recovery feature, with two snapshots: the session as the first login established it (database, collation, language, states), and as it is now (only what differs) | the session as it was, or a failed login |

**A state** is an id and a value that the client keeps without interpreting. Only the server knows what each one means. The client needs only its value at login and every change after that.

**When the driver recovers:**
- **By itself,** when an exchange finds the connection broken and no request in progress. The driver recovers once, then sends the request.
- **When asked:** `await connection.recover()`.
- **A request in progress when the connection broke is never sent again.** Whether it ran is unknown. The request's own error says so, and the next exchange doesn't recover by itself. `connection.recover()` recovers the session as the server last reported it; it neither determines nor undoes the interrupted request's effects.
- **The steps show the recovery:** *recover* (`● recover · session 81, on a new connection to …`), then the usual hello, secure and log in, then *recovered* (`● recovered · session 81 → 81 · database tempdb`: SQL Server can give the new session the old one's id, once the old one has ended). `connection.recoveries` counts the recoveries.
- **Serial channels continue:** each one that was open before is open again, with the same application id and owner, under MARS too. MARS wire ids are allocated afresh on the new physical connection; incoming frames map back to application ids. Connection/channel close permissions remain valid. Old responses belong to the failed exchange and cannot read or cancel new requests. Channels closed by the application stay closed.
- **It can't happen** when the login didn't ask for session recovery, the server didn't agree to it, the server marked the session not recoverable, or the recovery login failed. `SessionNotRecovered` then says why. It names the session and what broke the connection, and for a session marked not recoverable, the request after which the server marked it.

The same contract is implemented in Rust for its supported SQL/token subset:
`connection.recover().await`, `connection.recoveries()` and
`ErrorKind::SessionNotRecovered`. `ConnectOptions.session_recovery` defaults on.
Its persistent driver retires the physical epoch before waking failed waiters;
old request/read/cleanup guards check that epoch before revocation. Current-epoch
abandonment still discards. Python pins response sources and running procedures
to the failed core and transport. Already retained old data stay inspectable;
neither client may advance an old exchange through the replacement. The
[experiment record](../experiments/recovery-channel-identity.md) distinguishes
the original failure, the intervention and the local Python/Rust evidence.

## Options

This table lists every option of `tds.connect(host, port, *, user, password, …)`, with its default. The command line (`python -m tds --help`) offers the same, under the names shown.

| Option | Command line | Default | What it does | Decision |
|---|---|---|---|---|
| `user`, `password` | `--user`, `--password-var` | — | A SQL Server login. | — |
| `new_password` | — | none | Changes a SQL Server login's expired password as it logs in (error 18488 says it must). | D-54 |
| `login` | — | none: a SQL Server login | A Windows login (`tds.WindowsLogin`: Kerberos or NTLM) or an Entra ID login (`tds.EntraToken`, `tds.EntraLogin`), each taking its tokens from the application ([Conversations](conversations.md#what-each-way-of-logging-in-needs--built-d-54-d-55)). | D-55 |
| `database` | `--database` | the login's default | Where the session starts. If it can't be opened, the login fails, saying why; there is no fallback. | D-9 |
| `tds_version` | `--tds-version` | `"7.4"` | `"8.0"`: TLS first, always encrypted. Nothing falls back from 8.0. | D-10 |
| `strict` | — | `False` | `True` is `tds_version="8.0"`, as Microsoft's drivers spell it (Encrypt=Strict). | D-10 |
| `ssl_context` | `--ca-file` | the system's trusted authorities, checking the host name | How the server's certificate is checked: Python's `ssl.SSLContext`. | D-10 |
| `server_hostname` | `--server-hostname` | the host connected to | The name the certificate must carry. | D-10 |
| `timeout` | `--timeout` | 15 s | The connection timer, from opening TCP to ready (routing included). | — |
| `cleanup_timeout` | — | 5 s | Total channel-close cleanup budget, separate from connection/query time. Finite and nonnegative. Failure/cancellation discards the connection. | — |
| `mars` | `--mars` | off | Serial channels are MARS sessions, so several can run at once. | D-18 |
| `odbc` | `--no-odbc` | on | LOGIN7's ODBC flag: the session starts with ODBC's defaults (ANSI options on, TEXTSIZE unlimited). When off, the session starts with the server's own defaults (TEXTSIZE 4,096 bytes). | D-9 |
| `features` | one switch per feature, below | `tds.DEFAULT_FEATURES` | What the login asks for. `connection.features` shows what the server accepted. | D-8 |
| `app_name` | `--app-name` | `"tds (python)"` | The session's `program_name`, as administrators see it. | D-9 |
| `host_name` | `--host-name` | this machine's name | The session's `host_name`. The process ID is always the real one. | D-9 |
| `language` | `--language` | the login's default | The session's language, and so the language of its messages. | D-9 |
| `read_only_intent` | `--read-only-intent` | off | Tells an availability group the connection only reads, so it can be routed to a readable secondary. It is only a routing hint; writes still work. | D-9 |
| `follow_routing` | — | on | A valid TCP routing reply is followed once under the original deadline, verifying the destination's name. Non-TCP/invalid targets are rejected. When off, `tds.Routed` reports a valid target instead. | D-11 |
| `observe` | `--observe` | off | Shows the running client at off/outline/full. A failed callback is disabled; its exception is available as `connection.observation_error` until replaced. | D-12 |
| `capture` | — | none | Saves one physical connection for replay; cannot move to another. Write/flush failure raises `CaptureError` and discards the connection. Mutually exclusive with `capture_factory`. | D-12 |
| `capture_factory` | — | none | Callable creating a fresh capture with a distinct output for each physical connection, including routing/recovery. Required for pool recording; loans of the same transport keep its capture. The application owns/closes Python capture resources. | D-12 |

**Login features.** `features` is a list of `tds.Feature`. The command-line switches turn each feature on or off, overriding its default.

| Feature | Command line | Default | Version sent | What it changes |
|---|---|---|---|---|
| `JSON_SUPPORT` | `--json-support` | on | 1 | `json` columns arrive as `json`, not as text. |
| `VECTOR_SUPPORT` | `--vector-support` | on | 2 | `vector` columns arrive as vectors of float32 or float16, not as text. |
| `UTF8_SUPPORT` | `--utf8-support` | on | 1 | Text in a UTF-8 collation arrives as stored, invalid bytes included; `json` arrives as UTF-8 ([Data Types](types.md#edge-cases)). |
| `DATA_CLASSIFICATION` | `--data-classification` | on | 2 | A result whose columns are classified says how, with ranks (`ResultSet.classification`). |
| `SESSION_RECOVERY` | `--session-recovery` | on | — (no data; a recovery login sends the session) | A broken connection's session can be recovered ([Session recovery](#session-recovery)). |
| `COLUMN_ENCRYPTION` | `--column-encryption` | off | 1; 2 for enclaves | Always Encrypted: every result's column descriptions carry a key table, and each encrypted column carries its crypto metadata. `tds.encryption` asks for it (version 2 when it uses enclaves) and decrypts the values ([Always Encrypted](always-encrypted.md)). If the feature is asked for without `tds.encryption`, encrypted values arrive as ciphertext. |
| `AZURE_SQL_SUPPORT` | `--azure-sql-support` | off | 1 | Azure SQL: failover partner login with read-only intent. Azure SQL Database acknowledged it (1). |
| `AZURE_DNS_CACHING` | `--azure-dns-caching` | off | — | Azure SQL may say the client can cache its address. Azure SQL Database acknowledged it (1). The driver caches nothing itself; caching is the application's choice (D-39). |
| `ENHANCED_ROUTING` | `--enhanced-routing` | off | — | Routing that names a database too (ENVCHANGE 21). The test server acknowledged it with 0, meaning not enabled. |
| `GLOBAL_TRANSACTIONS` | `--global-transactions` | off | — | Azure SQL's elastic transactions across databases. Azure SQL Database acknowledged it (1). |

`connect(features=…)` can also give a feature's data, as `(feature, data)`. `tds.encryption` asks for column encryption version 2 this way. Federated authentication isn't asked for as a feature; it is part of the login itself (`login=EntraToken(…)`). The user agent feature is left out. SQL Server ignores it, and the driver is identified already (D-8).

## Example

[Worked Example](../2-example-login.md) follows the 7.4 path step by step: hello → secure → log in → ready.

## Edge cases

- **Login-only encryption** (both sides said *off*): TLS encrypts only the login packet, and everything after it is unencrypted. The driver refuses it (D-10).
- **8.0:** the hello's encryption value is ignored, and no second TLS handshake follows it.
- **A named instance's port** comes from the [Browser](browser.md), before connecting.
- **The dedicated administrator connection (DAC)** is SQL Server's reserved connection for an administrator, for when the server is too busy or unresponsive to accept a normal one. It is this same procedure on another port: 1434 on a default instance, otherwise the port the Browser gives. Only one DAC can be open at a time, only for sysadmins, and from another machine only when *remote admin connections* is on. The test container has it on, and forwards the DAC as port 14345.

**What MS-TDS doesn't state.** Observed from SQL Server 2025 (17.0.5015), or Azure SQL Database where named.
- **SQL Server accepts 8.0 only once it has a certificate configured.** Without one, it closes the connection when the client starts with TLS. The test container's setup is in [`docker/macos/tls`](../../../docker/macos/tls/README.md).
- **Under 8.0, SQL Server answers the hello's encryption option with *not supported*,** because TLS is already running.
- **Under 8.0, the login reply still says TDS 7.4** (`74 00 00 04`). Only ALPN says 8.0.
- **A refused DAC closes the connection at the hello, with no message:** for example, a second DAC while one is open. SQL Server gives the reason only in its error log. The driver's error says so.
- **Under 7.4, SQL Server negotiates TLS 1.2 at most,** even when the client offers 1.3. A context that requires TLS 1.3 makes the server close the connection during the handshake; under 8.0, TLS 1.3 is negotiated.
- **Which server name a routed login sends:** MS-TDS doesn't say. Azure SQL's nodes need the routed server and its port, as `server,port`; the name the application asked for is refused, with error 40613 and the message saying `server ''` (observed, Azure SQL Database, connection policy Redirect; SqlClient sends the same). The driver sends `server,port`.
- **Azure SQL with connection policy Redirect routes every connection, from outside Azure too:** the gateway's LOGINACK comes with a routing announcement to a node (`….worker.database.windows.net:11063`), where the login is made again. Under TDS 8.0 the node's certificate is valid for the node's own name.
- **Session recovery,** observed:
  - **What comes back:** the database, language and collation; the SET options (ANSI_NULLS, QUOTED_IDENTIFIER, NOCOUNT, XACT_ABORT, IMPLICIT_TRANSACTIONS and the rest); DATEFIRST and DATEFORMAT; TEXTSIZE; LOCK_TIMEOUT; DEADLOCK_PRIORITY; the isolation level; ROWCOUNT; CONTEXT_INFO.
  - **What doesn't:** values set with `sp_set_session_context`. The server reports no state for them, so a recovered session doesn't have them.
  - **What the server doesn't allow to be recovered:** it marks the session with state 254, whose value names why: 4, a transaction is open; 5, a temporary table exists (local or global); 13, the session is impersonating another login (`EXECUTE AS`); 3, the session was killed while a request ran. The mark is removed when the cause ends (the transaction ends, the table is dropped, `REVERT`). MS-TDS defines neither the state nor its codes. The driver names the codes it has seen, and shows any other code as it arrived.
  - **A session killed while idle can be recovered:** no response carries a mark, so the last state is still recoverable.
  - **The recovery login's reply** announces the recovered database, language and collation, and acknowledges session recovery; it carries no SESSIONSTATE.

---

**Source:** MS-TDS §2.1, §2.2.6.5, §3.1.5 (figures 3–4), §3.2.2, §3.2.4, §3.2.5.1–§3.2.5.4, §3.2.5.10
