# Conversations

**Where this sits:** above the bytes. A conversation is the ordered exchange of messages between client and server.
**Use this page to** see every conversation TDS 7.4 and 8.0 define, how each one runs, and which ones this project's client has built.

## Purpose

MS-TDS defines **nine distinct conversations**, in three families. It draws seven sequence diagrams (§3.1.5, figures 3–9). They show five conversations, because two are drawn twice: once for 7.x and once for 8.0. The other four conversations appear only in its text.

| Family | Shared shape | Conversations |
|---|---|---|
| **Connecting** | hello → secure → log in → ready | 4: one per way of logging in |
| **Requests** | one exchange: a request, then the server's token stream, ending in a final DONE | 4 |
| **Control** | interrupting an exchange that is in progress | 1 |

## Shape

### Connecting: four ways to log in

All four share the steps of [Connect](connect.md); only *log in* differs. In TDS 8.0 the secure step comes first, before the hello. Any of them can end in **routed** instead of ready. Then the server names another server, and the client closes the connection (D-11).

| # | Conversation | What *log in* involves | Messages (packet type) | Built |
|---|---|---|---|---|
| 1 | **SQL Server login** | a user name and password in LOGIN7 | LOGIN7 (`10`) → login reply | **yes**, TDS 7.4 |
| 2 | **Windows login** (SSPI) | Kerberos or NTLM, negotiated through SPNEGO. The first token is sent in LOGIN7. The server answers with an SSPI token, and the client answers that with an SSPI message when its security library has one. This repeats until authentication is done. | LOGIN7 (`10`) → SSPI token ⇄ SSPI message (`11`) … → login reply | **yes** (M17, D-55) |
| 3 | **Federated login, token in advance** | the client already holds a token (for example an Entra ID access token) and sends it in LOGIN7's feature list | LOGIN7 (`10`) → login reply, including FEATUREEXTACK | **yes** (M17, D-55) |
| 4 | **Federated login, token fetched mid-login** | the server first tells the client where to get a token, then receives it | LOGIN7 (`10`) → FEDAUTHINFO → federated token message (`08`) → login reply | **yes** (M17, D-55) |

### What each way of logging in needs · *built, D-54, D-55*

Each was built in M17 and tested on Azure (D-62). The tokens come from the application (D-55). `connect(login=…)` takes a WindowsLogin, an EntraToken or an EntraLogin (`tds.logins`). Adapters in `tds.adapters` make them from pyspnego and azure-identity.

| Login | Server side | The client gives | Tested |
|---|---|---|---|
| **1, variants:** changing an expired password at login; a contained database's user | any SQL Server. The new password goes in LOGIN7's change-password field; a contained user names its database | `connect(…, new_password=…)`; `connect(…, database=…)` | the local container |
| **2, Kerberos** | SQL Server on Windows, or on Linux with a key file for its service name (`MSSQLSvc/host:port`), in an Active Directory domain. On Linux, Kerberos is the only integrated login. | `WindowsLogin(Spnego())`: a ticket (kinit), and the server's full host name, not an address | a Windows Server domain controller and SQL Server on Windows, from a Linux VM in the domain's network |
| **2, NTLM** | SQL Server on Windows only. SQL Server on Linux refuses NTLM for remote connections. No domain is needed; a local Windows account is enough. | `WindowsLogin(Spnego(user, password, "ntlm"))` | SQL Server on Windows, with a local account and a domain account |
| **3, token in advance** | Azure SQL Database or Managed Instance; SQL Server 2022 or later through Azure Arc, on Windows or Linux but not in a container; or on Windows configured manually, without Arc | `EntraToken(token)`: a token for `https://database.windows.net/`, or a function that gives one | Azure SQL Database, as its Entra admin |
| **4, token fetched mid-login** | as 3 | `EntraLogin(fetch)`: `fetch(spn, sts_url)` gives a token for the resource the server names | as 3 |

**How each ran, observed** (SQL Server 2022 on Windows; Azure SQL Database):
- **NTLM** takes three messages before the login reply: the client's NEGOTIATE in LOGIN7, the server's CHALLENGE in an SSPI token, and the client's AUTHENTICATE in an SSPI message (`11`).
- **Kerberos** takes two: the client's ticket in LOGIN7, and the server's SSPI token (its mutual-authentication answer). The server sends the login reply immediately after its SSPI token, without waiting. The client sends nothing in between. An empty SSPI message would arrive after the login, and the server would close the connection.
- **A wrong Windows password** is refused with error 18452, “The login is from an untrusted domain”, not 18456.
- **Both federated logins** echo the hello's FEDAUTHREQUIRED. The client asks in the hello, and the server answers. In login 4, Azure SQL's FEDAUTHINFO named a token endpoint and the resource `https://database.windows.net/`.

Logins 2–4 start in the hello. A client choosing between a Windows login and a federated one can ask there whether the server requires federated authentication (FEDAUTHREQUIRED), and the server answers. The server may also send a nonce, which the federated login echoes back. The driver asks whenever the login is a federated one, and echoes the answer and any nonce. The driver uses no Kerberos, NTLM or token library itself; the application gives the tokens (D-55).

### Requests: what a ready connection carries

Each is one [exchange](../1-model.md#vocabulary) on a serial channel, except bulk load, which takes two. Batches, RPCs and transaction-manager requests begin with the headers that carry the current transaction descriptor ([Requests](requests.md#shape)). [Request Response](response.md) describes how the server's response is structured.

| # | Conversation | What it's for | Request (packet type) | What the response adds | Built |
|---|---|---|---|---|---|
| 5 | **SQL batch** | T-SQL text | SQL batch (`01`) | result sets, row counts, messages | **yes** |
| 6 | **Remote procedure call** (RPC) | stored procedures by name, plus built-in procedures by number: parameterized queries (`sp_executesql`, 10), prepared statements (`sp_prepare` 11, `sp_execute` 12, `sp_prepexec` 13, `sp_unprepare` 15), server cursors (1–9). Several calls can share one message. | RPC (`03`) | **output values** (RETURNVALUE) and a **return status** (RETURNSTATUS) | **yes** |
| 7 | **Bulk load** | inserting many rows efficiently; the rows are sent as a stream (D-41) | exchange 1: an `INSERT BULK …` SQL batch (`01`); exchange 2: bulk data (`07`), laid out as COLMETADATA, then ROW tokens, then DONE, as the server would send the same rows, except large values of known length ([Requests](requests.md#edge-cases)) | row counts | **yes** (D-50) |
| 8 | **Transaction-manager request** | transactions controlled through the protocol rather than SQL: begin, commit, roll back, savepoint, and the distributed-transaction operations (get coordinator address, enlist, promote) | transaction manager (`0E`) | announcements of the new transaction state (ENVCHANGE); the coordinator's address as one row | **yes** (D-51) |

### Control: interrupting an exchange

| # | Conversation | How it runs | Built |
|---|---|---|---|
| 9 | **Cancel** | While a response is open, the client sends an Attention message (`06`, header only), then reads and discards everything except SESSIONSTATE, up to the DONE marked *cancel acknowledged*. If the request was only partly sent, the client instead sends its next packet with the *ignore* and *last* flags. The server answers with a DONE marked *error*. | **yes** |

## Rules

- **Connecting happens once per connection;** requests and cancels follow on its serial channels.
- **A request conversation is one exchange,** except bulk load, which takes two. So every application operation is built on the same step (D-33).
- **Cancel is not a request.** It doesn't open an exchange; it ends the one in progress.

## Example

[Worked Example](../2-example-login.md) traces conversation 1 byte by byte. The Python client's command-line tool runs 1 and then 5 (`uv run tds --trust-server-certificate`, from `clients/python`).

## Edge cases

- **TDS 7.4 vs 8.0:** every conversation exists in both. Only *when TLS starts* differs.
- **Not conversations, although they can seem to be:**
  - **MARS sessions:** framing beneath packets, defined in a separate specification (MC-SMP).
  - **Connection reset:** a flag on the next request's first packet.
  - **Packet-size change:** an announcement inside the login reply.
- **Legacy variant:** bulk load also has an `UPDATETEXT`/`WRITETEXT BULK` form for the old text and image types.
- **Several calls in one RPC message** are separated by a marker: BATCH (run the call before it) or NO-EXEC (don't run the call before it; the server returns an error for it and continues). The driver uses only BATCH (D-40).
- **Large values in any request** can be sent in chunks without knowing their length in advance (PLP), and bulk load's rows are a stream. Both are streamed requests (D-41), and both are built.

---

**Source:** MS-TDS §3.1.5 (figures 3–9), §3.2.5, §2.2.1, §2.2.6.1–§2.2.6.9, §2.2.7.12, §2.2.7.22, §4.19
