# Request Response

**Where this sits:** message › **body**, a token stream › token. It is what the server sends back for a SQL batch or an RPC.
**Use this page to** find where each statement, result set and procedure call begins and ends in a response, and what every token in it means.

## Purpose

A response is one token stream, and it is flat: no token encloses another. Certain tokens mark its structure by their position. Four structures matter, and each one has a mark. Messages, errors and announcements appear where they happened.

## Shape

| Structure | Starts | Ends |
|---|---|---|
| **response** | at its first token | at the completion whose *more follows* bit is clear |
| **statement** | after the previous completion | at a **completion**: DONE in a batch, DONEINPROC inside a procedure |
| **result set** | at COLMETADATA | at the next completion, which carries its count |
| **procedure call**, outermost only | after the previous call ended | at RETURNSTATUS, then a RETURNVALUE for each output, then DONEPROC |

A *completion* is any of the three DONE tokens.

```
DECLARE @t …; INSERT 3 rows; SELECT; EXEC p; SELECT 9

  DONE        count 3                               the INSERT (DECLARE sends nothing)
  COLMETADATA  ROW ROW ROW  DONE count 3            the SELECT, with its result set
  DONEINPROC … DONEINPROC  RETURNSTATUS  DONEPROC   the statements inside p, then p's end
  COLMETADATA  ROW  DONE count 1 (final)            the last SELECT, and the end of the response
```

**The tokens**

| Tag | Token | Means | Fields |
|---|---|---|---|
| `81` | COLMETADATA | a result set begins: its columns | count, then each column: user type, flags, type, name. A count of `FFFF` means no columns follow, because the call asked for no metadata. Once column encryption is agreed, a key table follows the count, and an encrypted column has crypto metadata before its name ([Always Encrypted](always-encrypted.md)). |
| `A9` | ORDER | the result set is sorted on these columns | column numbers |
| `D1` | ROW | one row | each column's value, laid out as COLMETADATA says |
| `D2` | NBCROW | one row, with its NULLs in a bitmap | a null bitmap, then the non-null values |
| `AB` | INFO | a message: `PRINT`, a low-severity `RAISERROR`, a warning | number, state, severity, text, server, procedure, line |
| `AA` | ERROR | a statement failed | the same fields as INFO |
| `E3` | ENVCHANGE | a session setting changed | kind, new value, old value ([Login Response](login-response.md)) |
| `A4` | TABNAME | the base tables of the result set's columns (browse mode, server cursors) | each table's name, in parts |
| `A5` | COLINFO | where each column came from | each column: its number, its table in TABNAME (0 for an expression), status (`04` expression · `08` key · `10` hidden · `20` different name), and the base column's name when it differs |
| `A3` | DATACLASSIFICATION | the result set's data classification, when the login asked for it | sensitivity labels and information types (name, id), then each column's sensitivities; ranks from version 2 |
| `88` `D3` | ALTMETADATA, ALTROW | `COMPUTE` totals and their rows | deprecated in TDS 7.4; SQL Server no longer sends them |
| `E4` | SESSIONSTATE | the session's state, for recovering it, when the login asked for session recovery | sequence number, recoverable, then each state's id and value |
| `79` | RETURNSTATUS | the procedure's `RETURN` value | i32 |
| `AC` | RETURNVALUE | an output parameter's value, or a function's result | ordinal, name, status (`01` output · `02` function result), user type, flags, type, [crypto metadata, when encrypted: [Always Encrypted](always-encrypted.md)], value |
| `FD` | DONE | a statement in a batch ended | status, statement code, row count |
| `FF` | DONEINPROC | a statement inside a procedure ended | the same |
| `FE` | DONEPROC | an outermost procedure call ended | the same |

**Completion fields**

| Field | Size | Meaning |
|---|---|---|
| status | u16 | bits: `01` more follows · `02` error · `04` in a transaction · `10` count is valid · `20` acknowledges a cancel · `80` one of several calls (on every DONEPROC but the last) · `100` server error: discard this result set |
| statement code | u16 | the kind of statement, as a number the server chooses. MS-TDS leaves the values to the server. |
| row count | u64 | rows affected or returned; meaningful only when *count is valid* is set |

### Transaction announcements

ENVCHANGE kinds that come in responses. Each value is bytes with a u8 length; the descriptor is 8 bytes.

| Kind | Announces | New value | Old value |
|---|---|---|---|
| 8 | a transaction began | its descriptor | empty |
| 9 | the transaction committed | empty | its descriptor |
| 10 | the transaction rolled back | empty | its descriptor |
| 11 | enlisted in a distributed transaction | empty | the descriptor (per MS-TDS; not observed) |
| 12 | defected from a distributed transaction | the descriptor | empty (per MS-TDS; not observed) |
| 15 | the transaction was promoted | the coordinator's token: bytes with a **u32** length | empty |
| 16 | the coordinator's address | MS-TDS says it isn't used | |
| 17 | the transaction ended | empty | the descriptor (per MS-TDS; not observed) |
| 18 | the session was reset ([Packet](packet.md)) | empty | empty |

**The driver keeps the session's descriptor from the new value:** a non-empty value is the descriptor, and an empty value means no transaction. Every request carries it in its headers ([Requests](requests.md#shape)). Only the outermost transaction is announced.

### Severity

An INFO or ERROR's severity (MS-TDS calls it *class*) says what kind of problem it is. MS-TDS leaves the meanings to the server; Microsoft's "Database Engine error severities" gives them. A `ServerError` shows the severity's meaning after its level (D-53).

| Level | Means |
|---|---|
| 0–10 | information. The server sends 10 as 0. |
| 11–16 | errors the user can correct: 11 an object doesn't exist · 12 a query that takes no locks may have read inconsistent data · 13 a deadlock · 14 security, such as permission denied · 15 syntax · 16 general |
| 17–19 | for the administrator: 17 out of resources, or a limit the administrator set · 18 a problem in the server's software; the statement completed · 19 a server limit was exceeded; the batch stopped |
| 20–24 | fatal: the task running the statement ends, and in most cases the connection may end too · 20 a problem with the statement · 21 a problem affecting the whole database · 22 a damaged table or index · 23 the database's integrity is in doubt · 24 a media failure |
| 25 | fatal; `RAISERROR` can raise it |

## Rules

- **Every statement ends with a completion, except a declaration without an initial value.** `SET` options, `PRINT` and `RAISERROR` end with one that carries no count.
- **A count is valid only when its bit says so.** Under `SET NOCOUNT ON` the completions still arrive, with the bit clear. No count is not the same as a count of 0.
- **A result set's count comes after its rows,** in the completion that closes it. An empty result set still sends its columns and a count of 0.
- **Only the outermost procedure call ends with DONEPROC,** preceded by its RETURNSTATUS and RETURNVALUEs.
  - A procedure it runs ends with a DONEINPROC (statement code 224, no count) and sends no return status or outputs of its own.
  - This is the same whether the call came by RPC or as `EXEC` in a SQL batch.
- **Outputs come back only for parameters passed by reference,** one RETURNVALUE each.
  - The ordinal is the parameter's position in the call, from 0. It counts every parameter, including `sp_executesql`'s `@stmt` and `@params`.
  - Large-object outputs come after all the others.
  - In a SQL batch, output parameters are assigned to T-SQL variables, and no RETURNVALUE is sent.
- **An error appears where it happened,** followed by a completion marked *error*.
  - Whether later statements run depends on the error: some end only their statement, others end the whole batch.
  - *Server error* asks the client to discard that result set's rows.
- **In a request with several calls,** a call can fail in two ways:
  - A call the server refuses before running it ends with DONEPROC marked *error* · *more follows*, and the next call runs.
  - An error that ends the batch ends the whole request: DONEPROC marked *error* · *final*. Later calls don't run and send nothing.
- **A function called as an RPC** sends exactly one RETURNVALUE, marked *function result*, unnamed, at ordinal 0, and no RETURNSTATUS.
- **A cancel is acknowledged** by a completion with *acknowledges a cancel* set ([Conversations](conversations.md) #9).

## Example

Responses observed from SQL Server 2025 (17.0.5015.4). One line per token.

**Counts, with and without a result set**

```
DECLARE @t TABLE (i int); INSERT @t VALUES (1),(2),(3); UPDATE @t SET i = i + 1 WHERE i > 1; SELECT i FROM @t; DELETE @t

  DONE         more · count   3   code 195     INSERT
  DONE         more · count   2   code 197     UPDATE
  COLMETADATA  i int
  ROW          1
  ROW          3
  ROW          4
  DONE         more · count   3   code 193     SELECT
  DONE         count          3   code 196     DELETE, and the end of the response
```

**Errors: one statement fails, then one batch ends**

```
SET ANSI_WARNINGS ON; SELECT 1; SELECT 1 / 0; SELECT 2        SELECT 1; SELECT CAST(N'x' AS int); SELECT 2

  DONE         more              code 185                     COLMETADATA  ROW  DONE more · count 1
  COLMETADATA  ROW  DONE more · count 1                       COLMETADATA  b
  COLMETADATA  b                                              ERROR        245 Conversion failed …
  ERROR        8134 Divide by zero error encountered.         DONE         error · final
  DONE         more · error                                     (SELECT 2 never runs)
  COLMETADATA  ROW  DONE count 1
```

**Two calls in one RPC request, with an output**

```
#bump(@a = 41, by reference)  then  #outer(@o = NULL, by reference), which runs EXEC #bump inside

  COLMETADATA  seen_on_entry        ROW  41                   #bump sees the value sent
  DONEINPROC   ×3
  RETURNSTATUS 7
  RETURNVALUE  ordinal 0 · @a · output · 42
  DONEPROC     more                                           the first call ends
  DONEINPROC   …                    DONEINPROC code 224       the nested #bump ends: no status, no outputs
  COLMETADATA  step                 ROW  outer done
  DONEINPROC   ×2
  RETURNSTATUS 3
  RETURNVALUE  ordinal 0 · @o · output · 101
  DONEPROC     final                                          the second call, and the response, end
```

## Edge cases

**Where SQL Server differs from MS-TDS.** Observed from SQL Server 2025 (17.0.5015).
- **A *promote* announcement's length covers only its kind:** the length is 1, and the token and the empty old value follow outside it ([Token Stream › Edge cases](token-stream.md#edge-cases)).

**What MS-TDS doesn't state.** Observed from SQL Server 2025 (17.0.5015).
- **Browse mode adds columns the query didn't ask for.** `FOR BROWSE` appends each table's key and `rowversion` columns to the result set, and COLINFO marks them *hidden*. The rows carry them too.
- **Browse mode's tokens come with more than `FOR BROWSE`:** under `SET NO_BROWSETABLE ON` (which OLE DB clients use), on an ordinary `SELECT`; and from every kind of server cursor (`sp_cursoropen`). Before M11, each of these ended the connection.
- **Assignments count one row:** `DECLARE @x int = 41`, `SET @x = …`, and `RETURN` inside a procedure each end with a completion carrying count 1 (code 193).
- **`RAISERROR` at severity 10** arrives as INFO with severity 0.
- **ORDER is sent only when the server sorts.** `ORDER BY` over a single constant row sends none.
- **Session settings change what is an error.** A session logged in without the ODBC flag (`odbc=False`; the driver's default is on, D-9) starts with every ANSI option off, ANSI_WARNINGS among them ([Data Types › Edge cases](types.md#edge-cases)). With ANSI_WARNINGS off, division by zero returns NULL plus INFO 3607, and nothing fails. With it on (as the ODBC flag sets it), it is ERROR 8134, and that statement fails.
- **A parameter passed by reference to a parameter not declared `OUTPUT`** is refused with ERROR 8162 before the call runs. A parameter declared `OUTPUT` but passed by value is accepted, and its output isn't returned.
- **Statement codes seen:**

  | Code | Statement |
  |---|---|
  | 193 | `SELECT` |
  | 195 | `INSERT` |
  | 196 | `DELETE` |
  | 197 | `UPDATE` |
  | 185 | `SET … ON` |
  | 186 | `SET … OFF` |
  | 222 | `CREATE PROCEDURE` |
  | 224 | `EXEC` |
  | 246 | `RAISERROR` |
  | 247 | `PRINT` |
  | 253 | an empty batch: no statement at all |

---

**Source:** MS-TDS §2.2.1.6, §2.2.2.4–§2.2.2.9, §2.2.4.3, §2.2.6.6, §2.2.7.1–§2.2.7.9, §2.2.7.15, §2.2.7.17–§2.2.7.21, §2.2.7.23
