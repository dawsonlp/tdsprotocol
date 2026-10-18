# A · The Client

**Where this sits:** the model's second and third expressions: how the code is built, and what the running client shows.
**After reading this you can** name the client's parts, say what each may and may not do, and predict what happens when code misuses a serial channel.

Each section is marked with its status from [Decisions](4-decisions.md). Code below is **notation, not a chosen language**.

---

## 0 · The driver and the layers around it · *agreed, D-39*

```
application
   │
outer layers        statements (parameterized, prepared, cursors) · Python values → SQL types
                    · conveniences · DB-API            ← built only on the driver's public surface
   │
the driver          connections and the pool · serial channels · exchange → response
                    · Batch · Call (any procedure, typed parameters) · cancel · session state
   │
TDS · TLS · TCP
```

**The driver represents SQL Server as TDS exposes it, as clearly and simply as possible.** Its requests are the protocol's own: the [nine conversations](3-reference/conversations.md). Anything shaped by what an application wants (statements, prepared queries, cursors, type inference, conveniences, DB-API) is built in a layer around the driver and uses only its public surface. Building them there adds no round trips. Prepared statements and cursors, for example, are calls to built-in procedures.

## 1 · Two kinds of code · *agreed, D-27*

| | **Teaching surfaces** | **Machinery** |
|---|---|---|
| What | **Definitions** (what the bytes are), **procedures** (how conversations go), **observability output** (what the client shows) | The generic engine: encode/decode, framing, I/O, buffering, scheduling |
| Standard | Reads as plainly as the reference docs | As sophisticated as needed, but small, with written invariants, and fuzzed |
| Holds protocol knowledge | **All of it**: every tag, field, limit and policy decision | **None**: no tag values, field names or message types |

The surfaces serve three readers:
- **A security analyst** reads the definitions to see everything the client accepts: fields, size limits, redacted fields. The analyst reads the procedures to see every security decision: encryption, certificate, version, routing. The engine is reviewed separately for bounds safety, which is centralized there.
- **A new developer** finds each surface mirrored one-to-one by a docs page: the same names, the same order, and a link to it. MS-TDS is only needed to cross-check.
- **A maintainer facing a new MS-TDS release** matches the release's Change Tracking table against the MS-TDS section each surface element carries. That gives exactly what must change. A change that reaches the machinery means a new *kind* of structure has arrived.

**A definition** reads like its reference table:

```
token LoginAck  tag AD  length u16                -- Reference: login-response.md · MS-TDS §2.2.7.14
  interface       u8 as Interface { default 0 · t-sql 1 }
  tds version     4 bytes as TdsVersion
  server program  short text
  server version  major u8 · minor u8 · build u16be
  summary: "LOGINACK {server program} · TDS {tds version}"
```

**A procedure** reads like its reference page. Each `yield` gives an action to the shell (§2). The shell performs the action and returns the result:

```
connect(target, credentials)                       -- Reference: connect.md
  if target is 8.0:  yield StartTls(alpn = "tds/8.0")
  reply = yield Exchange(Hello(encryption = on))
  require reply.instance is match                  "reached the wrong server instance"
  require reply.encryption gives full encryption   "server won't encrypt the connection"   -- D-10
  if target is 7.4:  yield StartTls(inside = hello packets)
  login = yield Exchange(Login(credentials))
  require login.ack                                "login rejected: {login.errors}"
  require login.ack.tds version is 7.4             "server speaks TDS {version}; 7.4 or later required"
  session.apply(login.announcements)
  if login.routing:  return Routed(login.routing)                                         -- D-11
  return Ready
```

## 2 · Core and shells · *agreed, D-24, D-32*

```
client code ──► serial channels ──► CORE ◄──── bytes, time ────► SHELL ◄────► network
                                    pure protocol, TLS in memory   sockets, clock, tasks
```

| **Core**: never touches I/O | **Shell**: moves bytes and time, nothing else |
|---|---|
| Definitions and the codec · packet and MARS framing · procedures · session state · ownership rules · observation · TLS, run in memory (D-32) | Sockets · clock and timers · identifying the current task or thread · scheduling |

- **Shell → core:** bytes arrived · TLS output · deadline reached · client calls (open, send, read, cancel, close), each tagged with the caller's owner.
- **Core → shell:** send bytes · feed TLS · start TLS · set a deadline · deliver rows, results, errors or announcements to a channel · close.

Benefits:
- Procedures read as pure protocol.
- Every byte crosses one boundary, so observation happens at a single point.
- Replay is another shell, fed saved bytes, so its view is always identical to the live view.
- Tests are shells too.
- One core serves an async shell and a sync shell (for DB-API).

Costs:
- Rows must be delivered in batches to keep per-row overhead low.
- Backpressure must be part of the design. The core never buffers without limit.
- There are two thin shells to test.

## 3 · Connections and serial channels · *agreed, D-17–D-23, D-36*

```
pool                  lends whole connections, each to one borrower at a time (D-36)
 └─ connection        a session: its own login, transaction and settings; runs in parallel with other connections
     └─ serial channel   one exchange at a time; with MARS, several that take turns and share this connection's session
         └─ exchange      one request and its complete response
```

The connection manager sets up every connection and is the only code that knows TLS versions and MARS (D-17). An application gets connections in one of two ways:

```python
connection = await tds.connect(…)        # one connection, yours until you close it
async with pool.connection() as connection:  # borrowed whole: yours alone until the block ends
    async with connection.serial_channel() as channel:
        ...
```

**A pool lends connections, never channels.** A borrowed connection is its borrower's session alone. If the borrower uses MARS, every extra channel it opens is on *its own* session, for its own interleaving. Unrelated borrowers never share a transaction or settings.

**Requests are made only on a serial channel.** Neither the pool nor the connection makes requests itself (D-36).

| When the pool… | …this happens |
|---|---|
| is asked for a connection | lends an idle one, or opens a new one if the pool is below its size limit; otherwise waits until one is returned |
| gets a connection back | resets its session before lending it again. The reset flag is set on the next request's first packet, and the client's session state returns to what login established |
| gets a connection back with a request still in progress | closes it and never lends it again, because its next borrower would read another borrower's response |

Per MS-TDS, a session reset doesn't reset distributed transactions or the isolation level (§2.2.3.1.2). A connection's session id (from the packet header) identifies its session while the session exists. SQL Server reuses ids after a session ends, so a new connection can get the id of a closed one.

The Python client follows D-21: every serial channel is **owned by the task that opened it** and **closes when its block ends**. The [Rust proposal](D-rust-development.md#1--ownership-and-permissions-come-first) uses unique movable authority instead of task identity (D-64); its core move/borrow and awaited cleanup contracts are agreed.

| When client code… | …this happens |
|---|---|
| opens a second serial channel without MARS | fails immediately. The open channel and the connection are unaffected (D-20) |
| starts a request while a response is still open | fails immediately; never queued (D-22) |
| uses a serial channel from another task | fails immediately, every time (D-21) |
| cancels or closes from another task | allowed (D-23) |
| hands a serial channel to another task explicitly | allowed; ownership moves (D-21) |
| leaves the channel's block | channel authority is revoked; an active exchange is canceled/drained before release (D-21) |
| hits a fatal error on any channel | every channel on the connection fails with that error (D-17) |
| receives an announcement on any channel | the connection's shared session state is updated (D-17) |

Channel close revokes authority for one lifetime. If an exchange is active, close
cancels and drains through acknowledgement **and its message boundary**, within a
separate total cleanup budget (default 5 seconds). Failure or canceled cleanup
discards the connection. Repeated close calls share the first deadline; stale
controls cannot close a replacement. A plain channel's local lifetime id is not
a fixed wire id. Closing does not promise rollback. A pool can reuse a connection
after this cleanup is proved; an unresolved abandoned exchange still forces discard.

MARS exists for one pattern: reading one result while making other requests on the same connection.

```
with connection.serial_channel() as orders, connection.serial_channel() as lookups:   # the second needs MARS
  for row in orders.exchange("SELECT … FROM orders"):
    detail = lookups.exchange("SELECT … WHERE id = @id", id = row.id)
```

## 4 · Exchanges and responses · *agreed, D-33, D-34*

An **exchange** is one turn in the conversation on a serial channel: the client sends one request, then reads the server's response to its end. Every operation an application performs is built on it (D-33):

```
response = await channel.exchange(request)    always the same: send the request, return the open response
```

`exchange` and the response reader never branch on the kind of operation. What differs is in the request definitions (what is sent) and the conveniences (which parts of the response they keep).

### What a request can be

The driver's requests are the protocol's own (D-39):

| Request | What it sends | Decision |
|---|---|---|
| `Batch` | SQL text | — |
| `Call` / `Calls` | one RPC, or several in one message: a procedure by name or built-in number, with explicitly typed parameters | D-40 |
| `BulkInsert`, then `BulkRows` | bulk load: the application's `INSERT BULK` statement, then the columns and rows; the channel keeps the pair together | D-50 |
| `tds.transactions`: `Begin`, `Commit`, `Rollback`, `Save`, `Promote`, `Propagate`, `CoordinatorAddress` | transaction-manager requests | D-51 |

Cancel isn't a request: it ends the exchange in progress ([Conversations](3-reference/conversations.md) #9).

**Requests are built whole before sending,** except where only streaming makes the request practical. **Large values** (`…(max)`, `xml`), a table parameter's rows and **bulk load** rows can be sent as a stream, produced while being sent (D-41). If a stream's source fails partway, the driver abandons the whole request with the packet's *ignore* flag. The server runs nothing and says so. The driver reads that answer, so that the channel is clean, then raises the source's error. Nothing ever runs partially, so the driver doesn't need TDS's NO-EXEC separator (D-40).

### What a response holds · *D-42*

A response is **the record of what the server did**: one ordered sequence of items, one per server token, exactly as they arrived. The server marks its structure by where certain tokens fall ([Request Response](3-reference/response.md)). The driver shows that structure and builds no tree the server didn't send.

| Item | From | What it says |
|---|---|---|
| `ResultSet` | COLMETADATA, then ROW / NBCROW, ORDER; TABNAME, COLINFO, DATACLASSIFICATION, ALTMETADATA, ALTROW | columns, then rows (plain tuples), its sort order if sent, and the completion that closed it. Where sent: where its columns came from (`tables`, `column_info`: browse mode and server cursors), its `classification`, and `COMPUTE` totals (`totals`, `total_rows`) |
| `Completion` | DONE · DONEINPROC · DONEPROC | a statement ended (in a batch, or inside a procedure), or an outermost procedure call ended, with its count when the server gives one |
| `Message` | INFO | `PRINT`, a low-severity `RAISERROR`, a warning |
| `Error` | ERROR | a statement failed |
| `ReturnStatus` | RETURNSTATUS | a call's `RETURN` value |
| `OutputValue` | RETURNVALUE | an output parameter, or a function's result |
| `Announcement` | ENVCHANGE | a session setting changed; the session state is updated too |
| `SessionState` | SESSIONSTATE | the session's state, for recovering it, when the login asked for session recovery |

**Views.** Each is defined by one token rule, never by what was requested (D-33):

| View | Rule | Readable |
|---|---|---|
| result sets | COLMETADATA opens one; the next completion closes it | by iterating the response |
| `response.completions` | every DONE, DONEINPROC and DONEPROC | as far as the response has been read |
| `response.messages`, `response.errors` | every INFO; every ERROR | as far as read |
| `returns()` | one `Return` per DONEPROC: the RETURNSTATUS and RETURNVALUEs before it | at the end; `unread` decides |
| `response.sequence` | everything, in order | as far as read |

```python
Completion(kind, rows, status, statement)
    kind        STATEMENT · STATEMENT_IN_PROCEDURE · CALL       # DONE · DONEINPROC · DONEPROC
    rows        an int, or None when the server says the count isn't valid (SET NOCOUNT ON, an error)
    status      the DONE flags: MORE · ERROR · IN_TRANSACTION · COUNT · ATTENTION · SERVER_ERROR
    statement   the server's statement code, raw: 193 SELECT, 195 INSERT, … (MS-TDS doesn't define them)

Return(status, outputs, function_result, failed)
    status      the RETURN value, or None if the call never reached RETURN
    outputs     by ordinal (the parameter's position in the call, from 0) and by name
    failed      the call's DONEPROC is marked error
```

### Reading a response

A response is read **incrementally** as packets arrive, and **forward-only**: nothing later in it exists on the client until what comes before has been read.

```python
async with await channel.exchange(request) as response:
    async for result_set in response:           # each result set as it starts arriving
        result_set.columns                      # its columns come first
        async for row in result_set:            # then its rows: plain tuples
            ...
        result_set.completion                   # the completion that closed it: count and flags
    returns = await response.returns(unread=Unread.KEEP)   # one entry per call the server completed
```

| To | Use | Unread items |
|---|---|---|
| move forward | iterate the response, then each result set | moving to the next result set **discards** the current one's unread rows |
| read everything | `await response.fetch()` | **kept**: returns a `FetchedResponse` (below) |
| read to the end | `await response.finish()` | rows **discarded**; everything else kept |
| see how it starts | `await response.peek()` | nothing consumed: the record's first item, once it has arrived (tds.encryption uses it to see a refusal, D-60) |
| stop | `await response.close()` by the owner, or leave the `async with` block early | **abandoned**: the request is canceled, and the driver reads to the server's acknowledgement ([Conversations](3-reference/conversations.md) #9) |
| stop it from another task | `response.cancel()`, from any task (D-23) | sends Attention and returns immediately; the owner's next read raises `Cancelled` |
| read large values as they arrive | `result_set.streamed()` (below) | value by value; moving to the next value **discards** the unread rest of a large one |

### Live and fetched responses

`fetch()` returns a `FetchedResponse`: **a specialization of the response, backed by memory instead of the stream.** It reads exactly as a live response does, so code written for one works on the other, and it adds what memory makes possible:

| | Live response (backed by the stream) | `FetchedResponse` (backed by memory) |
|---|---|---|
| Holds the serial channel | yes, until it ends | no: `fetch()` freed it |
| `returns()` | `unread` decides | always available |
| Read again, or step back | no: forward-only | **yes** |
| Index directly, for example result set 2, row 10 | no | **yes** |

The extra abilities exist only on the specialization, so code that relies on them says so by the type it asks for.

**`returns()` is the one end-of-response item.** A call's returns come just before its DONEPROC, so they can't be read until the response has been read that far. It gives one entry per call the server completed. The driver offers no single-call shortcut, but an outer layer can offer one (D-39, D-40). It takes `unread`, an enumerated type that says what happens to anything not yet read:

| `Unread.` | If the item hasn't arrived yet |
|---|---|
| `REFUSE` (default) | raise an error that names the options |
| `KEEP` | read ahead, keeping everything, as `fetch()` does |
| `DISCARD` | read ahead, skipping rows, as `finish()` does |

**Rules:**
- **An open response holds its serial channel** (D-22). The channel is free once the response has been read to its end, finished, closed, or canceled and acknowledged.
- **A result set that the reader has moved past can't be read again.** It still says how many rows arrived. Reading its rows raises an error that points to `fetch()`.
- **Completions, messages and errors are collected as they pass,** so they're always readable as far as the response has been read.
- **Errors are raised at the end of the response,** by whichever call reaches it (`async for`, `fetch()`, `finish()` or `returns()`). The `ServerError` holds the errors and the whole record as a `FetchedResponse`:
  - every result set's columns, completion and row total, with its rows wherever they were kept;
  - every message, error and return, in order.
- **Its message is literate (D-53):** every field the server sent for each error, in SQL Server's own form, with what its level means ([Request Response › Severity](3-reference/response.md#severity)), and what else the driver knows:

  ```
  SQL Server reported 1 error for the 2 calls (shop.update_prices, shop.update_prices):

    Error · Msg 8060, Level 16, State 1, Line 1 · server lpdtest1 · an error the user can correct
    The incoming tabular data stream (TDS) remote procedure call (RPC) protocol stream is incorrect. …
    (in call 2 of 2: shop.update_prices)

  Then: the response ended.
  ```

  The messages that came with the errors are listed in order, and *Then* says what the server did next: the announcements it made, such as a rollback, and whether it continued.
- **A value the driver refuses** (D-48) says where it was: `the call to shop.update_prices › parameter @changes (shop.pc) › row 2 › column 2 (decimal(10, 2)): …`. This applies whether the value was refused before sending, while encoding, or while a source was producing it.

  The channel is already free when the error reaches the application, and the record is the same at every observability level.
- **A canceled response raises `Cancelled`** in the owner's next read. The server's acknowledgement is in the record: a completion marked *acknowledges a cancel*.
- **A response dropped while still open raises a `ResourceWarning`,** in the same way Python warns about an unclosed file.

### Large values · *agreed, D-47*

On the wire, a row is its values in column order, and a large value (the `(max)` types, `xml`, `text`, `ntext`, `image`) is chunks of unknown total length. A 1 GB value has to be read, or skipped, before the next column exists. So a result set can be read in two ways, both forward-only:

```python
async for row in result_set:                    # tuples: every value whole, large ones too
    ...

async for row in result_set.streamed():         # value by value, in column order
    async for value in row:
        if isinstance(value, tds.ValueStream):  # a large value, as it arrives
            async for piece in value:           # bytes, or str for text and xml
                sink.write(piece)
```

- **Tuples are the common case.** They hold large values whole, in memory. An application that wants to limit memory reads with `streamed()` instead. `fetch()` and `Unread.KEEP` also keep them whole.
- **A `ValueStream`** is readable while its row is current, and only once. Moving to the next value discards what is unread.
- **A result set with large values waits at its first row** until the application chooses how to read it: tuples, `streamed()`, `fetch()`, or moving to the next result set. Nothing is held whole, or streamed, before the application has said which.
- **Text is decoded as it arrives,** with the column's collation, and never split inside a character.
- **Sending works the same way** (D-41). A parameter's value can be whole (`bytes` or `str`), or a **source**: an async iterator whose pieces the driver sends as the iterator produces them, in a `Call` or in `Calls`:

  ```python
  Call("shop.set_photo", Param("@id", types.int, 7), Param("@photo", types.varbinary(types.MAX), file_chunks()))
  ```

  If the source fails, a chunk doesn't fit, or the task is canceled while sending, the whole request is abandoned. Nothing runs, the channel is free again, and the original error is raised.
- **Large values need the ODBC flag,** which is on by default (D-9). With `odbc=False` the server truncates them to 4,096 bytes before sending, and the driver shows what it sent.

### The serial channel's conveniences · *agreed, D-37: a layer around the driver, built in M16*

Each is one exchange plus a way of reading its response:

| Convenience | Sends | Returns |
|---|---|---|
| `exchange(request)` | any request: the primitive | live `Response` |
| `query(sql, **params)` | SQL | live `Response` |
| `fetch(sql, **params)` | SQL, read to the end | `FetchedResponse` |
| `fetch_value(sql, **params)` | SQL, expecting exactly one value | the value |
| `call(procedure, **params)` | a stored procedure call | `FetchedResponse`, with outputs and return status |
| `prepare(sql, **types)` | a prepare request, once | `PreparedStatement`, with the same `query` / `fetch` / `fetch_value` |
| `describe(sql)` | a shape request; nothing runs | columns |
| `transaction()` | begin, then commit or roll back | async context manager |

**Shortcuts check their shape.**
- `fetch_value` refuses anything but exactly one row and one column, and says what came back.
- `FetchedResponse.rows` exists only when there was exactly one result set; otherwise it says how many there were.

**There are no aliases:** one name per behavior.

## 5 · How outer layers read a response · *agreed, D-42*

The driver delivers the record of what the server did and never interprets it. An outer layer adds meaning, because only it knows what it sent: the SQL text and the calls. This section is the contract between them: what the structure guarantees, and how to answer common questions with it.

**What the structure guarantees** ([Request Response › Rules](3-reference/response.md#rules)):
- **Every result set** has its columns first and ends with a completion, which carries its count.
- **Completions arrive in statement order.** Each statement produces at most one.
- **Each DONEPROC ends exactly one outermost procedure call.** That call's return status and outputs come just before it.
- **The response ends** at the completion whose *more follows* bit is clear.
- **Messages and errors sit where the server sent them.**

**Common questions**

| An outer layer asks | It reads | The reality to expect |
|---|---|---|
| How many rows did my `UPDATE` change? | the statement's completion: `rows` | `None` under `SET NOCOUNT ON` or after an error. DB-API's `rowcount = -1` means exactly this. |
| Which completion belongs to which of my statements? | `response.completions` in order, against the SQL it sent | A declaration without an initial value produces none. `SET` options, `PRINT` and `RAISERROR` produce one without a count. Assignments and `RETURN` count 1. A nested `EXEC` adds one, with code 224. Only the layer that wrote the SQL can match them. Sending one statement per request makes this simple. |
| Did each of my calls run? | `returns()`, against the calls it sent | A refused call has an entry with `failed` set and `status` `None`. A call after a batch-ending error has no entry. Fewer entries than calls means the request stopped there, and the `ServerError` says why. |
| Where are my output values? | `returns()[i].outputs`, by ordinal or name | They exist only for RPC parameters with `output=True`. In a SQL batch, outputs go into T-SQL variables, which the SQL must `SELECT`. |
| Which messages came with which result set? | `response.sequence` | Messages sit where the server sent them, between result sets or among their rows. |
| Can I trust these rows? | `result_set.completion.status` | `ERROR`: the statement failed after its columns were sent. `SERVER_ERROR`: the server asks for the rows to be discarded, and a streaming reader may already have used them. |
| Is a transaction open? | the session state, kept current by announcements, and each completion's `IN_TRANSACTION` flag | — |
| Is this an error or a warning? | `Error` or `Message`, with the severity the server reported | Session settings decide. Division by zero is a message with ANSI_WARNINGS off (the driver's sessions, D-9) and an error with it on. `RAISERROR` at severity 10 arrives as severity 0. |

**For example, DB-API.** This is one way a DB-API layer could be built on the record, to show that the record is enough. The DB-API layer's own policies are decided later.

| DB-API | Built from |
|---|---|
| `cursor.execute(sql, params)` | `Call(Builtin.SP_EXECUTESQL, …)`, with SQL types inferred by the outer layer |
| `cursor.description` | the current `result_set.columns` |
| `fetchone()` · `fetchmany()` · `fetchall()` | iterating the current result set |
| `cursor.nextset()` | moving to the next result set |
| `cursor.rowcount` | the relevant completion's `rows`, or −1 when it's `None` |
| `cursor.callproc(name, params)` | `Call(name, …)`, then `returns()[0].outputs` |
| warnings | `response.messages` |

## 6 · What the running client shows · *agreed, D-12*

These examples use the [Worked Example](2-example-login.md)'s data (TDS 7.2, MARS on). The timings and TLS details are invented.

**outline** shows one line per message:

```
connect sales-db:1433 · ready in 41 ms
  → hello            47 B   encryption on · MARS on
  ← hello reply      43 B   server 16.0.1000 · encryption on
  ⇄ secure           TLS 1.2 · 4 records
  → log in          144 B   user sa · app OSQL-32
  ← login reply     353 B   8 tokens · LOGINACK Microsoft SQL Server · TDS 7.2
```

**full** opens a message, then a token:

```
  ← login reply     353 B
      ENVCHANGE   database master → master                    login-response.md · @000
        tag         E3                         ENVCHANGE
        length      1B 00                      27 bytes follow
        kind        01                         database
        new value   06 6D 00 61 00 73 00 …     "master"
        old value   06 6D 00 61 00 73 00 …     "master"
      INFO        5701  Changed database context to 'master'.
      …
      LOGINACK    Microsoft SQL Server · TDS 7.2
      DONE        final · 0 rows
```

**off** (optimized):

```
connect sales-db:1433 · ready in 39 ms
```

Every line is generated from the definitions; nothing is labeled separately for display.

**How it works** (D-12):
- **The observer says how much it wants.** `connect(observe=Printer(Level.FULL))`, or any callable with a `level`; a plain callable counts as full, and none is off. Off builds no events and no inspection trees: the optimized mode. Outline builds one line per step, message and change. Full also keeps every message's tree.
- **It can change between exchanges:** `connection.observe = Printer(Level.FULL)` starts observing a pooled connection that is already open. During an exchange the change is refused, because a request described at one level must have its response read at the same level.
- **Every byte is reachable:** `event.node.find("login reply", "LOGINACK", "tds version")`. Each structure in the full view names the reference page that explains it. Large values are summarized (D-47).
- **Timing:**
  - Each connect step shows its time since connecting began: `● hello · at 24 ms`.
  - Each response shows the time from sending to its first packet (roughly, how long the server took before answering) and to its end: `← response · … · first packet 12 ms · done 40 ms`.
  - The durations are shown at the end of the line, separate from its text. A capture records them.
  - A capture's first line records the wall-clock start.
  - `response.timing` gives applications the same: `sent`, `first_packet`, `ended`, `until_first_packet`, `until_end`. It's collected at every level.
- **Captures and replay:**
  - `capture=Capture("session.jsonl")`, or `connection.capture` between exchanges, records every event's line and every plaintext packet, with times;
  - `replay("session.jsonl", Printer(Level.FULL))` decodes the packets with the same definitions and shows the identical view;
  - the login's password is zeroed unless `keep_password=True`;
  - query text and data stay;
  - saved table inputs retain their declaration, default columns, ordering hints, placement and exact rows. They are input evidence, not result cells;
  - Rust's offline reader and CLI inspect the same recordings. [Design K](K-offline-replay.md) defines its evidence boundaries and remaining inspection/timing work.
- **The password stays hidden at full** unless an observer reveals it for the sessions it watches: `Printer(…, reveal_password=True)`.
- **Diagnostic output failure:** an optional observer that raises is disabled;
  database work and any recording continue. Its exception is available separately
  as `connection.observation_error`, cleared when an observer is installed.
  Pool callbacks follow the same policy (`pool.observation_error`). The current
  decoding mode remains unchanged until explicitly reconfigured. Saved-recording
  failure instead raises `tds.CaptureError`, retains its writer `cause`, closes
  the connection and wakes waiters. Each line is flushed to detect buffered write
  failures; this is not a disk-durability guarantee. Recovery cannot resume an
  incomplete recording. Sent SQL may have executed; closing does not prove rollback.

**Recording ownership:** one recording belongs permanently to one physical
connection. `Capture` rejects attachment to a different physical lifetime, even
after detachment/close. Pools require `capture_factory`, a callable returning a
new Capture with a distinct output for every opened connection. Reusing that
connection across loans keeps its recording. Connect also accepts the factory
for separate recordings when routing or recovery opens a new connection. A direct
capture refuses those transitions. The application owns/closes its Python capture
resources. This keeps the existing format, which has channel ids but no connection
ids, independently replayable. Rust moves one non-Clone Capture into each driver
and uses the same factory rule (Rust plan, section 8).

**Still to design** (carried over from the earlier draft):
- views: annotated hex dump, JSON
- TLS key-log export, so Wireshark can cross-check the decoding
- partial decoding that shows exactly where a malformed message broke
- linking errors and announcements to the exchange that caused them
