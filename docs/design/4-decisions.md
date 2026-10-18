# 4 · Decisions

**Use this page to** see what is settled and what is still a proposal, and to agree or change it.
**Status:** **Agreed** = decided together · **Proposed** = suggested; needs approval · **Open** = needs a decision; a suggestion is offered · **Deferred** = outside this project, kept for whoever builds it.

Each record is short: the decision and why. The explanation lives on the page it links to. Numbers are permanent IDs, so gaps are expected.

---

## Agreed

**D-1 · Documentation approach** · *2026-10-15*
Organize the docs by learning-science principles: Model → Worked Example → Reference → Decisions → Done When. Code and runtime observability use the same model and names.
*Why:* readers learn the overall structure first, then add the details to it. One model expressed three times is learned once.

**D-2 · Protocol versions** · *2026-10-15*
TDS 7.4 and 8.0 only. Login fails with a clear error on anything lower.
*Why:* this covers SQL Server 2012–2025 and Azure SQL, and leaves one message grammar to describe.

**D-3 · Scope order** · *2026-10-15*
Client first; the proxy is on the backlog. Design is agreed before any code, and before choosing a language.

**D-4 · Optimized mode exists** · *2026-10-15*
The client can run without collecting observability data. The levels are D-12.

**D-5 · One documentation set** · *2026-10-15*
`docs/design/` is the single design set. Anything still useful in the earlier SDD spec draft was moved into it, and the draft was removed. The first structure summary, `docs/tds-common-structure.md`, was removed on 2026-10-16, once the Requests and Request Response pages replaced its request-phase content.

**D-17 · The connection manager owns setup and everything shared** · *2026-10-15* · [The Client §3](A-the-client.md#3--connections-and-serial-channels--agreed-d-17d-23-d-36)
The connection manager is the only code that knows the TLS version or whether MARS is in use. It handles TCP, TLS, hello, login and MARS. It also owns everything shared between serial channels: session state, fatal errors, and per-channel buffering under MARS.
*Why:* setup is a different kind of work from requests. Keeping it in one place makes both halves easier to read.

**D-18 · Client code asks for a serial channel; MARS only changes how many** · *2026-10-15*
Client code is identical with or without MARS. Without MARS a connection allows one serial channel; with MARS it allows several, which take turns and share the connection's transaction and settings. Parallel work needs separate connections. The interface's structure makes this plain. MARS changes how many channels a connection offers. It never changes who shares that connection's session (D-36).
*Why:* MARS gives interleaving, not parallelism ([Microsoft](https://learn.microsoft.com/en-us/dotNET/framework/data/adonet/sql/enabling-multiple-active-result-sets)).

**D-19 · The name is `serial_channel`** · *2026-10-15*
*Why:* it states the property that matters: "connections are parallel; serial channels are not". It also avoids confusion with *token stream*.

**D-20 · One serial channel too many fails immediately** · *2026-10-15*
The serial channel already open, and the connection, are unaffected.

**D-21 · Serial channels are handed out, each with one owner** · *2026-10-15*
A serial channel is owned by the task that opened it, scoped to a block, and can be handed to another task explicitly. Use from any other task fails immediately. A synchronous wrapper checks the owning thread instead. This remains the Python contract; D-64 records the user-selected proposal for movable Rust authority.
*Why:* this makes misuse fail every time, not only when calls happen to overlap.
*Rejected:*
- a single switchable pipe, because of its hidden "current channel" mode;
- hand-out without owners, because misuse would depend on timing.

**D-22 · A new request while a response is open fails immediately** · *2026-10-15*
It is never queued. Cancel is the exception.
*Why:* the rule itself is TDS's ([Model, rule 1](1-model.md#rules-that-hold-everywhere)); failing at once keeps misuse visible.

**D-23 · Only the owner sends and reads; anyone may cancel or close** · *2026-10-15*
*Why:* a watchdog, a cancel button, or runtime cleanup may run on another task. Cancel and close are safe to repeat and never interleave with the owner's data.

**D-27 · Teaching surfaces and machinery** · *2026-10-15* · [The Client §1](A-the-client.md#1--two-kinds-of-code--agreed-d-27)
Definitions, procedures and observability output must read as plainly as the reference docs, and they hold all protocol knowledge. The engine holds none; it is small, its invariants are written down, it is fuzzed, and it holds every bounds check. Every surface element carries its MS-TDS section and the spec revision it was checked against.
*Why:* it serves three readers:
- a security analyst can validate the code;
- a new developer can start work without reading MS-TDS;
- a new MS-TDS release's Change Tracking table maps directly onto what must change.

**D-29 · The website is a view, not the record** · *2026-10-15*
`docs/design/` is the system of record. `site/` is a separate deliverable that presents the design interactively. When they disagree, the record is right and the site is fixed to match.

**D-28 · Python first** · *2026-10-15*
The first client is Python (3.14+): async first, with a sync shell for DB-API later. It lives in `clients/python/`.
*Why:* it serves the expected users directly, and its generators and in-memory TLS fit the core/shell split.

**D-24 · A sans-I/O core with a thin shell** · *2026-10-15*
The connection manager is one package of two files: `core.py` holds all protocol logic and never does I/O; `shell.py` (asyncio) owns the socket, the timer and the tasks. Procedures yield actions (send, read, receive); the shell performs them.

**D-31 · MARS is part of the connection manager's core** · *2026-10-15*
MARS framing, sessions and flow control live in `connection/core.py`, not in a separate module. Login happens before MARS framing starts; each serial channel is then one MARS session.
*Why:* MARS is how the connection manager provides serial channels (D-18), so it is core to the design.

**D-33 · One primitive: an exchange** · *2026-10-16*
Every operation an application performs is one exchange in the conversation: the client sends one request, then reads the server's complete response. `channel.exchange(request) → response` is the single primitive, and it is public, documented as the low-level interface. Conveniences (query, fetch, call, prepare, describe, …; D-37) only choose a request and how to read its response.
*Why:* one abstraction for the same kind of thing. A new capability is a new kind of request or a new way of reading a response, never a new mechanism. The channel rules, cancel and observability live in one place.
*Constraint:* `exchange` and the response reader never branch on the kind of operation. Differences live in the request definitions (what is sent) and the conveniences (which parts of the response they keep). A branch on the operation in either place is a design problem to report, not to work around.

**D-34 · Responses stream, forward-only, read through explicit choices** · *2026-10-16, revised the same day* · [The Client §4](A-the-client.md#4--exchanges-and-responses--agreed-d-33-d-34)
- `exchange` always returns the open response, which is read incrementally and forward-only.
- Iterating the response yields result sets; iterating a result set yields rows; moving to the next result set discards the current one's unread rows.
- `fetch()` reads to the end and returns a `FetchedResponse`: a specialization of the response, backed by memory, with the channel already freed. It reads exactly like a live response and adds re-reading and indexing. `finish()` reads to the end, skipping rows.
- **Stopping:** `close()`, by the owner, cancels a response that hasn't ended and reads to the server's acknowledgement. `cancel()` may be called **from any task** (D-23): it sends Attention and returns at once. The owner's next read then raises `Cancelled`, and the channel is free.
- `returns()` is `await`able and takes `unread: Unread` (`REFUSE` by default, `KEEP`, `DISCARD`), because the returns come at the end of the response. It gives one entry per call the server completed (D-42). Completions and messages are read as they pass (D-42). Single-call shortcuts belong to an outer layer (D-39, D-40).
- An open response holds its serial channel. Errors are raised at the end, by whichever call reaches it, carrying the whole record (D-42). A response dropped while open raises a `ResourceWarning`.

*Why:*
- Streaming is the one mechanism; reading everything is a way of using it, not a second mechanism.
- One way to read results, live or fetched: code written for a response works on both.
- Unread items are never kept or discarded silently: each way of moving forward says what happens to them.
- No mode flags on `exchange` (D-33).

**D-35 · Never hide reality; expose it gracefully** · *2026-10-16*
The driver never hides what the protocol and the server actually do. It shows them in a form that is easy to read and use, and stays elegant throughout. Every design choice is checked against two questions: *what reality could this hide?* and *how can it be shown plainly?*
Already applied:
- MARS is shown as taking turns, not parallelism (D-18).
- Misuse fails every time rather than by timing (D-21, D-22).
- Unread items are never kept or discarded silently (D-34).
- Errors arrive with the partial results (D-34).
- A response is the record of what the server did, in order, with no invented structure (D-42).
- Every value read goes back exactly; nothing is rounded or replaced on the way (D-48).
- Observability shows every byte (D-12).
- Observed server behavior that MS-TDS doesn't state is written down (Packet › Edge cases).

**D-36 · Connections are lent whole; requests happen only on a serial channel** · *2026-10-16* · [The Client §3](A-the-client.md#3--connections-and-serial-channels--agreed-d-17d-23-d-36)
- **A pool lends whole connections, exclusively.** A borrowed connection is its borrower's session alone, and serial channels are opened from it with `connection.serial_channel()`. The pool never reaches inside a connection.
- **Giving a connection back resets its session** before anyone else uses it: the reset flag is set on the next request's first packet.
- **A connection given back with a request still in progress is closed, never lent again:** its next borrower would read someone else's response.
- **Neither the pool nor the connection makes requests.** Requests are made only on a serial channel. Convenience methods may be added later if experience shows they're needed. Whether SQL and procedure helpers belong on the connection is an open question.

*Why:*
- A connection is a session: one login, one transaction, one set of settings. Lending MARS channels of a busy connection to unrelated callers would silently share their transactions and settings (D-35).
- A pool that runs SQL is a surprise, because a pool deals in connections. A connection that runs SQL hides the serial channel, the abstraction MARS adds.

*Rejected:*
- lending channels (serial channels of a connection someone else is using);
- lending "channels" that are really exclusive connections under another name;
- shortcut request methods on the pool and the connection.

**D-39 · The driver represents SQL Server as TDS exposes it; application abstractions wrap it** · *2026-10-16* · [The Client §0](A-the-client.md#0--the-driver-and-the-layers-around-it--agreed-d-39)
- **The driver** represents SQL Server's functionality as TDS exposes it, as clearly and simply as possible:
  - connections and the pool, serial channels, exchanges and responses;
  - the protocol's own requests: `Batch`, and `Call` for any procedure, by name or built-in number, with **explicitly typed** parameters;
  - cancel, and the session's state and changes.
- **Application-level abstractions live in layers around the driver** and use only its public surface. That covers: parameterized statements (`sp_executesql`), prepared statements, server cursors, inferring SQL types from Python values, convenience methods, and DB-API.
- **Type inference is outside the driver.**

*Why:* the driver then teaches TDS and nothing else. Each outer layer teaches its own conventions, and is the driver's first real client: if it can't do something through the driver's public surface, the driver is missing something. Composition adds no round trips.

**D-40 · `Call`: an RPC as TDS defines it** · *2026-10-16, revised the same day*
- **`Call(target, *params, options=…)`.** The target is a procedure name or a `tds.Builtin` (an enum of the 15 numbered procedures). `Param(name, type, value, output=False)` mirrors the wire. Parameters are an ordered list; a name may be empty, meaning positional.
- **`output=True` passes the parameter by reference,** TDS's only output mechanism. The value is sent as given (`None` is NULL), and the procedure sees it: SQL Server output parameters are always input too.
- **`tds.types` is one vocabulary of SQL Server types,** declaring parameters and describing columns alike. Values are checked against their declared type before sending, and nothing is inferred. `varchar` is encoded with the session's collation unless it's given one.
- **`tds.DEFAULT`** as a value means "use the procedure's default".
- **`tds.Calls(call, call, …)` sends several calls in one request.** The response's `returns()` gives one entry per call the server completed, in call order: return status, output values keyed by ordinal and name, and a function's return value (D-42). An error that ends the batch ends the request, and the calls after it have no entries. Outputs are matched by ordinal, the parameter's position in the call from 0, because the server moves large outputs to the end. There are no single-call shortcuts in the driver.
- **`CallOptions` flags as TDS defines them:** `RECOMPILE`, `NO_METADATA`, `REUSE_METADATA`. A `NO_METADATA` call must supply the columns from an earlier response, since rows can't be decoded without them; the driver refuses it otherwise.

*Why:* exactly what TDS offers, no more and no less (D-39). Conveniences such as keyword arguments, inferred types and "the only call's outputs" belong to outer layers.
*Rejected:*
- `Direction.IN` / `OUT` / `IN_OUT`. The wire has one *by reference* flag, and SQL Server output parameters are always input too, so *OUT* versus *IN_OUT* only decides whether a library sends NULL for the application. That is a convention for an outer layer.
- the NO-EXEC separator, which tells the server to skip the preceding call in a multi-call request, report an error for it and continue. It exists to withdraw one call a client has already started sending. The driver sends `Calls` only once they are fully built and checked, so it never has a call to withdraw. A streamed request that fails is abandoned whole (D-41), so nothing runs partially.

**D-41 · Streamed requests, for bulk load and large values** · *2026-10-16* · [The Client §4](A-the-client.md#4--exchanges-and-responses--agreed-d-33-d-34)
- **Requests may be sent as a stream**, produced while being sent, where TDS supports it and it matters:
  - **bulk load**, whose data message is a stream of rows;
  - **large values** (`varchar(max)`, `nvarchar(max)`, `varbinary(max)`, `xml`), which TDS can send in chunks without knowing their length in advance (PLP).
- **The abstraction doesn't change.** `exchange(request)` is still the one primitive; a streamed request's values are *sources* (async iterators of chunks or rows) rather than complete values. Encoding becomes incremental, which is a machinery change: full packets are sent as data arrives, and MARS flow control already waits for credit.
- **If a source fails partway, the whole request is abandoned:** the next packet carries the *ignore* and *last* flags, the server runs nothing and answers with a DONE marked *error*, the driver reads that answer so the channel is clean, then raises the source's own error. Observability records the request as abandoned.
- **Sources may be given to any parameter of a `Call`, in `Calls` too** (*amended 2026-10-16*). Abandoning with *ignore* drops the whole message, every call in it, so the request still either happens or doesn't.
- **A whole large value** (`bytes` or `str`) is sent in chunks with its length known; **a source** is sent as it produces, with its length unknown. Each chunk is checked as it is encoded, and a chunk that doesn't fit is refused (D-48).
- **One way to abandon a request mid-send** (*agreed 2026-10-16*): a source fails, a chunk is refused, or the task is canceled while sending. In each case the next packet carries *ignore* + *last*, the driver reads the server's answer so the channel is free, then raises the original error, or `CancelledError`. A canceled task finishes that cleanup before re-raising.
- **Status:** large values are built in M4; bulk load comes later.

*Why:* streaming is what makes bulk load practical and large values affordable. All-or-nothing abandonment makes a failure unambiguous: the request either happened or it didn't.

**D-42 · A response is the record of what the server did; its structure is read through token rules** · *2026-10-16* · [The Client §4](A-the-client.md#4--exchanges-and-responses--agreed-d-33-d-34) · [Request Response](3-reference/response.md)
- **The record.** A response is one ordered sequence of items, one per server token; rows belong to their result set. `response.sequence` holds it as far as it has been read; a `FetchedResponse` and a `ServerError` hold all of it.

  | Item | From |
  |---|---|
  | `ResultSet`: columns, rows, sort order, and the completion that closed it. *Added in M11:* where its columns came from (`tables`, `column_info`), its `classification`, and `COMPUTE` totals | COLMETADATA, ROW / NBCROW, ORDER · TABNAME, COLINFO, DATACLASSIFICATION, ALTMETADATA, ALTROW |
  | `Completion`: a statement or call ended | DONE, DONEINPROC, DONEPROC |
  | `Message` · `Error` | INFO · ERROR |
  | `ReturnStatus` · `OutputValue` | RETURNSTATUS · RETURNVALUE |
  | `Announcement` | ENVCHANGE |
  | `SessionState` (*added in M11*) | SESSIONSTATE |

- **Views, each defined by one token rule,** never by what was requested (D-33):
  - **result sets** (iteration): COLMETADATA opens one; the next completion closes it and is its `completion`.
  - **`response.completions`**, as far as read. `Completion(kind, rows, status, statement)`: `kind` is which DONE token; `rows` is `None` when the server says the count isn't valid; `status` is the DONE flags; `statement` is the server's statement code, raw.
  - **`response.messages`** and **`response.errors`**, as far as read.
  - **`returns()`**: one `Return` per DONEPROC, that is, per outermost procedure call the server completed. It has `status` (`None` if the call never reached `RETURN`), outputs by ordinal and name, a function's result, and `failed`.
- **Rows are plain tuples.** Names and types are on `result_set.columns`.
- **Rows that streamed past are counted, not kept.** A result set always says how many rows arrived; its rows can be read again only where they were kept.
- **Errors carry the whole record,** identical at every observability level: observability is a trace, the record is part of the API.

*Why:* the token stream is flat and its nesting is irregular: a batch mixes statements with `EXEC`s, nested procedures flatten into their caller, a call can fail before it starts, and a request can stop partway through its calls. Presenting the record as it is, with views that are each one rule, keeps every one of those facts visible and leaves interpretation to outer layers, which know what they sent ([The Client §5](A-the-client.md#5--how-outer-layers-read-a-response--agreed-d-42)).
*Rejected:*
- a tree (response → call → statement → result set), which would invent structure the server doesn't send;
- turning "no count" into 0;
- access by column name in the driver, since SQL Server column names may be empty or repeated.

**D-43 · The type vocabulary covers every type TDS 7.4 defines** · *2026-10-16* · [Building the Client §3](B-building-the-client.md#3--the-components)
- **All of them, built in milestones (D-46):**
  - the short types: numbers, dates and times, text, binary and `uniqueidentifier`;
  - large values: the `(max)` types, `xml`, and `text` / `ntext` / `image`;
  - `sql_variant`, `json` and `vector`, CLR types, and table-valued parameters.
- **`json` and `vector` arrive as their real types.** Without features requested at login, the server sends both as plain nvarchar, which would hide what the column is. So the login asks for JSONSUPPORT and VECTORSUPPORT (D-8).
- **CLR types** (`hierarchyid`, `geometry`, `geography`, user CLR types) are bytes plus the type's full name. Turning them into shapes or paths belongs to an outer layer (D-39).
- **The legacy codes** (`37` `3F` `2F` `27` `2D` `25`) are recognized and refused with an error that names them. The server sends modern codes instead; one is added only if it is ever seen.
- **The Python value for each type** follows D-48: a Python type only where it holds every value exactly, and a driver type otherwise ([Building the Client §3](B-building-the-client.md#types-and-collations)).

*Why:* an application must handle whatever types its schema uses. A vocabulary with gaps fails on real databases, and a down-converted type hides reality (D-35).

**D-44 · Collations come from one definition file generated from the server** · *2026-10-16* · [Building the Client §3](B-building-the-client.md#types-and-collations)
- **`tds/collations.py`** maps locale id → code page and sort id → code page, and records the UTF-8 flag. It is loaded whole with the module.
- **It records where SQL Server reads or writes each code page differently from Python's codec,** measured on the live server: every single byte, and every double-byte pair. Built 2026-10-16, measured on SQL Server 17.0.5015:
  - **single-byte code pages:** SQL Server gives a character to bytes Python refuses: C1 controls such as 0x81 → U+0081, and private-use characters. That is 5 in cp1252, 23 in cp1255 and 31 in cp874.
  - **double-byte code pages:** SQL Server maps whole user-defined areas to private-use characters (2,151 sequences in cp936, 6,219 in cp950), and reads 249 cp950 sequences as other characters than Python does. cp932 has duplicate encodings (NEC and IBM extensions), and SQL Server writes the IBM form.
- **A byte sequence reads as the server's character only when the server writes that character back as the same bytes** (it is *canonical*). Any other sequence the server holds, such as a duplicate encoding or a default character, is carried as escapes, so it goes back unchanged (D-48). Encoding checks that each character reads back as itself.
- **UTF-8 collations:** SQL Server stores some invalid UTF-8, but sends it with U+FFFD in place of the invalid bytes (observed without the UTF-8 login feature, D-8). Those values can't come back exactly; the driver shows what the server sent.
- **It is generated from the server**, using `sys.fn_helpcollations()` and `COLLATIONPROPERTY`, by a script kept in the repo. The file records the server version it came from, and is regenerated when a new SQL Server ships. MS-TDS contains no such table.
- **A collation missing from the file fails clearly,** naming its locale id, sort id and bytes. The fix is one new row. The driver never sends its own lookup query (D-36).
- **A `varchar` value is decoded with its column's own collation,** and a parameter is encoded with the session's collation or one given explicitly (D-40).

*Why:* the server's 5,540 collations reduce to 81 locale ids, 76 sort ids and 17 code pages. Loading the whole table costs microseconds, so a lazy-loading tier would add a second code path and save nothing. The server, not Python, defines what a byte means.

**D-45 · Where requests, types and responses live** · *2026-10-16* · [Building the Client §2](B-building-the-client.md#2--where-the-code-lives--agreed-d-45)
- `requests.py` replaces `batch.py`: the shared headers, `Batch`, and `Call` / `Calls` / `Param` / `Builtin` / `CallOptions` / `DEFAULT`.
- `types.py` replaces `datatypes.py`, matching the public `tds.types`.
- `response.py` is new: the record, its views and the reading state machine, with no I/O. The live `Response` is a thin async layer in `shell.py`.
- `tokens.py` adds RETURNVALUE, RETURNSTATUS, NBCROW and ORDER.
- Each surface is mirrored by a reference page: Requests, Data Types, and Request Response.

*Why:* strongly related concepts stay together, and each teaching surface mirrors one reference page (D-27).

**D-46 · Milestones M1–M8** · *2026-10-16* · [Building the Client §4](B-building-the-client.md#4--milestones--agreed-d-46)
1. requests and the response record;
2. every short type;
3. calls;
4. large values in both directions;
5. `sql_variant`;
6. `json` and `vector`;
7. CLR types;
8. table-valued parameters.

Each uses only what earlier ones built, ends with its tests passing against the live server, and comes with its reference pages. Its checks are in [Done When](5-done-when.md).
*Why:* everything is included, and nothing depends on something not yet built. `sql_variant` needs the base types; `json` needs large values and a login feature.

**D-48 · Every value round-trips exactly** · *2026-10-16* · [Building the Client §3](B-building-the-client.md#types-and-collations)
- **The rule:** select → insert → select compares equal, for every type, on the server and in Python. It is tested with values the server generates, not hand-made ones (§5 of Building the Client, and every milestone in Done When).
- **A value goes back with its column's type.** The column's type is the same object as a parameter's, carrying collation, precision, scale and length (D-40).
- **A Python type is used only where it holds every value of the SQL type exactly, at every scale; otherwise the value is a driver type.**

  | SQL Server type | Value |
  |---|---|
  | `tinyint` … `bigint` · `bit` | `int` · `bool` |
  | `decimal`, `numeric`, `money`, `smallmoney` | `Decimal`, encoded from its digits, never through `float` or decimal arithmetic, which rounds at 28 digits |
  | `float`, `real` | `float`; a `real` widens and narrows back exactly |
  | `date` · `smalldatetime` | `datetime.date` · `datetime.datetime` (whole minutes) |
  | `time`, `datetime2`, `datetimeoffset` | driver types holding the server's 100 ns ticks, plus the offset |
  | `datetime` | a driver type holding the server's 1/300-second ticks |
  | `char`, `varchar`, `text` | `str`, decoded with the server's own byte table (D-44) |
  | `nchar`, `nvarchar`, `ntext` | `str`, keeping unpaired surrogates, which SQL Server stores |
  | `binary`, `varbinary`, `image`, `rowversion` | `bytes` |
  | `uniqueidentifier` | `uuid.UUID` |
  | `sql_variant` | the value together with its base type |
  | `vector` | a driver value: element type and values |
  | CLR types | bytes and the type's full name |
  | `xml`, `json` | `str`; the server normalizes these on insert, and the round trip is verified from the first normalized value |
  | NULL | `None` |

  Each driver time type converts to Python's types exactly, or refuses unless rounding is asked for.
- **Refuse rather than round, in both directions.** A value that doesn't fit its declared type exactly is refused before sending: too much scale, too long, finer time precision than declared, or a character the column's code page can't hold. Rounding is an outer layer's explicit choice.
- **Where the server sets the limit** (observed, M3): the driver sends each value with its column's exact type and bytes, but SQL Server types a declared `varchar` parameter in the database's default collation and converts into it. A `varchar` value in another collation goes back exactly through a parameter declared `nvarchar`, except the sequences the server itself writes back differently. SQL Server also sends invalid UTF-8 it stores with U+FFFD in its place (D-44). The driver shows both; it can't undo them.

*Why:* a driver that rounds, truncates or replaces silently hides reality (D-35), and code that reads a value and looks for it again would fail in ways nobody can see. Exactness, not convenience, decides each type.

**D-9 · Login flags are named options of `connect`; the ODBC flag is on unless turned off** · *2026-10-16, revised the same day* · [LOGIN7](3-reference/login7.md#shape)
- **Login flags are passed to `connect` by name,** named as MS-TDS names them. The first is `odbc`: LOGIN7's ODBC flag (fODBC, bit 1 of option flags 2).
- **The ODBC flag is on by default, and stays explicit.** It is a named parameter that `odbc=False` turns off, and the login line in observability shows which was asked for, because the server never announces it.
  - *Revised:* it was off by default until M4's design showed the cost. When it is off, TEXTSIZE is 4,096 bytes, so every large value is silently cut, which breaks D-48.
- **The driver never changes a session with SET statements of its own.**
- **What the ODBC flag gives,** measured on SQL Server 2025:

  | | `odbc=True` (the default) | `odbc=False` |
  |---|---|---|
  | ANSI_NULLS, ANSI_PADDING, ANSI_WARNINGS, CONCAT_NULL_YIELDS_NULL, QUOTED_IDENTIFIER | on | off |
  | ARITHABORT | off | off |
  | TEXTSIZE: how much of a large value (`text`, `ntext`, `image`, the `(max)` types) a SELECT returns | unlimited | 4,096 bytes |

- **It is what ODBC, .NET and JDBC clients send.** With `odbc=False`:
  - writes to tables with filtered indexes, indexed views or indexes on computed columns fail (error 1934);
  - overflow and division by zero give NULL instead of an error;
  - `NULL + N'x'` is `N'x'`;
  - a `char(n) NULL` column created in the session holds its values unpadded;
  - large values arrive cut to 4,096 bytes.
- **The other identity flags** (*agreed 2026-10-16*):
  - **`read_only_intent=False`:** tells the server the connection only reads, so an availability group can route it to a readable secondary replica. It is a routing hint, not enforcement: observed, a standalone server accepts it and still allows writes. The documentation says so, and the command line prints a brief note to the terminal whenever `--read-only-intent` is used.
  - **`language=`:** the session's language, which sets its messages' language. The default is the login's own (`CREATE LOGIN … DEFAULT_LANGUAGE`, or else the server's `default language`); `connection.session.language` shows which it got. A language the server doesn't have fails the login with the server's error (4019).
  - **Identity sent truthfully:** the real process ID (administrators see it as `host_process_id`; the driver sent 0 before), the host name (`host_name=`, default `socket.gethostname()`), and `app_name=` (D-8).
  - **The database must succeed, always.** Without `database=`, the server uses the login's default database and announces it (`connection.session.database`). If the database can't be opened, the login fails: there is no fallback to `master`, which MS-TDS allows but which would leave code running in a database it didn't expect. The error explains why and what to do: the database may have been dropped or set offline, or the login may have no user in it; name one with `database=`, or have an administrator change the login's default (`ALTER LOGIN … WITH DEFAULT_DATABASE`).
  - **Left out:** the OLE DB flag (the ODBC flag already sets the session); binary XML and unknown collation handling (SQL Server ignores both); user type (reserved values); user instances and attaching a database file (SQL Server Express on Windows). Changing an expired password stays with the login variants (M17).

*Why:* the default gives the session most users expect, and keeps large values whole. Turning it off takes one named parameter, and both settings are documented (D-35).

**D-47 · Large values in responses: read whole, or streamed value by value** · *2026-10-16* · [The Client §4](A-the-client.md#large-values--agreed-d-47)
- **Two ways to read a result set, both forward-only:**
  - `async for row in result_set` gives **tuples**, with every value whole, large ones included. The memory is the application's choice.
  - `result_set.streamed()` gives **rows read value by value**, in column order. Each large value (`(max)` types, `xml`, `text`, `ntext`, `image`) arrives as a `ValueStream`.
- **A `ValueStream`** is an async iterator of `bytes` (binary types) or `str` (text and `xml`), in the order the bytes arrive.
  - It is readable while its row is current, and only once.
  - Moving to the next value discards what is unread, as moving to the next result set does (D-34).
  - Text is decoded as it arrives, with the column's collation, and never split inside a character.
- **`fetch()` and `Unread.KEEP` keep large values whole.**
- **`(max)` is spelled with a constant:** `types.varbinary(types.MAX)`, `types.nvarchar(types.MAX)`, `types.varchar(types.MAX, collation=…)`. A column declared `(max)` arrives as the same objects.
- **Observability never holds a large value whole.** It shows each large value's chunk count, total length and first bytes.

*Why:* on the wire a row is its values in column order, and a large value is chunks of unknown total length. A 1 GB value must be read, or skipped, before the next column exists. Tuples keep the common case simple; `streamed()` shows that reality to the code that needs it, with no mode flag on `exchange` (D-33).
*Rejected:*
- stream objects inside every tuple, whose later values wouldn't exist yet;
- declaring per column which values stream, which would be a mode flag.

**D-49 · A table-valued parameter is a table type and its rows** · *2026-10-16* · [Data Types](3-reference/types.md#shape)
- **The type is written with its columns' types, in order, and no names:** `types.table("shop.price_change", types.int, types.decimal(10, 2))`. TDS sends no column names; the name field must be empty.
- **A column the server fills** (identity, computed, or one with a default) is marked `types.default(type)`. It is described, with MS-TDS's default flag, and rows omit its values.

  ```python
  types.table("shop.order_line", types.default(types.int), types.int, types.int, types.default(types.int))
  rows = [(7, 2), (9, 1)]   # only product and qty; line and total are the server's
  ```

- **The rows are any iterable of tuples, or an async source of tuples,** sent as they arrive. A source that fails partway abandons the request the same way a large value's source does (D-41). `DEFAULT` sends TDS's "no table" marker. *Amended by D-53:* `None` sends it without the default bit, and the server refuses it; the table type checks only what its encoding needs.
- **The optional wire features are included:** a sort and uniqueness hint (TVP_ORDER_UNIQUE), and a different order for sending the columns (TVP_COLUMN_ORDERING), as options on the table type.

*Why:* each part matches what TDS sends. Names that never reach the server would suggest they matter; a per-row placeholder would hide that the flag is per column. The ordering features are wire features, not conveniences, and column ordering is how a large value is sent last so it can be streamed.

**D-50 · Bulk load is two requests, and the application writes both** · *2026-10-16* · [Requests › Shape](3-reference/requests.md#shape)
- **`tds.BulkInsert(sql)`** is the application's own `INSERT BULK …` statement, sent as a SQL batch. It is a request type of its own, so the serial channel knows a bulk load is open without reading the SQL.
- **`tds.BulkRows(columns, rows)`** is the bulk data message: its header of columns (COLMETADATA), then the rows, then DONE. The rows are an iterable or a source of tuples (D-41). Large values are sent in chunks with their length unknown, the form MS-TDS defines and the server accepts.
- **The two must describe the same columns exactly:** the same columns, order, types and nullability. The documentation recommends taking the columns from `SELECT TOP 0 * FROM table`, as `result_set.columns`, and writing the statement from the same columns.
- **The server checks the agreement,** and its refusals leave the connection usable. The driver refuses only what it can't encode (D-48). *Amended 2026-10-16:* the driver was to check, before sending, for empty names and for types that bulk data refuses. A general rule replaced this: little semantic checking before sending; let the server say what's wrong.
- **The channel keeps the pair together.** After a successful `BulkInsert`, the channel's next request must be `BulkRows`, and `BulkRows` is refused at any other time. Bulk data out of turn makes the server close the connection.
- **Amended 2026-10-17:** the user explicitly approved bulk continuation ordering as an exception to D-53 and a borrowed Rust `BulkWriter`. Each preparation/data/Attention message still has its own exchange; the writer owns the obligation between them. Awaited abort and channel close cancel/drain under the existing cleanup budget. Unresolved pool return, failed cleanup or Rust writer Drop discard the physical connection. Recovery refuses an unresolved continuation. No automatic transaction commit/rollback or request replay is implied.
- **The docstrings state this contract,** for the convenience layer to follow. That layer will provide a helper that writes the statement and its options from the columns (D-39); used directly, the two requests are verbose.

*Why:* each request is exactly what TDS sends, and the driver writes no SQL. The only failure that can't be recovered from, bulk data out of turn, is prevented by the channel.
*Rejected:*
- the driver writing `INSERT BULK` from the columns, which would make it the one place the driver writes SQL, and hide the statement sent;
- one `BulkLoad` request making both exchanges, which breaks D-33;
- `INSERT BULK` options named in the driver: they are part of the statement, and belong to the helper.

**D-51 · Transaction-manager requests: one request class each, exposed as the server provides them** · *2026-10-16* · [Requests › Shape](3-reference/requests.md#shape)
- **One class per MS-TDS request, with plain names, in `tds.transactions`:** `Begin(isolation=None, name="")`, `Commit(name="", begin=None)`, `Rollback(name="", begin=None)` (the name may be a savepoint's), `Save(name)`, `Promote()`, `Propagate(cookie)`, `CoordinatorAddress()`. `begin=Begin(…)` is MS-TDS's *begin another* flag. `Isolation` is an enum; `None` leaves it unchanged.
- **The results are in the response, as the server provides them:** the transaction state in the session and the response's announcements, promote's token in its announcement, the coordinator's address in the response's one row. Each is documented with the request that produces it.
- **Little semantic checking before sending:** the server says what's wrong, and the documentation says what follows. A refused savepoint name, for instance, rolls back the open transaction. Only what can't be encoded is refused: a name longer than its u8 byte count allows.
- **`Propagate` is sent as MS-TDS defines it, and marked untested:** it needs a cookie from a coordinator, so only its refusal is tested. The enlist, defect and transaction-ended announcements are marked unobserved.

*Why:* each request is one exchange (D-33), and the session already follows the announcements, so these are requests and nothing more. Checks that duplicate the server's would be a second, weaker statement of its rules.

**D-52 · Milestones M9 and M10** · *2026-10-16* · [Building the Client §4](B-building-the-client.md#4--milestones--agreed-d-46)
The second sequence begins with **M9 · Bulk load** (D-50) and **M10 · Transaction manager** (D-51), checked as [Done When](5-done-when.md) lists. For both, every behavior documented on Requests, Request Response and Token Stream, deviations from MS-TDS included, has a live test.

**D-53 · The server judges; errors are literate** · *2026-10-16* · [The Client §4](A-the-client.md#reading-a-response)
- **Little semantic checking before sending.** The driver refuses only what it can't encode, or couldn't encode exactly (D-48): a value out of range, a name too long for its length field, a row whose values can't be placed. Everything else goes to the server, which says what's wrong. The documentation says what a refusal causes, such as a rolled-back transaction.
- **Errors are literate: they carry all the applicable information.**
  - **A `ServerError`** shows every error in SQL Server's own form (`Msg`, `Level`, `State`, `Procedure`, `Line`, the server, the text), then what its level means, as Microsoft documents it. The messages that came with it are listed in order. It says which request was refused, which call for a request of several calls, and what the server did next: its announcements, and whether it continued.
  - **A refused login** shows the server's report the same way.
  - **The driver's own errors** say what was refused, why, and what to do instead. A refused value says where it was, each layer adding its place: `the call to shop.update_prices › parameter @changes (shop.pc) › row 2 › column 2 (decimal(10, 2)): …`. This holds whether it was refused before sending, while encoding, or while a source was producing it.
- **Applied to what is built:** D-50's checks before sending were dropped. D-49's table type now checks only what its encoding needs. `None` for a table is sent, and the server's refusal (error 8060) reaches the application. So does an output table, a column count the type doesn't have, a table nested in a table, and a hint the server rejects. Each refusal is tested live.

*Why:* the server is the authority on its own rules, and a second, weaker copy of them in the driver would hide what the server says. When it refuses, its full report is what the application needs.

**D-54 · The other logins come last, tested on transient Azure infrastructure** · *2026-10-16* · [Conversations › What each way of logging in needs](3-reference/conversations.md#what-each-way-of-logging-in-needs--built-d-54-d-55)
- **Deferred until the rest of the driver is built:** Windows logins (Kerberos, NTLM), federated logins (Entra ID tokens, given in advance or fetched during login), and the SQL login variants (changing an expired password, contained-database users). *Built and tested in M17, 2026-10-17 (D-55, D-62).*
- **They are documented now:** what each needs on the server and the client, and how each will be tested.
- **They will be tested on transient infrastructure in Azure,** created for the purpose and deleted afterward: a Windows Server domain controller and SQL Server for Kerberos and NTLM, and an Azure SQL Database with an Entra ID tenant for federated logins.

*Why:* none of them can be tested against the local container alone. SQL Server on Linux accepts only Kerberos for integrated logins, and needs a domain. Federated logins need Entra ID.

**D-56 · Milestones M11–M18** · *2026-10-16* · [Building the Client §4](B-building-the-client.md#4--milestones--agreed-d-46)
The rest of the second sequence, in this order:
1. M11, every token the server can send;
2. M12, Slice 1's failures, tested;
3. M13, TDS 8.0 and the observability levels;
4. M14, connection and login options: session recovery, the remaining login features and flags, the DAC, routing and a Browser client;
5. M15, Always Encrypted;
6. M16, the convenience layer and the synchronous shell (DB-API removed 2026-10-16: it would be a separate project, depending on this one); built after M17 and M18 (D-62);
7. M17, the other logins, on Azure;
8. M18, the Azure-only login features, on the same infrastructure (*added 2026-10-16*, D-8).

Each is checked as [Done When](5-done-when.md) lists, and names the decisions it needs first.
*Why:* a token the driver can't read ends the connection on ordinary SQL, so it comes first. Then quick tests that complete Slice 1. Then the core behaviors testable locally, then the layers around the driver. What needs Azure comes last.

**D-10 · Encryption and certificates** · *2026-10-16* · [Connect](3-reference/connect.md)
- **TDS 8.0 is chosen explicitly:** `connect(…, tds_version="8.0")`, or `strict=True`, which says the same and matches Microsoft's drivers (`Encrypt=Strict`). The default is `"7.4"`.
  - **There is no automatic fallback.** If 8.0 fails, the error says why, and what the options are, such as `tds_version="7.4"`. Falling back would silently downgrade a connection that asked for 8.0.
- **Under 7.4, the whole connection is encrypted, or the connection fails** with an explanation, as built. There is no unencrypted mode.
- **Certificate checking uses Python's standard,** an `ssl.SSLContext` passed as `ssl_context`. The default verifies the certificate against the system's trusted authorities and the host name connected to. Anything else is set through the context: trusting a specific authority (`cafile=`), pinning a certificate, a minimum TLS version, or no verification at all. A certificate that names another host is checked against `server_hostname=`, which Python passes alongside the context, as `asyncio.open_connection` does. Each is documented with an example.
  - `trust_server_certificate` is removed: `ssl_context` says the same.
  - Under 8.0, a context that doesn't verify the certificate is refused, with an error saying why, as Microsoft's drivers refuse `TrustServerCertificate` in strict mode: TLS without verification can't prevent a man-in-the-middle attack.
- **The test container presents a certificate from a test authority,** set up by a script kept in the repo and documented so the setup can be reproduced. Tests trust that authority, not every certificate.

*Why:* the choice of protocol version changes what is protected, so it is the application's to make, and visible. Python's `ssl` module already expresses everything about certificates; a second vocabulary would hide it.

**D-12 · Observability levels** · *2026-10-16* · [The Client §6](A-the-client.md#6--what-the-running-client-shows--agreed-d-12)
1. **Three levels:** **off**, no inspection trees and no event text, the cheapest; **outline**, one line per step, message and change; **full**, every message opened to its fields and bytes.
2. **Set per connection at `connect`, and changeable between exchanges** on a live connection, so a pooled connection can be inspected while in use.
3. **Events go to the `observe` callable;** the printer is one observer. Adapters to `logging` or OpenTelemetry live outside the core (D-39).
4. **Full shows each field's first bytes, with every byte reachable in the tree.** Large values are summarized (D-47), and each structure is labeled with the reference page that explains it.
5. **Captures and replay:**
   - a capture holds every message's bytes in both directions, after TLS, with timestamps, as JSON lines;
   - the password is removed by default, because LOGIN7's scrambling is reversible; keeping it requires an explicit option;
   - query text and data stay, and the documentation warns that captures hold data;
   - replay decodes a capture into the identical view.
6. **The password stays hidden at full level** unless explicitly revealed for that session.
7. **Timing** (*agreed 2026-10-16*): each event has a time on a monotonic clock. Each connect step shows its time since connecting began (`at 24 ms`). Each response shows the time from sending to its first packet and to its end (`first packet 12 ms · done 40 ms`). Durations are shown at the end of the line, separate from its text. A capture records them, so replay shows the same values. A capture's first line records the wall-clock start, to align it with server logs. `response.timing` gives applications the same (sent, first packet, ended), collected at every level: three clock reads per exchange.

*Why:* the application chooses how much the client collects, and can change that choice on a live connection. The view is generated from the definitions, so a capture replays to exactly what was seen.

**D-6 · Vocabulary** · *2026-10-16*
The [Model's vocabulary](1-model.md#vocabulary): connection, serial channel, exchange, packet, message, body (structure or token stream), token, field, conversation, step, session state.
*Why:* each term names one layer, so any byte can be placed by asking "which layer?".

**D-7 · Plain names** · *2026-10-16*
Docs, code and output use plain names (*packet size*, *session id*). MS-TDS names (`PacketSize`, `SPID`) appear only in one reference-table column.

**D-8 · Features requested at login: a list, with a documented default** · *2026-10-16* · [LOGIN7](3-reference/login7.md)
- **`connect(features=…)` takes the list of features the login asks for;** the default is `tds.DEFAULT_FEATURES`. Features are named as MS-TDS names them (`tds.Feature.UTF8_SUPPORT`, …), and the driver chooses the version it implements for each. A feature the driver can't read yet is refused with an error that says why and when: column encryption until Always Encrypted (M15), federated authentication until the other logins (M17). The command line has an on/off switch for each feature, with its default shown in `--help`. `connection.features` shows what the server accepted.
- **The default list:**
  - **JSON support (version 1) and vector support (version 2):** `json` and `vector` arrive as their real types (D-43). SQL Server 2025 accepts vector version 1, float32 only.
  - **UTF-8 support:** without it, SQL Server sends bytes stored in a UTF-8 column that aren't valid UTF-8 with U+FFFD in their place. With it, they arrive as stored, and go back exactly (D-48).
  - **Data classification, version 2:** a result set whose columns are classified carries their labels, as `result_set.classification` (below). The negotiated version reaches the reader, since version 2 adds ranks.
  - **Session recovery,** once M14 builds recovery.
- **Not requested:** column encryption until M15, which changes every result's column descriptions. The Azure-only features (Azure SQL support, Azure DNS caching, enhanced routing, global transactions) wait for M18, on Azure. The user-agent feature is left out: the server ignores it, and SQL Server already identifies the driver (`client_interface_name` "tds").
- **`connect(app_name=…)`** sets the name SQL Server records as the session's `program_name`, so administrators can distinguish applications. The default is "tds (python)".
- **Every option is documented in one place:** the Options section of [Connect](3-reference/connect.md), mirrored by `tds --help`.

**Reading data classification.** Each result set says what the server knows about its columns' sensitivity:

```python
rs = fetched.result_sets[0]                         # or the live result set, once it has started
if rs.classification is not None:                   # None: no column is classified, or the feature is off
    for column, sensitivities in zip(rs.columns, rs.classification.columns):
        for s in sensitivities:                     # a column can carry several
            s.label                                 # ("Confidential", "<label id>"), or None
            s.information_type                      # ("Contact Info", "<type id>"), or None
            s.rank                                  # −1 not defined · 0 none · 10 low · 20 medium · 30 high · 40 critical
    rs.classification.rank                          # the result set's own rank, in the same values
```

Ranks arrive from version 2; under version 1 they are `None`. The labels are the database's (`ADD SENSITIVITY CLASSIFICATION`). The driver only shows them; masking, warning or logging access belongs to the application (D-39).

*Why:* each feature changes what the server sends, so the list is the application's, with a default that gives exact values and everything the server knows (D-35, D-48). A feature the reader can't handle would break ordinary queries, so it can't be asked for.

**D-11 · Routing: followed once** · *2026-10-16* · [Connect](3-reference/connect.md)
- **A routing announcement in the login reply is followed, once, by default:** the driver closes the connection, connects to the named server and port with the same options, and logs in again. The steps show the hop (`● routed → node:11003`), and `connection.routed_from` records where it was sent from. `follow_routing=False` raises `Routed(server, port)` instead, for an application that decides for itself.
- **Only one redirect:** a second routing announcement fails with an error naming the whole chain.
- **Credentials go to the new server only after its certificate is verified for the new name** (D-10). Routing never relaxes certificate checking. A `server_hostname` given by the application applies to the first server only.
- **One connection timer covers both connections:** the connection must be ready within the timeout, on whichever server it reaches.
- **Enhanced routing** (ENVCHANGE 21, with a database) isn't followed yet: in M18 the test server acknowledged the feature with 0, so none arrived.
- **A routed login names the routed server and port,** `server,port`, in LOGIN7: Azure SQL's nodes refuse the name the application asked for (observed 2026-10-17; SqlClient does the same).
- **Tested** locally with a fake router in the tests, presenting the test certificate and routing to the real container; live on Azure SQL Database (connection policy Redirect) in M17, under TDS 7.4 and 8.0.

*Why:* Azure SQL Database routes every connection made from inside Azure (its redirect mode), and availability groups route read-only intent. Following once is what those designs expect, and what Microsoft's drivers do; more than once would risk a loop.

**D-13 · Step names** · *2026-10-16* · [Connect](3-reference/connect.md#shape)
*start · secure · hello · log in · ready · routed · closed*, rather than MS-TDS's long state names. They map one-to-one.

**D-15 · Diagrams as plain text; byte layouts as tables** · *2026-10-16*
*Why:* they render everywhere: viewers, terminals, code comments. Mermaid is the alternative.

**D-16 · Location** · *2026-10-16*
`docs/design/`, numbered in reading order.

**D-30 · Code layout** · *2026-10-16*
`clients/python/tds/`, one file per concept, mirroring the reference pages. As built: `wire` (machinery) · `packet` · `prelogin` · `login7` · `tokens` · `types` · `collations` · `requests` · `transactions` · `response` · `session` · `observe` · `capture` · `browser` · `connection/{core,shell}` · `encryption/{cell,keys,normalize,context,backend}` (Always Encrypted, D-60) · `__main__` (the command-line tool). A file exists only if it holds one concept a reader would look for: no `utils`, `constants` or `errors` modules, and no empty modules for future slices. Errors live next to what raises them. (Proposed with `datatypes` and `batch`; D-45 named them `types` and `requests`.)

**D-57 · Session recovery: automatic, and explicit** · *2026-10-16* · [Connect](3-reference/connect.md)
- **The login asks for session recovery by default** (it joins `tds.DEFAULT_FEATURES`, D-8). The server acknowledges it with the session's initial state, and SESSIONSTATE tokens report each change after that.
- **Automatic:** when an exchange is about to start and the connection is found broken while idle, the driver recovers it once, then sends. **Explicit:** `await connection.recover()` does the same on demand.
- **Recovery opens a new connection** with the same options and logs in carrying the session's state: its initial state and its current one (database, language, collation, and the session states). The server rebuilds the session from them.
- **A request in progress when the connection broke is never resent.** Nobody can know whether it ran. Its error says so, and the application decides.
- **Visible:** the steps show it (`recover`), and `connection.recoveries` counts recoveries. A server that refuses, or a session it marked not recoverable, gives a literate error naming why.
- **Continuing permissions, agreed 2026-10-17 after experiment:** the logical connection and unrevoked application channels retain their owners and connection/channel close permissions. Every physical connection allocates fresh SMP wire ids from zero and maps them back to stable application ids. Application-closed lifetimes stay closed. Old exchange read/cancel/abandonment permissions cannot act on the replacement; retained data remain inspectable. Rust retires the physical epoch before waking failed waiters, and checks that epoch when revoking from an old future or response. Python pins old response sources and running procedures to the failed core/transport. [Experiment and results](experiments/recovery-channel-identity.md).
- **No replay or inferred rollback:** an interrupted request fails with uncertain execution. Explicit recovery restores server-reported reconstructible session state; it neither determines nor undoes the request's database effects. A new request after an observed idle break can recover first. Each physical connection owns a separate recording. Optional log failure disables the log; requested recording failure stops the connection.

*Why:* applications using Microsoft's drivers expect idle connections to survive a brief network failure or a failover; the rule for requests in progress ensures that recovery never runs a request twice.

**D-58 · The mirroring partner is shown, not acted on** · *2026-10-16* · [Login Response](3-reference/login-response.md)
The login reply's mirroring partner announcement (database mirroring) is kept as `connection.session.mirroring_partner`. The driver never connects to it on its own: trying the partner is the choice of the application, or of a layer around the driver (D-39). Mirroring is deprecated, and SQL Server on Linux doesn't have it, so it's tested live on Windows (M17).

*Why:* the driver shows what SQL Server says; deciding where to connect next is an application's policy.

**D-37 · The serial channel's conveniences** · *2026-10-16; a layer around the driver (D-39), built in M16* · [The Client §4](A-the-client.md#4--exchanges-and-responses--agreed-d-33-d-34)
- `exchange` (the primitive), `query` (live response), `fetch` (`FetchedResponse`), `fetch_value` (exactly one value), `call` (stored procedure), `prepare` (a statement with the same `query` / `fetch` / `fetch_value`), `describe` (shape without running), `transaction`. Cancel is not among them: it is the response's own `cancel()` (D-34).
- **Shortcuts check their shape.** `fetch_value` refuses anything but exactly one row and one column, saying what came back. `FetchedResponse.rows` exists only when there was exactly one result set, and otherwise says how many there were.
- **No aliases:** one name per behavior.

*Why:* each convenience is one exchange plus a way of reading its response (D-33, D-34). The shape checks never quietly pick "the first one" (D-35).

**D-38 · Two entry points with the same shape** · *2026-10-16*
`tds.connect()` gives one `Connection`; `tds.Pool()` lends `Connection`s. Code that uses a connection is the same either way.

**D-14 · Worked examples use the spec's own bytes** · *2026-10-16*
Where no sample exists, construct the bytes and label them.
*Why:* readers can check against an independent authority.
*Cost:* the samples come from a TDS 7.2 client, so a note on what this client sends differently is needed.

**D-32 · TLS runs in the core** · *2026-10-16*
Python's TLS engine works entirely in memory (`ssl.MemoryBIO`), so the core drives the handshake and the shell only moves socket bytes. This refines D-24's first design, which put the TLS engine in the shell.

**D-59 · The Browser client: ASCII unless told, a timeout in milliseconds, and separate from connect** · *2026-10-16* · [Browser](3-reference/browser.md)
- **Text is ASCII unless `encoding=` names the code page** the client and server share. MC-SQLR never says which it is, so the driver doesn't guess: a name ASCII can't hold is refused before sending, and a reply ASCII can't read is reported with the byte that failed. The Browser page says how to find a server's code page and pass it.
- **Every call waits `timeout_ms` for its reply,** 1000 ms by default (MC-SQLR suggests 1 second). A broadcast gathers replies for that long.
- **The Browser stays separate from `connect()`.** Finding a port and connecting to it are two steps the application combines; a connector that does both is a convenience, in a layer around the driver (D-39).

*Why:* each is the protocol as it is: a shared code page nobody states, a timer the client chooses, and a separate protocol from TDS.

**D-60 · Always Encrypted: a protocol extension in its own module, over a connection** · *2026-10-17*
- **What it is.** Always Encrypted is partly TDS and mostly not. MS-TDS defines a login feature (column encryption, versions 1 to 3), a key table and crypto metadata in every COLMETADATA once the feature is negotiated, encrypted parameters with their cipher info, crypto metadata in RETURNVALUE, and an opaque enclave package in RPC and SQL batch requests. The rest is outside TDS: master keys in client-side key stores, column keys the client decrypts, the encryption itself (AEAD_AES_256_CBC_HMAC_SHA256), normalized plaintext, and `sp_describe_parameter_encryption`, an ordinary stored procedure that says which parameters to encrypt with which key.
- **The split.** The core reads and writes every Always Encrypted wire element, with no keys and no cryptography. A connection that negotiated the feature, without the module, shows an encrypted value as it arrives: ciphertext, with its metadata (D-35). `tds.encryption` holds the keys, the cryptography and the orchestration. It is protocol capability, not a convenience, and a protocol extension rather than machinery in D-27's sense.
- **The facade.** A shared `Encryption` context (key stores, decrypted column keys, describe results) opens or wraps connections and pools whose login asked for column encryption, and refuses a connection that didn't, saying why. Its serial channels wrap `exchange`: they describe a call's parameters and encrypt them before sending, and decrypt values as they are read, through a decrypt hook the core gives each exchange, so every way of reading a response works unchanged. Composition, not a subclass of `Connection`, so it works for `connect()` and `Pool` alike.
- **The cryptography dependency.** The `cryptography` package, as an optional extra, behind a small interface another backend could replace. The core stays without dependencies (as D-55 suggests for the security libraries).
- **Key stores in M15:** a local key store, an RSA key file, for the tests and for real use. Azure Key Vault and the Windows certificate store come with M17's Azure infrastructure.
- **Enclaves are deferred to the Azure work.** The core carries the enclave package as opaque bytes; attestation and enclave sessions come with Azure, since SQL Server on Linux has no enclaves.
- **Tested, level one (D-61's pass 1): what the driver writes, it reads back exactly** (D-48), for every type an encrypted column can hold. Level two, matching Microsoft's implementation, is D-61's pass 2.
- **What the server allows locally** (observed, SQL Server 2025 on Linux): a master key with any key store name and a column key with any encrypted value, since the server never decrypts keys; `sp_describe_parameter_encryption` returns the keys and the parameters to encrypt. Without the login feature, encrypted columns arrive as `varbinary` ciphertext.

*Why:* it is complex enough, and has enough real alternative implementations (key stores, cryptography libraries, attestation protocols), to be a module of its own; the wire elements stay in the core because negotiating the feature changes every result on the connection.

**D-61 · Always Encrypted is tested in two passes: the driver's own round trip, then against .NET** · *2026-10-17*
- **Pass 1:** what the driver writes, it reads back exactly (D-48).
- **Pass 2:** .NET's SqlClient, with a custom key store, in the .NET SDK container the CLR tests already use, reads what the driver wrote, and the driver reads what SqlClient wrote, for every type. Both passes are part of M15.

*Why:* MS-TDS names the normalization version, but not how each type's plaintext is laid out, and the server never sees plaintext, so a difference from Microsoft's drivers passes every test of reading back what the driver wrote. It shows only when another client reads the driver's data: each misreads what the other wrote, and a lookup on a deterministic column compares ciphertexts, so it finds no rows rather than failing.

**D-55 · Windows and federated logins take a token producer from the application** · *2026-10-17* · [Conversations](3-reference/conversations.md#what-each-way-of-logging-in-needs--built-d-54-d-55)
- **The driver carries each login's token exchange as TDS defines it,** and nothing else: where tokens go in the hello, the login, the server's challenges and the client's answers.
- **The application gives the tokens:** a small object that produces them (the first token, then one answer to each of the server's challenges), or, for a federated login, the token itself or a function that fetches one when the server says where from.
- **Adapters for particular libraries live outside the core,** as optional extras: Kerberos and NTLM through a SPNEGO library, Entra ID tokens through Azure's identity library. `tds` itself keeps no dependencies (D-39).

*Why:* each library has its own ways of finding credentials, caching and prompting, which are the application's concern; the protocol's part is the same whatever library makes the tokens.

**D-62 · Azure test infrastructure: Terraform, one resource group, deleted after testing** · *2026-10-17* · [Building the Client §4](B-building-the-client.md#4--milestones--agreed-d-46)
- **M17 and M18 are built together,** before M16: the logins are core, the conveniences aren't. They share one set of infrastructure, created once and deleted once.
- **Terraform describes it,** in `infra/azure/`: one resource group in a subscription given when it's applied, region East US 2, tagged as temporary. Its state stays local, and no secret is ever printed.
- **What it holds:** an Azure SQL logical server and databases (Entra admin: the person running it; connection policy Redirect, so routing happens from outside Azure too; one database with an enclave, for Always Encrypted with enclaves); a network open only to the developer's address; a Windows Server domain controller; SQL Server 2022 Developer on Windows, joined to the domain, with the Browser running; a small Linux VM in the network, from which the Kerberos tests run; a Key Vault with an RSA key, as an Always Encrypted master key.
- **Cost guards:** the VMs shut down each night; the cost is checked against Azure's prices before applying, and `terraform plan` is shown before anything is created.
- **Deleted after testing:** `terraform destroy`, then a check that the resource group is gone.

*Why:* Windows logins need a domain and SQL Server on Windows, federated logins need Entra ID and Azure SQL, and none of it should remain after the tests.

**D-63 · The roadmap after M18: Rust, Python conveniences, application drivers** · *2026-10-17; order revised by the user* · [Roadmap](C-roadmap.md)
- **Three phases, in this order:**
  1. **A Rust client:** the same design and learning intent, with the Python code and tests as a reference. Begin with local SQL Server setup, Python tests, source analysis, and a Rust development plan that establishes ownership and permissions carefully.
  2. **Python conveniences** (M16): the standard patterns of use in one call each, asynchronous and synchronous (D-37, D-38, D-50).
  3. **Application drivers:** DB-API 2.0 for Python, and possibly other standard interfaces, built on the conveniences.
- **Rust does not depend on Python M16.** Phase 3 depends on phase 2.
- **Each phase's design is agreed before its code is written.** The [Rust development plan](D-rust-development.md) is a proposal, including its runtime, APIs, ownership enforcement and exact representations; the priority and learning intent above are agreed. Accepted milestones are then added to [Done When](5-done-when.md).
- **The [Python baseline](E-python-baseline.md) records fresh evidence and limitations.** Skipped local/remote tests are not completed interoperability checks.
- **DB-API remains phase 3**, as a package that depends on this driver (D-39). D-25 and D-26 stay deferred until phase 3 starts.

*Why:* the user requested Rust first. A second language tests whether the design depends on Python. The existing Python implementation provides a concrete reference without requiring its convenience layer to be finished. Rust must preserve the learning purpose while making resource ownership, permission to act, exact values and cleanup explicit.

---

**D-65 · Finish Rust locally, validate Windows authentication on transient GCP, then destroy** · *Agreed, 2026-10-18* · [Roadmap](C-roadmap.md#rust-completion-sequence--agreed-2026-10-18-d-65)

- Finish the solid local Rust implementation first, including local-key Always Encrypted and independent .NET interoperability checks. API/provider designs are agreed before affected implementation.
- Add a parallel Terraform test setup under `infra/gcp/`. Create the Windows/domain infrastructure only when local work is ready; use it to implement and validate Windows authentication (NTLM/Kerberos), then destroy it. Preserve the historical Azure setup.
- Entra authentication is deferred because tenant access is unavailable. Azure-specific providers/features, Windows certificate-store key-provider support and enclaves/attestation are outside this completion scope. Rust completion is explicitly scoped, not full Python parity.
- Require an explicit target project, cost estimate, finite test window, expiry fallback and verified full teardown. Keep evidence after infrastructure is gone. No deployment is established by accepting this sequence.
- Once local and Windows acceptance pass and teardown is verified, finish the scoped Rust phase and proceed to Python M16. Publishing Rust is a separate action.

*Why:* GCP is accessible from the current development location, Windows authentication needs a real Windows/domain test environment, and the user wants cloud resources present only for the test campaign.

---

**D-66 · Encryption key reuse defaults to the transaction; applications choose the tradeoff** · *Agreed direction, 2026-10-18* · [Lifetimes and cost](M-rust-encryption-lifetimes.md)

- Transaction scope is the default for retained encryption key material. Preserve the proposed exchange fallback outside explicit transactions; never create or extend a SQL transaction to retain keys.
- Applications can select exchange scope or time-based handling to trade repeated key work against secret retention. The user clarified that time-based handling is the broader-retention option: it may reuse keys across transactions and autocommit exchanges within the same physical connection and exclusive pool lease, until a fixed application-selected maximum age. Reuse does not refresh that deadline. Pool return, reset, recovery, close and explicit invalidation still revoke the owner; it is not an application-global cache.
- RAII cleanup erases owned plaintext keys and backend-owned secret copies when their permitted lifetime ends. Key expiry requires reloading on later use, rather than imposing a SQL transaction-duration limit.
- Implementation checkpoint: [design N](N-encryption-policy-implementation.md) records the optional key-policy/local-crypto service, independent settings, bounded entries and actual driver lifecycle link. [Acceptance evidence](experiments/encryption-policy-evidence.md) distinguishes those results from the remaining transparent encrypted SQL and Rust/.NET work.
- This changes D-60's long-lived shared-cache direction. Python implements the same retention choices in its existing transparent SQL facade ([Python design and evidence](experiments/python-encryption-retention.md)); it clears owned mutable key buffers without claiming Rust's stronger guarantees for Python/library copies. Rust's implemented foundation remains distinct from its pending transparent encrypted SQL support.

*Why:* the user accepted transaction scope as the default and explicitly requested application control over exchange and time-based handling after reviewing measured setup and value costs.

---

## Proposed and open

**D-64 · Rust channels use movable authority rather than task identity** · *Proposed direction selected by the user, 2026-10-17* · [Rust ownership and permissions](D-rust-development.md#1--ownership-and-permissions-come-first)

- The Rust plan proposes one non-`Clone` send/read authority. A native Rust move transfers it; an exclusive borrow lends it temporarily. Task identity does not restrict sequential use after a valid move or loan.
- This is a deliberate language-specific variation to D-21. Python retains its opening-task check and explicit `hand_over(task)`. A mutex may permit sequential lending in Rust; it does not make an unread response available for a new exchange.
- Separate generation-scoped cancel/close handles may be shared. Persistent busy, continuation, lease and generation checks still govern protocol use after a guard or future is dropped.
- Active-response transfer, borrow shapes and `Send` bounds remain API choices for R0. No runtime, TLS backend or cleanup mechanism is selected by this direction.

*Why:* the user chose to propose Rust ownership through moves and borrowing. It should be expressed in Rust's own terms while preserving one advancing reader, safe pool return, explicit cleanup and the shared session semantics.

---

## Deferred

Deferred 2026-10-16 to the DB-API driver, which is phase 3 of the [Roadmap](C-roadmap.md) (D-63): a package that depends on this driver (D-39). These questions are decided when phase 3 starts.

**D-25 · DB-API layer: how long a serial channel lives** · *Deferred 2026-10-16*

| Option | For | Against |
|---|---|---|
| **a. One per result**, opened by `execute()` | Pool hand-offs between threads work without extra steps; misuse during a result fails every time; free without MARS | Extra packets per query under MARS |
| **b. One per pool check-out** | Fewest opens; misuse caught for the whole check-out | Needs a pool hook; hand-offs outside a pool break |
| **c. One per cursor** | One-to-one mapping; natural under MARS | Without MARS only one cursor can exist at a time |
| **d. One per connection, moved when idle** | Most compatible | Misuse detection depends on timing again |

**D-26 · DB-API layer: cursor B runs while cursor A has unread rows** · *Deferred 2026-10-16*

| Option | For | Against |
|---|---|---|
| **a. Fail** | Hides nothing; consistent with D-22 | Surprises users of drivers with independent cursors |
| **b. Buffer A, then run B** | Works with most existing code | Hidden memory and latency; needs a size limit |
| **c. Always buffer whole results** | Simplest semantics | No streaming; memory grows with result size |
| **d. MARS: a serial channel per cursor** | True streaming independence | Requires MARS and its shared-state semantics |
| **e. Configurable** | Fits different workloads | More to test; still needs a default |

---

**Next:** [Done When](5-done-when.md)
