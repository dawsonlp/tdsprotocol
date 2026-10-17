# B · Building the Client

**Where this sits:** between the design and the code. It covers how the agreed design becomes code, in what order, and how each step is checked.
**After reading this you can** say which file each part of the design lives in, what each milestone builds, and how to tell that it is done.

> **Status: agreed, 2026-10-16.** This plan, and the decisions it builds on (linked inline), are agreed. Implementation follows the milestones in order.

---

## 1 · Where the code stands

| Agreed design | Code before M1 | Change |
|---|---|---|
| Connections, serial channels, MARS, pool (D-17–D-24, D-31, D-36) | built, and tested against the live server | none |
| One primitive, `exchange(request)` (D-33) | `exchange(sql: str)`; the core assumes every request is a SQL batch | request objects; the core never knows the kind of request |
| Streaming responses, and the response as a record (D-34, D-42) | the whole message is read into `Result` lists | the live `Response`, `FetchedResponse`, the record and its views, errors raised at the end |
| Cancel (D-34) | none | Attention, from any task |
| `Call` (D-40) | none | RPC requests and `returns()` |
| The type vocabulary (D-43) | int, bit and nvarchar, read only | every type, both directions, in milestones |
| "The core never buffers without limit" (The Client §2) | unbounded channel inboxes; MARS ACKs sent on arrival | backpressure |
| Streamed requests (D-41) | none | M4 |

## 2 · Where the code lives · *agreed, D-45*

| File | Holds | Kind (D-27) | Mirrored by |
|---|---|---|---|
| `tds/requests.py` | the headers every request carries; `Batch`; `Call`, `Calls`, `Param`, `Builtin`, `CallOptions`, `DEFAULT` | teaching surface | Reference › Requests *(new)* |
| `tds/types.py` | the vocabulary: each SQL Server type's description on the wire (TYPE_INFO), value layout and checks | teaching surface | Reference › Data Types *(new)* |
| `tds/collations.py` | locale id → code page, sort id → code page; generated from the server (D-44) | teaching surface: a definition table | Data Types › Collations |
| `tds/tokens.py` | adds RETURNVALUE, RETURNSTATUS, NBCROW, ORDER | teaching surface | [Token Stream](3-reference/token-stream.md), [Request Response](3-reference/response.md) |
| `tds/response.py` | the record's items, its views, the reading state machine, `Unread`, `FetchedResponse`, `ServerError`, `Cancelled`. No I/O. | teaching surface | [Request Response](3-reference/response.md), [The Client §4](A-the-client.md#4--exchanges-and-responses--agreed-d-33-d-34) |
| `tds/connection/core.py` | `exchange(request)`, packets delivered per channel, cancel, MARS credit returned as packets are consumed | procedures (surface) and machinery | [Connect](3-reference/connect.md), [Conversations](3-reference/conversations.md) |
| `tds/connection/shell.py` | the live `Response` (asyncio), bounded inboxes | machinery | — |
| `tds/wire.py` | incremental token decoding; writing TYPE_INFO | machinery | — |
| `tools/generate_collations.py` | writes `collations.py` from a live server | tool | — |

`batch.py` and `datatypes.py` are removed. Their contents move into `requests.py` and `types.py`.

## 3 · The components

### Requests

- **A request knows its packet type** and encodes its own body from a small context: the transaction descriptor, the number of outstanding requests, and the session's collation. The core asks for exactly that and nothing more, so it never branches on the kind of request (D-33).
- **`Batch(sql)`:** the headers, then the SQL text.
- **`Call(target, *params, options=…)`:**
  - the target is a name (written as a length and text) or a `Builtin` (`FFFF` followed by its number);
  - the `CallOptions` flags follow;
  - then each `Param`: its name, its status flags, the type's description on the wire, then the value. The flags are *by reference* when `output=True`, and *default value* when the value is `tds.DEFAULT` (D-40).
- **`Calls(…)`:** the headers once, then the calls separated by the BATCH marker (`FF`).
- **Values are checked when the request is built.** A value that doesn't fit its declared type fails before any byte is sent.

### Types and collations

- **One object per SQL Server type:** `types.int`, `types.nvarchar(50)`, `types.decimal(10, 2)`, `types.datetime2(7)`, … A column's type is the same object, with nullability on the column (D-40).
- **Each type knows:**
  - its description on the wire, read and written;
  - its value layout, read and written;
  - its check: range, length, precision and scale.
- **Wire codes:**
  - parameters use the nullable codes;
  - columns arrive in either the nullable or the fixed-size code, and both map to the same type;
  - the code itself stays visible at the full observability level.
- **Every value round-trips exactly (D-48).** Select → insert → select compares equal, on the server and in Python. A value goes back with its column's type, which carries collation, precision, scale and length.
- **Refuse rather than round.** A value that doesn't fit its declared type exactly is refused before sending: too much scale, too long, finer time precision than declared, or a character the column's code page can't hold.

**Values · *agreed, D-48*.** A Python type is used only where it holds every value of the SQL type exactly, at every scale. Otherwise the value is a driver type.

| SQL Server type | Value | Why |
|---|---|---|
| `tinyint` … `bigint` · `bit` | `int` · `bool` | exact |
| `decimal`, `numeric`, `money`, `smallmoney` | `decimal.Decimal` | exact, provided encoding works from the Decimal's digits. It never goes through `float` or decimal arithmetic, which rounds at 28 digits. A `decimal(38)` has 38 digits. |
| `float`, `real` | `float` | exact. A `real` widens exactly and narrows back exactly; a float that isn't exactly a float32 is refused as `real`. |
| `date` · `smalldatetime` | `datetime.date` · `datetime.datetime` | exact: the same range, and whole minutes |
| `time`, `datetime2`, `datetimeoffset` | driver types holding 100 ns ticks, plus the offset | Python stops at microseconds |
| `datetime` | a driver type holding 1/300-second ticks | microseconds can't hold a third of a millisecond |
| `char`, `varchar`, `text` | `str`, decoded with the server's byte table | Python's codecs refuse bytes SQL Server stores (D-44) |
| `nchar`, `nvarchar`, `ntext` | `str`, keeping unpaired surrogates | SQL Server stores them; Python's strict UTF-16 decoder rejects them |
| `binary`, `varbinary`, `image`, `rowversion` | `bytes` | exact |
| `uniqueidentifier` | `uuid.UUID` | exact. Its bytes are mixed-endian on the wire, and the definition says so. |
| `sql_variant` | the value together with its base type | exact |
| `vector` | a driver value: element type and values | float32 and float16 widen exactly |
| CLR types | bytes and the type's full name (D-43) | exact |
| a table (parameters only) | an iterable or source of tuples, sent with the table type's columns (D-49) | exact: each value as its column's type |
| `xml`, `json` | `str` | The server normalizes these on insert; the round trip is verified from the first normalized value. `json` stays text; parsing it belongs to an outer layer. |
| NULL | `None` | |

Each driver time type converts to Python's types exactly. If it can't, it refuses, unless the application explicitly asks for rounding.

**Collations (D-44)**
- **Which collation applies:** a `varchar` value is decoded with its column's own collation, and a parameter is encoded with the session's collation or one given explicitly.
- **The server's reading, not Python's codec.** The generated file records every byte sequence SQL Server reads or writes differently: single bytes Python refuses (5 in cp1252, 31 in cp874), whole user-defined areas in the double-byte code pages, and cp932's duplicate encodings.
- **Canonical sequences read as characters; any other is carried as escapes,** so every value decodes and encodes back to the same bytes. Encoding checks that each character reads back as itself.
- **UTF-8:** without the UTF-8 login feature (D-8), invalid bytes that SQL Server stores arrive with U+FFFD in their place. Those values can't come back exactly.
- **Special cases:** the UTF-8 flag means UTF-8. Code page 0 can't hold `varchar`. A collation missing from the file raises an error that names its locale id, sort id and bytes.

### Tokens

RETURNVALUE, RETURNSTATUS, NBCROW and ORDER join the definitions. ORDER was seen on the live server for every `ORDER BY`. An unknown tag still ends the connection with a clear error.

### The response

- **A pure state machine in `response.py`.**
  - It is fed packet bodies and produces the record's items (D-42).
  - It keeps the views and applies `Unread` (D-34).
  - It knows nothing of I/O or of what was requested.
- **Incremental decoding:** a token split by a packet boundary waits for the next packet. `wire.py` distinguishes "needs more bytes" from "malformed".
- **Rows in batches:** each read returns every item decodable from what has arrived, keeping per-row overhead low (The Client §2).
- **Rows are counted as they pass.** They are kept only by `fetch()` or `Unread.KEEP`.
- **The end:**
  - the response ends at the completion without *more follows*, and the channel is free;
  - if there were errors, the call that reached the end raises `ServerError(errors, FetchedResponse)`.
- **Cancel:**
  - `response.cancel()` sends Attention (packet type `06`, header only) on the channel;
  - reading then discards everything up to the completion marked *acknowledges a cancel*, and the owner's read raises `Cancelled`;
  - if the request is still being sent, for example while waiting for MARS window credit, the next packet carries *ignore* + *last* instead. This comes in **M4**, with streamed requests, which share the same abandonment (D-41). Until then, a task canceled mid-send leaves its request partly sent, and a pool closes that connection (D-36).
- **A response dropped while open** raises a `ResourceWarning`. Its channel stays busy, so a pool closes that connection (D-36).

### Connection core and shell

- **Packets go to channels.** The packet joiner delivers packets, not whole messages. While connecting, they are still assembled into messages.
- **Backpressure:**
  - **under MARS,** the client returns window credit as the application consumes packets, so a slow reader on one channel slows only that channel;
  - **without MARS,** the reader pauses the socket when the channel's inbox holds a set number of packets.
- **The live `Response`** in `shell.py` is a thin async layer over the state machine. The later synchronous shell (for DB-API) reuses the same state machine.

### Observability

- **Outline:** one line per response when it ends, with a tally of its tokens. Cancel shows as `→ attention` and `← cancel acknowledged`.
- **Full:** each token's tree as it is decoded.
- **Levels** are left for D-12 to decide.

## 4 · Milestones · *agreed, D-46*

Each milestone uses only what earlier ones built, ends with its tests passing against the live server, and comes with its reference pages. Its checks are in [Done When](5-done-when.md).

| Milestone | Builds | Needs |
|---|---|---|
| **M1 · Requests and the response record** | `Batch`, `exchange(request)`, the streaming response and its record (D-34, D-42), cancel, backpressure, NBCROW and ORDER | — |
| **M2 · Every short type** | all numbers, dates and times, `uniqueidentifier`, `char` / `varchar` / `nchar` / `nvarchar` / `binary` / `varbinary` up to 8,000 bytes, `rowversion`, `sysname`; nullable and fixed-size codes; the collation file | M1 |
| **M3 · Calls** | `Call` / `Calls` / `Param(output=)`, `returns()`, `CallOptions`; every M2 type as a parameter | M2 |
| **M4 · Large values, both directions** | the `(max)` types (`types.MAX`), `xml`, and `text` / `ntext` / `image`; `result_set.streamed()` and `ValueStream` (D-47); sources in `Call` and `Calls`, and abandoning a request mid-send (D-41) | M3 |
| **M5 · `sql_variant`** | values that carry their own base type | M2 |
| **M6 · `json` and `vector`** | the login asks for both features (D-8); `json` (`F4`); `vector` (`F5`) in float32 and float16 | M4 |
| **M7 · CLR types** | `hierarchyid`, `geometry`, `geography` and user CLR types, as bytes plus the type's full name | M4 |
| **M8 · Table-valued parameters** | `F3`, parameters only | M3 |
| **M9 · Bulk load** (D-50, D-52) | `BulkInsert` and `BulkRows`, kept together by the channel; rows from a list or a source | M4 |
| **M10 · Transaction manager** (D-51, D-52) | `tds.transactions`: begin, commit, roll back, savepoints, promote, propagate, the coordinator's address | M1 |
| **M11 · Every token the server can send** (D-56) | a definition for every token MS-TDS 7.4 defines, so no response can end the connection with an unknown tag: browse-mode TABNAME and COLINFO, SESSIONSTATE, DATACLASSIFICATION, ALTMETADATA and ALTROW, SSPI and FEDAUTHINFO | M1 |
| **M12 · Slice 1's failures, tested** (D-56) | each way connecting can fail, tested: a server that can't encrypt, an instance mismatch, a version below 7.4, a malformed reply, the connection timer | — |
| **M13 · TDS 8.0 and the observability levels** (D-56) | strict encryption: TLS before the hello, ALPN `tds/8.0`, the certificate validated (D-10); the levels off, outline and full (D-12); replaying a saved conversation offline | M12 |
| **M14 · Connection and login options** (D-56) | session recovery (SESSIONSTATE); the remaining login features (D-8) and identity flags (D-9): UTF-8 support, data classification, read-only intent, failover partner; the dedicated administrator connection (DAC); routing (D-11), against constructed bytes; a Browser client (MC-SQLR), against constructed bytes | M11 |
| **M15 · Always Encrypted** (D-56, D-60) | in the core: every Always Encrypted wire element, with ciphertext shown as it arrives; in `tds.encryption`: the shared context, describing and encrypting parameters, decrypting values, a local key store; read back exactly what it writes. Enclaves come later, on Azure (M18) | M14 |
| **M16 · The convenience layer and the synchronous shell** (D-56) | the serial channel's conveniences (D-37); the bulk-load helper (D-50); the error translator; the synchronous entry point (D-38). DB-API is outside this project (D-25) | M10 |
| **M17 · Other logins, on Azure** (D-56) | Kerberos, NTLM, federated logins and the SQL login variants (D-54, D-55); routing and the Browser, live; Always Encrypted's Azure Key Vault and Windows certificate store key stores (D-60); on transient Azure infrastructure | M14 |
| **M18 · Azure-only login features** (D-8, D-56) | Azure SQL support (failover partner with read-only intent), Azure DNS caching, enhanced routing (D-11), global transactions; Always Encrypted with enclaves (D-60); on the same transient Azure infrastructure | M17 |

**The scenario that grows with them:** a `shop` schema in a `tds_test` database.
- **M1–M3:** products, customers and orders, using every short type, with procedures that return outputs.
- **M4:** `varbinary(max)` photos and `nvarchar(max)` descriptions.
- **M5–M7:** an `sql_variant` attributes table, `json` details and a `vector` embedding, and a `geography` store location.
- **M8:** bulk price updates through a table-valued parameter.
- **Legacy:** an old `ntext` notes column, added in M4.

M8 is done when all of it round-trips.

## 5 · How it's tested

- **Core tests, no server.** The core is sans-I/O, so a test feeds it bytes and checks what it does. The channel rules, request encoding and the response state machine are tested this way. The token sequences on [Request Response](3-reference/response.md) were captured from the live server and become fixtures.
- **Live tests, against the SQL Server 2025 container.** Every fact on Request Response, its rules and its edge cases, is a live test. If a new server version behaves differently, a test fails and the page is updated.
- **Round trips, with values the server generates (D-48):**
  - **The values:**
    - `SYSDATETIME()`, `SYSDATETIMEOFFSET()`, `GETDATE()`;
    - `NEWID()`, `CRYPT_GEN_RANDOM(n)`, `RAND(CHECKSUM(NEWID()))`;
    - every byte under every code page;
    - every UTF-16 code unit, including unpaired surrogates;
    - each type's minimum and maximum, and NULL.
  - **The test:** select them, insert them into a second table through a `Call` with each column's type, and select again.
  - **Passing:** `EXCEPT` in both directions returns nothing on the server, and the values compare equal (`==`) in Python.
  - **When:** from M3, when `Call` exists, for every type each milestone adds.
- **The `shop` scenario** grows with each milestone (§4).
- **The password never appears in output.** Live tests take it through the masked `Secret`, and test output is scanned for it.

## 6 · After these milestones

The second sequence is M9–M18 (§4, D-52, D-56), checked as [Done When](5-done-when.md) lists. The other logins come last, tested on transient Azure infrastructure ([Conversations](3-reference/conversations.md#what-each-way-of-logging-in-needs--built-d-54-d-55), D-54). What follows the milestones is in the [Roadmap](C-roadmap.md) (D-63).

---

**Next:** [Done When](5-done-when.md) · **Decisions:** D-33, D-34, D-40–D-52, D-54, D-56
