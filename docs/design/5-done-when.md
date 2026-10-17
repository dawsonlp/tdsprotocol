# 5 · Done When

**Use this page to** know when each slice and milestone is finished. Checks come in four kinds: what a reader can do, what the client does, what the runtime shows, and how the code reads. The milestones are planned in [Building the Client §4](B-building-the-client.md#4--milestones--agreed-d-46).

## Slice 1 · Connect & log in

**Status: partly built, checked 2026-10-16; updated by M12 and M13.**
- **Built and tested:** the spec's samples round-trip (client 1); connecting on 7.4 with whole-connection encryption (2); every clear failure (4, M12); serial channels (6); the password never shown (runtime 5).
- **Built in M13:** connecting on 8.0 (3); offline replay (runtime 3); the observability levels (runtime 1, 2 and 4).
- **Not built:** routing (5, waits on D-11). *Built in M14.*
- **Not done:** the reader test (*A reader can…*), and a check of the code against its pages (*The code…*).

### A reader can… (the documents work)

Test by giving pages 1–3 to someone new to TDS, or to an assistant with no other context, together with a login capture that does **not** appear in the docs.

1. Split the capture into packets and messages, and name each message.
2. Label every field of the hello and the login, and say what each one does.
3. From the login reply alone, say whether the login succeeded and what the session's database, language and packet size are.
4. Say what would differ under TDS 8.0.

### The client… (the behavior is right)

1. **Round-trips the spec's samples.** It decodes the MS-TDS hello, login and login-reply samples and re-encodes them byte-for-byte.
2. **Connects on 7.4** to SQL Server 2022 with whole-connection encryption, and reaches *ready* with the session state the server announced.
3. **Connects on 8.0** to SQL Server 2022 in strict mode, offering ALPN `tds/8.0` and validating the certificate.
4. **Fails clearly** in each of these cases. Each failure names the step, what was expected and what arrived:
   - wrong password, carrying the server's own error message
   - server can't encrypt
   - instance mismatch
   - server version below 7.4
   - malformed reply
   - connection timer expiry
5. **Handles routing** as D-11 decides.
6. **Provides serial channels as agreed.** Without MARS, a ready connection opens exactly one. Asking for a second fails without disturbing the first (D-18 to D-23).

### The runtime shows… (observability is right)

1. At **full** level, every byte of the connect conversation can be reached by expanding the view, level by level. Each byte appears with its field name, its meaning and the page in Reference that describes it.
2. The names on screen are the names in these docs and in the code (D-7).
3. A saved connect conversation, replayed offline, produces the identical view.
4. At **off** level, nothing about individual messages is kept (D-12).
5. The password never appears, either decoded or as raw bytes, unless it has been explicitly revealed for that session.

### The code… (reads like the docs)

1. The PRELOGIN, LOGIN7 and token definitions can be read side by side with their Reference pages. They match field for field, in the same order and with the same names.
2. The connect procedure reads top to bottom as the steps in [Connect](3-reference/connect.md), and all of it lives in the connection manager (D-17).
3. Every definition and procedure carries its MS-TDS section and spec revision. The engine contains no tag values, field names or message types (D-27).

## M1 · Requests and the response record

**Status: built, 2026-10-16.** All 108 tests pass: core tests on responses captured from the live server, and live tests. Not yet covered:
- **The RPC facts on Request Response** (calls, outputs and ordinals, refused calls, error 8162) are checked against captured responses in core tests. Their live tests need `Call`, which comes in M3.
- **Canceling a request while it is still being sent** (the *ignore* flag) moved to M4, agreed 2026-10-16. Until then, a task canceled mid-send leaves its request partly sent, and a pool closes that connection rather than lending it again (D-36).

### The client…
1. **Takes request objects.** `exchange(Batch(sql))` returns the open response. `exchange(str)` is gone, and the command-line tool and tests use `Batch`.
2. **Reads responses as The Client §4 says:**
   - iterate the response, then each result set;
   - `fetch()` returns a `FetchedResponse` that can be read again and indexed;
   - `finish()` skips rows to the end;
   - `close()` cancels;
   - `returns()` works with each `Unread` choice: `REFUSE` raises, `KEEP` keeps everything, `DISCARD` skips rows.
3. **Records what the server did.** For every example and rule on [Request Response](3-reference/response.md), live:
   - the record (`sequence`, `completions`, `messages`, `errors`, result sets with their completions) matches it token for token;
   - this covers counts under `NOCOUNT`, errors that end a statement or the batch, nested `EXEC`, and ORDER.
4. **Raises errors at the end** with the whole record. The channel is free, and the record is the same at every observability level.
5. **Cancels from any task.** During `WAITFOR DELAY`, another task's `response.cancel()` ends the owner's read with `Cancelled`, and the next request on that channel works. This holds with and without MARS.
6. **Streams in bounded memory.**
   - A response far larger than the inbox limit is read with memory that stays flat.
   - Under MARS, a channel nobody is reading doesn't stall another channel.
7. **Warns about dropped responses.** A response dropped while open raises a `ResourceWarning`, and a pool closes that connection.

### The runtime shows…
1. **Outline:** one line per response, with its token counts. Cancel shows as `→ attention` and `← cancel acknowledged`.
2. **Full:** every token of a response, reachable by expanding the view.

### The code and docs…
1. `response.py` reads side by side with Request Response and The Client §4.
2. Neither `exchange` nor the response reader branches on the kind of request (D-33).
3. Reference › Requests describes the SQL batch, matching `requests.py` field for field.
4. Every observed fact on Request Response has a live test.

## M2 · Every short type

**Status: built, 2026-10-16.** 194 tests pass. Done as listed, with two findings:
- **UTF-8:** when SQL Server has stored invalid bytes, it sends U+FFFD in their place, so those values can't come back exactly (without the UTF-8 login feature, D-8). Valid UTF-8 round-trips.
- **Without the ODBC flag, sessions start with every ANSI option off,** which changes overflow, NULL concatenation and `char` padding. The flag became the named option `connect(odbc=…)`, on by default since M4's design (D-9).

The select → insert → select round trip (D-48) is checked from M3 onward, once `Call` exists.

### The client…
1. **Reads every short type in the `shop` tables,** including NULL, in both the nullable and fixed-size codes, giving the values D-48 defines.
2. **Decodes losslessly.** Every byte 0x00–0xFF stored under each code page's collation decodes to the character SQL Server gives it, including the bytes Python's codecs refuse. `nvarchar` values with unpaired surrogates decode intact.
3. **Generates its byte tables from the server.** The generator compares the double-byte code pages and UTF-8 collations with Python's codecs, and records every difference in `collations.py`.
4. **Decodes `varchar` with each column's own collation.** There is one column per code page family (Latin1, Cyrillic, Greek, Japanese, Chinese, Korean, Thai) and one UTF-8 collation.
5. **Fails clearly on an unknown collation,** naming its locale id, sort id and bytes. This is a core test with constructed bytes.
6. **Encodes and checks every short type.** It round-trips through encode and decode in core tests. A value that doesn't fit its declared type exactly is refused before sending: out of range, too long, too much scale, finer time precision, or a character the code page can't hold.
7. **Keeps time exact.** The driver time types hold 100 ns and 1/300-second ticks. They convert to Python's types exactly, or refuse unless rounding is asked for.

### The code and docs…
1. `types.py` reads side by side with Reference › Data Types.
2. `collations.py` is generated by `tools/generate_collations.py` and records the server version it came from.

## M3 · Calls

**Status: built, 2026-10-16.** All 228 tests pass. Done as listed. `docs/tds-common-structure.md` was retired. Findings, now on [Requests › Edge cases](3-reference/requests.md#edge-cases):
- **A declared `varchar` parameter is in the database's default collation.** A value from a column in another collation is converted when the server receives it. So it goes back exactly only through a parameter declared `nvarchar`, and even then not the sequences that the server itself writes back differently. Through a `varchar` procedure parameter, Greek α arrived as `a`.
- **`sp_execute` called by number refuses a named handle** (error 4002).
- **The server ignores the *no metadata* option.** The driver reads either form.

### The client…
1. **Calls procedures by name and by `Builtin`.** It reads return status, outputs (`output=True`) and function results as Request Response describes.
2. **Handles `Calls`.** For a refused call, one that ends the batch, and calls that all run, `returns()` has exactly the entries the server completed.
3. **Round-trips every M2 type exactly, live (D-48).**
   - Server-generated values are selected, inserted through a `Call` with each column's type, and selected again.
   - `EXCEPT` in both directions returns nothing, and the values compare equal in Python.
   - The values include every byte under every code page, unpaired surrogates, and each type's minimum and maximum.
4. **Applies `CallOptions` as defined.** A `NO_METADATA` call without columns is refused before sending.

### The code and docs…
1. Reference › Requests adds the RPC, matching `requests.py`.
2. `docs/tds-common-structure.md` is retired (D-5).

## M4 · Large values, both directions

**Status: built, 2026-10-16.** All 277 tests pass. Done as listed:
- **1 GB each way, in bounded memory:** read through `streamed()` in about 10 seconds and sent from a source in about 6, while the process's memory grew by less than 200 MB.
- **Every large type round-trips exactly,** `text`, `ntext` and `image` included.
- **Abandoning:** the server answers *ignore* + *last* with a DONE marked *error*, and the pool lends the same connection again. *Corrected 2026-10-16:* a message comes before that DONE ([Requests › Edge cases](3-reference/requests.md#edge-cases)).

Found while building: a result set with large values **waits at its first row** until the application chooses how to read it (tuples, `streamed()`, `fetch()`, or moving to the next result set). The first row's bytes arrive with the column metadata, so without that pause a value meant to be streamed would already have been held whole.

1. **The streaming design is agreed first** (D-47, with D-41). *Agreed 2026-10-16.*
2. **The `(max)` types, `xml`, `text`, `ntext` and `image` round-trip exactly** (D-48), with server-generated values. For `xml`, this is from its first normalized form.
3. **Both ways of reading work** (D-47).
   - Tuples hold large values whole.
   - `result_set.streamed()` provides each large value as a `ValueStream`, which is read once, while its row is current.
   - Moving on discards the unread rest.
   - Text is never split inside a character, under every code page.
4. **A value larger than memory streams both ways with bounded memory.** The test uses a 1 GB `varbinary(max)`, read through `streamed()` and sent from a source.
5. **Sources work in `Call` and in `Calls`** (D-41), and a whole large value is sent with its length known.
6. **Large values arrive whole with the ODBC flag** (the default), and cut to 4,096 bytes with `odbc=False`, exactly as the server sends them (D-9).
7. **Observability never holds a large value whole:** its tree shows the chunk count, total length and first bytes (D-47).
8. **A streamed request whose source fails partway is abandoned whole** with the *ignore* flag. Nothing runs, and the source's own error is raised (D-41).
9. **A request canceled while it is still being sent is abandoned the same way.** This includes a task canceled while it waits for MARS window credit. The next packet carries *ignore* + *last*, the driver reads the server's answer, the channel is free, and the connection is lent again.

## M5 · `sql_variant`

**Status: built, 2026-10-16.** All 301 tests pass. Every base type round-trips exactly, with the same base type, precision, scale, collation, size and bytes (`SQL_VARIANT_PROPERTY`). Found while building: the server writes a decimal in the smallest size that holds it. A `sql_variant` makes this visible, so the driver now does the same.

1. **Every base type a `sql_variant` can hold round-trips exactly** (D-48), and each value reports its base type.

## M6 · `json` and `vector`

**Status: built, 2026-10-16.** All 312 tests pass. Done as listed, except float16, which this server doesn't have. It accepts vector support version 1 only, and refuses `vector(n, float16)`, so the driver's float16 handling is tested with constructed bytes, not live. Findings, now on [Data Types](3-reference/types.md):
- **`json` arrives as UTF-16LE, but parameters must be UTF-8.**
- **A `vector` column has user type 255.**

1. **The login asks for JSONSUPPORT and VECTORSUPPORT** (D-8), and the server's acknowledgement is visible in the login reply.
2. **`json` arrives as `json`, and `vector` as `vector`,** in float32 and float16. Both round-trip exactly as parameters (D-48).

## M7 · CLR types

**Status: built, 2026-10-16.** All 317 tests pass. Values the server generates round-trip exactly, compared as bytes on the server and in Python:
- **`hierarchyid`, `geometry` and `geography`:** random paths, buffered shapes over 1,000 bytes, and points.
- **A user CLR type:** `dbo.Point`, from `tests/clr/Point.cs`, built with Microsoft's .NET SDK Docker image (`tests/clr/build.sh`) and loaded as a trusted assembly. Its values are random points, the extremes of `int`, and NULL.

Found while building, now on [Data Types](3-reference/types.md):
- **A CLR column's type names the database the column belongs to** (`tempdb.sys.geometry` for a temporary table).
- **A fixed-size CLR type is flagged:** `dbo.Point` (.NET's Native format) has a max size of 9, and its column carries MS-TDS's fixed-length CLR flag (`0x100`), now `ColumnFlags.FIXED_LENGTH_CLR_TYPE`.

1. **`hierarchyid`, `geometry`, `geography` and a user CLR type** arrive as bytes with the type's full name, and round-trip exactly as parameters (D-48).

## M8 · Table-valued parameters

**Status: built, 2026-10-16.** All 327 tests pass. Done as listed:
- **Every short type, exactly:** a table of 203 rows with a column of every short type (server-generated values, each type's limits, and NULL) reaches a procedure and is stored exactly. This holds whether the rows are given as a list or come from a source.
- **The `shop` scenario round-trips:**
  - customers, products, attributes and stores, with every type M1–M7 built, go back exactly, compared as bytes on the server and in Python;
  - orders are placed through a procedure whose output is each new order's id;
  - every price is updated in one table parameter, and reads back exactly as the server picked it.
- **Columns the server fills, `DEFAULT`, the sort and unique hint, and the send order** behave as MS-TDS describes.

Found while building, now on [Data Types](3-reference/types.md#edge-cases):
- **The server requires the default status bit for *no table*,** where MS-TDS says it must be zero (error 8060 without it). So `DEFAULT` sends it. *Amended by D-53:* `None` is sent too, without the bit, and the server's refusal reaches the application.
- **The sort hint is checked** (error 4819 for rows out of order).
- **An identity column sent with values is refused** (error 1077).
- **`sp_executesql` needs the table type's name** (error 8059).

1. **A table-valued parameter with a column of every short type** is sent to a procedure, and the procedure sees every row, exactly (D-48).
2. **The whole `shop` scenario round-trips** (Building the Client §4).

## M9 · Bulk load

**Status: built, 2026-10-16.** All 366 tests pass. Done as listed:
- **Exact loads:** 203 rows of every short type, NULL and NOT NULL, from a list and from a source, and the large and special types (`(max)`, `xml`, `text`, `ntext`, `image`, `sql_variant`, `json`, `vector`, `geography`, `hierarchyid`) load exactly, compared as bytes on the server and in Python.
- **1 GB** (1,024 rows of 1 MB) loads from a source while the process's memory grows by less than 200 MB.
- **A source that fails partway** is abandoned with *ignore*: nothing loads, and the channel accepts the next bulk load.

Found while building, now on [Requests › Edge cases](3-reference/requests.md#edge-cases):
- **`json` travels as `nvarchar(max)`,** declared so in the statement as well, like `text`, `ntext` and `image`. `xml` and CLR types may be declared either way.
- **How the options behave,** including that a load without `CHECK_CONSTRAINTS` leaves the constraint *not trusted*.

1. **Every type from M2–M7 loads exactly** (D-48, D-50): server-generated values, each type's limits, and NULL, with the columns from `SELECT TOP 0 *` and the rows from a list or a source. `xml`, CLR and legacy text columns are included.
2. **1 GB loads in bounded memory,** from a source.
3. **Bulk data can't be sent at the wrong time.** After `BulkInsert`, the channel accepts only `BulkRows`, and `BulkRows` is refused at any other time. A source that fails partway is abandoned with *ignore*, and the connection stays usable.
4. **Each `INSERT BULK` option tested live behaves as documented:** `CHECK_CONSTRAINTS`, `FIRE_TRIGGERS`, `KEEP_NULLS`, `TABLOCK`, `ORDER`, `ROWS_PER_BATCH`, `KILOBYTES_PER_BATCH`.
5. **Every bulk-load behavior on [Requests › Edge cases](3-reference/requests.md#edge-cases) has a live test,** deviations from MS-TDS included.

## M10 · Transaction manager

**Status: built, 2026-10-16.** All 366 tests pass. Done as listed. `Propagate` is tested only for its refusal of a bad cookie (error 8509), and the enlist, defect and transaction-ended announcements remain unobserved.

1. **Each request works live, and the session follows its announcements** (D-51), through nesting and savepoints.
2. **Commit-and-begin keeps its isolation level** for the session.
3. **Promote's token is visible** in its announcement, and **the coordinator's address** is read as one row.
4. **`Propagate` is sent as MS-TDS defines it, and only its refusal is tested.** It needs a cookie from a coordinator. The enlist, defect and transaction-ended announcements are unobserved.
5. **Every transaction behavior on Requests, Request Response and Token Stream has a live test,** deviations from MS-TDS included.

## M11 · Every token the server can send

**Status: built, 2026-10-16.** Done as listed.
- **Tested live:** browse mode's TABNAME and COLINFO. Found while building, now on [Request Response](3-reference/response.md#edge-cases):
  - the server sends them under `SET NO_BROWSETABLE ON` and for every kind of server cursor, as well as for `FOR BROWSE`, so each of these used to end the connection;
  - browse mode adds hidden key and `rowversion` columns.
- **Tested with bytes built from MS-TDS:**
  - data classification (both versions) and SESSIONSTATE, which need login features (M14);
  - ALTMETADATA and ALTROW, which SQL Server no longer sends;
  - SSPI and FEDAUTHINFO, which belong to other logins (M17).
- **Corrected:** OFFSET is no longer in the list, because it was removed in TDS 7.2. Also, NBCROW's and ORDER's MS-TDS section numbers in the code were wrong. They are now §2.2.7.15 and §2.2.7.17.

1. **Every token MS-TDS 7.4 defines has a definition,** so no response ends the connection with an unknown tag: TABNAME, COLINFO, SESSIONSTATE, DATACLASSIFICATION, ALTMETADATA, ALTROW, SSPI and FEDAUTHINFO, in addition to those already built.
2. **What each token says is in the response record** (D-42), shown as the server sends it.
3. **Each token the local server can be made to send is tested live,** such as browse mode's TABNAME and COLINFO (`SELECT … FOR BROWSE`). The rest are tested with bytes built from MS-TDS, and the page says which.

## M12 · Slice 1's failures, tested

**Status: built, 2026-10-16.** All 388 tests pass.
- **Tested:** each failure, the server closing mid-connect, and a server that can't be reached.
- **How:** the hello and login replies are fed to the core's connect procedure. The connection timer and the unreachable server use real local sockets.
- **The version check** uses MS-TDS's own sample login reply, which acknowledges TDS 7.2.
- **Made literate while building:**
  - the connection timer used to appear as a bare `TimeoutError`, and a malformed reply as a parse error without its step;
  - now each is a `ConnectError` naming its step (`start`, `hello`, `secure`, `log in`);
  - a malformed reply also shows the bytes that arrived.

1. **Each failure in Slice 1's client item 4 is tested,** and its error names the step, what was expected and what arrived (D-53): a server that can't encrypt, an instance mismatch, a version below 7.4, a malformed reply, the connection timer.

## M13 · TDS 8.0 and the observability levels

*D-10 and D-12 agreed 2026-10-16.*

**Status: built, 2026-10-16.** All 406 tests pass.
- **TDS 8.0:** connects with TLS 1.3 and ALPN `tds/8.0`, verified against the test container's authority. This also works with MARS.
- **Certificate checking:**
  - certificates are checked with Python's `ssl.SSLContext`, and `trust_server_certificate` is gone;
  - every test now verifies the certificate;
  - a wrong name, an unknown authority, and a non-verifying context under 8.0 are each refused with an error that says what the options are.
- **The test container** presents a certificate from a test authority, created reproducibly ([`docker/macos/tls`](../../docker/macos/tls/README.md)).
- **The levels:**
  - off builds nothing;
  - outline and full show the same lines;
  - full opens every message to its fields;
  - the level changes between exchanges, never during one.
- **Every structure names its reference page** in the full view.
- **Captures replay into the identical full view,** byte for byte: under 7.4 and 8.0, with and without MARS, across results, messages, an output parameter, an error, transactions, a bulk load and a cancel. The password stays out of a capture unless it is kept, and is revealed in the view only for a session that asks.

Found while building, now on [Connect](3-reference/connect.md#edge-cases):
- **SQL Server needs a certificate configured before it accepts 8.0.**
- **Under 8.0, SQL Server answers the hello's encryption with *not supported*, and its login reply still says TDS 7.4.** This confirms Login Response's open edge case.
- **Under 7.4, SQL Server negotiates TLS 1.2 at most.**

Fixed while building:
- At outline, a request's line said "0 packets", because the count came from headers kept only at full.
- Written requests showed parameter types as opaque bytes, where reading showed their fields. Both now show the fields.
- Bulk data, a procedure's name and a call's parameters gained reading definitions, for replay.

Not yet: replay can't decode table-valued parameters' rows. Instead, it shows that message's line and says so.

**Timing,** agreed and built 2026-10-16 (D-12 item 7):
- connect steps show their time since connecting began;
- responses show the time to their first packet and to their end;
- captures record those times and the wall-clock start;
- `response.timing` is kept at every level. All 407 tests pass.

1. **Connects on 8.0** in strict mode, offering ALPN `tds/8.0` and validating the certificate (Slice 1, client 3).
2. **The observability levels work as D-12 decides,** and Slice 1's *The runtime shows…* items 1, 2 and 4 pass.
3. **A saved conversation, replayed offline, produces the identical view** (Slice 1, runtime 3).

## M14 · Connection and login options

*Needs D-8, D-9 and D-11 decided first.*

**Status: built, 2026-10-16.** All 470 tests pass.
- **Built:**
  - the login's feature list (D-8: `connect(features=…)`; JSON, vector, UTF-8 support, data classification and session recovery are on by default, each with a command-line switch);
  - the identity options (D-9: application and host name, language, read-only intent, the real process ID);
  - session recovery (D-57): automatic at the next exchange if the connection broke with no request in progress, or through `connection.recover()`. A request in progress is never sent again. It is tested live, with sessions killed and connections cut through a relay, under MARS and TDS 8.0. Its login data is tested against MS-TDS's own example;
  - the mirroring partner, shown as `connection.session.mirroring_partner` and not acted on (D-58), tested with constructed bytes, because SQL Server on Linux has no database mirroring;
  - routing, followed once (D-11), tested against a stand-in router; the DAC, live; and the Browser client, against MC-SQLR's own examples and a stand-in on a local port.

  Every option is listed in [Connect › Options](3-reference/connect.md#options); the Browser has its own page, [Browser](3-reference/browser.md).
- **Found while building:**
  - with UTF-8 support, `json` arrives as UTF-8, not UTF-16LE ([Data Types › Edge cases](3-reference/types.md#edge-cases));
  - a refused DAC closes the connection at the hello with no message; what session recovery brings back and what it doesn't; the undocumented state 254 by which SQL Server says a session can't be recovered, and its reason codes ([Connect › Edge cases](3-reference/connect.md#edge-cases));
  - the answer to an abandoned request has a message before its DONE, which MS-TDS doesn't mention. An M4 test had been matching another response, and claimed otherwise ([Requests › Edge cases](3-reference/requests.md#edge-cases)).

1. **Session recovery:** the login asks for it, SESSIONSTATE is kept, and a broken connection can be resumed with its session as the server allows.
2. **The remaining login features and identity flags work as D-8 and D-9 decide,** each tested live: UTF-8 support, data classification, read-only intent, failover partner (shown, D-58; tested with constructed bytes, because no mirrored server was available in M17 either).
3. **The dedicated administrator connection:** the test container accepts it from outside (remote admin connections on, port 1434 forwarded), and the driver connects through it.
4. **Routing works as D-11 decides,** tested with constructed bytes, and live in M17.
5. **A Browser client (MC-SQLR)** asks for an instance's port, lists instances, and asks for the DAC port, tested with constructed bytes, and live in M17. The MC-SQLR specification is fetched beside MS-TDS into `docs/specification` (`tools/fetch_specifications.py`).

## M15 · Always Encrypted

*Design agreed: D-60, D-61.*

**Status: built, 2026-10-17.** All 563 tests pass.
- **Built:**
  - the core reads and writes every Always Encrypted wire element: the feature, the key table, crypto metadata in columns and output parameters, encrypted parameters with their cipher info, and the enclave package as opaque bytes. A connection with the feature but without `tds.encryption` shows ciphertext;
  - `tds.encryption`: the shared `Encryption`, which opens, pools or wraps connections; describing and encrypting parameters (for `sp_executesql` and procedure calls, positional ones too), describing again when the server refuses a call encrypted with an earlier description it kept; encrypting bulk rows; decrypting values through the core's hook; a local key store of RSA files; `cryptography` as the optional extra `tds[encryption]`.
- **Pass 1:** 28 types, from `tinyint` to `varbinary(max)`, at their edges and NULL, deterministic and randomized, read back exactly, through parameters and through bulk load, and each deterministic lookup finds its row. A column re-encrypted with another key is described again, and the call is sent again. Output parameters, ciphertext without the package, keys that can't be decrypted, the server's refusals, bulk load and a pool are tested live. The wire elements, the encryption, keys and normalization are tested against constructed bytes.
- **Pass 2:** SqlClient 7.1.1 reads every value the driver wrote, inserted and bulk-loaded, and the driver reads every value SqlClient wrote, for the same 28 types, with lookups both ways. Two differences are SqlClient's own: unpaired surrogates, and `time(0)` parameters ([Always Encrypted › Edge cases](3-reference/always-encrypted.md#edge-cases)).
- **Found while building:** table types can't hold encrypted columns; bulk load into an encrypted column names it by its ciphertext's type, as SqlClient's SqlBulkCopy does (found by recording its statement on the server); MS-TDS numbers the algorithm two ways; the client's bulk data needs a key table once the feature is agreed.

1. **The core reads and writes every Always Encrypted wire element** (D-60): the column encryption feature and its acknowledgement (version, enclave type); the key table and each column's crypto metadata in COLMETADATA; crypto metadata in RETURNVALUE; encrypted parameters with their cipher info; the enclave package, as opaque bytes. Each is tested against constructed bytes, and live. A connection that negotiated the feature, without `tds.encryption`, shows encrypted values as ciphertext with their metadata.
2. **`tds.encryption` works as D-60 decides:** a shared `Encryption` context opens or wraps connections and pools, and refuses one whose login didn't ask for column encryption. Its serial channels describe and encrypt parameters, and decrypt values through the core's hook, in every way of reading a response.
3. **A local key store** (an RSA key file) decrypts column keys, and the tests create their master and column keys with it.
4. **Pass 1: what the driver writes, it reads back exactly** (D-48), for every type an encrypted column can hold, deterministic and randomized: through parameters, result sets and output parameters. A lookup on a deterministic column finds its row.
5. **Errors are literate** (D-53): no key store for a key's provider, a key store that can't decrypt a column key, a value whose authentication fails, the server's refusals (such as error 33277, an encryption scheme mismatch), and a connection without the feature.
6. **Observed and documented:** an encrypted large value can't be streamed, since nothing is released before its authentication is checked; whether bulk load into encrypted columns sends the key table; whether table-valued parameters can hold encrypted columns; and what the describe exchange shows at each observability level. Key material is never shown.
7. **Pass 2 (D-61): .NET's SqlClient reads what the driver wrote, and the driver reads what SqlClient wrote,** for every type, deterministic and randomized, with a custom key store over the same keys, in the .NET SDK container.

## M16 · The convenience layer and the synchronous shell

*Needs D-37 and D-38 decided first. DB-API is outside this project (D-25).*

1. **The conveniences** (D-37), **the bulk-load helper** (D-50) and **the error translator** are built around the driver, using only its public surface (D-39).
2. **The synchronous entry point has the same shape as the asynchronous one** (D-38).

## M17 · Other logins, on Azure

*Needs D-55 decided first.*

**Status: built, 2026-10-17,** before M16 (D-62). 583 tests pass on macOS, local and Azure; the Kerberos tests pass on the Linux runner, and the Windows certificate store's tests on SQL Server's Windows VM. The infrastructure was created with Terraform (`infra/azure`) and deleted afterward.
- **Built:** `connect(login=…)` with WindowsLogin, EntraToken and EntraLogin, their tokens from the application (D-55), and adapters for pyspnego and azure-identity; `new_password=`; the hello's FEDAUTHREQUIRED and nonce; LOGIN7's Windows token and federated authentication feature; the SSPI exchange; FEDAUTHINFO and the token message; captures and observability that never show a credential. Key stores: Azure Key Vault, and the Windows certificate store through CNG.
- **Live:** NTLM with a local and a domain account, Kerberos (and SPNEGO choosing it), both Entra ID logins, routing on Azure SQL, the Browser on SQL Server on Windows, changing an expired password and a contained database's user on the local container, Always Encrypted with a Key Vault master key, and with a certificate store master key on Windows.
- **Found:** a routed login must name the routed `server,port` (the original name is refused, 40613); Kerberos's mutual authentication needs no answer, and an empty one breaks the connection; a wrong Windows password is refused as an “untrusted domain” (18452); Azure SQL's Redirect policy routes connections from outside Azure too. Each is on [Connect](3-reference/connect.md#edge-cases) or [Conversations](3-reference/conversations.md).

1. **Each login in [Conversations](3-reference/conversations.md#what-each-way-of-logging-in-needs--built-d-54-d-55) works live** on transient Azure infrastructure, and the infrastructure is deleted afterward (D-54).
2. **Routing and the Browser are tested live** there, including which server name a routed login should send ([Connect › Edge cases](3-reference/connect.md#edge-cases)).
3. **Always Encrypted's other key stores** (D-60): Azure Key Vault and the Windows certificate store decrypt column keys, beside the local one.

## M18 · Azure-only login features

*Needs D-8 decided for these features. Comes after M17, on the same Azure infrastructure.*

**Status: built, 2026-10-17, with two parts open.**
- **The features** can be asked for, each off by default (`--azure-sql-support`, `--azure-dns-caching`, `--enhanced-routing`, `--global-transactions`). Azure SQL Database acknowledged Azure SQL support, DNS caching and global transactions with 1, and enhanced routing with 0 (not enabled). What each changes wasn't seen: the test server had no failover partner, the driver caches no addresses (D-39), no elastic transaction was run, and no ENVCHANGE 21 arrived. *Open:* whether any of them should be a default (D-8).
- **Enclaves:** version 2 and the enclave package, without attestation, were tested live on Azure SQL Database's VBS enclave, with LIKE and range comparisons on randomized columns ([Always Encrypted › Enclaves](3-reference/always-encrypted.md#enclaves)). Found: the package's length is a u16, not MS-TDS's u32. The describing call's attestation parameters must be `varbinary(n)`. *Open:* version 3 (keys cached in the enclave), and attestation through Microsoft Azure Attestation or a Host Guardian Service.

1. **Each Azure-only login feature is requested and acknowledged on Azure SQL,** and what it changes is observed and documented: Azure SQL support (failover partner with read-only intent), Azure DNS caching, enhanced routing (with D-11), global transactions.
2. **Always Encrypted with enclaves** (D-60): the column encryption feature's versions 2 and 3, attestation, and the enclave package, on Azure SQL.
