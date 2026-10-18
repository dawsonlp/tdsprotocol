# Rust TDS client

Build an encrypted TDS conversation that a reader can follow from definition to
wire to response. Keep the code clear, succinct, correct and literate. The shared
[reference pages](../../docs/design/3-reference/connect.md) define the protocol;
Python is the behavioral baseline: inspect its code and tests first when a
question arises, assess the decision against the shared model and observed
behavior, and preserve it when reasonable. Bring suspected design defects to the
user and plan corrections for both languages. Rust ownership changes expression,
not correct behavior; previously agreed differences remain explicit.

The unpublished `tds-client` crate uses edition 2024. It is tested with Rust
1.99.1 on Apple Silicon. There is no promised minimum supported Rust version yet.
`Cargo.lock` records the tested dependency resolution. Tokio is the default,
optional shell; `--no-default-features` builds the protocol core without Tokio.
rustls uses its aws-lc provider explicitly, without installing a global provider.
Trust roots come from the caller; the client has no insecure verification mode.

The [interrupted I/O acceptance matrix](INTERRUPTIONS.md) records deterministic
partial-write, task-abort, cleanup, pool/recovery and runtime-shutdown evidence.

## Run the command line client

The executable is **`clients/rust/target/debug/tds`** after building. From the
repository root:

```sh
cargo build --offline --manifest-path clients/rust/Cargo.toml --bin tds
clients/rust/target/debug/tds --help
clients/rust/target/debug/tds --query "SELECT 42 AS answer"
clients/rust/target/debug/tds --tds-version 8.0 --mars --query "SELECT 42 AS answer"
clients/rust/target/debug/tds --demo-transactions
clients/rust/target/debug/tds --demo-bulk
```

Development defaults use the existing Docker server (`127.0.0.1:14325`, `tds_test`),
its test CA and `MSSQL_SA_PASSWORD` or the ignored Docker `.env`. For another
server, specify host/port/database/user, `--ca-file` and `--password-env NAME`.
There is no password argument or insecure TLS mode. SQL permissions remain the
server login's actual permissions.

Typed procedure parameters are sent as RPC values, never interpolated into SQL:

```sh
clients/rust/target/debug/tds --proc sp_executesql \
  --param '@stmt:nvarchar(4000)=SELECT @n AS answer; SET @n=42' \
  --param '@params:nvarchar(4000)=@n int OUTPUT' \
  --output '@n:int=7'
```

This prints `answer`, the input `7`, the call's return status and output `@n=42`.
`--null`, `--out-null` and `--default` distinguish NULL input, NULL input/output
and a procedure default. Parameter literals use explicit types; `--help` lists
the supported formats. `varchar` literals use the accepted session collation and
refuse unrepresentable characters. CLR declarations preserve identifier case.

Native JSON and exact vectors use the same RPC path:

```sh
clients/rust/target/debug/tds --proc sp_executesql \
  --param '@stmt:nvarchar(max)=SELECT @j AS document, @v AS embedding' \
  --param '@params:nvarchar(max)=@j json, @v vector(3)' \
  --param '@j:json={"note":"é🦀"}' \
  --param '@v:vector(3)=[1,2.5,3]'
```

`--demo-transactions` sends begin/save/rollback-to-savepoint/commit requests and
prints both the announced descriptor and `@@TRANCOUNT`/`XACT_STATE()`. It does not
infer rollback from cancellation. A vector literal such as `[0.1]` is refused
because it has no exact float32 representation. Variant inputs use the library's
explicit `SqlVariant`; returned variants are displayed by the CLI.

`--demo-bulk` creates a temporary table, uploads two rows through a unique row
source (including a large Unicode cell), then prepares another load and explicitly
aborts it. It prints the surviving rows and byte lengths. This exercises the
same public `BulkWriter` used by applications, in either version with/without MARS.

Rows print forward one at a time. `--fetch` explicitly retains the response.
`--observe outline` is the default; `full` also prints redacted packet bytes and
native decoded records, while `off` prints just results/messages/returns.
`--capture conversation.jsonl` creates a recording exclusively; later physical
connections use `.1`, `.2`, etc. Query text and data are recorded; credentials are
masked. The tool reports each recording filename on stderr. Rust-native offline
replay reads the same format as Python: `tds --replay conversation.jsonl`.

The command line uses the public library API, including approved borrowed large
readers and binary file sources. See [the streaming design](../../docs/design/I-rust-rpc-and-streaming.md).
It does not silently buffer unsupported `(max)` columns.

## Table-valued inputs and bulk loads

`ParamValue` separates scalar cells from input-only table rows; returned `Value`
does not contain tables. Scalar `Param::new` calls are unchanged. Code inspecting
the unpublished `Param.value` field must now match `ParamValue::Scalar` or
`ParamValue::Table`. A table declaration identifies an existing SQL table type;
the application creates that type/procedure explicitly.

```rust,ignore
let table = TableType::new("dbo", "lines", vec![
    TableColumn::default_value(int_type.clone()), // identity/computed/default
    int_type,
]);
let rows = vec![vec![Some(Value::Integer(42))]]; // omit default columns
let call = Call::new("dbo.consume_lines", vec![Param::table("@lines", table, None)]);
let request = StreamedCall::new(call).table_source(0, rows.into_iter());
let result = channel.exchange(request).await?.fetch().await?;
```

`Param::table(..., Some(rows))` supplies owned rows instead. `Some(vec![])` is an
empty table; `None` sends the wire NULL form, leaving its refusal to the server.
`Param::default_value` requests the procedure default explicitly. Sort/unique
hints and column placement are declaration metadata; row values stay in declared
supplied-column order. A `RowSource` owns production and yields one whole owned
row at a time. It shares the existing validation, backpressure and partial-input
cleanup machinery with large parameter sources. No producer is replayed.

```rust,ignore
let metadata = channel.exchange(Batch::new("SELECT TOP 0 a FROM #target"))
    .await?.fetch().await?;
let columns = metadata.result_sets()[0].columns.clone();
let writer = channel.bulk("INSERT BULK #target(a int)", columns).await?;
let result = writer.finish_source(rows.into_iter()).await?;
// Alternatively, explicitly stop a newly prepared writer with writer.abort().await?.
```

The application supplies matching `INSERT BULK` SQL and column metadata. The
writer borrows its channel until awaited `finish`, `finish_source` or `abort`.
Abort cancels/drains under the normal cleanup budget; Drop discards. Delegated
close also drains the pending preparation. An unresolved lease return discards,
and recovery refuses the continuation. Successful cleanup preserves whatever
transaction state the server announces; it does not commit/roll back for you.
Bulk ordering is the approved D-50 exception to server-only semantic validation.
Each wire message remains an ordinary exchange. Custom request encoders set the
new `Encoded.continuation` field to `Continuation::None` for ordinary requests.
Python retains its request pair
with the same cleanup/reuse rules. Full contracts and evidence are in
[completion design](../../docs/design/J-rust-completion.md).

The library artifact is `clients/rust/target/debug/libtds_client.rlib`. Run all
ordinary tests with `cargo test --offline --manifest-path clients/rust/Cargo.toml`.
For Docker tests, add `--tests -- --ignored --test-threads=1`. `cargo test --no-run`
prints exact test executable paths under `target/debug/deps/`.

## Read the source in this order

| Source | What it explains |
|---|---|
| [wire.rs](src/wire.rs) | Checked lengths/offsets; incomplete versus malformed input |
| [packet.rs](src/packet.rs) | Header, fragmentation, message end, incremental receive |
| [mars.rs](src/mars.rs) | SMP frames, independent channel credit, sequence wrap and FIN |
| [prelogin.rs](src/prelogin.rs), [login7.rs](src/login7.rs) | Encryption agreement, offset tables, login credentials |
| [requests.rs](src/requests.rs), [requests/rpc.rs](src/requests/rpc.rs) | Request boundary, literal batch, typed calls, names/numbers and parameter status |
| [values.rs](src/values.rs), [types.rs](src/types.rs), [types/codec.rs](src/types/codec.rs), [types/encode.rs](src/types/encode.rs) | Exact scalar payloads, declared SQL types, transactional readers and checked parameter writers |
| [large.rs](src/large.rs) | Incremental PLP/text-pointer framing and exact UTF-16 chunk boundaries |
| [text.rs](src/text.rs), [types/variant.rs](src/types/variant.rs), [types/vector.rs](src/types/vector.rs) | Explicit SQL-corrected character views, bounded variant bases, exact vector layouts |
| [transactions.rs](src/transactions.rs) | Explicit transaction requests; state changes only through announcements |
| [tokens.rs](src/tokens.rs), [session.rs](src/session.rs) | Ordered records, column metadata and announcements |
| [response.rs](src/response.rs) | Retained record, complete-set row availability, independent fetched data |
| [requests/decode.rs](src/requests/decode.rs), [replay.rs](src/replay.rs) | Offline input reading, exact recorded evidence, independent channel decoding and located diagnostics |
| [observe.rs](src/observe.rs), [capture.rs](src/capture.rs) | Owned descriptions, failure isolation, one recording per transport and credential redaction |
| [connection/core.rs](src/connection/core.rs) | 7.4/8.0 procedures, in-memory TLS, busy state, terminal failure |
| [connection/shell.rs](src/connection/shell.rs) | Persistent task, bounded commands, partial writes, deadlines, endpoint retirement |
| [requests/source.rs](src/requests/source.rs), [shell/reading.rs](src/connection/shell/reading.rs), [shell/sending.rs](src/connection/shell/sending.rs) | Unique producers, borrowed readers, incremental sending and partial-input cleanup |
| [pool.rs](src/pool.rs) | Whole-connection leases, capacity, explicit return, reset and discard |
| [config.rs](src/config.rs), [config/shell.rs](src/config/shell.rs) | Comparable settings, safe errors, ordered reads and independently owned acceptance state |
| [live_connection.rs](tests/live_connection.rs) | Actual Docker conversations and failure consequences |

The core acquires no socket, task or clock. The shell supplies Unix time for
certificate validation, host/process identity and received bytes. The crypto
provider supplies cryptographic randomness. Protocol state produces outbound
bytes; the shell performs the writes. Error stage and execution uncertainty are
separate. A transmission failure never causes automatic request replay.

## Ownership and permission contract

Agreed 2026-10-17: one persistent Tokio task owns the socket/core. `Connection`
is a unique owning handle; dropping it revokes all descendants. `SerialChannel`
is movable and non-`Clone`; its internal shared endpoint does not duplicate
public send/read authority. A response exclusively borrows its channel. Native
Rust moves replace Python's task-identity restriction. Multiple MARS channels
coexist without an exclusive borrow of the whole connection.

The core marks an exchange busy before producing its bytes and releases it only
after final completion **and** its message boundary. Once Attention is sent, only
its acknowledgement (and message boundary) permits release; an earlier ordinary
final DONE is insufficient. A forgotten response keeps
that busy state. Dropping an unfinished response, aborting its owner, or canceling
a submitted exchange/read future revokes the connection. Dropping an unpolled
future submits nothing. If execution may have begun, the error says so.

`CloseHandle` grants only connection-close permission. Its revocation flag and
wakeup do not use the command mailbox, so closing can interrupt a waiting reader
or writer. Driver destruction also revokes descendants, including on runtime
shutdown. Explicit `Connection::close()` awaits driver/socket destruction;
destructors do not await or perform blocking network I/O. An idle dropped channel
is released; an abandoned busy channel forces connection discard.

Every connection and pool lease gets a fresh authority endpoint. Channel and
exchange counters are checked, monotonic identities; wire channel ids continue
across reuse of the same transport. A returned lease's endpoint is permanently
revoked before another borrower receives the connection. `CancelHandle` grants cancellation
permission for one connection/channel/exchange lifetime; stale and repeated
controls cannot target a replacement exchange.
Under the agreed initial policy, abandoned MARS exchanges also discard sibling
channels. Awaited channel cancellation/close preserves siblings after proven cleanup.

## Pooling

`Pool::new(options, capacity)?` is lazy; `pool.acquire().await?` lends one whole
connection. Share the pool through `Arc<Pool>` for concurrent tasks. A lease lends
Connection methods through `Deref`, so its borrower opens every channel and owns
its session alone. The pool has no request/exchange method.

**Approved:** `lease.release().await?` is required for reuse. Dropping a lease or
an unfinished release future discards the connection. `ReleaseOutcome::Returned`
means authority was retired and the transport was proved quiescent;
`Discarded` means an active/failed connection or closed pool prevented reuse.
Cleanup errors remain errors. Release does not implicitly cancel an active
exchange. Finish or explicitly cancel/drain it first. Idle channels may survive as
Rust values, but their old send/read/close/cancel controls cannot act on the next
borrower. Explicit return waits for MARS FIN replies under the total cleanup
budget. Cancellation guards cover both old and replacement endpoints.

Python's reset semantics are preserved: the next successfully encoded request's
first TDS packet carries RESETCONNECTION once. Encoding failure leaves it pending.
The client's database/language/packet-size/collation baseline is restored only
when RESET_COMPLETE arrives; a snapshot before the first response still describes
the last announced state. Transactions follow their own server announcements.
No client SQL silently normalizes isolation level or distributed transactions,
which the TDS reset contract exempts. DTC requests/tokens remain unsupported.

Capacity includes opening/reserved and lent connections; idle entries are taken
before opening another. Canceled acquisitions/openings release their reservation.
Failed idle transports can be replaced before lending; in-flight requests are
never replayed. `pool.close().await` wakes waiters and closes idle connections.
Like Python, borrowed connections remain usable until returned/dropped; a login
that completes after shutdown is closed instead of lent. Pool Drop performs the
same revocation without awaiting driver teardown. Credentials remain in the pool's
redacted configuration for subsequent logins.

The [Pool rustdoc example](src/pool.rs) shows the complete acquire/use/release path.

`Pool::from_config(Arc<dyn ConfigService>, capacity, services, policy)?` supplies
current SQL connection values without replacing the pool. Implement `read()` by
returning a `ConfigRead<'_>` future with an owned `ConnectionConfig`. Construction
does no I/O. Each physical opening or eligible recovery reads once within the
opening deadline; ordinary idle checkout does not. `ConnectionServices` holds
fixed TLS roots/server-name override and observation/recording bindings;
`PoolPolicy` holds fixed opening/cleanup budgets.

The pool compares effective values, including passwords, with its own last
accepted snapshot. Active borrowers continue; known obsolete idle/returned
sessions are discarded. A superseded late login fails explicitly. A rejected
login does not retry, fall back or poison the pool: later openings read again.
Recovery allows password-only changes and preserves the routed target and
original logical channel handles. Borrowed recovery remains possible after pool
closure. No source watcher, notification service or extra OS thread is created.
Sources must cooperate with asynchronous scheduling/cancellation and must not
reenter this pool from `read()`.

Deferred reset remains visible: an undiscovered credential change can fail the
first SQL request on a reused session. SQL is never replayed. The full shared
contract and evidence are in [Pool Configuration Snapshots](../../docs/design/H-pool-configuration.md).

## Observation and recordings

`ConnectOptions.observe` accepts an `Observer::new(Level::Outline, callback)`;
the short synchronous callback returns `std::io::Result<()>`. Off builds no
descriptions. Outline and Full have the same step/message/packet/token lines;
Full additionally exposes exact redacted packet header/body and native decoded
Records in `event.inspection`. The core queues owned descriptions; the driver
invokes callbacks after each core step, before publishing writes/results. A
returned callback error disables the observer and remains separately inspectable
through `connection.observation_error()`. Installing an observer clears it.
Panics unwind/discard through the driver guard. Callbacks must not block or
reenter the connection.

`ConnectOptions.capture_factory` returns a fresh non-Clone `Capture` and a distinct
output for each physical connection. `Capture::create(path)` creates exclusively,
so it cannot truncate an earlier file. A writer moves into one driver and stays
with that transport across pool loans. `connection.set_capture(Some(capture))`
attaches it between exchanges; detachment drops it rather than returning a writer
that could combine connections. `set_observe` is also refused during an exchange.

The JSON-lines format retains Python's start/event/packet vocabulary. Every line
is flushed; write/flush failure discards the connection with `ErrorKind::Capture`
and its I/O cause, preserving each response's received prefix and execution
uncertainty. Sent SQL may have executed. This is not a disk-durability promise.
LOGIN7 credentials are zeroed across packet boundaries. Explicit
`Capture::keep_password(true)` authorizes saving credentials but never unredacts
callback inspection. Query text/result data stay in the recording.

Four fresh Docker recordings (7.4/8.0 × plain/MARS) replay through Python's
replay implementation, with correct rows and redacted credentials.
Native offline replay is implemented for supported SQL conversations. Per-field
inspection trees/reference links, detailed response timings and pool-level event
lines remain open; this is not complete D-12 parity.

## Offline replay

```sh
clients/rust/target/debug/tds --replay conversation.jsonl
clients/rust/target/debug/tds --replay conversation.jsonl --observe full
```

Replay opens no connection and reads no password or CA configuration. It accepts
only `--observe` alongside `--replay`. Outline distinguishes recorded events from
decoded messages/records. Full includes packet bodies and exact decoded values;
credential-bearing packet bodies stay withheld. Off prints diagnostics and counts.
Recorded timestamps and durations remain recorded evidence, not replay timings.

The public `replay::replay(BufRead, callback)` emits owned `replay::Item` values.
It reuses the live packet/token/value decoders and input-specific request readers.
`Content::Event.text` is exact `SqlText`, including Python's lone UTF-16
surrogates. Requests materialize whole inputs; responses use the incremental
reader. This is not a constant-memory promise for offline inspection.

One file represents one physical connection; channel numbers identify logical
lifetimes. Decode each routing/recovery recording separately. Malformed lines,
unsupported content and unfinished messages/responses produce located diagnostics.
The valid prefix remains available. CLI issues return a nonzero exit status;
library protocol issues are counted, while reader/callback I/O failures return
`io::Error`. Zero issues does not prove physical closure or that every obligation
created by arbitrary SQL can be inferred. Missing saved NO_METADATA columns,
providers/encrypted content, binary XML and alternate compute tokens remain
explicit limits. Full field trees and reference links are separate work.

Python replay now reads TVP declarations, default columns, hints, column placement
and exact rows, including following parameters and batched calls. It represents
that evidence as `types.TableInput`, separate from result cells. See
[design K](../../docs/design/K-offline-replay.md) and the latest acceptance section.

## Login options

`app_name` defaults to `tds (rust)`; `host_name` defaults to the machine's name
(None/empty), and the shell supplies its process id. `language` is empty by
default: the login's own language is used and the server announces it.
`odbc` defaults true, matching Python: SQL Server selects ODBC's ANSI/TEXTSIZE
defaults from the LOGIN7 flag. With false, the server's own defaults apply. No
hidden SET statements are sent. `read_only_intent` is an availability-group
routing hint and does not prevent writes or grant permissions.

The first minimal encoder used explicit `us_english` and no ODBC flag; these are
now configurable and its defaults match Python. Test scenarios needing English
messages select it explicitly. Deterministic artificial LOGIN7 fixtures generated
by Python match Rust byte for byte, including flags, LCID and empty-field offsets.
The [fixture generator and provenance](tests/fixtures/login7/README.md) keep that
comparison reviewable without requiring Python at Rust test time.

## One-hop routing

`follow_routing` defaults true, matching Python. A successful login announcing
a valid TCP route opens one new physical connection, verifies the destination's
own certificate name and uses the original connection deadline. A TLS name
override for the router is not inherited. The destination's LOGIN7 server name
is `server,port`, matching Python's observed Azure contract. Authentication and
other options carry across; the recording factory produces a separate file.
`connection.routed_from` retains the original typed `Route` across pool reuse.

With `follow_routing=false`, `ErrorKind::Routed` reports the target without
following it. `RepeatedRoute` rejects a second redirect and retains the whole
chain. Both clients reject non-TCP routes, zero ports, empty/NUL-containing names
and nonempty old routing values. A recording failure while reporting the route
prevents the next connection and retains both errors. Controlled tests use
disjoint router/destination certificates and a delayed router; actual Docker
queries pass through a local router under both versions × plain/MARS.

## MARS

Set `ConnectOptions::mars = true` before connecting. PRELOGIN must accept the
option; SMP framing starts after login, for both TDS 7.4 and 8.0. Open channels
independently with `connection.serial_channel().await`. Each channel has its own
response decoder, send queue, advancing reader and cancellation state. All share
one authenticated connection, transaction/session announcements and fatal failure.
MARS provides interleaving; it does not promise parallel SQL execution.

Application ids are monotonic across the logical connection. Each physical
connection allocates its own MARS wire ids from zero; these ids are never reused
within that transport. Exhaustion of its 16-bit wire space requires a new physical
connection. Recovery remaps surviving logical channels in both directions.
Closing sends FIN after quiescence and retains protocol state until the peer FIN;
that transport state grants no application authority. A peer FIN revokes only its
channel; a failed cancellation drain discards the connection. Malformed frames and
fatal server errors fail all waiters, including readers that have not submitted
their next command. Each error retains its own channel's consumed response prefix.
`error.cause()` resolves shared wrappers for typed cause inspection; it preserves
explicit `Cleanup { original, cleanup }` pairs.

## Awaited cancellation cleanup

The response and cancel handle are returned only after the entire batch is
written. Canceling a partly transmitted `exchange()` future discards the socket.
Source failures and channel close during production instead use IGNORE/EOM and
a bounded response drain; cleanup failure discards the connection.

`response.cancel_handle().cancel()` requests Attention without waiting for the
command mailbox. The persistent driver then drains independently of application
reads. The first request starts a separate total cleanup budget,
`ConnectOptions::cleanup_timeout` (default **5 seconds**), covering transmission
and acknowledgement. Repeated requests do not extend it. This budget is unrelated
to a connection deadline or a caller's already-expired query timeout.

`response.close().await` waits for proven cleanup and then permits channel reuse.
An owner's `next()` after external cancellation returns `ErrorKind::Canceled`
only after acknowledgement; later reads return `None`. Canceling/aborting a read
future still discards the connection, including while it awaits cancellation.
Drop continues to discard an unfinished response; it does not begin awaited
cleanup or promise transaction rollback.

`response.close_after(original).await` preserves an existing driver/application
`tds_client::Error`: successful cleanup returns that original error. Failure
returns `ErrorKind::Cleanup { original, cleanup }`. Plain `close()` uses
cancellation as its original cause. Cleanup timeout, malformed/unsupported input,
transport loss or a dropped cleanup future revokes the connection. Cleanup uses
the supported token decoder, not a byte search for something resembling an ACK.
Unknown types therefore force discard instead of claiming safe drain.

The live transaction test confirms that canceling under `SET XACT_ABORT OFF`
leaves its explicit transaction open; session announcements remain authoritative.
This is evidence for that scenario, not a general promise that cancellation
preserves or rolls back transactions under all server settings.

## Delegated channel close

`channel.close_handle()` grants close permission for exactly that channel lifetime.
`handle.close().await` revokes public send/read authority when polled. An active
exchange is canceled/drained under the first close/cancel deadline before release;
an idle channel releases directly. A waiting owner receives closure/cancellation
with its received record. Failure or a dropped close future discards the connection.
Repeats share the result and never extend the deadline. Weak lifetime references
make stale controls harmless without keeping a dropped channel alive.

`channel.close().await` uses the same path. After proven delegated release, dropping
an old response cannot discard a replacement channel. Close can interrupt a full
command mailbox or pending socket write; remaining transmission time counts toward
the cleanup budget, and Attention follows the complete request message. Exhaustive
forced-backpressure write-abort testing remains open.

The same close/reopen contract is implemented in Python, using its existing task
identity rules and a private serialized drainer. Python plain channel ids now name
local lifetimes; they are not a constant wire id. These corrections preserve
ownership isolation and do not grant server permissions or promise rollback.

## Current scope and limits

The live path supports SQL authentication, TDS 7.4 (PRELOGIN then tunneled TLS 1.2)
and 8.0 (verified TLS/ALPN first), plain or MARS channels, literal SQL batches,
heterogeneous scalar rows, multiple results, server messages/errors,
completions, and database/language/packet-size/collation/transaction announcements.
The shell requests implemented Python defaults: SESSIONRECOVERY, UTF-8, JSON,
vector version two and data classification version two. The accepted bytes in
`Session.features` preserve server downgrades. `ConnectOptions` and comparable
`ConnectionConfig` expose these choices explicitly; zero disables versioned
features, and false disables boolean features. Bare `Login::default()` advertises
none, keeping standalone wire definitions opt-in. Unknown types/tokens and unsupported session
changes fail explicitly; the connection is discarded on protocol failure.

Native JSON retains text in `Value::Unicode`; its wire encoding belongs to
`TypeInfo.json_utf8` and the accepted session. Inputs use strict UTF-8 under either
result encoding. CLR retains named serialization bytes without interpreting a
shape/path or loading an assembly. Variants carry their bounded base declaration.
Vectors preserve float32/float16 bits, with checked exact `SqlHalf` conversions.
Browse table/column provenance and sensitivity labels/ranks remain result metadata,
independent of row retention. Full details and approved TVP/bulk contracts are in
[completion work](../../docs/design/J-rust-completion.md).

`SqlTextBytes` keeps raw bytes and collation. Its explicit `decode()` view returns
`SqlText`; `SqlTextBytes::from_text` and `Collation::encode` refuse substitution.
`Collation::decoder` holds only a split character between application-owned
chunks. Sixteen legacy pages and UTF-8 use the generated Python/SQL mappings;
unknown/Unicode-only varchar collations are refused. Reproduce the tables with
`clients/python/.venv/bin/python tools/generate_rust_collations.py` from the root.
Canonical encoding may select a different byte alias; retain raw bytes for exact
wire identity. This does not change Browser's separate strict codec policy.

`Response::next()` reads owned wire records in order. SQL errors appear as
`Record::Error` where they happen; reading through the terminal boundary reports
all of them once as `ErrorKind::ServerErrors`. Read through `None`/`Err`, or call
`finish()`/`fetch()`; stopping at a final DONE alone does not check SQL errors.
Transport, TLS, decoding, fatal server errors and acknowledged cancellation
return typed failures. Response failures carry `error.response`, an owned
semantic snapshot of what arrived, including metadata during cancellation drain.
A failed snapshot never claims an unobserved terminal boundary.

`response.finish().await` drains normally without Attention, discards unread
rows, retains everything else, and returns `()`, as Python does. Inspect the
record with `response.snapshot()`. `response.fetch().await` returns an independent
`FetchedResponse`. Fetch also leaves unread wire records available to the live
reader, now from memory. `ResultSet::rows()` is available only when the set has
completed and every row was retained. A partly streamed set keeps its metadata
and row count but refuses a complete row list; subsequent untouched sets are
still retained. SQL errors/cancellation are reported once per live response.

Semantic metadata is retained from response creation. Ordinary streamed rows are
not automatically retained. Like Python, semantic history and explicit fetch
have no cumulative retention budget; large responses can use substantial memory,
and owned snapshots/replay records can make additional copies. Transport bounds
below do not bound this retained record. A new budget policy must be reviewed for
both clients, rather than silently introduced only in Rust.

SQL text retains UTF-16 code units and converts to `String` fallibly. Rows
own `Option<Value>` cells; `None` is SQL NULL. Column `type_info` preserves the
declared SQL type separately from the original wire code/maximum byte length.
Borrowed result-set/row/value views lend one advancing reader. Procedure returns
retain their own ordered metadata and owned output values. The low-level decoder
adds incremental cell/value events only where a row contains large types.

Prototype bounds are explicit implementation limits, not a final tuning API:
one command in the mailbox; one record per reply; 16 KiB socket reads; 1 MiB per
pending packet/token/envelope buffer and bounded whole-message codec; at most
4096 columns. Large RPC bodies use incremental packet framing; source sends hold
one caller-sized chunk per channel and a packet buffer, while explicitly owned
inputs retain their static body. Outgoing packet/TLS framing adds bounded overhead. The plain driver reads for
a requested record or cancellation drain, and stops while an ordinary caller is
idle, applying TCP backpressure. With `ConnectOptions::mars = true`, the driver
continues routing frames to independent four-frame receive windows. Credit returns
when DATA frames are consumed, including when they split or combine TDS packets.
Each frame is at most 1 MiB (a transport allocation bound). A slow channel cannot
expand its window by leaving rows unread. Send credit stalls only that channel's
queued batch. Pending readers and cancellation drains advance in round-robin order;
queued commands also get a turn during a drain. Memory and latency benchmarks
remain open.
No general memory/throughput claim has been measured.

SQL Server requires encryption to preserve TDS packet boundaries under 7.4.
Encrypting an entire multi-packet message at once failed live; draining TLS after
each packet fixed it. The smoke test sends over 64 KiB to retain this regression.

Pending: other authentication, binary XML, alternate compute tokens,
remaining field inspection and timing work,
platform coverage and a supported Rust version floor.
The broader [Rust plan](../../docs/design/D-rust-development.md) remains a proposal
for those portions. This first slice does not complete R1/R2 in their full scope.

## Session recovery: continuing ownership, new transport

The [experiment](../../docs/design/experiments/recovery-channel-identity.md)
distinguishes a successful recovery login from an actually usable old channel.
The same `Connection`, movable `SerialChannel` values and delegated root/channel
close handles survive eligible recovery. Application-closed channels stay closed.
Each replacement owns fresh TCP/TLS/protocol state, MARS wire ids and a recording
from `capture_factory`. A direct recording without a factory refuses recovery.
Certificate validation remains enabled and one connection deadline covers the
replacement login and channel establishment.

`connection.is_closed()` reports an observed broken transport as well as terminal
closure. Only an observed transport failure can enter recovery; explicit close,
Drop discard, protocol/fatal/cleanup/recording failure cannot. The server must
have agreed to recovery and reported reconstructible session state. Temporary
tables, open transactions and other server-marked state can prevent recovery.
`ErrorKind::SessionNotRecovered` retains a reason and an inspectable cause.

An idle break is recovered before a newly submitted exchange sends its SQL. If a
request was in progress, its waiters fail with their partial responses and
uncertain execution. Subsequent SQL fails until `connection.recover().await`
succeeds. Nothing resends that request or infers that its effects were undone.
`connection.recoveries()` counts successful replacements. Failed attempts leave
the original break inspectable and require an explicit retry; a failed saved
recording discards the connection. Dropping a submitted recovery future discards
its candidate too. Pools discard unhealthy returned transports instead of
recovering on behalf of another borrower.

The driver retires the physical epoch before waking failed exchange waiters.
Exchange/read/cleanup commands and abandonment guards carry their original
epoch. A late old cancel, failed read, or response/future destructor therefore
cannot revoke or consume the replacement. Root and channel close controls retain
logical authority. Epoch comparison and revocation share a short lock so a
replacement cannot slip between them. Already retained data stay readable; old
buffered tokens can precede the original failure, but never come from new SQL.
The driver still discards on abandonment of work in the current epoch.

## Run the checks

From this directory:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --no-default-features
cargo doc --all-features --no-deps
```

Offline tests include ephemeral loopback peers for silence, malformed/refused
PRELOGIN, connection-future abort and failed 8.0 negotiation without fallback.
Controlled verified-TLS peers also exercise delayed/missing Attention ACKs,
cleanup error preservation, stale handles, dropped cleanup futures and a changed
LOGINACK version. Their artificial [TLS fixtures](tests/fixtures/generate_tls.py)
are committed test data, separate from Docker's credentials/certificates; no
machine-specific setup or Python executable is required to run these tests.
Response tests replay seven unchanged Python captures in whole and one-byte
packet bodies, and check finish, fetch, partial fetch, once-only errors, cancel
records and incomplete failure snapshots. See [capture provenance](tests/fixtures/responses/README.md).
Rustdoc compile-fail examples check overlapping responses and use after move.

Start the project's [Docker SQL Server](../../docker/macos/tls/README.md), then run:

```sh
cargo test --offline --test live_connection --test live_recovery --test live_login --test live_scalars -- --ignored --test-threads=1 --nocapture
```

This command fails when SQL Server, credentials or the test CA are unavailable.
The tests use `127.0.0.1:14325`, database `tds_test`,
`../../docker/macos/tls/test-ca.pem`, and `MSSQL_SA_PASSWORD` from the environment
or ignored `../../docker/macos/.env`, exactly as the Python fixture does. No
password is embedded or printed. Compose prepares `tds_test`; Rust does not
silently create databases or grant privileges. Run shared-state mutation suites
serially. See [ACCEPTANCE.md](ACCEPTANCE.md) for the actual results and limitations.

## Browser and the next type boundary

`browser` is a separate MC-SQLR module, not a connection fallback. Its pure request,
reply and instance definitions also build without Tokio. The optional shell sends
one unicast datagram or gathers IPv4 broadcast replies until the original timer
expires. A malformed broadcast reply is ignored; a malformed unicast reply keeps
its bytes and typed error. No advertised address is automatically connected to.

```rust,no_run
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let options = tds_client::browser::Options::default(); // UDP 1434, 1000 ms, ASCII
let instance = tds_client::browser::instance("db.example.com", "SALES", &options).await?;
if let Some(port) = instance.tcp_port()? {
    // The application chooses whether/how to connect to that host and port.
    println!("TCP port {port}");
}
# Ok(()) }
```

Encoding is selected explicitly: `Ascii`, `Utf8` or `Windows1252`. Undefined
CP1252 bytes and invalid UTF-8 fail; names are limited to 32 encoded bytes and
cannot contain zero. Other code pages remain open. Controlled tests use loopback
and unchanged Python/MC-SQLR examples; they do not prove a Windows Browser service.

The full [support matrix](SUPPORT.md) separates implemented behavior, remaining
code, pending decisions and runtime evidence. The approved
[type/value API](../../docs/design/F-rust-value-api.md) now represents scalar rows
with exact heterogeneous values and separate SQL type metadata. Direct
`ConnectOptions.new_password` requests a one-time LOGIN7 password change; a fully
successful final login promotes that credential for recovery and clears the
request. Pools reject this option. Lost completion can leave the server password
changed: `Error.password_change_uncertain` reports that ambiguity; `execution`
still describes application SQL. Canceling connect cannot undo a password change.
Both credential fields stay masked. See [Credential Lifetime](../../docs/design/G-login-credential-lifetime.md).
RETURNSTATUS and RETURNVALUE stay in response order. Each DONEPROC produces a
`ProcedureReturn` with status, outputs, optional function result, completion and
error flag. DONEINPROC does not close the outer call.


## Reading exact scalar values

```rust,no_run
# async fn example(channel: &mut tds_client::SerialChannel) -> tds_client::Result<()> {
use tds_client::{Batch, Value};
let mut response = channel.exchange(Batch::new("SELECT CAST(1.50 AS decimal(10,2))")).await?;
let fetched = response.fetch().await?;
let cell = &fetched.result_sets()[0].rows().expect("complete rows")[0][0];
if let Some(Value::Decimal(number)) = cell {
    assert_eq!(number.magnitude(), 150);
    assert_eq!(number.scale(), 2);
}
# Ok(()) }
```

Scalar reads cover integer/bit, float bits, exact decimal/money, GUID, SQL temporal
values, bounded Unicode/text/binary and both NULL row forms. Decimal rescaling
and time scale conversion are explicit and reject rounding. Legacy datetime
keeps 1/300-second ticks; datetimeoffset keeps UTC coordinates plus the original
offset. `SqlDate` provides checked calendar conversion. Bounded non-Unicode text
retains raw `SqlTextBytes` and its collation; explicit decoded views now cover
the supported SQL code pages without altering the raw payload. Bounded scalar
parameter writers now use the same exact types and reject incompatible payloads,
range overflow and rounding before request bytes are produced.
`SqlText::to_string()` refuses unpaired UTF-16 rather than replacing it.

See [the approved representation](../../docs/design/F-rust-value-api.md) for the
shared Python temporal validation correction, and [design J](../../docs/design/J-rust-completion.md)
for the implemented special-type slice.


## Typed calls and forward results

```rust,no_run
# async fn example(channel: &mut tds_client::SerialChannel) -> tds_client::Result<()> {
use tds_client::{Call, IntegerSize, Param, SqlType, Unread, Value};
let request = Call::new("dbo.read_order", vec![
    Param::new("@order", SqlType::Integer { size: IntegerSize::Int },
               Some(Value::Integer(42))),
]);
let mut response = channel.exchange(request).await?;
while let Some(mut set) = response.next_result_set().await? {
    while let Some(row) = set.next_row().await? {
        println!("{row:?}");
    }
}
let completed = response.returns(Unread::Refuse).await?;
# Ok(()) }
```

`Call::new` takes a name or `Builtin`; `Calls(vec![...])` submits several calls as
one request. `Param::default_value` selects a procedure default, distinct from
`None`/NULL. `.output()` sends the input and asks for the returned value. Call
options are explicit booleans; metadata suppression requires saved column lists.
`SqlType::Character` uses an explicit `Collation`; Unicode values are exact
`SqlText`, and non-Unicode values are `SqlTextBytes` with matching collation.

A live result set exclusively borrows its response. Advancing to the next set
drains unread rows; it does not silently retain them. `returns(Unread::Refuse)`
requires completion; `Keep` reads ahead like fetch, and `Discard` like finish.
Retained outputs and completed-call groups survive row discard and connection
closure. An incomplete call does not receive a fabricated return group.

The [slice design](../../docs/design/I-rust-rpc-and-streaming.md) records current
RPC behavior and the approved, implemented large-value/source ownership boundary.


## Borrowed large values and input sources

```rust,no_run
# async fn example(channel: &mut tds_client::SerialChannel) -> tds_client::Result<()> {
use tds_client::{Batch, Cell, Chunk};
let mut response = channel.exchange(Batch::new(
    "SELECT REPLICATE(CAST(N'x' AS nvarchar(max)), 1000000)"
)).await?;
while let Some(mut set) = response.next_result_set().await? {
    while let Some(mut row) = set.streamed_row().await? {
        while let Some(cell) = row.next_value().await? {
            if let Cell::Stream(mut value) = cell {
                while let Some(chunk) = value.next_chunk().await? {
                    if let Chunk::Unicode(text) = chunk {
                        println!("{} exact UTF-16 units", text.0.len());
                    }
                }
            }
        }
    }
}
# Ok(()) }
```

The borrow chain is response → set → row → value. A chunk is owned data, not a
reading handle. Dropping a view performs no I/O; advancing its parent drains
unread content. `next_row()` and `fetch()` instead assemble existing owned
`Value::Unicode`, `Text` or `Binary` payloads. A streamed prefix cannot later
be reconstructed by fetch. Output parameters remain whole owned values.

PLP supports nvarchar(max), raw collated varchar(max), varbinary(max) and XML.
Legacy text/ntext/image results use text-pointer framing, with provenance stored
in `TypeInfo::legacy`. Legacy inputs are whole, as in Python. Unicode chunks keep
unpaired surrogates and never divide a valid surrogate pair. Non-Unicode chunks
carry raw bytes and their collation, without guessing an encoding.

A `Source` yields `Chunk` through a `SourceRead` future. Bind it with
`StreamedCall::new(call).source(index, source)`: the indexed parameter declares a
PLP type, output status and `None` placeholder. This wrapper owns the producer
uniquely. A source is different from NULL; empty chunks are different from EOF.
Sources must perform asynchronous I/O and must not block the executor. The driver
services MARS siblings and close requests while production waits. On a source
failure, no sent packet means no cleanup; a partial request is abandoned with
IGNORE + EOM and drained before reuse. Cleanup failure discards the connection
and preserves both errors. No SQL or source is replayed. Batched `Calls` accept
whole values. `StreamedCalls(vec![first, second])` consumes several uniquely
owned calls/producers in one RPC message, validating the entire batch before
polling any source. It is not atomic: a later producer failure cannot establish
that earlier calls did not execute. Cleanup never replays the batch.

From the repository root, run the built executable:

```sh
clients/rust/target/debug/tds --stream --query \
  "SELECT REPLICATE(CAST(N'x' AS nvarchar(max)),1000000) AS text"

clients/rust/target/debug/tds --stream --proc sp_executesql \
  --param '@stmt:nvarchar(max)=SELECT DATALENGTH(@b) AS bytes, @b AS data' \
  --param '@params:nvarchar(max)=@b varbinary(max)' \
  --param-file '@b:varbinary(max)=/path/to/file.bin'
```

`--stream` prints chunk counts/sizes and bounded previews. Its advertised total
counts wire bytes; per-chunk sizes count owned payload bytes (UTF-16 for Unicode),
so native UTF-8 JSON can have different totals. `--fetch` retains and
prints whole values; the two reading modes are mutually exclusive. File inputs
are binary; no implicit file text encoding is selected. See `--help` for
connection overrides, observation and recording options.
