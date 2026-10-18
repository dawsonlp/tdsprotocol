# D · Building the Rust Client

**Where this sits:** the next phase of the [Roadmap](C-roadmap.md). The protocol model and reference pages remain common to both clients.
**After reading this you can** explain who owns each resource, what each caller may do, how Rust will preserve the protocol's rules, and what evidence completes each milestone.

> **Status: substantial local implementation; completion scope agreed 2026-10-18 (D-65).** The [support matrix](../../clients/rust/SUPPORT.md) and [acceptance record](../../clients/rust/ACCEPTANCE.md) identify current behavior and evidence. Earlier slice notes below are historical. The [roadmap](C-roadmap.md) now requires local completion including local-key Always Encrypted, followed by a transient Terraform GCP Windows lab, Windows-authentication implementation/acceptance and verified teardown. Entra, Azure-specific providers and Windows certificate-store key-provider support are deferred. The Rust crate remains unpublished; detailed new API/provider choices still need agreement.

## 0 · Vision and requirements

Build a Rust client for TDS 7.4 and 8.0 whose source teaches the protocol and whose running behavior makes its conversations visible. A reader should be able to follow a reference page into a definition, through a procedure, and into an observed exchange. Code should be clear, succinct, correct, and literate. Brevity serves comprehension; it does not justify hiding state, errors, or consequences.

The driver exposes connections, whole-connection pool leases, serial channels, explicitly typed requests, streaming responses, cancellation, and server session state. It preserves exact values and the server's ordered response record. Application conveniences, inferred SQL types, ORM interfaces, and a synchronous shell remain later work. Rust does not depend on finishing Python M16.

The design authority is the shared model, reference pages, and agreed decisions.
**Agreed behavioral rule, 2026-10-17:** inspect Python's implementation and tests
first when a question arises. Assess the decision for correctness and preserve it
when reasonable. Bring suspected design defects to the user and plan corrections
for both languages. Correct behavior should agree; language-specific ownership
expression and previously agreed differences remain explicit. A discrepancy is
investigated against the specification and observed server behavior; Python output
alone does not settle correctness.

## 1 · Ownership and permissions come first

Three different meanings must remain separate:

- **Resource ownership:** which Rust value owns memory, a socket, a buffer, or a lease, and how long a borrow remains valid.
- **Permission to act:** which caller may send, read, cancel, close, or transfer a serial channel. A Rust mutable borrow does not identify an async task.
- **Server authorization:** what the authenticated SQL principal may do. SQL Server decides this; possession of a client handle grants no database privilege.

### Concepts and relationships

A pool owns idle connections and lends each whole connection to one borrower. A connection represents one authenticated session with shared transaction, settings, TLS state, and fatal failure. It provides at most one open serial channel without MARS, and multiple channels with MARS. Channels on one connection interleave and share its session. Separate connections provide independent sessions.

A channel has at most one active exchange. An exchange comprises request production, transmission, and the complete response or acknowledged abandonment. A live response has one advancing reader. Its current result set and streamed value depend on that reader. A fetched response owns retained data independently of the live channel. A cancellation handle refers to one particular exchange; a close handle refers to one particular channel or connection lifetime.

These are relationships, not a requirement that every Rust value be nested by ownership in the same tree. In particular, MARS must allow two channels on one connection to remain usable together.

### Proposed ownership and permission table

Names below describe roles, not final API signatures.

| Resource | Owner and lifetime | Permitted actions | Required enforcement |
|---|---|---|---|
| Pool | Application; internally tracks idle, opening, lent, and closing connections | Borrow a whole connection; close pool | Size limit and exclusive lease; no exchange method |
| Connection / pool lease | One borrower; manager owns socket, TLS, session and channel registry | Open channels; inspect session snapshots; recover only when eligible; close | No direct requests; descendants cannot remain usable after return or close |
| Serial channel | One logical owner within its connection's lease | Owner sends and reads; explicit handover; delegated close | Unique, non-`Clone` movable authority; exclusive borrows plus runtime lease/generation/busy checks |
| Exchange / live response | Exclusive advancing use of its channel until a proven terminal boundary | Read forward; fetch; finish; owner close and drain | Exclusive borrow where practical, plus persistent busy state independent of whether a Rust guard was dropped |
| Current result set / streamed value | Borrow of the response's current position | Advance this view; explicitly keep or discard unread data | No read after advancing past it; no borrow into a buffer that the decoder may overwrite |
| Fetched response | Owns its data, metadata and completion record | Re-read and index independently | No live session authority or socket borrow |
| Cancel handle | Deliberately shareable control permission for one exchange | Request cancellation, repeatedly, from another task | Connection generation + channel identity + exchange generation; stale handles never cancel a later exchange |
| Close handle | Deliberately shareable permission for its target lifetime | Request channel or connection closure | Idempotent; cannot send SQL or read rows; cannot target a replacement lease |
| Input source | Application transfers or lends it for the exchange | Produce typed chunks or rows under backpressure | No request task outlives borrowed input; source error and abandonment are preserved |
| Session state | Connection manager | Apply server announcements; expose read-only views | Every MARS channel sees one authoritative session; fatal failure reaches every channel |
| Observer / capture | Configured by the application, called at a defined boundary | Observe redacted events; explicitly authorized capture | No protocol mutation or reentrant exchange; bounded retention and a documented callback failure policy |
| Credentials / decrypted keys | Login options or encryption context | Authenticate / encrypt through the configured provider | No accidental `Debug`, error, tracing, or capture disclosure; explicit key lifetime and cache policy |

**Selected proposal: unique movable Rust ownership.** On 2026-10-17 the user chose to propose movable channel authority and document the change from Python task identity. The detailed API remains a proposal; preserving task identity is no longer the recommended Rust direction.

Python D-21 binds a serial channel to its opening task and requires `hand_over(task)` to change that identity. The Rust proposal binds send/read permission to possession of one non-`Clone` channel authority and its exclusive borrows. Moving that authority into another task transfers ownership; the previous task cannot continue using the moved value. No task-ID lookup or wrong-task error is required merely because the handle moved. Rust's `Send` and `Sync` describe thread transfer and sharing; they do not identify async tasks. See the [Rust concurrency documentation](https://doc.rust-lang.org/book/ch16-04-extensible-concurrency-sync-and-send.html).

| Python contract | Proposed Rust contract | Preserved consequence |
|---|---|---|
| Opening task owns the channel; explicit `hand_over(task)` changes identity | A Rust move transfers unique channel authority; an exclusive borrow lends temporary access | Two independent send/read authorities cannot exist |
| Sequential use by another task fails without handover | Sequential use after a permitted move or exclusive loan is valid | At most one advancing caller and one active exchange |
| Runtime owner check rejects a shared handle used by the wrong task | Types prevent unintended aliases; runtime checks enforce channel, lease, generation and exchange state | Invalid protocol state fails before bytes are emitted |
| Cancel/close may be called from another task | Separate generation-scoped control handles may be shared | Delegated control grants no send/read permission |

A deliberate `Mutex<SerialChannel>` can permit sequential lending across tasks under this proposal. That is valid Rust ownership, unlike Python's strict task-identity contract. The library must still never queue an exchange behind an unread response: a lock only protects access to the value, while the core's busy state protects the conversation. Moving or lending a channel does not reset that state, grant SQL privileges, or detach a response from its channel or lease.

Prefer native moves for handover rather than an API naming a destination task. An active response's exclusive borrow prevents moving its channel independently. Whether a complete channel-and-response owner may move together, and the relevant `Send` bounds for borrowed views and sources, are API details to settle in R0. No `unsafe impl Send/Sync` is justified by this direction.

A response borrows the channel's advancing authority in the preferred API sketch. This alone is insufficient: after that response is dropped, Rust may permit another borrow while the server still has an exchange in progress. The core must continue to reject reuse until it has seen the correct terminal response. Pool leases similarly need persistent registry state, not reliance on destructor order. Safe Rust can deliberately omit destructors with [`mem::forget`](https://doc.rust-lang.org/std/mem/fn.forget.html).

### Cleanup and cancellation contract

The proposed lifecycle is:

```text
idle -> sending -> reading -> idle                  final completion consumed
            |          |
            +----> abandoning / canceling -> idle   required response or acknowledgement consumed
                              |
                              +-> unusable          failure, cleanup timeout, or lost driver
```

A successful `INSERT BULK` opening response also leaves an explicit continuation obligation. Its channel is not available for unrelated requests until the paired bulk-data conversation completes or is safely abandoned. Preserve D-50 and Python's `OutOfTurn` checks.

- **Before any request byte is sent:** validation failure releases local exchange state. A pending session-reset flag remains pending.
- **Partly transmitted message:** preserve D-41: send IGNORE + LAST and consume the server's abandonment response. A source error is reported with its parameter/row/column context.
- **Complete request sent:** Attention requests cancellation. Reuse requires consuming its acknowledgement, including any later message carrying it. Requesting cancellation is not evidence that the operation did not run or that its transaction rolled back.
- **Explicit async close, agreed/implemented 2026-10-17:** `response.close().await` sends Attention and drains through its acknowledgement under a separate configurable total deadline (default 5 seconds). Repeated cancellation does not extend it; it does not inherit an expired query timeout. `close_after(original)` preserves the original error, pairing it with a cleanup cause if needed. An ordinary final DONE after Attention is not sufficient for reuse.
- **Response/future drop, task abort, panic, timeout or canceled `select!` branch:** do not assume Python's awaited `__aexit__` has an equivalent. [`Drop::drop`](https://doc.rust-lang.org/stable/core/ops/trait.Drop.html) is synchronous. The agreed current policy discards an unfinished connection even though explicit awaited cleanup is available. Automatic cleanup after Drop requires a separate decision. Any such future cleanup would own all required state and finish before reuse; never spawn a detached task borrowing a dying response.
- **Drop during cleanup or runtime shutdown:** remain unavailable for reuse; close/discard the connection if cleanup cannot finish. No blocking network I/O or panic in `Drop`.
- **Network failure after transmission begins:** report the known send stage and uncertainty about execution; never automatically resend an in-flight application request (D-57). Idle recovery is a different operation.
- **Pool return:** return to the idle set only with no active exchange, continuation, surviving live authority, or unresolved cleanup; arrange the protocol session reset before the next borrower's first request. Preserve the documented isolation-level and distributed-transaction reset exceptions. Do not promise a stronger reset than SQL Server provides.

The shell must define cancellation behavior for every await point: socket read/write, TLS handshake, window credit, producer polling, pool acquisition, authority transfer, and cleanup. Apply Tokio's [cancellation-safety discussion](https://docs.rs/tokio/latest/tokio/macro.select.html#cancellation-safety), including the distinction between cancellation-safe partial I/O and convenience operations that can lose progress when dropped.

### Authentication and server permissions

Verify the server's identity before releasing credentials. Preserve full encryption, hostname validation, version checks, one routing hop, and a single connection deadline (D-10, D-11). The routed destination is verified under its own name. A captured server announcement does not independently authorize access to keys or a key store; provider policy controls those operations.

The test `sa` account exists for setup and tests that create databases, logins, CLR types, or server settings. It is not the application's default identity. Add tests with a restricted test principal: allowed query succeeds, denied read/write returns SQL Server's actual error, and permission denial does not trigger privilege escalation or unsafe retry. Keep privileged setup separate from restricted-principal assertions. No automatic grants, impersonation, or schema changes in normal client use.

Secret-bearing types have redacted `Debug` and error formatting. Credential redaction covers passwords, changed passwords, Windows tokens and federated tokens, including fields split across packets. Raw capture contains query text and data; it is explicitly enabled. Revealing credentials requires a distinct explicit option, consistent with D-12. Decrypted key storage, clearing on drop, cache bounds and invalidation need a documented policy; zeroization is not a guarantee that every historical copy has been erased.

## 2 · Rust practices and the learning contract

Each teaching module begins with its concept, reference-page link, specification section/revision, a short explanation of the wire shape, and its invariants. Definitions retain the documentation's field order and protocol vocabulary. A worked example follows actual bytes through encode, fragmentation, receive, decode, and the response record. Explain why a check or transition exists; avoid comments that repeat a statement.

Use ordinary structs, enums, newtypes, slices, explicit matches, `Option`, `Result`, and `?`. Keep fields private where constructors establish invariants. Use checked offset/length arithmetic and fallible integer conversions for untrusted sizes. Distinguish incomplete input from malformed input and end-of-stream. Report byte offset and field context. Unknown tokens cannot be skipped unless their framing makes that safe under an explicit rule.

Keep generic machinery small. Python's dynamic `Field` / `Struct` vocabulary is evidence of intent, not a requirement to build an elaborate Rust DSL. Start with explicit typed definitions and a small checked reader/writer. Add a table or macro only when repeated concrete structures justify it and a reader can still see names, wire types, order, lengths, redaction and source. No procedural-macro framework or generic protocol ontology in the initial slice.

Prefer static types for the known vocabulary; use traits for actual alternatives such as request encoding, observation, token production and key providers. Select static versus dynamic dispatch at the boundary that needs it. Avoid propagating runtime/provider generics through every public type. A small action/state enum can express the Python generators' protocol steps without pretending Rust has identical generator semantics.

Use safe Rust for client implementation. Do not add `unsafe`, manual `Send`/`Sync`, packed-memory wire casts, or unchecked UTF-8 to bypass a difficult API. TLS and cryptography use maintained libraries, with dependencies and feature sets reviewed in R0. The Python core's lack of dependencies does not imply reimplementing TLS in Rust. Share state only where the connection model requires it; document each `Arc`, lock, queue and task's owner, bound, wakeup and shutdown behavior. Avoid holding a mutable core borrow or synchronous lock across I/O or user callbacks.

Library errors are typed and implement `Display` and `std::error::Error`; callers can inspect server number, state, severity, request stage, source and partial record. Production paths do not `unwrap`, `expect`, panic, or use lossy conversion for network or application input. Test assertions may do so where failure is intentional. Public fallible methods document errors; async methods document cancellation, buffering, unread data and cleanup. Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/documentation.html).

Prefer owned row values and metadata initially. Introduce borrowing or shared byte storage only where it remains easy to explain and measured work justifies it. No self-referential response/buffer design. A streamed value may hold a bounded chunk or a borrow whose lifetime prevents decoder advancement; it cannot expose a dangling slice after the next read.

Literate means readable executable source, useful rustdoc, a short reading path, examples, and exact error explanations. It does not mean putting every line into a separate prose document. The off/outline/full observation modes must produce the same result/error semantics. Off avoids inspection-tree construction. Full output has documented byte-retention limits and redacts every representation of credentials.

## 3 · Settle exact representations before procedures

The Python [baseline analysis](E-python-baseline.md#porting-findings) identifies behavior that an idiomatic-looking Rust port could lose. The following representations are proposals for R0; adapters to application types are separate.

| Concept | Proposed exact representation / obligation |
|---|---|
| SQL type vs value vs column | Keep declared SQL type (length, precision, scale, collation), nullable value, and column metadata distinct. One vocabulary describes parameters and result columns; no inferred SQL types in the driver. |
| Decimal and money | Checked integer coefficient plus scale and sign as needed, covering precision 38 and wire signed zero. No float intermediate. Verify the chosen decimal library's actual range; a 96-bit coefficient is insufficient. |
| Date/time | SQL-specific dates/ticks/offsets with full server range, 100 ns precision and legacy 1/300-second ticks. Conversions explicitly fail if the target cannot represent the value. |
| Unicode text | An exact SQL text value capable of retaining UTF-16 code units, including unpaired surrogates; fallible conversion to `String`. Rust [`String`](https://doc.rust-lang.org/std/string/struct.String.html#utf-8) always contains valid UTF-8. Never use replacement decoding for the authoritative value. |
| Non-Unicode / UTF-8 text | Preserve raw noncanonical bytes alongside the relevant collation and a defined decoded view. Python's surrogate escapes are an implementation technique, not a Unicode format to copy blindly. Keep read/write equality for duplicate code-page encodings and invalid stored UTF-8. |
| Binary / GUID / floats | Preserve bytes and the GUID's mixed wire endianness. Keep float width and exact bit patterns in comparison fixtures, including signed zero and nonfinite cases where supported. |
| Variant / CLR / vector | Preserve base type and metadata, CLR qualified type name and opaque bytes, vector element type and exact element representation. No fabricated geometry or JSON semantics. |
| Response record | Ordered items plus token-derived views. Missing row count is `None`, not zero. Duplicate/empty column names remain legal. Errors retain the record; rows already streamed past are counted, not reconstructed. |
| Live vs fetched | Distinct stream and owned-data types with consistent reading concepts; Rust does not need Python inheritance. Agree any public API difference explicitly. |
| PLP / legacy large values | Separate NULL, empty, known/unknown total length, chunks and terminal marker. Define bounded incremental decoding and exact re-encoding across character boundaries. |

Agree a small language-independent fixture schema: hex/base64 bytes, UTF-16 code units, decimal coefficient/sign/scale, integer ticks, float bits, explicit SQL metadata, provenance and expected record. JSON numbers alone are insufficient for large integers and exact floats; ordinary JSON strings are insufficient for every SQL text value. Keep existing Python fixtures until a loader verifies that conversion changes no bytes or meaning.

## 4 · Components and implementation boundaries

Proposed location: `clients/rust/`, preserving the concept names in `clients/python/tds/`. Start with one small crate and modules; split crates only for an evidenced distribution or dependency boundary. Agree package name, edition, minimum supported Rust version, toolchain and dependency policy in R0. No directories or empty modules are created before their slice needs them.

| Component | Responsibility | Must not own |
|---|---|---|
| `wire` | Checked reader/writer, offsets, lengths, incremental progress, bounded inspection nodes | Protocol tags, field names, policy, sockets |
| `packet`, `prelogin`, `login7`, `tokens`, `types`, `requests`, `transactions` | Named protocol definitions, exact values, constraints and source links | Runtime scheduling or application conveniences |
| `response` | Token-driven record, current read position, unread choices and terminal conditions | Operation-specific interpretation or network I/O |
| `session` | Login baseline, announcements, transaction descriptor and recovery state | Independent state copies per MARS channel |
| `connection::core` | Protocol procedures, authority/lease checks, channel state, framing, TLS state, MARS credit and failure propagation | Socket/task/time acquisition |
| Async shell | Socket ownership, scheduling, deadlines, bounded transport queues, performing core actions | Protocol decisions duplicated outside the core |
| `observe`, `capture` | Readable events, secret masking, compatible packet capture and replay | Unbounded data retention or authority to execute requests |
| `logins`, optional adapters, `encryption` | Token exchange contracts, provider integration, encrypted wire values and optional cryptographic orchestration | Identity-library policy inside generic machinery |
| Pool | Exclusive leases and safe return/discard using the connection's contract | Requests or sharing channels between unrelated borrowers |

**Approved shell structure, 2026-10-17:** one persistent Tokio task owns the socket and core. Unique movable channel handles own shared endpoints, not long-lived `&mut Connection` borrows; responses exclusively borrow their channels. Connection closure revokes descendants. Bounded commands/replies carry work; an independent revocation flag/wakeup permits shutdown when the mailbox is full or I/O waits. Unfinished-response/future abandonment discards the whole connection, independently of the implemented explicit awaited cleanup. This shape now supports independently advancing MARS channels with per-channel credit and shared failure; whole-connection pooling is now implemented with explicit awaited return and endpoint retirement.

**Approved runtime/TLS pairing, 2026-10-17:** Tokio and rustls. The initial crate uses rustls's in-memory [client connection](https://docs.rs/rustls/latest/rustls/client/struct.ClientConnection.html), its explicit standard aws-lc provider and caller-supplied trust roots. Certificate-validation time is supplied by the shell. Live smoke tests now prove 7.4's tunneled handshake/raw TLS transition and 8.0's TLS-first `tds/8.0` negotiation, including hostname/CA rejection. A larger request exposed the documented packet/TLS-boundary constraint and now guards its fix. General provider/root adapters, routing, exhaustive partial-write cancellation and platform coverage remain open. A generic TLS stream wrapper alone would not prove the 7.4 transition.

Bound pending transport bytes, per-channel packets, inspection capture and shell
command/reply queues. Return MARS credit as packets are consumed; a slow reader
must not cause unlimited transport buffering or block every sibling channel.
Semantic response history and explicit fetch follow Python's current retention
policy, with no new cumulative budget. Their memory cost is separate from
transport bounds. Any proposed semantic-retention limit and its failure behavior
must be reviewed for both languages. Backpressure tests measure behavior, not a
throughput claim.

## 5 · Proposed milestones and completion evidence

R numbers retain the original milestone proposals. D-65 supersedes R8's full-authentication/provider scope and its ordering: local-key Always Encrypted precedes the GCP campaign; Windows authentication follows; Entra and the excluded providers are deferred. R numbers do not mark Python milestones complete or change existing acceptance records. Each unresolved choice is agreed before the affected code begins. Each implementation milestone includes its teaching documentation and relevant offline and live checks; skipped checks remain incomplete evidence.

| Milestone | Deliverable | Completion evidence |
|---|---|---|
| **R0 · Agree ownership, permissions and representation** | Resolve the decision list below; write lifecycle tables and API sketches; compare normal/error examples | Review one channel, overlapping use, move/loan across tasks, use-after-move rejection, stale cancel, two MARS channels, dropped response/future, forgotten guard, pool return, permission denial and unknown execution outcome. No unresolved semantic choice is hidden in a signature. |
| **R1 · Literate crate and byte foundations** | Crate/toolchain; module reading path; small checked codec; packet, PRELOGIN and LOGIN7 definitions; neutral fixture loader | Spec samples encode/decode exactly; every relevant byte split; malformed offsets/lengths/overflow/unknown tags; redaction across split credential messages. Working rustdoc example follows bytes and invariants. |
| **R2 · First complete connection and exchange** | SQL login, TDS 7.4 TLS, a plain serial channel, `Batch`, minimal token/type set, streaming response, cancel, close and observation | Trusted TLS `SELECT 1` live; reject wrong host/untrusted cert/login/version; response record matches Python; unique-authority/busy rules; drop/timeout at send/read boundaries never permits dirty reuse. Limited type support is explicit. |
| **R3 · Exact short types and calls** | All short types/collations; typed `Call`/`Calls`, output parameters and returns | Python type corpus and response samples; precision 38, time extremes, unpaired surrogates, noncanonical encodings, NULL/empty; outputs by ordinal and name; invalid whole values emit no bytes. Restricted-principal allowed/denied scenarios. |
| **R4 · Large values and request sources** | PLP and legacy large values, streamed input/output, unread keep/discard/refuse, abandonment | Chunk-boundary/character tests; bounded slow consumer; producer error; task abort before/partway/after send; IGNORE + LAST or Attention and matching response; original error and protocol state retained. |
| **R5 · MARS and pool isolation** | Multiplex framing and credit, interleaved serial channels, whole-connection leases, reset/discard | Two MARS readers share one session without sharing advancing authority; slow-reader independence; fatal failure fanout; stale handles after reuse; pool saturation/canceled acquisition; dirty return closes; reset exceptions explicit. Extend R2–R4 checks under MARS. |
| **R6 · Remaining requests, types and tokens** | Variant, JSON/vector, CLR metadata, TVP, bulk pair, transaction manager, remaining tokens | Matching Python unit/live scenarios, bulk continuation refusal, transaction announcements and exact values. Independent .NET encryption interop belongs to R8, not this type round trip. Mark float16/server limitations explicitly. |
| **R7 · TDS 8.0 and connection resilience** | TLS-first/ALPN, full option vocabulary, routing, Browser, recovery, capture/replay | 7.4/8.0 and MARS matrix; routed certificate check and one deadline; idle recovery preserves state and never resends an in-flight request; captures replay both directions for the supported message set. TVP replay is implemented; missing saved NO_METADATA context and unsupported extensions remain explicit gaps. |
| **R8 · Additional logins and Always Encrypted** | SSPI/federated token contracts and optional adapters; encrypted wire metadata; key providers, exact normalization, optional encryption context | Local crypto vectors and mutual .NET read/write checks, deterministic lookups; separately scheduled Windows/Kerberos/Azure/provider evidence. No claim of enclave attestation without its implementation and tests. |
| **R9 · Readability and release review** | Complete reading path, examples, public docs, supported feature matrix, license/notices, package checks | New reader can trace a login and failed/canceled exchange; full meaningful regression suite; documented skips/gaps; fmt/Clippy/docs checks; fuzz malformed/fragmented inputs; no unreviewed unsafe or credential disclosures. Publish only in an explicitly authorized release task. |

R2 establishes safe failure behavior before feature breadth. R5 exercises cross-channel and cross-borrower boundaries before resilience or provider work. Within R6, each capability is a small independently reviewable slice rather than one large port.

## 6 · Verification strategy

Use three independent comparisons: specification samples, captured/constructed Python fixtures, and fresh SQL Server scenarios. Shared bugs can pass client-to-client comparison. Always Encrypted adds Microsoft's SqlClient as an independent implementation because a self round trip can conceal incompatible normalization (D-61).

Compare deterministic protocol bodies and semantic records, not TLS ciphertext or incidental session IDs/timing. Fixtures explicitly identify variable fields such as PID, client identifiers, nonces, routing targets and negotiated session state. Do not normalize a field merely because a comparison failed. Capture compatibility needs an explicit schema/version policy and a test for what each client can actually replay.

Compile-fail examples check aliasing, retained views after response advancement, unintended cloning, use after move and duplicate advancing authority. Runtime tests check busy protocol state after drop, generations, permitted sequential lending, stale close/cancel, and MARS limits. A control handle must remain usable when the producer is waiting or a data queue is full. Authority transfer cannot leave two authorities valid or detach an active response; settle the permitted move/borrow shapes in R0.

Use `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, unit/integration tests, and rustdoc tests for the chosen feature matrix. Test the no-runtime core separately and test supported feature combinations rather than assuming all-features covers them. Network tests require an explicit mode that fails when SQL Server is unavailable, so an all-skipped live suite cannot pass a milestone. Add property/fuzz tests for bounded decoding and fragmentation where they can find distinct failures; do not create tests that only mirror implementation statements.

Live test setup owns only this project's isolated container and disposable test databases/logins. Existing Python tests modify server settings and reuse named databases, so run them serially and never against an unrelated database server. Do not run Python and Rust fixture mutation suites concurrently on the same test database. Retain exact commands, image digest/server version, test counts, skip reasons and known limitations in each baseline.

## 7 · Decisions needed before implementation

| Choice | Recommended starting proposal | What must be agreed |
|---|---|---|
| Ownership semantics | User-selected proposal: unique movable authority, with the documented Rust variation to D-21 | Exact move/loan API, active-response transfer and `Send` bounds; no task-identity checks |
| Handle/lifetime structure | Unique channel authority; borrowed advancing response; generation-scoped controls; lease invalidation | How multiple MARS channels coexist and how live descendants prevent pool reuse |
| Cancellation/drop | Approved/implemented: persistent task, discard on abandonment, awaited Attention/drain, separate configurable 5-second cleanup budget, original/cleanup error pairing | MARS/window-credit integration and exhaustive partial-write tests; automatic cleanup after Drop remains a separate choice |
| Exact values | Small SQL-specific exact types; convenient checked conversions outside the wire representation | SQL text type, decimal/sign/scale, times, row/value vocabulary and fetched/live reading API |
| Runtime/TLS | Approved: Tokio shell and in-memory rustls; runtime-independent core | Supported platforms, dependency configuration, provider/root/time policy and actual 7.4/8.0 interoperability |
| Dependencies/layout | `clients/rust/`, one crate initially, safe Rust, limited optional adapters | Crate name, MSRV/edition/toolchain, library choices and feature boundaries |
| Fixtures/captures | Incremental neutral fixture corpus; existing captures retained | Schema/version, exact encodings, provenance and cross-replay scope |
| Budgets/observers/keys | Bounded transport buffers, Python-compatible semantic retention, explicit fetch costs, redacted observation; approved observer failure isolation, recording failure discard and one recording per physical connection | Any new semantic-retention limits require a shared-language decision; key cache bounds/invalidation and secret clearing remain open |

The connection-first slice, awaited cancellation cleanup and Python-compatible
response retention are working for the supported integer/token subset. This does
not complete broader R1/R2 acceptance. The response record is retained from
creation, ordinary rows stream without retention, finish drains without Attention,
and fetch exposes complete retained result sets only. Partial fetch preserves the
live unread tail but cannot reconstruct rows already passed. Checked completion
reports SQL errors once with the received record. Like Python, there is no new
cumulative semantic-retention budget; any such policy needs a decision for both
languages. Full result-set iteration, large values and procedure returns remain
open. Keep Compose prerequisites, fixture provenance and comparison boundaries
explicit. The Rust acceptance record and Python baseline separate observed
behavior from planned parity.

### Shared channel lifetime and close: agreed and implemented

On 2026-10-17 the user selected cancel/drain before release, with connection
discard on cleanup failure, for both languages. A core-only Python probe had
shown that closing a busy plain channel permitted premature replacement and
that stale channel id `0` could close its replacement. No live cross-delivery
was claimed. The correction now revokes public authority immediately and keeps
the channel occupied until cleanup and the message boundary are proved.

Rust exposes `ChannelCloseHandle`; Python permits another task to call the same
`SerialChannel.close()`. Repeats share the first total cleanup deadline (default
5 seconds), independently of normal command capacity and connection/query time.
Original/cleanup failures and received metadata remain inspectable. Dropping or
canceling an active close discards; close does not promise transaction rollback.

Lifetime ids are never reused on a connection. Python plain packets map to the
current local id, with released plain state/inboxes reclaimed. MARS wire ids are
16-bit and fail explicitly on physical-connection exhaustion; Python recovery
allocates fresh wire ids while preserving application identities and excluding
lifetimes revoked by application close. Rust controls hold weak channel lifetime references. Old close controls
are harmless, and old send/read/handover authority cannot address a replacement.

Python serializes owner operations and its private close drainer. A partially
sent request uses the existing IGNORE/LAST undo. A complete request uses Attention.
Terminal DONE/ACK now waits for its message boundary in both clients. Python scope
exit preserves an original exception if cleanup also fails, and avoids a redundant
network drain after an already observed connection failure.

Controlled tests cover owner wakeup, repeated/stale controls, delayed/missing ACK,
message-end proof, failed/canceled cleanup and mailbox/deadline behavior. Live
close/reopen runs under both TDS versions; Python also covers MARS sibling reuse,
unclaimed large values, partial-send undo and pool return with/without proven
cleanup. Rust MARS/credit/sibling behavior is now tested; exhaustive forced-backpressure
send-abort coverage remains separate open work.


### MARS and pooling implemented

The connection-first checklist now implements opted-in MARS under 7.4 and 8.0
for the supported integer/token subset. Each channel owns a response decoder and
four-frame receive window. DATA-frame consumption returns credit, independent of
TDS packet boundaries. The driver keeps reading/routing while owners or senders
wait, advances pending readers/drains in round-robin order and permits queued
commands to progress during cancellation. One shared fatal cause reaches all
waiters with their own consumed response prefixes; a peer FIN alone closes its
channel. Abandonment or failed awaited cleanup still discards siblings.

Both clients now validate SMP lengths, flags, sequence/window progression and
32-bit wraparound. Python previously counted TDS packets rather than DATA frames
for credit; split/combined-packet regressions now check the corrected shared rule.
MARS wire ids start at zero in each physical connection, are never reused within
it and explicitly refuse 16-bit exhaustion. Application ids remain monotonic
across recovery and map independently to those wire ids.
Rust retains FIN protocol state until the peer responds, without retaining public
authority. No semantic-history/fetched-row limit was introduced. The crate's
acceptance record gives actual checks; broader types/streams still need MARS tests
when implemented. R5's current integer/token connection slice now includes pooling.

**Pool return approved and implemented:** Python awaits its context exit; Rust
requires `lease.release().await` for reuse and discards on Drop. The persistent
driver retires the old endpoint, closes idle channels, resolves MARS FIN and
rotates to a fresh borrower endpoint. Guards cover both endpoints if return is
canceled. Pool capacity covers opening/lent reservations and waits for return;
shutdown wakes waiters, closes idle connections and refuses late logins. Existing
borrowers live until return/drop, matching Python. Release discards active/failed
connections rather than inventing implicit cancellation.

RESETCONNECTION is on the next request's first packet only, after successful
encoding. RESET_COMPLETE restores the client's login environment baseline;
transaction announcements remain authoritative. No extra SQL normalizes the
protocol's isolation-level/distributed-transaction exceptions. DTC acceptance is
not claimed. Eight controlled pool tests and three Docker pool scenarios check
capacity, cancellation, stale controls, failure/FIN cleanup, physical connection
GUID reuse/replacement and session isolation under both versions with/without
MARS. The crate acceptance record gives the complete current counts.

The transaction descriptor header is corrected in both clients: autocommit sends
outstanding-count one even when MARS overlaps requests; explicit transactions
retain the active count (MS-TDS §2.2.5.3.2). This was a specification defect in the
Python baseline, not a Rust-only semantic change.

### Approved observation failure policy

The user approved continuing after live-log failure and stopping after saved
recording failure. A core-only
Python probe throwing from the channel observer leaves a registered channel with
no returned handle, while `failure` stays unset and the next open is refused.
Python now disables the failed callback and exposes `observation_error` separately;
database work and any attached recording continue. Installing an observer clears
the diagnostic. The current decoding mode is preserved through failure. Pool
callbacks follow the same failure isolation, without stranding a completed loan.

Saved-recording event/packet failure raises `CaptureError` retaining the writer
cause, closes the socket synchronously and wakes waiters. Recording lines are
flushed to expose buffered-writer errors during the connection's lifetime; this
does not promise fsync durability. Recovery is refused after recording failure,
including when a cleanup error wraps it. Closing a failed connection avoids
calling the broken recording again. SQL already sent may still have executed;
discard is not evidence of rollback. Rust now implements the same failure policy:
owned descriptions leave the core before the driver invokes callbacks. A returned
Observer error disables that observer and is separately inspectable; a Capture
write/flush error discards the connection and preserves the cause/response prefix.
Rust panics unwind and discard through the driver guard.

The pool comparison also corrected Python's late-login/canceled-commit races,
matching Rust: a login completing after shutdown is closed, and canceling its
commit to the pool frees capacity and closes the unlent session.

### Approved recording ownership across connections

Python Pool previously forwarded a single capture object to all connections, while the
recording schema/replay keys only direction and channel. An offline shell/core
probe with two connections and channel 0 on each recorded row packets 11 then 22,
but consumed the responses 22 then 11. The actual results remained correct;
replay associated the rows with the wrong response events. This is a diagnostic
identity defect, not live database cross-delivery.

The user selected separate recordings per physical connection, preserving the
format. Python Capture now claims one physical core identity permanently. Pools
require `capture_factory`, also supported by connect for fresh recordings on
routing/recovery. A direct capture refuses those transitions instead of combining
conversations. The application owns Python capture resources and supplies distinct
outputs. Detachment permits resuming on the same physical connection, never moving
the capture elsewhere.

Rust Capture is non-Clone and moves into the driver; a ConnectOptions factory
creates a fresh recording for each physical connection. Pool endpoint rotation
keeps its existing writer. Capture::create uses exclusive creation so a bad path
choice cannot truncate another recording. Changing observation/recording is
refused during an exchange. The core queues descriptions without calling any
application callback; the driver delivers them before writes/results.

The initial Rust Off/Outline/Full slice preserves results at every level. Outline
and Full have the same lines; Full additionally exposes exact redacted packet
header/body and native decoded Records. Per-field inspection trees, view reference
links, native replay and detailed response timings remain open. Four actual Rust
recordings (7.4/8.0 × plain/MARS) replay through Python's unchanged implementation,
yielding rows 42 then 43 and redacted credentials, without decoding failures.
This is evidence for the supported slice, not full D-12 parity.

### First configurable login options

The app/host/process identity, language, ODBC flag and read-only intent are now
implemented. The initial minimal Rust encoder's forced English and absent ODBC
flag were replaced with Python's assessed defaults: use the login's language and
enable ODBC session defaults. The shell obtains machine/process identity; the
core acquires neither. Deterministic artificial LOGIN7 bodies generated by the
Python definition match Rust byte for byte. Docker verifies configured identity,
ANSI/TEXTSIZE defaults, invalid-language refusal and the continued ability to write
with read-only intent under both versions with/without MARS. This is a hint for
routing, not a client-side permission check. Remaining feature/authentication/
resilience options are still part of the connection checklist.

### One-hop routing

Routing is implemented with one deadline across the redirect, destination-specific
certificate validation and a fresh physical recording. A first-hop TLS name
override is retired; the destination's LOGIN7 name is server,port, preserving
Python's observed Azure behavior. follow_routing=false reports a typed Route;
a second hop reports the chain and is refused. Both clients now validate TCP,
nonzero port, a nonempty/NUL-free server name and an empty old routing value before
following a route. Python previously ignored the protocol field. Six new core
cases test this shared correction.

Five controlled TLS checks cover distinct router/destination certificates, names,
opt-out, loop refusal, invalid targets, the original deadline and recording failure
stopping a redirect. A local TLS router reaches Docker under 7.4/8.0 × plain/MARS
and produces two independent recordings. The final failed core step is still
delivered to diagnostics; simultaneous protocol/recording failures preserve both
causes and any fatal response record.

### Recovery identity and permissions: implemented in both clients

The user approved implementation after the feasibility check. The
[experiment record](experiments/recovery-channel-identity.md) preserves the
original observations, intervention, commands, results and limits.

The Rust driver keeps one logical endpoint through recovery and rotates its
physical epoch on a transport break before waking failed exchange waiters.
Connection/channel close permissions retain their logical lifetimes. Submitted
exchange/read/cleanup guards carry the epoch they belong to; revocation from an
old epoch cannot discard a replacement. Each replacement performs verified TLS,
requests server session recovery with initial/current snapshots, checks the
acknowledgement, opens fresh wire sessions, then permits new SQL. The same total
connection deadline covers the recovery login and channel establishment. A
failed attempt does not authorize replay. Pool return remains a separate logical
authority transition and never reconnects an unhealthy pooled transport.

The original Python/Docker probe closed channel 0, retained channel 1 and successfully
queried row 11. After an idle relay cut, recovery login completed and preserved the
server session id, but the retained channel 1 then stalled. The probe ran in its
owning task; the reader remained alive without core failure until the deadline.
A fresh physical MARS connection returned a row starting at wire id 0; a fresh
connection starting at wire id 1 was rejected. These are observed SQL Server
17.0.5015 behaviors, not a universal MC-SMP first-id claim.

Python conflated application-channel lifetime identity with physical SMP session
id and adopted the same number on recovery. The correction separates
these concepts: an application connection owns continuing authority, a physical
epoch owns TCP/TLS/login/recording and a fresh wire namespace, an application
channel has its own lifetime, and an exchange belongs to one physical request.
The checklist records the concrete identities and constraints before process/API
implementation.

Keep Python's intended idle-channel continuity, assign fresh wire
ids from zero after recovery, retain logical connection/channel close permissions,
and retire every old exchange read/cancel/abandonment permission. Pool return still
retires all old borrower authority, and in-flight SQL is never replayed. The
alternative would invalidate old channel/close handles and require fresh ones
after recovery. The user preferred continuity if the channels remain usable and
asked for proof. Python now keeps its logical ids/owners but allocates fresh wire
ids and routes incoming frames back to logical channels. The same channel 1
object returns row 22 after recovery, using wire id 0.

Eight new Docker cases pass across 7.4/8.0 × plain/MARS: repeated automatic and
explicit recovery, session settings and retained results, multiple surviving
channels consumed in reverse order, stale closed-channel controls, valid delegated
channel/connection close, later channel allocation and independently replayable
recordings. Old unfinished responses cannot cancel, read or close a replacement
exchange. Two pure-core cases cover both mapping directions and wire exhaustion
independent of application ids. A third Python core/shell case pins a paused
procedure to its original transport and prevents its late write after recovery.

Rust now negotiates SESSIONRECOVERY, decodes state announcements and serializes
initial/current snapshots matching Python and the MS-TDS example byte for byte.
It preserves channels/root controls across eligible recovery, with separate
application/wire identities and epoch checks on request/read/cleanup abandonment.
Idle breaks may recover before new SQL; in-flight failures require explicit
`Connection::recover()` and never replay old SQL. `is_closed()` includes an
observed broken transport; `recoveries()` counts successful replacements.
Refusal reasons and causes remain inspectable. Protocol/fatal/cleanup/recording
failure and explicit closure do not qualify for automatic recovery. A failed
optional observer stays disabled even if its recovery attempt fails; failure of
a requested saved recording is terminal. Root-close/canceled recovery interrupts
the candidate, and an unsuccessful login cannot authorize new application SQL.

The Rust Docker matrix exercises original channels and pre-recovery close
permissions through three replacements, retained settings/results, stale
cancellation, unfinished old response and armed read-future Drop after recovery,
explicit recovery after uncertainty, and server refusals. Separate recordings for
all 16 physical epochs replay through unchanged Python with correct logical row
attribution and redacted LOGIN7 credentials. Controlled TLS checks cover missing,
malformed, duplicate and unrequested acknowledgements, a silent candidate's
deadline, explicit retry, root close and recovery-future Drop, direct-capture
refusal and new-recording factory/write failures. These are local SQL Server and
controlled-peer results, not universal deployment evidence; full protocol/type
and platform coverage remain open. See the acceptance record for commands/counts.

### Browser, restricted logins and the next public representation

Rust now has independent MC-SQLR request/reply definitions and a Tokio UDP shell:
instance/machine/DAC queries, IPv4 broadcast with a single collection deadline,
strict encoded-name limits, malformed-reply inspection and explicit
ASCII/UTF-8/Windows-1252 selection. Lookup does not connect or change TDS options.
Other code pages and real Windows Browser acceptance remain open. Unchanged
Python/MC-SQLR examples and controlled loopback datagrams provide local evidence.

A separately authenticated disposable SQL login now proves actual low privilege,
error 229 and allowed-query reuse under 7.4/8.0 × plain/MARS. Setup and fresh
cleanup connections have privileged authority. Raw RETURNSTATUS is decoded and
retained in response order, including when fetched; typed RPC/output/grouped
returns remain open.

The [support matrix](../../clients/rust/SUPPORT.md) distinguishes remaining code,
architectural choices and runtime evidence. The current boundaries are:

- [Public value API](F-rust-value-api.md): approved `Row = Vec<Option<Value>>`, an
  explicit non-NULL value enum, separate declared SQL types and exact numeric/
  temporal structs. Scalar read codecs and the integer migration are implemented;
  typed RPC, code-page decoded views and large/special values remain in R3.
- [Credential lifetime](G-login-credential-lifetime.md): both clients promote a
  direct password-changing login's credential only after final success. Recovery
  uses the accepted credential without repeating the change. A lost completion
  reports an uncertain server outcome. Pools reject one-time change requests;
  the distinct configuration service supplies current credentials for openings.

The shared [pool configuration design](H-pool-configuration.md) records the
implemented Python/Rust APIs, value scope, retirement/recovery policies and
acceptance matrix. New openings and eligible recovery read a snapshot within one
fixed deadline; failures remain explicit and later acquisitions can succeed
through the same pool. Current borrowers continue, known stale idle/returned
connections are discarded, and late superseded candidates fail. Snapshot equality
excludes mutable TLS contexts/callbacks. No built-in file provider or watcher is
added. Deferred reset can still expose an undiscovered rotation on the next SQL
request; that request is never replayed. The value page records scalar evidence
and the separate planned Python offset validation correction.


## Typed requests and runnable client

The typed RPC slice implements bounded scalar parameter writers, named/built-in
calls, batched calls, NULL/default/input-output semantics, RETURNVALUE and grouped
DONEPROC returns. Borrowed result-set views stream scalar rows; explicit
Refuse/Keep/Discard governs return access. Python's directly constructed/aware
datetimeoffset validation now enforces UTC/local ranges before parameter encoding.

`clients/rust/target/debug/tds` is the runnable Rust client after `cargo build`.
Its query/procedure/typed-input/observation/capture paths use the public library
API. [Design I](I-rust-rpc-and-streaming.md) records the approved and implemented
borrowed row/value boundary, exact typed chunks, PLP/XML/legacy readers, owned
fetch/output assembly and async PLP input sources. Static validation precedes
producer polling; partial sends use IGNORE/EOM cleanup. The CLI demonstrates
chunked reading and binary file input. Both clients now reject contradictory
known PLP lengths. The crate acceptance log records focused and full evidence;
native platform coverage and remaining special types remain separate work.


## Completion continuation

[Design J](J-rust-completion.md) records implemented transaction-manager requests,
batched unique sources, browse/sensitivity metadata, CLR serializations, bounded
variants, native JSON, exact vectors and explicit SQL collation views. Feature
negotiation follows accepted server versions and controls result encodings. The
CLI demonstrates transactions and special inputs through the public library.
Shared Python fixes cover negotiated replay context, input-only inspection
layouts, JSON metadata reuse and vector validation. Approved TVP representation and borrowed bulk
continuation ownership are implemented in design J. The support matrix keeps
inspection/provider/platform gaps separate from completed local evidence.


## Native offline replay

[Design K](K-offline-replay.md) records the approved representation, existing
capture-format compatibility and failure reporting. Rust decodes supported
requests/results without a connection, using the live packet/token/value readers
and input-specific definitions. Python now reads saved TVP metadata/rows. The
actual Rust CLI offers `--replay`; full field trees and timing analysis remain
separate work. The final acceptance section records fresh two-client evidence.
