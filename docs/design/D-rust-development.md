# D · Building the Rust Client

**Where this sits:** the next phase of the [Roadmap](C-roadmap.md). The protocol model and reference pages remain common to both clients.
**After reading this you can** explain who owns each resource, what each caller may do, how Rust will preserve the protocol's rules, and what evidence completes each milestone.

> **Status: development proposal, 2026-10-17.** The user has requested Rust before Python M16, with ownership and permissions established first and the same learning intent as Python. That priority and intent are agreed. Rust API, runtime, dependency, representation, and cleanup choices below require agreement before affected implementation. The user selected movable ownership as the Rust proposal, replacing task identity as its recommended direction. No Rust code has been written. The [Python baseline](E-python-baseline.md) records source analysis, actual test results, and the resolved local-server setup issue.

## 0 · Vision and requirements

Build a Rust client for TDS 7.4 and 8.0 whose source teaches the protocol and whose running behavior makes its conversations visible. A reader should be able to follow a reference page into a definition, through a procedure, and into an observed exchange. Code should be clear, succinct, correct, and literate. Brevity serves comprehension; it does not justify hiding state, errors, or consequences.

The driver exposes connections, whole-connection pool leases, serial channels, explicitly typed requests, streaming responses, cancellation, and server session state. It preserves exact values and the server's ordered response record. Application conveniences, inferred SQL types, ORM interfaces, and a synchronous shell remain later work. Rust does not depend on finishing Python M16.

The design authority is the shared model, reference pages, and agreed decisions. Python supplies executable examples and regression evidence. A discrepancy is investigated against the specification and observed server behavior; Python output alone does not settle correctness.

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
- **Explicit async close:** perform and await the required cleanup. A cleanup deadline prevents indefinite occupancy. Its duration and relationship to exchange timeouts must be agreed in R0.
- **Response/future drop, task abort, panic, timeout or canceled `select!` branch:** do not assume Python's awaited `__aexit__` has an equivalent. [`Drop::drop`](https://doc.rust-lang.org/stable/core/ops/trait.Drop.html) is synchronous. Prefer a conservative unusable-connection fallback until a persistent driver has demonstrated safe bounded cleanup. Background cleanup, if chosen, owns all required state and must finish before reuse. Do not spawn a detached task that borrows a dying response.
- **Drop during cleanup or runtime shutdown:** remain unavailable for reuse; close/discard the connection if cleanup cannot finish. No blocking network I/O or panic in `Drop`.
- **Network failure after transmission begins:** report the known send stage and uncertainty about execution; never automatically resend an in-flight application request (D-57). Idle recovery is a different operation.
- **Pool return:** return to the idle set only with no active exchange, continuation, surviving live authority, or unresolved cleanup; arrange the protocol session reset before the next borrower's first request. Preserve the documented isolation-level and distributed-transaction reset exceptions. Do not promise a stronger reset than SQL Server provides.

The shell must define cancellation behavior for every await point: socket read/write, TLS handshake, window credit, producer polling, pool acquisition, authority transfer, and cleanup. Tokio's [cancellation-safety discussion](https://docs.rs/tokio/latest/tokio/macro.select.html#cancellation-safety) is a candidate-shell reference; no runtime is selected by this plan.

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

A persistent driver task is a candidate shell structure for MARS and cleanup, not a settled requirement. Compare it with direct driving using concrete examples: one plain channel, two interleaved MARS readers, a stalled source, external cancellation, lease return and runtime shutdown. Choose the smallest structure that preserves the rules. A single long-lived `&mut Connection` borrow held by a channel is insufficient if it prevents a second MARS channel.

**Candidate runtime/TLS pairing:** Tokio and rustls, subject to R0. Tokio provides scheduling and task facilities; rustls exposes an in-memory [client connection](https://docs.rs/rustls/latest/rustls/client/struct.ClientConnection.html) with TLS byte processing and ALPN. Prove TDS 7.4 handshake records inside PRELOGIN and subsequent raw TLS, then TDS 8.0 TLS-first with `tds/8.0`, trust roots, hostname validation, routing, partial writes and close. A generic TLS stream wrapper alone does not prove the 7.4 transition. Core deadlines use time supplied by the shell, and tests supply synthetic time.

The core has explicit budgets for pending bytes, per-channel packets, inspection bytes and retained metadata. Bound the async shell's queues too. Return MARS credit as packets are consumed; a slow reader must not cause unlimited buffering or block every sibling channel. `fetch()` deliberately retains data and documents its memory cost; decide its configurable limit and failure cleanup in R0. Backpressure tests measure behavior, not a throughput claim.

## 5 · Proposed milestones and completion evidence

R numbers are Rust proposals. They do not mark Python milestones complete or change existing acceptance records. Final scope and each unresolved choice are agreed before the affected code begins. Each implementation milestone includes its teaching documentation and relevant offline and live checks; skipped checks remain incomplete evidence.

| Milestone | Deliverable | Completion evidence |
|---|---|---|
| **R0 · Agree ownership, permissions and representation** | Resolve the decision list below; write lifecycle tables and API sketches; compare normal/error examples | Review one channel, overlapping use, move/loan across tasks, use-after-move rejection, stale cancel, two MARS channels, dropped response/future, forgotten guard, pool return, permission denial and unknown execution outcome. No unresolved semantic choice is hidden in a signature. |
| **R1 · Literate crate and byte foundations** | Crate/toolchain; module reading path; small checked codec; packet, PRELOGIN and LOGIN7 definitions; neutral fixture loader | Spec samples encode/decode exactly; every relevant byte split; malformed offsets/lengths/overflow/unknown tags; redaction across split credential messages. Working rustdoc example follows bytes and invariants. |
| **R2 · First complete connection and exchange** | SQL login, TDS 7.4 TLS, a plain serial channel, `Batch`, minimal token/type set, streaming response, cancel, close and observation | Trusted TLS `SELECT 1` live; reject wrong host/untrusted cert/login/version; response record matches Python; unique-authority/busy rules; drop/timeout at send/read boundaries never permits dirty reuse. Limited type support is explicit. |
| **R3 · Exact short types and calls** | All short types/collations; typed `Call`/`Calls`, output parameters and returns | Python type corpus and response samples; precision 38, time extremes, unpaired surrogates, noncanonical encodings, NULL/empty; outputs by ordinal and name; invalid whole values emit no bytes. Restricted-principal allowed/denied scenarios. |
| **R4 · Large values and request sources** | PLP and legacy large values, streamed input/output, unread keep/discard/refuse, abandonment | Chunk-boundary/character tests; bounded slow consumer; producer error; task abort before/partway/after send; IGNORE + LAST or Attention and matching response; original error and protocol state retained. |
| **R5 · MARS and pool isolation** | Multiplex framing and credit, interleaved serial channels, whole-connection leases, reset/discard | Two MARS readers share one session without sharing advancing authority; slow-reader independence; fatal failure fanout; stale handles after reuse; pool saturation/canceled acquisition; dirty return closes; reset exceptions explicit. Extend R2–R4 checks under MARS. |
| **R6 · Remaining requests, types and tokens** | Variant, JSON/vector, CLR metadata, TVP, bulk pair, transaction manager, remaining tokens | Matching Python unit/live scenarios, bulk continuation refusal, transaction announcements and exact values. Independent .NET encryption interop belongs to R8, not this type round trip. Mark float16/server limitations explicitly. |
| **R7 · TDS 8.0 and connection resilience** | TLS-first/ALPN, full option vocabulary, routing, Browser, recovery, capture/replay | 7.4/8.0 and MARS matrix; routed certificate check and one deadline; idle recovery preserves state and never resends an in-flight request; captures replay both directions for the supported message set. Unsupported TVP replay remains an explicit gap. |
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
| Cancellation/drop | Explicit awaited cleanup; conservative discard if cleanup cannot be proved | Persistent driver versus direct driving; cleanup deadline; behavior when cleanup itself is canceled |
| Exact values | Small SQL-specific exact types; convenient checked conversions outside the wire representation | SQL text type, decimal/sign/scale, times, row/value vocabulary and fetched/live reading API |
| Runtime/TLS | Runtime-independent core; evaluate Tokio shell and in-memory rustls | Supported runtimes/platforms, TLS backend/provider/root policy and actual 7.4/8.0 interoperability |
| Dependencies/layout | `clients/rust/`, one crate initially, safe Rust, limited optional adapters | Crate name, MSRV/edition/toolchain, library choices and feature boundaries |
| Fixtures/captures | Incremental neutral fixture corpus; existing captures retained | Schema/version, exact encodings, provenance and cross-replay scope |
| Budgets/observers/keys | Bounded buffers, explicit retained-data costs, redacted observation | Numeric limits, fetch limit, callback failure policy, key cache bounds/invalidation and secret clearing |

The next implementation step is R0 agreement using the recorded Python baseline. The Python suite now initializes its test database through Compose and binds captured report identities to each live server explicitly. Its original capture bytes and all other asserted fields remain intact. Keep those environment prerequisites and comparison boundaries explicit when sharing fixtures with Rust. The server setup history and any remaining test failures or environment gaps are recorded separately, so a written plan is not mistaken for completed runtime parity.
