# Temporary Rust development checklist: connection first

Working checklist on `rust-client`, created 2026-10-17. This records execution order, not a new set of approved architecture decisions. Reconcile or remove it as the work moves into the permanent design and acceptance records.

**Intent:** build and test the Rust connection package against the existing Docker SQL Server, with clear, succinct, correct, literate code that teaches the protocol. Follow Python's core/shell responsibilities while expressing ownership through Rust moves and borrowing.

References: [Rust development proposal](docs/design/D-rust-development.md), [Python baseline](docs/design/E-python-baseline.md), Python [connection core](clients/python/tds/connection/core.py) and [async shell](clients/python/tds/connection/shell.py).

## 1. First working connection against Docker

**First demonstrable result:** connect with a verified certificate, log in, open one serial channel, run `SELECT 1`, consume its completion, and close cleanly. Reach this before attempting the whole Python feature set.

- [x] Work on `rust-client`, based on the `v0.1.1` test-setup patch.
- [x] Confirm the existing `mssql-2025` service is running and healthy. Checked 2026-10-17; zero restarts at this check. Its health probe includes `tds_test` readiness.
- [x] Select the async runtime and TLS library: the user approved Tokio and rustls on 2026-10-17. Dependency configuration and certificate/trust policy still need definition.
- [x] Check the installed Rust toolchain: `rustc 1.99.1`, `cargo 1.99.1`, `stable-aarch64-apple-darwin`. This establishes the local build environment, not an MSRV support claim.
- [x] Agree the first slice's handle/borrow shape and abandonment contract: the user approved the persistent driver, unique movable channels, borrowed responses and conservative discard. One unpublished crate now lives at `clients/rust/`, edition 2024; no MSRV promise is made.
- [x] Write the small ownership contract before signatures: the checkpoint below records the agreed roles; the crate README explains their enforcement and which controls remain unimplemented.
- [x] Create the Rust crate and its short reading path. Give `connection::core` and `connection::shell` written responsibilities and invariants.
- [x] Implement only the supporting definitions and codec needed for the first exchange: checked byte access, incremental packet framing, PRELOGIN, LOGIN7, login-reply tokens, minimal session state, SQL batch, and the integer result/completion/error record.
- [x] Keep protocol decisions and TLS state in the I/O-free core. The shell owns sockets, scheduling and time, and performs explicit core actions. Supply time and environment values to the core rather than reading them there.
- [x] Implement the TDS 7.4 sequence: TCP → PRELOGIN → verified TLS handshake carried in PRELOGIN packets → LOGIN7 → ready. Preserve full-connection encryption and the single connection deadline.
- [x] Handle the login's announcements and messages; apply negotiated packet size and session settings before the first request. Advertise only features the reader can handle. SESSIONRECOVERY, UTF-8, JSON, vector and classification are implemented/default on; accepted versions remain explicit. Unsupported announcements fail explicitly.
- [x] Implement one plain serial channel, `exchange(Batch(...))`, and enough incremental response reading to return `SELECT 1` and its final completion.
- [x] Run a Rust live integration test against `127.0.0.1:14325`, database `tds_test`, using the existing test CA and ignored credential configuration. No password is embedded or printed.
- [x] Prove a second sequential exchange works after the first response ends, then close the channel and connection cleanly. Also prove channel reopening, multiple results and transaction announcements across batches.
- [x] Show the live connection procedure in readable steps, with reference links in source and default credential redaction. Initial observation now includes steps/messages/packets and decoded tokens; per-field trees remain open.

**First-slice acceptance:** an actual Rust live test passes against Docker with certificate verification enabled. A skipped or unavailable-server run does not complete this item. Record the server/version, options, command and result.

**Evidence:** see [Rust acceptance](clients/rust/ACCEPTANCE.md). The expanded explicit live run passes all 16 tests without skips. Smoke and cancellation cases exercise both 7.4/TLS 1.2 and 8.0/TLS 1.3 against SQL Server LOGINACK 17.0.5015. This completes the minimal live path and agreed cleanup slice, not full R1/R2 or connection-package parity.

## 2. Connection correctness and failure handling

- [x] Add TDS 8.0: TLS first, ALPN `tds/8.0`, the same login/channel model, and no silent fallback to 7.4. The same live smoke scenario passes in both versions; a controlled peer checks failure without fallback.
- [x] Check untrusted CA, wrong hostname, wrong credentials, unavailable database and unreachable port. Certificate/login/database cases run live in both versions; a closed loopback port checks TCP failure.
- [x] Exercise silent/slow peers, truncated or malformed replies, instance mismatch, refused encryption and unsupported TDS version. Controlled TCP/TLS peers assert the failing step and closure, including rejection of a different LOGINACK version after verified TLS.
- [ ] Split supported headers/messages/tokens across input boundaries, including one-byte fragments; distinguish incomplete input from malformed input.
- [x] Refuse a second channel without MARS and a second exchange while its response remains open. Compile-fail, core and live tests cover overlap and busy state, including a forgotten response.
- [x] Test moving channel authority, use-after-move rejection and permitted exclusive lending. A live channel moves into a task and returns; mutable borrowing and compile-fail examples preserve the deliberate difference from Python's task-identity checks (D-64).
- [x] Implement Attention/acknowledgement, `Response::close`, exchange-scoped `CancelHandle`, and the agreed separate configurable 5-second cleanup deadline. Normal final DONE before the ACK does not release the channel. Repeated/stale cancellation and a full command mailbox do not defeat the deadline or grant send/read authority.
- [x] Add `ChannelCloseHandle` for one lifetime. Active close revokes immediately, cancels/drains under the first cleanup deadline and releases only afterwards. Stale controls cannot affect replacements. Apply the same close contract to Python.
- [ ] Test future/response drop, timeout and task abort at relevant send/read/cleanup boundaries. Keep the connection unusable until cleanup is proved; discard it when that cannot be done safely.
- [x] Preserve errors and the partial response record for the supported integer/token subset; checked completion retains metadata and reports SQL errors once. Report uncertainty after an in-flight network failure; never resend that request automatically.
- [x] Verify allowed/denied operations under restricted authority. Earlier coverage used `EXECUTE AS USER`; new live acceptance separately authenticates an isolated SQL login under 7.4/8.0 × plain/MARS, checks no sysadmin/db_owner membership, preserves error 229 and proves reuse. Privileged setup and fresh cleanup connections remain separate.

## 3. MARS and shared connection state

- [x] Add MARS negotiation, framing, channel open/close and send/receive credit in the core; keep socket scheduling in the shell.
- [x] Demonstrate two interleaved serial channels on one connection and one shared session, using supported result types. The borrow structure must permit both channels to exist.
- [x] Bound transport and per-channel buffering. Return MARS credit as data is consumed, and prove a stalled reader does not cause unbounded buffering or prevent a sibling channel from progressing.
- [x] Test fragmented MARS frames, window exhaustion/resumption, channel closure, and fatal-error propagation to every channel.
- [x] Repeat the relevant exchange, cancel, drop and cleanup checks under MARS and both TDS versions.

## 4. Pool and connection lifetime

- [x] Port whole-connection leasing after the single-connection rules work; the pool does not lend channels or execute requests.
- [x] Test capacity, waiting borrowers, canceled acquisition, connection-opening failures, and pool shutdown.
- [x] Prevent live channel/response authority from surviving lease return. Check stale handles and connection generations.
- [x] Reset a reusable session before the next borrower's first request, including the client's session baseline. Preserve the documented reset exceptions for isolation level and distributed transactions.
- [x] Discard connections with active exchanges, unresolved cleanup, fatal failure or any outstanding conversation obligation. Never lend another caller the previous borrower's response.
- [x] Verify session isolation between borrowers against Docker, including after cancellation and failed cleanup.

## 5. Remaining connection-package behavior

These remain part of the connection work even though the first slice is intentionally smaller than the current Python package.

- [ ] Add connection/login options in small groups with explicit compatibility and feature negotiation tests; do not copy Python's complete default feature list ahead of the supporting decoder.
  Implemented first group: app/host/process identity, language, ODBC defaults and
  read-only intent. ODBC now defaults on and empty language uses the login's
  default, matching Python. Python-generated LOGIN7 bodies match byte for byte;
  Docker verifies session settings, identity, invalid language refusal and writes
  remaining possible with read-only intent under both versions × plain/MARS.
- [x] Add session recovery state and idle recovery. Verify eligible recovery, refusal cases, session reconstruction and the prohibition on replaying in-flight requests. Original handles survive with fresh wire ids; old epoch commands/Drop guards cannot revoke the replacement. The experiment and acceptance records give the exact coverage.
- [x] Add one-hop routing with destination-specific certificate validation and one deadline across the hop. Five controlled TLS checks cover distinct router/destination certificates, server-name override retirement, routed LOGIN7 identity, opt-out, second-hop refusal, invalid targets, one deadline and recording failure stopping a redirect. A local TLS router reaches Docker under 7.4/8.0 × plain/MARS, with two independent recordings.
- [ ] Establish login token-provider action boundaries without pulling identity-library policy into the core. Keep Windows/Entra/provider acceptance separate until suitable infrastructure is available.
- [ ] Complete the connection's observation levels and capture integration as their supporting definitions become available. Keep off/outline/full result semantics identical.
- [x] Maintain an explicit list of Python behaviors still unsupported in Rust: `clients/rust/SUPPORT.md` distinguishes implementation, pending choices and missing runtime evidence. Completion of the smoke path is not parity.

## 6. Checks for each implemented slice

- [ ] Source explains the concept, protocol order, ownership and failure consequences; it uses the shared vocabulary and links to the relevant reference page.
- [ ] Keep safe Rust, typed errors, checked lengths/offsets and exact supported values. Avoid framework-building, incidental cloning and abstractions that conceal the wire or lifecycle.
- [ ] Run focused core tests and meaningful live integration tests as each behavior is added. Compare deterministic protocol bodies and semantic records, with environment-dependent fields identified explicitly.
- [ ] Run formatting, Clippy, relevant feature configurations and rustdoc examples. Keep any missing remote/platform evidence visible.
- [ ] Record actual evidence beside completed items. Preserve the SQL data volume, and run suites that mutate shared test objects serially.

The full type vocabulary, general RPC/TVP/bulk support, encryption providers, convenience layers and standard application drivers follow as separate slices in the development proposal. Add only the portions required by the connection slice currently being implemented.

## Current decision checkpoint: connection driver and abandonment

**Agreed and implemented, 2026-10-17.** The following records the reviewed contract. The next unresolved checkpoint appears at the end of this file.

**Pre-implementation groundwork, 2026-10-17:** the Python shell runs a persistent socket reader and distributes packets to channel inboxes (`shell.py`, `_read_for_every_channel`). Its core owns TLS state, protocol transitions and channel busy state (`core.py`). The installed Rust toolchain and healthy Docker SQL Server established prerequisites. The subsequent Rust results are recorded separately above.

**Agreed structure:** one persistent Tokio task per connection owns the socket and `ConnectionCore`, including its in-memory rustls connection. Public handles submit bounded commands and receive bounded replies. Protocol transitions and authority checks remain in the core; the task performs I/O, scheduling and deadlines. This replaces Python's generator-driven calls plus reader task with one exclusive owner of mutable connection state.

The concrete ownership contract proposed for that structure is:

| Role | Proposed authority and lifetime |
|---|---|
| `Connection` | Unique, non-`Clone` owning handle. Opens channels, reads session snapshots and closes the connection. Dropping it revokes its descendants and requests driver shutdown; it does not wait for network cleanup. |
| `SerialChannel` | Non-`Clone`, movable handle with an internal shared endpoint and connection/lease/channel identity. It can move into a Tokio task without a long-lived borrow of `Connection`. Shared storage grants no additional public send/read authority. |
| Live response | Exclusively borrows `&mut SerialChannel`; advancing methods require `&mut self`. An active response prevents independently moving or reusing its channel. An enclosing async task can still own the channel and create/use its response inside that task. |
| Cancel / close controls | Deliberately shareable controls with target identities; cancel includes exchange generation. They grant no SQL send/read authority. Stale controls cannot affect a replacement exchange or lease. |
| Core registry | Authoritative busy/terminal/failure state persists independently of handles and destructors. A forgotten response therefore cannot make the channel reusable. |
| Pool lease, later | Returning a lease revokes its generation. Outstanding channel authority, active exchanges or uncertain cleanup force discard; a surviving Rust value can remain memory-safe while its operations are rejected. |

Opening channels does not hold an exclusive borrow of the whole connection, so two MARS channels coexist. Every command is checked against current lifetime and exchange state before protocol work. Parent closure may invalidate a handle while an operation is awaiting a reply; it must fail that waiter, rather than allow it to hang or target a replacement connection.

**Agreed abandonment policy:** dropping an unfinished response or a submitted exchange/read/cleanup future makes the entire connection unusable and requests shutdown. Availability of explicit Attention/drain does not change this Drop policy. The core marks the exchange busy before transmission, retains that state if the caller disappears, and the shell checks abandonment before further transmission. Dropping a future before it submits any work has no server effect. If transmission may have begun, report uncertain execution and never retry it automatically. `Drop` performs no blocking I/O, cannot await, and cannot depend on free capacity in the ordinary command queue. An independent revocation/wakeup path is implemented.

Awaited response cleanup is now implemented with Attention/acknowledgement in section 2. Only its proven terminal boundary permits reuse. Automatic background recovery after response Drop remains a separate unapproved choice. Under MARS the conservative abandonment policy also terminates sibling channels; independent MARS progress and explicit cleanup are now implemented and tested.

| Alternative | Benefit | Cost / constraint |
|---|---|---|
| Persistent connection task (recommended) | One core owner; continues independently of a caller; supports later MARS and external cancellation | Task lifecycle, bounded mailboxes, reply abandonment and shutdown must be visible and tested |
| Caller drives the connection directly | Smallest initial single-channel implementation; fewer queues | Needs another structure for independent channel progress and cancellation; a channel borrowing the whole connection exclusively prevents two MARS channels |

That agreement covers the persistent driver, handle lifetime contract and conservative abandonment policy. The subsequent agreement covers awaited cleanup and its separate 5-second budget. The crate has documented prototype bounds, not a final memory tuning API or Rust support floor. Value types beyond the supported subset and the remaining response surface stay open; the agreed retention behavior below follows Python.

Library evidence: rustls exposes [in-memory TLS processing and ALPN](https://docs.rs/rustls/latest/rustls/client/struct.ClientConnection.html); Tokio documents [owned spawned tasks](https://docs.rs/tokio/latest/tokio/task/fn.spawn.html) and [cancellation safety](https://docs.rs/tokio/latest/tokio/macro.select.html#cancellation-safety). These APIs support the proposed structure; they are not evidence that its TDS handshake or lifecycle has been implemented correctly.

## Agreed cleanup slice: completed 2026-10-17

The initial `Response::next()` exposed SQL errors as records. The subsequent
retention slice adds once-only checked completion; SQL errors still occupy their
original positions in the record. Transport/protocol/fatal errors remain typed
failures.
Python keeps its record and raises server errors at the end; the subsequent
agreement below preserves that policy in the Rust checked reading surface.

**Approved and implemented contract:**

- `response.close().await` requests Attention and consumes the required acknowledgement before making its channel reusable. A separately shareable cancel handle names only that connection/channel/exchange generation. Repeated or stale cancellation cannot target a later exchange.
- Give that cleanup a separate configurable deadline, initially **5 seconds total**, covering Attention transmission and acknowledgement/drain. It does not restart or inherit an already-expired query timeout. Failed/timed-out/canceled cleanup discards the connection; `Drop` retains the agreed immediate-discard policy.
- `close_after(original)` returns the original error after successful cleanup, or pairs it with the cleanup cause on failure. Successful cleanup is proved against both controlled TLS peers and SQL Server; failure, timeout and dropped-future paths discard. `exchange()` returns its response/control only after the complete batch is written. Partial-send future abandonment remains discard; streaming request IGNORE/LAST work is deferred.

## Agreed response retention and checked completion

The user confirmed Python's retention semantics on 2026-10-17. **General rule:**
when a behavioral question arises, inspect the Python implementation and tests,
assess correctness, and use its decision when reasonable. Bring suspected design
defects to the user; changes in correct behavior are planned for both languages.
Previously agreed Rust ownership and abandonment differences remain explicit.

Implemented for the currently supported integer/token subset:

- [x] Retain ordered metadata, messages, errors and completions from response creation, including autonomous cancellation drain. Ordinary streamed rows are not retained automatically.
- [x] `finish(&mut self)` drains normally, discards unread rows and returns `()`. Metadata remains available through `snapshot()`. It sends no Attention.
- [x] `fetch(&mut self)` returns an independent owned response and leaves unread records available to the live reader from memory. A partly streamed set cannot expose a complete retained row list; subsequent untouched sets can. Earlier rows are not reconstructed.
- [x] Report SQL errors once at checked completion (`next()` through the end, `finish()` or `fetch()`), with the retained response. Preserve later successful result sets after a statement error. Capture the actual cancellation acknowledgement and attach incomplete records on fatal/protocol/transport failure.
- [x] Match Python's lack of cumulative semantic-retention budgets. The earlier Rust-only budget proposal is withdrawn. Existing transport limits are distinct from retained history/fetched rows. Consider any future limit policy for both languages.
- [x] Verify seven unchanged Python captures with whole/one-byte packet bodies, explicit semantic assertions, controlled cancellation/failure peers, and live finish/fetch/partial-fetch/error/reuse under both TDS versions.

The raw ordered-record reader remains smaller than Python's full result-set and
large-value streaming interface. Procedure returns, other SQL types, observation,
separately authenticated restricted-login tests, exhaustive partial-write abort
coverage remain open. See the crate acceptance record for
current test counts and evidence boundaries.

## Agreed shared channel-close correction

**Approved and implemented, 2026-10-17:** cancel and drain, then release; discard
on cleanup failure. The original core-only Python probe reproduced premature
busy-channel replacement and a stale close affecting its replacement. No live
cross-delivery was claimed. The correction is applied to both clients:

- [x] Revoke public channel authority immediately when close is polled. Keep the
  core busy until acknowledged cleanup and the response message boundary.
- [x] Use unique channel lifetime identities. Python plain packets route to the
  current local lifetime; closed plain registry/inbox entries are reclaimed.
  MARS uses non-reused 16-bit wire ids per physical connection and explicitly
  refuses exhaustion. Python recovery allocates fresh wire ids, preserves the
  application identity counter and excludes revoked lifetimes. Rust's
  channel/exchange ids remain monotonic across recovery, with fresh physical wire ids.
- [x] Serialize Python's owner operation and private cleanup reader; wake a
  blocked owner without allowing two consumers of one inbox. Preserve immediate
  wrong-task/overlap rejection. A partly sent Python request uses existing undo.
- [x] Add Rust `ChannelCloseHandle`, independent of command-mailbox capacity.
  Repeated close callers share the first deadline and outcome. The earliest
  cancel/close deadline wins. A close during transmission includes the remaining
  write time in the budget; Attention follows the complete message.
- [x] Keep original/cleanup causes and received metadata on failure. A canceled
  cleanup discards. Python scope exit preserves an existing exception and avoids
  a second network drain on an already failed connection.
- [x] Require Python's terminal DONE/Attention ACK to reach its message boundary,
  matching Rust. Reject truncated tokens and fatal drain replies.
- [x] Verify delayed/missing/malformed ACK, message-end proof, owner wakeup,
  stale controls, canceled close and full-mailbox/deadline behavior with
  controlled tests. Check close/reopen against Docker under both TDS versions;
  Python additionally covers MARS siblings, unclaimed large values, partial-send
  undo and pool return after successful cleanup versus genuine abandonment.

Broader value/response APIs, separately authenticated
restricted-login tests and exhaustive forced-backpressure send-abort coverage
remain open. The crate acceptance record distinguishes completed evidence from
those gaps. No Rust implementation has been published from this branch.

Final verification for the shared close correction: Python **611 passed, 13
expected environment skips, zero failures**; Rust **12 explicit Docker tests**
and all offline/feature/documentation checks pass. See
[ACCEPTANCE.md](clients/rust/ACCEPTANCE.md) for commands and limits.


## MARS slice and next decision

Implemented for the supported integer/token subset: opted-in negotiation after
login, independent decoders/credit, bounded DATA queues, round-robin advancement,
credit-blocked senders, FIN exchange and shared failure fanout. Docker checks cover
both versions; controlled TLS checks include split/combined TDS packets, malformed
sequences, independent sender/reader progress, cleanup during exhausted send credit,
peer FIN isolation, abandonment and each channel's own partial response record.
SMP credit counts DATA frames, not TDS packets. Shared Python corrections validate
lengths/flags/sequences/windows, wrap 32-bit counters and account consumed frames;
11 new framing regressions exercise these rules. The full Python run passes
**622 tests with 13 environment skips**, and all **16 explicit Rust Docker tests**
pass; Rust core/TLS/feature/Clippy/docs checks pass. No semantic retention cap was added.

**Pool return policy approved and implemented:** `pool.acquire().await` returns
a unique whole-connection lease; `lease.release().await` retires descendants,
proves quiescence and returns it for reset/reuse. Drop discards. This is the
user-selected policy; background return on Drop is not enabled.

## Pool implementation evidence

The persistent driver rotates to a fresh endpoint only after idle channel closure
and all MARS FIN replies. Old root/channel controls remain bound to the retired
endpoint. Return cancellation guards both endpoints. A semaphore reservation owns
capacity across acquisition, opening and return; no pool lock crosses I/O. Pool
shutdown rejects late logins and wakes waiters, while borrowed sessions live until
return/drop, matching Python. Active exchanges are discarded on return; proved
awaited response cleanup can reuse the same physical connection.

Eight controlled pool TLS tests cover cancellation, failed login, saturation,
dirty return, failed cleanup, missing FIN, canceled return, stale authority,
reset acknowledgement/baseline and shutdown races. Three Docker pool tests cover
both versions with/without MARS, including distinct session GUIDs, unchanged GUID
on reuse, changed GUID after Drop, database/language/temp-table reset, rollback of
a local transaction, stale controls and waiting borrowers. All **19 explicit
Docker tests** pass; core/feature/Clippy/rustdoc checks pass. Reset excludes extra
client SQL for isolation/distributed transactions; DTC acceptance is still open.

The shared transaction-header correction sends outstanding-count one in
autocommit, as MS-TDS §2.2.5.3.2 requires. Explicit transactions still count active
requests. Rust byte checks and four Python Batch/RPC cases guard the correction.

## Approved observer/capture failure policy

The user selected the shared policy on 2026-10-17:
continue after live-log failure; stop after saved-recording failure.
A core-only Python probe made its channel observer throw: `open_channel` raised,
one channel remained registered with no returned handle, `core.failure` stayed
unset and the next open raised TooManySerialChannels. This establishes a local
state inconsistency, not a live cross-delivery claim.

- [x] Python: disable a failed optional observer; retain its exception separately
  as `connection.observation_error` (cleared on replacement). Pool callbacks have
  the same isolation and an inspectable `pool.observation_error`.
- [x] Python: continue delivering events to the saved recording after optional
  observer failure; preserve the current decoding mode until reconfigured.
- [x] Python: event/packet recording failure raises `CaptureError` with its writer
  cause, latches failure, closes the socket synchronously and wakes all waiters.
  Cleanup cannot revive it; recovery is refused. Flush each JSON line to surface
  buffered-writer errors while the connection is still active. No fsync claim.
- [x] Verify failures in channel creation, sending, reading and closing across
  TDS 7.4/8.0 × plain/MARS, plus offline state/pool/wakeup cases.
- [x] Rust: owned core descriptions are delivered by the driver after each step,
  before writes/results. An Observer error disables it and is retained as
  `connection.observation_error()`; a Capture write/flush error discards the
  connection, preserving the cause and each channel's response prefix. A panic
  unwinds/discards through the driver guard; ordinary returned errors are isolated.

The Python pool comparison also corrected late-login and canceled-commit races:
shutdown refuses a login finishing after closure; cancellation after login but
before lending closes the session and frees capacity. Two deterministic offline
tests exercise these boundaries without sleeps or infrastructure assumptions.

## Approved recording ownership across connections

Python Pool previously passed the same `capture` option to every connection. Capture/replay
groups packets by direction/channel only, without a connection identity. An
offline shell/core reproduction uses two plain connections and one recording:
both channel ids are 0; row packets arrive 11 then 22; the application consumes
22 then 11. Actual rows are correct, but replay associates the first response
event with 11 and the second with 22. The full live view and replay differ.
This is a diagnostic/replay defect, not database result cross-delivery.

The user selected **one recording per physical connection**, preserving the
existing JSON-lines format. Implemented in both clients:

- Python Capture permanently claims a physical core identity. Detach/reattach on
  that connection is allowed; moving it to another connection is refused before
  changing routes. Pools require `capture_factory`; routing/recovery also use a
  fresh factory result for the new physical connection. A direct capture refuses
  those transitions instead of combining conversations. The application owns
  Python capture resources and must give factory results distinct outputs.
- Rust Capture is non-Clone and moves into one driver. `ConnectOptions.capture_factory`
  creates a fresh writer per physical connection, while pool lease rotation keeps
  that writer. `Capture::create` uses exclusive creation and cannot truncate an
  existing recording. `set_capture` moves a writer only between exchanges.
- Rust Off/Outline/Full share result semantics. Outline and Full have identical
  lines; Full adds exact redacted packet header/body and native decoded Record
  values. Per-field trees, source links in the view, native replay and detailed
  response timings remain open; this is not full D-12 parity.
- Default recording redaction works on the complete LOGIN7 before splitting,
  including one-byte bodies. Explicit password capture never unredacts callback
  inspection. Query/result data remain in recordings by design.
- Seven controlled TLS tests cover failure policy/configuration/reuse and pool
  recording identity; Docker verifies both versions × plain/MARS. Python's
  unchanged replay reads four fresh Rust recordings, decodes rows 42 then 43 and
  confirms LOGIN7 credential redaction without decoding failures.

Python's five offline ownership/factory cases and eight Docker pooling/recovery
cases pass. The complete regression results are recorded in the Rust acceptance
file. Recording ownership is settled; the next permission checkpoint appears below.

## Shared routing correction

Both clients validate TCP (protocol 0), nonzero port, nonempty/NUL-free server
name and an empty old routing value before following a login route. Python had
ignored the protocol field. Six new pure-core cases exercise invalid targets and
the exact valid target. Rust records the routing login's final core step even
though it returns a redirect; a recording error at that boundary prevents the
next connection. Fatal SQL plus recording failure preserves both causes and the
fatal response record. Test certificates now use disjoint router.test and
localhost identities, independent of Docker's certificate authority.

## Recovery identity and permissions: implemented in both clients

**Original observation:** on SQL Server 17.0.5015, Python channel 1 returned row 11 after
channel 0 had closed. After an idle relay cut, recovery login completed, preserving
the server session id, and `recoveries` became 1; its surviving channel 1 then
stalled. The reader stayed alive with no core failure until the probe deadline.
The reproduction ran the exchange in the channel's owning task. A separate fresh
physical connection returned row 11 when its first wire channel id was 0, but a
fresh connection starting at id 1 was rejected with ConnectionError. These are
local observations, not a claim that MC-SMP universally requires first id zero.

The saved read-only reproduction is
`clients/python/.venv/bin/python tools/probe_mars_recovery_identity.py` from the
repo root. It also confirms recovered channel 0 returns row 22 as a direct
control. The earlier regression suite did not cover this nonzero-survivor path.

Python used one number for application-channel identity and wire SMP session id,
then adopted those same ids on recovery. The correction separates application
lifetime identity from per-physical wire identity in both framing directions.

**Concepts before process:**

| Concept | Meaning and scope |
|---|---|
| Application connection | Unique owner of the continuing SQL conversation/session; pool return ends that borrower's authority |
| Physical connection epoch | One TCP/TLS/login lifetime; owns one recording and a fresh wire-channel namespace |
| Application channel lifetime | One unique send/read authority, with a monotonic application id; retained across eligible recovery unless revoked by the application |
| Wire SMP session id | u16 number allocated within one physical connection; fresh allocation begins at 0 after reconnection |
| Exchange authority | One submitted request/advancing response; old reads, cancellation and abandonment guards must never affect a recovered replacement |

**Shared correction, verified in Python:** preserve Python's intended continuity of idle
application channels. On eligible recovery, rebind those logical channels to
fresh wire ids starting at 0, keeping their owners. Connection-close and
channel-close permissions continue to apply to their logical lifetimes. Every
old exchange permission is retired, including pending read/Drop guards and
cancellation; no in-flight SQL is replayed. Pool return still retires all previous
borrower authority. Each physical epoch gets its own recording.

The user preferred continuity if it actually works, and requested evidence before
settling the choice. The saved probe now returns row 22 through the same channel
1 object, bound to fresh wire id 0. The fresh-first-wire-id-1 control still fails.
Eight new Docker cases pass across TDS 7.4/8.0 × plain/MARS. They cover three
recoveries per connection (automatic and explicit), original channel objects and
owners, session settings and retained fetched rows, multiple surviving MARS
channels with reverse response consumption, later channel allocation, stale
closed-channel controls, delegated channel/connection close, separate recordings
replayed through the unchanged reader, and old response read/cancel/close controls
leaving a demonstrably unfinished replacement exchange undisturbed. Two pure-core
tests prove mapping in both directions and wire exhaustion independent of large
application ids. The interrupted-request test flushes SQL output with NOWAIT and
asserts the response is unfinished before cutting the relay; a row alone would
not prove that.

Full Python regression after the correction: **695 passed, 13 skipped, zero
failures**, in 112.17 seconds. The skips remain 10 Azure, 2 Kerberos and 1 Windows
certificate-store case. A further focused run of all ten new core/live tests
passes with explicit pre-recovery close controls and an assertion that old
response controls emit no Attention, independently of server scheduling.

The user approved implementation after the feasibility check. The
[experiment record](docs/design/experiments/recovery-channel-identity.md) preserves
its original observations, commands, intervention, results and limits. Python's
shell also pins each procedure's transport and refuses late actions after core
replacement. Rust now preserves logical channel/root close authority while
rotating physical epochs, reconstructing server-approved state and allocating
fresh wire ids. Eight controlled TLS tests cover recovery failure/recording/close
boundaries; three Docker tests contain the 7.4/8.0 × plain/MARS continuity,
interrupted-request and refusal matrices. Old armed read futures and unfinished
responses can be dropped after recovery without revoking the replacement; current
epoch abandonment still discards. Sixteen independently saved physical recordings
replay through Python with logical row attribution and LOGIN7 redaction checked.
The Rust acceptance record tracks final counts and broader unsupported scope.

Final implementation regression: Python **696 passed, 13 skipped** in 123.24 s;
Rust **31 unit + 61 controlled-network + 4 rustdoc**, **28 core-only**, and all
**25 explicit Docker tests** pass. Strict Clippy in both feature configurations,
formatting, rustdoc generation, recording replay and design-page checks pass.

## Next connection additions and architectural checkpoint

- [x] Browser core and Tokio UDP shell: instance/machine/DAC and IPv4 broadcast,
  strict request/reply bounds, original collection deadline, raw malformed reply,
  no automatic TDS connection. ASCII/UTF-8/Windows-1252 are implemented; other code
  pages and actual Windows Browser evidence remain open.
- [x] Unchanged Python/MC-SQLR fixture bytes, all 256 CP1252 decoding/encoding
  comparisons, every truncated example and five controlled loopback UDP cases.
- [x] Raw RETURNSTATUS decoding and ordered retention, with split-byte negative
  status and controlled fetched-response tests. This does not implement typed RPC,
  output values or grouped procedure returns.
- [x] Separately authenticated restricted SQL-login acceptance under both TDS
  versions and plain/MARS; error 229, role membership and reuse checked. Disposable
  setup/cleanup belongs to privileged connections, not the application login.
- [x] LOGIN7 password-change codec and Python byte comparison; both old/new
  credential fields are redacted. No new shell/pool option is exposed yet.
- [x] Agree the public heterogeneous row/value representation in
  [F](docs/design/F-rust-value-api.md). Approved explicit Value enum/exact SQL
  structs; integer migration and scalar read codecs are implemented. Typed RPC
  and streaming remain separate slices.
- [x] Establish the shared boundary: server password changes belong to explicit
  database/login operations; a stable pool reads current connection configuration.
  [G](docs/design/G-login-credential-lifetime.md) retains the Python defect and
  rotation/reset observations. [H](docs/design/H-pool-configuration.md) designs
  the agreed snapshot/read abstraction; its lifecycle policies still need review.

This checkpoint's checks: 36 Rust unit, 67 controlled-network, 4 rustdoc, 33
core-only and all 26 explicit Docker tests pass. Browser testing is controlled
UDP, not a claim about the Linux container running a Browser. The Python code was
not changed in this slice; the credential correction awaits the pending choice.


## Approved value representation: scalar reads

- [x] Migrate live/retained rows to `Vec<Option<Value>>`; retain existing lifetime,
  cancellation, cleanup, pool and recovery semantics.
- [x] Separate declared `SqlType` from wire `TypeInfo` code/raw maximum length.
- [x] Decode fixed/nullable scalar aliases and ROW/NBCROW: integer/bit, float bits,
  decimal/numeric, money, temporal/GUID, bounded Unicode/raw text/binary.
- [x] Checked exact decimal/calendar/time/offset structs, no implicit rounding.
- [x] Compare 95 deterministic valid Python scalar cases and four pure regression
  tests; test heterogeneous retained values/reuse in the four Docker modes.
- [x] Add SQL text decoded views/code-page fidelity, parameter writers/typed RPC,
  output values/grouped returns and scalar/large/special payloads. TVP/bulk are
  separate pending input-ownership choices in design J.
- [x] Correct Python's directly constructed datetimeoffset parameter validation
  to enforce UTC/local bounds, ticks and offsets; invalid success fixture noted
  in F. Rust already enforces those invariants in its checked constructor.

The earlier pool-password question is superseded by the agreed configuration
snapshot/read boundary. Existing code still retains fixed opening settings;
the shared design in H specifies the proposed implementation, not a completed API.

Scalar-slice checks: 36 unit + 4 pure scalar-fixture + 67 controlled-network + 4
rustdoc tests; core-only 33 unit + 4 scalar-fixture; all 27 explicit Docker tests
pass. Fixture generation is deterministic and the source/acceptance documents
separate parameter/streaming work from completed scalar decoding.

## Shared pool configuration: implemented

- [x] Agree demand-driven `ConfigService.read()` returning an immutable value;
  compare with each pool's last accepted settings. No public hash, timestamp,
  revision, change flag, watcher or notification task is needed.
- [x] Design both language change maps and the shared acceptance matrix in
  [H](docs/design/H-pool-configuration.md); preserve the direct-login distinction
  and evidence in [G](docs/design/G-login-credential-lifetime.md).
- [x] Approve SQL-only reloadable field scope, fixed runtime bindings and
  lazy first-read behavior.
- [x] Approve stale checkout/return/late-login handling and password-only
  compatible recovery. Current borrowers are not interrupted by adoption alone.
- [x] Implement comparable values, source adapters and safe failures in both clients.
- [x] Wire capacity-safe, deadline-bound opening reads and independent configuration
  access for recovery; keep I/O outside protocol cores and registry locks.
- [x] Preserve explicit authentication failures, later recovery after operator
  correction, deferred-reset error visibility and the prohibition on SQL replay.
- [x] Correct direct password-changing login credential retention independently.
- [x] Run the shared deterministic and Docker matrices and full language checks;
  native Windows/Linux/macOS file-provider evidence is separate acceptance work.

Both clients implement this slice. No built-in file provider or watcher is added.
The earlier pending-design checkpoints above are historical; H and the current
support/acceptance records describe the implemented contract.


Configuration-slice validation (2026-10-17): full Rust suite and four rustdoc
checks pass; seven dedicated configuration tests pass, including superseded
recovery and lost password-change completion. Core-only: 33 unit + 4 scalar
fixtures. All 29 explicit Docker tests pass. Both strict Clippy configurations,
formatting, documentation and library build pass. Python's full regression passes
713 tests with 13 skips; the expanded eight-case configuration live suite also
passes, including the subsequently added late recovery case. H/G and the client
READMEs describe the implemented contract and its remaining platform/provider
limits. No standalone Rust SQL CLI exists yet.


## Typed calls, forward results and executable

- [x] Assess Python's typed requests/defaults/output/grouped-return contract.
- [x] Add exact bounded scalar parameter writers; compare deterministic Python
  bodies and reject incompatible payloads/range overflow/rounding before send.
- [x] Implement named and built-in Call/Calls, options, NULL/default/output
  parameters, RETURNVALUE, grouped DONEPROC returns and saved metadata.
- [x] Apply pool reset to RPC requests and preserve validation-before-send even
  while a MARS sibling is executing.
- [x] Add borrowed result-set row iteration and explicit Refuse/Keep/Discard
  access to procedure returns; preserve Python retention and checked errors.
- [x] Correct Python datetimeoffset direct/aware parameter UTC/local validation.
- [x] Provide the Rust `tds` executable for verified query/RPC, typed inputs,
  observation, exclusive per-physical capture, forward rows and explicit fetch.
- [x] Agree and implement the large-value row/value/source surface in
  [I](docs/design/I-rust-rpc-and-streaming.md); keep chunked paths incremental,
  parent-bound, cancelable and safe under MARS backpressure.
- [x] Add CLI chunked large-value demonstrations after that API is settled.

The default/debug executable is `clients/rust/target/debug/tds`; `--help` shows
its actual options. Typed calls, large-value streams, borrowed readers and binary
file sources are implemented. Special types and batched source bindings remain
explicit gaps; this is not full Python parity.


Typed-call/CLI evidence: **130 default Rust checks**, **32 explicit Docker tests**,
both strict Clippy configurations, formatting, core-only tests/rustdoc and the
executable build pass. Python: **723 passed, 13 skipped** after the shared temporal
validation correction. Four CLI RPC recordings replay in Python with correct
rows/outputs and credential redaction. This was the scalar checkpoint; the next
checkpoint below supersedes its large-value status.


## Approved streaming checkpoint

- [x] Implement the borrowed set/row/value chain, typed owned chunks and deferred
  discard on parent advancement; preserve explicit fetch and owned output values.
- [x] Add incremental PLP/XML/legacy decoding, owned large input parameters and
  async typed PLP sources with IGNORE/EOM cleanup on partial-send failure.
- [x] Prove partial-value abandonment, producer cleanup failure and interrupted
  source close with controlled peers; count only complete rows as Python does.
- [x] Verify large values, sources, MARS backpressure/sibling progress, cancellation
  and reuse on Docker; add CLI chunk summaries and binary file input.
- [x] Correct contradictory PLP-total validation in both clients and Python's
  unclaimed-large-row replay pause; cross-replay streamed and scalar recordings.
- [x] Record the approved surface and evidence in design I, the crate README,
  support matrix and acceptance log; regenerate the offline design pages.

Rust: **142 default checks**, **39 Docker tests**, both feature/lint configurations,
rustdoc and executable builds pass. Remaining special types, batched source
bindings, provider/platform acceptance and measured performance stay explicit.

Python's final full regression passes **734 tests, 13 skips**. The level-comparison
fixture now verifies each independent connection's own server-assigned session ID
before normalizing that field alone; it no longer assumes server ID reuse.


## Completion continuation while architectural choices are collected

- [x] Explicit transaction-manager operations; state follows announcements;
  deferred reset applies to TM as well as SQL batch/RPC.
- [x] Batched uniquely owned RPC sources with validation-before-production and
  partial-send cleanup; no atomicity or request replay promise.
- [x] Browse table/column provenance and sensitivity classification v1/v2.
- [x] Exact CLR serializations, bounded variants, native JSON and vector codecs;
  advertise only implemented features and preserve acknowledged versions.
- [x] Explicit SQL-corrected collation views and incremental character decoders;
  raw text bytes remain available, with no replacement or guessed encoding.
- [x] Extend the actual CLI with transaction and special-value examples; compare
  Python-generated corpora and cross-replay all sixteen fresh recordings.
- [x] Correct shared vector validation, negotiated replay context, input-only
  inspection layouts and saved JSON metadata encodings in Python/Rust.
- [x] A1: user approved an input-only table-valued parameter representation.
- [x] Implement approved A1: `ParamValue`, `TableType`, owned rows and unique
  `RowSource` bindings; compare Python bytes and real procedures in four modes.
- [x] A2: user approved borrowed `BulkWriter`, explicitly preserving the D-50
  ordering exception; implement awaited finish/source/abort and Drop discard.
- [x] Correct Python close/release/recovery in the prepared bulk gap; preserve
  explicit transactions after proven Attention cleanup and discard unresolved leases.
- [x] Check bulk ACK ordering/timeouts, forgotten writers, delegated close,
  producer/encoding failures, exact/large cells and CLI `--demo-bulk`.

[Design J](docs/design/J-rust-completion.md) contains the two architectural
questions, recommendations, implemented behavior and evidence boundaries. The
current [support matrix](clients/rust/SUPPORT.md) supersedes earlier historical
gap lists. Rust: **157 default**, **61 core-only**, **50 Docker**, plus the
**14-case affected live rerun**; fmt, both strict Clippy modes, rustdoc and CLI
build pass. Final Python totals are recorded with the completion acceptance.

Final Python regression on the final source: **761 passed, 13 skipped**. All
sixteen CLI recordings replay in Python with LOGIN7 masking; generated tables
reproduce exactly, and offline page syntax/source-file links pass checks.


### Table inputs and borrowed bulk completion

Approved A1/A2 are implemented, including the shared Python prepared-gap fix.
Current evidence: **164 default Rust checks** (10 rustdoc), **63 core-only**
(3 rustdoc), **55 Docker tests**, an **8-test affected live rerun**, both strict
Clippy modes, formatting/docs/build; Python **766 passed, 13 skipped**. All
**20 fresh CLI recordings** replay through Python and preserve LOGIN7 masking.
The original bulk experiment now asserts corrected close/pool outcomes in four
modes. See the latest acceptance section for exact scope and remaining limits.


## Native offline replay: implemented 2026-10-18

- [x] Agree the physical-recording/logical-channel representation and retain the
  existing JSONL format; distinguish recorded events from decoded wire evidence.
- [x] Public offline replay API and actual `tds --replay` CLI, without live setup.
- [x] Input-specific SQL/RPC/transaction/table/bulk reading, exact values, shared
  negotiated result context and independent channel decoders.
- [x] Shared Python saved TVP declaration/row inspection, including hints/defaults,
  placement, following parameters and batched calls.
- [x] Located malformed/unsupported/incomplete diagnostics, Attention ACK proof,
  raw credential withholding, exact Python UTF-16 event text and prefix retention.
- [x] Actual CLI/corpus checks, four-mode fresh captures, owned/produced Rust TVPs,
  sixteen Rust recovery epochs and sequential full-language regressions.
- [x] Update support, acceptance, handover and the generated offline design page.

Recorded checks: Rust **175 default**, **73 core-only**, **56 Docker**; affected
**11 default/9 core-only** rerun after diagnostic-only refinements; Python
**782 passed, 13 skipped**. Both readers accept **48 fresh saved recordings** with
credential masking; live Rust additionally verifies four owned/produced TVP
recordings in memory. Strict lint, fmt/docs/build and page syntax checks pass.
[Design K](docs/design/K-offline-replay.md) and the final acceptance section
supersede earlier native-replay/TVP-inspection gap lists. Field trees/timings,
unsupported wire extensions and provider/platform evidence remain separate work.
