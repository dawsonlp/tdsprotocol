# Rust client development: evidence

Observed locally through 2026-10-18, branch `rust-client`. This is a development slice,
not a release or a claim of Python connection-package parity.

The check table is current. The sections below retain earlier checkpoints;
[interrupted I/O acceptance](#interrupted-io-acceptance)
records the latest scope and shared corrections.

## Environment

- macOS Apple Silicon, `stable-aarch64-apple-darwin`.
- `rustc 1.99.1 (58cf8f9c3 2026-10-13)`; `cargo 1.99.1`.
- Locked dependencies: Tokio 1.53.3, rustls 0.23.46, aws-lc-rs 1.18.2.
  Capture uses serde_json 1.0.154, base64 0.22.1 and time 0.3.55; the shell's
  portable machine-name lookup uses hostname 0.4.2.
- Existing `mssql-2025` container, image
  `mcr.microsoft.com/mssql/server:2025-CU9-GDR1-ubuntu-24.04`.
- Server LOGINACK reports 17.0.5015; database `tds_test`, language `us_english`,
  negotiated packet size 4096. The fourth product-version component is not in
  LOGINACK and is not inferred here.
- TCP `127.0.0.1:14325`, explicit project test CA, certificate/host verification
  enabled. TDS 7.4 negotiated TLS 1.2; TDS 8.0 negotiated TLS 1.3 with `tds/8.0`.
- Credentials read from ignored configuration/environment; none committed or
  printed. Database setup belongs to the existing Compose initialization hook.

## Checks

Run from `clients/rust/`:

| Command | Evidence |
|---|---|
| `cargo test --offline` | 190 checks pass, including 15 deterministic interruption tests and 11 rustdoc checks; 56 Docker tests are explicitly ignored in the ordinary run |
| `cargo test --offline --tests -- --ignored --test-threads=1` | All 56 live test functions pass, each exercising its documented protocol/framing or feature matrix |
| `cargo test --no-default-features --offline` | 73 checks pass, including 4 rustdoc checks; the shell/executable are excluded |
| `cargo fmt --all -- --check` | Pass |
| `cargo clippy --offline --all-targets -- -D warnings` | Pass, zero warnings |
| `cargo clippy --offline --no-default-features --all-targets -- -D warnings` | Pass, zero warnings |
| `cargo doc --offline --no-deps` | Pass |
| `cargo build --offline --bin tds` | Pass; runnable debug binary |

These results do not assert a minimum Rust version or any other
operating-system/runtime coverage.

The live scenarios prove sequential exchanges and channel reopening, multiple
result sets, integer widths/NULL, transaction announcements across batches,
channel movement into a task, SQL error records followed by completion/reuse,
wrong CA/host/password/database rejection, unfinished-response discard,
forgotten-response busy refusal, read timeout, owner task abort, external close,
parent-drop revocation, and uncertain outcome after observed request transmission
through a deliberately broken proxy. The proxy also observes no reconnect.

Cancellation adds live Attention/acknowledgement and reuse under both versions,
including after unread packet-producing results. Shared cancel handles cannot
cancel the next exchange. Under `SET XACT_ABORT OFF`, the explicit transaction
and its announced descriptor remain until an explicit COMMIT; cancellation is
not treated as evidence of rollback.

A separate permission test creates an isolated database user/table, runs allowed
and denied queries under `EXECUTE AS USER`, observes error 229 and a failed
completion, then proves connection reuse. Privileged setup/cleanup use another
connection; cleanup occurs before asserting the observations. This checks a
restricted database security token, not low-privilege SQL-login authentication.

Controlled TLS peers prove that an ordinary final DONE before a later ACK never
releases the channel; split ACKs wait for their message boundary; missing ACKs
time out even without an application read; malformed drain replies preserve the
original failure; and dropping cleanup/ack-wait futures discards immediately.
A paused-clock test proves that cancellation bypasses a full command mailbox,
starts the 5-second budget once and does not restart it on repeated requests.
The peer's artificial certificates/key are repository test fixtures, not Docker
credentials, and require no local certificate generation at test time.


## Response retention parity

The user confirmed Python as the assessed behavioral baseline. Seven unchanged
captures from `clients/python/tests/response_samples.py` cover counts, NOCOUNT,
statement/batch errors, messages, NULL bitmap and environment announcements.
Their copied binary bodies preserve original server names and bytes; an AST-based
comparison verified exact equality without changing the Python source. Controlled
TLS tests replay whole and one-byte packet bodies and assert semantic results.

The nine response tests cover complete and partial fetch, the live unread tail,
finish without Attention, errors after all result sets and once only, cancellation
acknowledgement retained during autonomous drain, fetch preserving kept rows during
external cancellation, and honest incomplete/fatal failure snapshots. The added
live test checks finish/fetch/partial-fetch/error/reuse under both TDS versions.
Owned fetched data remain usable after connection destruction.

`finish()` returns `()` and retains the record for inspection. A partly streamed
set refuses `rows()` even though its unread tail can still be read live; subsequent
untouched sets remain fetchable. No Rust-only retention caps were introduced.
Transport bounds do not bound semantic history, fetched rows or snapshot copies.

## Findings that changed implementation

An ordinary small query passed before a request larger than 64 KiB exposed a TLS
packet-boundary bug. Encrypting concatenated TDS packets allowed TLS to split
records at unrelated boundaries; SQL Server closed the 7.4 connection. The shared
Packet reference and Python `Link.plain` already describe the constraint. The
Rust sender now encrypts and drains one packet at a time. The same larger request
then passed under both versions. Keep this regression case.

Server PRELOGIN replies can have an empty THREADID entry. It is a client field;
the Rust reader validates directory bounds but does not demand four reply bytes.

The first cancellation test's single SELECT row could be buffered until WAITFOR
completed. It now produces enough integer rows to force packets and cancels after
the first observed row, so it tests unread response cleanup rather than assuming
immediate flushing by this infrastructure. No throughput claim follows from it.

## Scope still open

Still open: full SQL
type/request vocabulary, field inspection trees, detailed observation timings,
Rust-native replay, a general neutral fixture corpus, full result-set iteration,
large-value streaming and grouped procedure returns/output parameters. Routing, initial observation/capture
and eligible session recovery are implemented in the later slices below.
Checked finish/fetch, once-only SQL
errors and retained response snapshots now cover the supported integer/token
subset. Fatal server errors and transport/protocol failures attach the received
record and discard the connection. This is not full Python response API parity.

The transport bounds and backpressure path are explicit in the README and code;
semantic history/fetch are deliberately retained without cumulative budgets, as in Python;
maximum retained memory and performance have not been measured. MARS fairness
has functional tests, not a latency or throughput benchmark. At this historical
checkpoint, runtime shutdown and forced partial socket-write boundaries did not
have separate deterministic acceptance. The [interrupted I/O matrix](INTERRUPTIONS.md)
below now covers selected boundaries, including current-endpoint revocation after
pool rotation; exhaustive scheduling coverage remains outside that evidence.
The shared channel-close correction changes Python core,
shell and terminal-message handling; its final regression evidence is recorded
below. Earlier response-only evidence was 63 focused Python tests, not a complete
Python/live revalidation.

## Shared channel-close correction

Approved: revoke authority, cancel/drain, release only after proof; discard on
cleanup failure. Rust adds a weak, lifetime-scoped `ChannelCloseHandle`. One paused
clock test proves mailbox-independent revocation and a shared first deadline.
Five controlled TLS tests cover ordinary DONE before ACK, ACK before its message
end, waiting owners/repeated closers, timeout without owner reads, stale controls,
a dropped cleanup future, and shared malformed/fatal drain failures with partial
records. The new live case checks close/reopen/stale authority
under both TDS versions.

Python uses monotonic local ids for plain channel lifetimes and reclaims released
plain registry/inbox entries. Its MARS wire ids remain non-reused and explicitly bounded
to 16 bits per physical connection; recovery now allocates fresh wire ids while
preserving application ids and excluding revoked lifetimes. Owner operations and private drain are
serialized. Live tests cover both TDS versions with/without MARS, sibling reuse,
unclaimed large values and partial-send undo. Pool tests distinguish a genuinely
abandoned channel (discard) from awaited cleanup (reuse, then session reset).

The initial full Python run exposed redundant scope-exit cleanup on a failed
connection and an old pool test whose managed channel is now cleaned on exit.
The first was corrected; the second retains both discard and proven-reuse cases.
The pool test measures liveness during the lease, before normal pool shutdown.
Prior close-correction Python validation from `clients/python/`:

```sh
.venv/bin/python -m pytest -q -rs --tb=short
```

**611 passed, 13 skipped, zero failures**, in 118.66 seconds. The skips are
10 Azure infrastructure cases, 2 Kerberos runner cases and 1 Windows certificate
store case. The local SQL Server and controlled-network tests ran. This includes
the final plain/MARS recovery-revocation guard, Attention write-failure case,
terminal-message boundary checks and both pool-return outcomes. The separate
focused recovery/channel-core run passed 30 tests.

Before MARS, the close-correction validation passed 15 unit, 5 TCP, 7 cancellation TLS,
9 response TLS, 5 channel-close TLS and 3 rustdoc checks, plus all 12 explicit
Docker tests. Both Clippy feature configurations, core-only tests, formatting,
rustdoc generation, site JavaScript syntax and `git diff --check` pass.

Changes remain uncommitted on `rust-client`; no implementation commit, push or
release was made for this slice.


## MARS and shared framing correction

`ConnectOptions::mars` now opts into negotiation; a refusal fails before login.
Framing starts only after successful login. Each channel has its own response
state, four-frame receive window and credit-blocked sender. The shared socket
continues routing while a reader is idle. Returned request handles require all
request packets to acquire credit and reach the socket. Pending readers and
autonomous drains use round-robin turns; a buffered drain also services queued
commands. Session/transaction announcements and terminal connection failure remain
shared. A peer FIN alone revokes its own channel; failed cleanup discards siblings.
Non-reused channel ids start at zero and refuse exhaustion of the 16-bit wire space.

Observed interoperability: the initial Rust sender began at channel id one and
SQL Server immediately disconnected it. Starting at zero, matching Python and
MC-SMP's first-session example, made the same live scenarios pass. This is an
observed SQL Server constraint, not a claim that SMP generally forbids other SIDs.

Six controlled TLS tests verify a sender stalled after four DATA frames while a
sibling exchanges, outstanding request counts, one-byte TLS plaintext fragments,
TDS packets split across frames or combined within one, each channel's own response
prefix on shared fatal failure, malformed-sequence fanout, cleanup timeout during
send-credit exhaustion, abandonment, and peer-FIN isolation/reciprocal FIN.
Three core SMP tests cover fragmented headers, invalid flags/lengths, receive-window
exhaustion, consumed-frame credit, send resumption, FIN and 32-bit sequence wrap.
A core channel test checks identity non-reuse and 16-bit exhaustion.

Four Docker MARS scenarios run under both 7.4 and 8.0: stalled-reader independence,
large requests/responses beyond initial credit, shared server session, busy
channel close and stale controls, externally requested cancellation with retained
acknowledgement/reuse, and whole-connection discard after response abandonment.
The full explicit Docker run contains 16 tests; normal test runs still mark them
ignored so missing credentials cannot silently count as live acceptance.

Python's parser previously accepted invalid SMP lengths/flags/sequence/window
progression, including a zero length that could leave its loop making no progress.
It also returned credit per TDS packet, although SMP counts DATA frames. Both
clients now validate those fields, handle 32-bit wrap and return credit per frame
consumed. Eleven new Python framing tests cover malformed/oversized headers,
control lengths, sequence/window violations, unknown ids, every split boundary,
split/combined TDS packets and DATA already in flight after FIN. The focused run
passed **88 tests**, including existing live MARS and capture parity.

Final full Python validation on the MARS correction: **622 passed, 13 skipped,
zero failures**, in 107.48 seconds. The skips remain 10 Azure, 2 Kerberos and 1
Windows certificate-store case; the local Docker/network scenarios ran. Rust's
19 unit, 32 controlled-network and 3 rustdoc checks pass; all **16 explicit Docker
tests** pass with no skips. Both feature configurations pass Clippy with warnings
denied; core-only tests, formatting and rustdoc generation pass.

SMP framing rules were checked against Microsoft's
[MC-SMP v20251031](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-smp/04c8edde-371d-4af5-bb33-a39b3948f0af),
especially §§2.2, 3.1.4 and 3.1.5. The 1 MiB frame bound is an explicit client
transport allocation limit, not a protocol maximum or a semantic retention budget.

The later pool implementation and accepted Drop policy are recorded below.
No publish, commit or push is implied by this evidence.


## Whole-connection pooling

The user approved explicit `lease.release().await` for reuse; Drop discards.
`Pool::new(options, capacity)` is lazy. A semaphore reservation bounds acquisition
and lending; idle entries are popped before a new login. A failed/canceled opening
releases its reservation. No pool mutex is held across I/O. Shutdown wakes waiters,
closes idle connections and refuses a login finishing after closure; current
borrowers remain usable until return/drop, matching Python.

The connection's one persistent driver survives successful pool reuse but the
borrower's authority endpoint does not. Return revokes old descendants, closes
idle channels, waits for all MARS FIN obligations, then switches to a fresh mailbox
and endpoint. Old root close/channel close/cancel/send/read handles cannot act on
that next lease. Cancellation guards protect both endpoints around the commit.
Driver destruction revokes its current endpoint even after a rotation. Active
exchanges or unresolved cleanup are discarded; return never starts implicit
Attention cleanup. Return/FIN drain uses the configured total cleanup budget.

Python's reset contract is retained: the next successfully encoded request sets
RESETCONNECTION on its first packet once. RESET_COMPLETE (ENVCHANGE 18 with empty
old/new fields) restores login database/language/collation/packet-size state.
Transaction state follows its own announcements; the client adds no SQL to
normalize isolation level or distributed transactions. A unit case checks that
baseline restoration does not blindly zero a transaction descriptor. DTC itself
is unsupported, so no distributed-transaction live acceptance is claimed.

Eight controlled pool TLS tests cover explicit return/reset/stale controls,
saturation/canceled waiters/Drop, canceled opening/failed login, dirty return,
shutdown/late login, missing FIN/timeouts/canceled return, reciprocal FIN before
reuse, and replacement after failed response cleanup (plain/MARS). Three live pool
tests run a 7.4/8.0 × plain/MARS matrix. They check independent borrowers and
capacity, database/language/date-first/temp-table reset, a plain local transaction
rolled back by reset, stale controls and proved cancellation reuse. Reuse and
replacement are compared using SQL Server's connection GUID split into two exact
integers, so recycled SPIDs cannot masquerade as a reused transport.

The first live cancellation attempt sent Attention immediately after writing
WAITFOR and received no acknowledgement within the cleanup budget. The client
correctly discarded it. The reuse acceptance now first observes a row from a
packet-producing result, then closes; this proves server activity without a
fixed sleep or assuming socket-write completion means execution has started.
The actual immediate-cancel acknowledgement gap is not claimed fixed by that
acceptance change; controlled peers still test immediate cancellation and timeout.

A second shared correction follows MS-TDS §2.2.5.3.2: autocommit MUST send one in
the transaction header even under concurrent MARS. Both clients previously sent
the active count. Rust's encoder and Python's common request-header definition
now normalize only autocommit; explicit transactions still count active requests.
Exact header-byte tests cover both cases, including Python Batch and RPC.

At the pool checkpoint, Rust checks passed: **22 unit + 40 controlled network + 4 rustdoc**, plus
**19 explicit Docker tests with no skips**. Core-only: **20 tests**. Both Clippy
configurations pass with warnings denied; formatting and rustdoc generation pass.
The observer/capture failure policy was subsequently approved; its shared Python
correction and the next recording-ownership decision are recorded below.

## Approved diagnostic-failure policy and shared Python corrections

The user selected continuing after optional live-log failure, disabling that
callback and exposing its exception separately; saved-recording write failure
instead discards the connection. Python implements this with inspectable
`observation_error` on Connection/Pool and `CaptureError.cause` for recording
failure. Event/packet recording failure closes the socket synchronously, wakes
waiters and prevents recovery, even through a cleanup-error wrapper. JSON lines
are flushed so buffered-write failures surface before connection teardown; no
fsync durability claim is made. Recording still receives an event after the
optional observer fails. Pool return/opening failures retain cleanup errors and
cannot strand capacity. Late-login and canceled-commit races are corrected too.

The full Python regression run after the pool and diagnostic changes passed
**664 tests, 13 skips, zero failures**, in 122.59 seconds. The skips remain
10 Azure, 2 Kerberos and 1 Windows certificate-store scenario. Additional focused
checks cover the final recording-failure latch through cleanup and pool-return
error pairing. The live policy matrix covers channel creation, request sending,
response reading and close under TDS 7.4/8.0 × plain/MARS.

Before Rust observation/capture integration, their ownership boundary required
another shared decision. Python Pool previously forwarded the same capture to every
connection, but its schema and replay keys have no connection identity. An offline
two-connection shell/core probe recorded integer packets 11 then 22, consumed
responses 22 then 11, and observed correct actual rows but replayed row bytes
`d10b000000` then `d116000000`. Thus replay and the live view differ; this is a
diagnostic identity defect, not SQL result cross-delivery.

## One recording per physical connection: approved and implemented

The user selected independent physical-connection recordings, preserving the
existing file format. Python Capture now claims one physical identity permanently;
a pool requires capture_factory, also used by connect for new recordings on
routing/recovery. Loans on the same transport keep its recording. Applications
own/close Python capture resources and must provide distinct outputs. Five offline
and eight Docker ownership/factory/pool/recovery cases pass. The full Python suite
now passes **679 tests, 13 skips, zero failures**, in 127.94 seconds. The 13 skips
remain the same remote/platform scenarios; local Docker tests ran.

Rust's non-Clone Capture moves into the physical driver; a factory creates each
writer, and endpoint rotation keeps that writer across leases. Exclusive file
creation prevents truncation. Core descriptions have no application callbacks;
the driver invokes them after core operations and before writes/results. Off,
Outline and Full preserve result rows/counts; Outline/Full have identical lines.
Full adds exact redacted packet header/body and native Records. Ordinary observer
errors are disabled/reported separately; a panic unwinds and discards through the
driver guard. Recording failures retain the I/O cause and channel response prefix,
close the driver and wake waiters. Controlled tests include a consumed row before
recording failure and refusal to send SQL whose recording failed before writing.

Two unit cases cover complete LOGIN7 redaction through one-byte packet bodies,
explicit credential inclusion, header preservation, buffered flush failure and
exclusive creation. Seven controlled TLS tests cover policy, configuration and
pool recording identity. The new Docker scenario verifies both versions with and
without MARS. Four retained credential-redacted Rust files were replayed by
Python's unchanged replay/Printer implementation: each yielded rows 42 then 43,
one redacted LOGIN7 and no decoding-failure view. This is live cross-language
evidence for the supported subset, not full replay parity.

Per-field inspection trees/reference links, detailed response timings, a printer,
pool-level event lines and Rust-native replay remain open. The richer Python
message-tree presentation is not claimed implemented by the native Record view.

## First configurable login-option group

Rust now exposes app/host identity, language, ODBC defaults and read-only intent.
ODBC defaults on and empty language uses the login's default, matching the
assessed Python behavior; the initial minimal Rust encoder had selected English
and omitted ODBC. The shell supplies the machine's hostname and process id.
No internal SET statements normalize these options. Deterministic artificial
LOGIN7 fixtures generated from Python's actual definition match Rust byte for
byte, including LCID and zero-length offsets; independent assertions cover the
option flags and language count.

Docker checks both versions × plain/MARS with ODBC on/off: ANSI/TEXTSIZE defaults,
configured Unicode app name, host and process identity, Deutsch announcement,
login-default language selected dynamically from the current principal, and
invalid-language refusal. Read-only intent still permits a temp-table write on a
writable server. The generic live helper selects English explicitly for fixture
scenarios instead of assuming the server's default language.

After this group, **25 unit + 47 controlled-network + 4 rustdoc** checks and all
**21 explicit Docker tests** pass (7.08 seconds for Docker). Core-only: **23**.
Both Clippy configurations, rustdoc generation and formatting pass. Python's
additional factory-None guard is covered by the focused 13 ownership/recovery
tests; a factory cannot silently leave a requested conversation unrecorded.

## One-hop routing and the next recovery checkpoint

Routing now follows one valid TCP destination with a single original connection
deadline, its own certificate name and a fresh recording. A router's TLS name
override does not carry across. Routed LOGIN7 sends server,port. A typed Route can
be reported with following disabled; a second hop is refused with the whole chain.
The five controlled routing tests use distinct router.test/localhost certificates,
verify destination SNI and LOGIN7 identity, opt-out, invalid targets, loop refusal,
separate recordings and recording failure preventing the next connection. A
delayed router plus silent second handshake verifies that the timer is not reset.
Both 7.4/8.0 × plain/MARS also reach actual Docker SQL Server through a local
verified TLS router and produce two independent recordings.

Python now rejects unsupported protocol, zero port, empty/NUL-containing name and
nonempty old routing values before following the route. Six new core cases cover
the shared validation. The final Python regression result is **685 passed,
13 skipped, zero failures**, in 137.23 seconds. The skips remain 10 Azure,
2 Kerberos and 1 Windows certificate-store scenario. Docker/network cases ran.

Driver teardown now delivers the failed core step's queued observations, including
the routing reply. A recording failure at that point preserves both causes and
stops the redirect. A further controlled observation case combines synthetic
fatal SQL with failure writing its diagnostic event and verifies both causes and
the fatal response record. Current controlled Rust checks: **25 unit + 53 network + 4 rustdoc**; core-only **23**. Both Clippy configurations, formatting and rustdoc
generation pass. All **22 explicit Docker tests** pass in 7.66 seconds. The artificial TLS fixture generator now produces disjoint
router and server leaves; these keys protect no real service.

The separate manual diagnostic
`tools/probe_mars_recovery_identity.py` originally demonstrated an uncovered Python recovery
path on SQL Server 17.0.5015: fresh first SMP id 0 returns row 11; fresh first id 1
is rejected. After an idle relay cut, retained application channel 0 recovers and
returns row 22. Retained channel 1's recovery login completes (`recoveries=1`)
but its query then times out while the reader remains alive with no core failure.
The probe owns each channel in the task doing its reads, uses only SELECTs and
discards its failed connections. These observations are not a universal MC-SMP
numbering claim, nor evidence that all recovery paths are correct because the
normal regression suite passes.

The user preferred retaining usable channels and requested proof of feasibility.
Python now separates logical lifetime ids from per-physical SMP ids, allocates
fresh wire ids on recovery and maps incoming frames back to logical channels.
The probe now returns row 22 through the original channel 1, bound to wire id 0;
the fresh-first-wire-id-1 control still fails. Two pure-core tests cover both
mapping directions and physical wire exhaustion independent of application ids.
Eight new Docker cases pass across TDS 7.4/8.0 × plain/MARS. They exercise repeated
automatic/explicit recovery, retained owners/settings/fetched results, multiple
surviving channels with reverse response consumption, new channel allocation,
stale closed-channel handles, valid delegated close permissions and independent
recordings replayed through the unchanged reader. Old unfinished response
read/cancel/close operations cannot disturb the replacement request. NOWAIT
flushes SQL output before the relay cut; each interrupted response is asserted
unfinished, rather than assuming a SELECT row proves active execution.

Full Python regression after this correction: **695 passed, 13 skipped, zero
failures**, in 112.17 seconds. Skips remain 10 Azure, 2 Kerberos and 1 Windows
certificate-store case. All ten new core/live cases also pass in a focused rerun
with pre-recovery close permissions retained explicitly and an assertion that
stale response controls emit no Attention, independent of server scheduling.

Those were Python feasibility results against local SQL Server 17.0.5015. The
user subsequently approved implementation; the completed Rust slice follows.

## Recovery implementation and acceptance

The [experiment record](../../docs/design/experiments/recovery-channel-identity.md)
preserves the failure and the intervention. Both clients now keep application
channel identities/owners and allocate fresh physical SMP ids, routing in both
directions. Python also pins running procedures to their original transport and
refuses late actions after core replacement. Both discard the failed socket
before recovery. Rust's one logical driver rotates its epoch before notifying
failed exchange waiters, so old commands/cancel/read/future/response Drop controls
cannot affect a replacement. Root/channel close permissions survive; application
closure and pool borrower retirement still revoke their respective lifetimes.

Rust requests SESSIONRECOVERY by default (the only advertised extension), reads
FEATUREEXTACK/SESSIONSTATE and tracks initial/current values, per-state sequence
numbers, server refusals, reset and sequence exhaustion. Initial and recovery
LOGIN7 bodies and a recovery snapshot match artificial Python-generated fixtures
and the MS-TDS recovery example exactly. New-token parsing covers every byte
boundary and malformed bounded bodies. Unknown/unrequested features fail login.

Observed idle transport loss can recover before new SQL. Interrupted SQL fails
with partial records and uncertain execution, and requires explicit recovery;
it is never replayed. An ordinary new login without recovery acknowledgement
does not authorize application SQL. One deadline covers replacement TLS/login
and channel establishment. Silent candidate timeout closes it, and a later
explicit attempt can succeed. Failed optional observation remains disabled across
a failed attempt; failed saved-recording factory/write is terminal. Direct
capture without a factory refuses recovery. Canceling a submitted recovery future
or using an existing root-close permission tears down its candidate.

Current Rust checks after recovery implementation:

| Check | Result |
|---|---|
| `cargo test --all-features --offline` | 31 unit, 61 controlled-network and 4 rustdoc checks pass; live cases explicitly ignored |
| `cargo test --no-default-features --offline` | 28 core tests pass |
| `cargo test --offline --test live_connection --test live_recovery -- --ignored --test-threads=1 --nocapture` | 22 existing Docker tests pass in 7.57 s; 3 recovery matrix tests pass in 4.96 s; zero skips |
| Strict Clippy, all features and core-only, plus fmt/rustdoc generation | Pass |
| Python replay of the 16 new Rust physical recordings | Pass, including logical channel row attribution and LOGIN7 credential redaction |
| Full Python regression after final transport pinning/closure | 696 passed, 13 skipped, zero failures; 123.24 s |

The three live recovery tests contain 4 continuity scenarios (three replacements
each), 8 interrupted-request/stale-control scenarios and 10 refusal/opt-out
scenarios across TDS 7.4/8.0 × plain/MARS. A deliberately retained armed old read
future and unfinished response are dropped after recovery; the original channel
then successfully runs new SQL. A separately tested path observes the partial
failure, rejects further SQL without automatically reconnecting, then explicitly
recovers. Channels closed through delegated controls are retained as stale objects
and never revived. New channels get later logical ids and fresh wire ids.

SQL Server rolls back a transaction left open at the end of a MARS batch (3997),
so that batch cannot establish an idle open-transaction refusal. The transaction
refusal uses plain connections; temporary-table refusal and feature opt-out cover
both modes. No effects/rollback of interrupted application SQL are inferred.
The environment remains the local SQL Server/verified TLS setup above, with
controlled peers for failure timing. Remote failover/platform/provider coverage,
performance and broader SQL types remain separate acceptance work.

## Browser, restricted SQL login and the next public API

Browser discovery now has pure MC-SQLR codecs and Tokio UDP helpers. Unchanged
Python/specification examples cover instance, machine and DAC reply layouts; a
strict CP1252 scalar fixture covers every byte. Five controlled UDP tests cover
unicast, timeout, malformed replies, foreign sender filtering and collection to
the broadcast deadline. The broadcast test targets loopback only. These results
do not establish interoperability with a Windows Browser service. ASCII, UTF-8
and Windows-1252 are explicit options; other code pages remain unsupported.

The separate `live_login` test supplements the earlier `EXECUTE AS USER` case:
it creates a disposable SQL login/user/table and actually authenticates with the
restricted credentials under TDS 7.4/8.0 × plain/MARS. It verifies absence of
sysadmin/db_owner membership, denied SELECT with error 229, and successful reuse
for SELECT 7. Privileged cleanup runs through a fresh connection before assertions.
All four scenarios passed against the existing Docker server.

RETURNSTATUS now decodes and remains in response order alongside DONEPROC. A
byte-boundary unit case and controlled response case cover negative and repeated
status values, retention and later reads. Grouped procedure results, RPC parameter
encoding and output parameters remain open.

LOGIN7 can encode a password-change request. A complete artificial Python byte
fixture verifies distinct old/new credentials, feature-offset layout and masking
of both fields. This is codec-only support: the public connection and pool do not
expose the option yet. A separate live Python probe demonstrated that successful
password change followed by recovery repeats stale credentials and is rejected.
The shared correction and pending pool ownership policy are recorded in
[the credential lifetime proposal](../../docs/design/G-login-credential-lifetime.md).

The next type slice changes the unpublished integer-only row API. Its concrete
[Value/SqlType representation](../../docs/design/F-rust-value-api.md) was subsequently
approved and implemented for scalar reads, as recorded below. The [support matrix](SUPPORT.md) distinguishes
implemented behavior, missing code and environment-specific acceptance work.
Current checks are the totals at the top of this document; counts in earlier
sections describe their respective milestones. Python production source was not
changed for this slice; its latest full regression remains the recovery result
recorded above, with the additional password-change probe run separately.


## Approved heterogeneous scalar read slice

Rows now contain `Option<Value>` and columns carry declared SQL types separately
from their original wire code/maximum length. `values.rs` supplies exact decimal,
float bits, money, calendar/time/legacy datetime, offset and GUID payloads;
`types/codec.rs` implements the bounded scalar layouts. Ordinary and fetched
responses use the same new row representation. Parameters, code-page decoded
views and streaming/special values are still pending.

Four pure tests compare 95 deterministic Python codec boundary cases (including
fixed/nullable aliases, negative zero, unpaired surrogates and empty/NULL values),
fragmentation, NBCROW omission, malformed bodies and conversion refusal. The
unchanged existing connection/lifetime tests have been migrated to the explicit
Value cells. The one old unsupported-type fixture now uses native JSON: varchar,
its former unsupported case, is implemented.

The new explicit Docker test covers 17 scalar columns, a NULL counterpart result,
raw text with explicit SQL collation and empty Unicode/binary values. Its four
scenarios run under 7.4/8.0 × plain/MARS, prove reuse and compare retained values
after connection closure. All 27 Docker tests pass. The top check table records
current counts; earlier sections remain historical evidence.

The approved design page records a Python validation gap: a directly constructed
datetimeoffset may have a local date outside SQL's range. That invalid success
fixture is explicitly excluded from the valid-SQL corpus. Rust rejects it, and
Python's corresponding parameter-validation correction is planned in F. No
Python production code was changed in this scalar slice.

## Shared configuration and credential lifetime

Implemented after approval of [H](../../docs/design/H-pool-configuration.md).
Both clients expose an application-supplied async reader, immutable accepted
SQL settings, fixed runtime bindings and independent per-pool acceptance state.
Opening/recovery reads share one deadline with network setup. Known obsolete
sessions are discarded; active borrowers retain authority. No fallback, login
retry loop, source watcher or configuration thread is introduced.

Deterministic Python barriers and seven Rust configuration tests cover safe
source errors, corrected reads on the same pool, no idle-checkout read, invalid
values, superseded late opening/recovery, cancellation, shutdown, bounded gate
waits and root close during a borrowed recovery read. The original full Rust
suite passes; the added seventh configuration test passes separately. The one
pure equality test is included in those seven, rather than counted twice.

Docker disposable-logins test rotation through the same pool under all four
protocol/framing modes. Current borrowers can continue; stale openings fail;
new credentials open; obsolete returns discard. Password-only recovery preserves
the original channel after pool shutdown, while changed identity refuses. Direct
password-change login followed by recovery passes under 7.4/8.0 in both clients.
Temporary-login cleanup waits for SQL Server to retire closed sessions; a local
TCP close alone is not treated as server-side completion.

Controlled peers drop the transport after receiving a password-changing LOGIN7.
Both clients expose an uncertain server-side change and never retry it. Rust's
`password_change_uncertain` is separate from application SQL `execution`.
These peers do not claim to implement an actual password store.

Current checks:

```sh
cargo test --offline
cargo test --offline --test config
cargo test --offline --no-default-features
cargo test --offline --tests -- --ignored --test-threads=1
cargo clippy --offline --all-targets -- -D warnings
cargo clippy --offline --no-default-features --all-targets -- -D warnings
cargo fmt --all -- --check
cargo doc --offline --no-deps
cargo build --offline
```

All **29 explicit Docker tests** pass. Core-only remains **33 unit + 4 scalar**;
the default build has **36 unit + 4 scalar**, the original **67 controlled-network**
tests, **7 configuration** tests and **4 rustdoc** tests. Both strict Clippy
configurations, formatting, documentation and library build pass. Python's full
run: **713 passed, 13 skipped**; the expanded **8-case live configuration suite**
also passes, including the subsequently added superseded-recovery case.

The built library is `target/debug/libtds_client.rlib`; Cargo prints runnable test
paths under `target/debug/deps`. No standalone Rust SQL CLI exists. File providers,
Windows/Linux native runtime acceptance, remote failover and seamless rotation
remain outside this evidence. A reused session can fail its deferred reset after
an undiscovered rotation; neither client replays that SQL.


## Typed parameters, procedure calls, row iteration and the CLI

After authorization of the next slice, Rust implements checked bounded scalar
parameter writers, named/built-in calls, batched calls, NULL/default/input-output
parameters, call options, saved metadata and RETURNVALUE. DONEPROC groups status,
outputs and optional function results. DONEINPROC does not fabricate a call group.
Protocol cores still do no I/O and dispatch no application operations. A request
encodes itself before bytes/busy state; a failed new parameter remains NotSent
even while a MARS sibling executes. RESETCONNECTION also applies to RPC.

`LiveResultSet` borrows the one advancing response and returns one scalar row at
a time. Advancing sets drains unread rows. Returns require explicit Refuse/Keep/
Discard. Ordinary/fetched retention, once-only errors, cancellation and failure
snapshots preserve the Python contract. A compile-fail example prevents advancing
a response behind its live result set.

Evidence, 2026-10-17:

- The shared scalar corpus has 96 cases. Parameter encodings match Python's
  actual codec, including compact decimal magnitudes and exact NULL/text/numeric/
  temporal/GUID representations. Three deterministic RPC bodies match Call/Calls.
- Controlled peers cover every RETURNVALUE fragmentation boundary, omitted
  metadata validation, result iteration/discard, return read-ahead, cancellation
  retaining completed returns and an unsent refusal with a busy MARS sibling.
- Two Docker tests each run 7.4/8.0 × plain/MARS. They exercise real defaults,
  input/output values, per-call grouping, NO_METADATA saved columns, exact scalar
  round trips, failed-call reuse and deferred pool reset on an RPC request.
- The `tds` executable is built at `target/debug/tds`. Actual subprocess tests
  verify help/argument validation, four-mode RPC/output, NULL/fetch and SQL error
  exit status. Manual queries and typed calls pass. It is a public-API client,
  not another driver implementation.
- Four fresh CLI recordings replay through Python's existing reader with RPC,
  ROW/RETURNSTATUS/RETURNVALUE and zeroed LOGIN7 credential fields. Reproduce with
  `clients/python/.venv/bin/python tools/probe_rust_rpc_cli.py` from the repo root.
- Python's datetimeoffset parameter check now refuses UTC/local overflow, invalid
  ticks and nonintegral/out-of-range offsets. Nine direct/aware refusal cases and
  the corrected valid boundary replace the previously documented invalid success.
  Full Python regression: **723 passed, 13 skipped**.
- Full default Rust tests: **130 passed**, including **6 rustdoc** checks. All
  **32 explicit Docker tests** pass. Core-only: **33 unit + 5 scalar + 3 RPC**,
  plus the feature-guarded example compilation. Both strict Clippy configurations,
  formatting, rustdoc generation and executable build pass.

Healthy response test peers now wait for client closure instead of racing their
own socket destruction against channel cleanup. Truncation/fatal-EOF scenarios
retain their deliberate peer closes; those tests still measure actual failures.

At this scalar checkpoint, chunked large-value reading/writing still awaited
review. The approved implementation and subsequent evidence are recorded below.
No publication, remote failover or native Windows/Linux runtime acceptance is
claimed by either checkpoint.


## Approved large-value ownership, sources and executable

The user approved borrowed response → result-set → row → value readers with owned
typed chunks. Implemented in `large`, `tokens`, `connection::shell::reading` and
`connection::shell::sending`; [design I](../../docs/design/I-rust-rpc-and-streaming.md)
explains the wire and ownership boundaries.

- PLP nvarchar(max), raw collated varchar(max), varbinary(max), XML, and legacy
  text/ntext/image rows decode incrementally. NULL, empty, known/unknown totals,
  UTF-16 pairs/unpaired units, odd/truncated payloads, schema/table metadata and
  malformed known totals have deterministic coverage. Six pure tests include
  every fragment size for small values, a >3 MiB value and **21 Python-generated
  codec cases** covering both result payloads and owned parameter bytes.
- `next_row()` and ordered `next()` materialize owned values; fetch retains full
  values and its live unread suffix. `streamed_row()`/`next_value()`/`next_chunk()`
  transfer chunks without whole-value assembly. Dropped views defer tail draining
  to parent advancement; a dropped submitted read future discards the connection.
  Complete row counts match Python even when a partial large row is abandoned.
- Unique async `Source` bindings use PLP unknown length and typed chunks. Static
  validation occurs before production or request commitment. Empty chunks do not
  mean EOF. Source/type failure before the first packet needs no server cleanup;
  partial transmission uses IGNORE + EOM and a bounded drain. Cleanup failures
  preserve both causes and discard. No sources or SQL are replayed.
- Five controlled-peer tests cover validation-before-poll/send, IGNORE/EOM and
  reuse, cleanup timeout with both causes, abandoned chunk reads, and channel
  close interrupting a partly sent waiting producer (including producer drop and
  retirement of the old channel lifetime).
- Six Docker test functions cover 7.4/8.0 × plain/MARS large values and sources,
  multi-megabyte owned inputs/output parameters, legacy/XML/raw text, partial-row
  fetch, source errors/type refusals, stalled source/reader sibling progress,
  Attention cleanup/reuse and close while waiting for production. A large owned
  output exposed a credit deadlock; pending receive-credit acknowledgements now
  flush before waiting for another socket read even without a yielded record.
- The actual `tds` executable supports `--stream` summaries/previews, whole max/XML
  literals, and `--param-file NAME:varbinary(max)=PATH`. A subprocess test sends a
  2 MiB file and reads a 1.2 MiB Unicode result in all four modes. The ordinary
  query/RPC/fetch/error exit-status subprocess regression passes too.
- Four fresh streamed CLI recordings replay through Python with ROW, RETURNSTATUS,
  RETURNVALUE, completion and masked LOGIN7 credentials. Four scalar recordings
  also still replay. Reproduce with `tools/probe_rust_streaming_cli.py` and
  `tools/probe_rust_rpc_cli.py`, using the Python client venv after building `tds`.
- Shared corrections: both readers reject contradictory known PLP totals.
  Python replay now claims/discards large rows for inspection rather than pausing
  indefinitely without a live caller and omitting later outputs/completions.

Final Rust checks on 2026-10-17: **142 default checks** (including **7 rustdoc**),
**39 explicit Docker tests**, core-only **33 unit + 6 large + 5 scalar + 3 RPC +
1 feature-guarded rustdoc**, both strict Clippy configurations, formatting,
rustdoc generation and `tds` build. Commands are the same as the previous
checkpoint, plus the focused `large_values`, `streaming_shell` and
`live_streaming` targets. Logs for this run are under `/private/tmp/tds-stream-*`.

This slice does not establish native Windows/Linux behavior, memory/throughput
benchmarks, every forced partial-socket-write/task-abort boundary, binary XML,
decoded non-Unicode codecs, batched RPC source bindings, or special/TVP/bulk types.
Those remain explicit work in the support matrix. No commit, publication or
remote failover acceptance is implied by passing local tests.


The final Python rerun exposed a separate test-portability assumption in
`test_each_level_builds_what_it_shows`: independent outline/full connections need
not receive the same SQL Server session ID. The test now checks each ready event
against its own connection's actual ID and normalizes only that field for the
level comparison. It still compares every other line/field and full inspection
content. This changes test expectations, not client session identity or logging.


Final full Python regression after both protocol/replay corrections and the
session-ID portability fix: **734 passed, 13 skipped** (`python -m pytest -q
--tb=short` from `clients/python`). No Rust Docker mutation suite ran concurrently
with this final Python run. The focused observation/replay/large-value group also
passes all 36 cases. Generated planning-page JavaScript passes `node --check`;
`git diff --check` is clean.


## Transactions, special values and collation continuation

Implemented after the user's authorization to continue independent work while
collecting architectural questions. [Design J](../../docs/design/J-rust-completion.md)
explains the representation, source reading path and remaining A1/A2 choices.

- Explicit transaction-manager messages match **24 Python-generated cases**.
  Docker proves nested/savepoint/commit-and-begin behavior, refusals followed by
  reuse, shared MARS state and deferred reset on the first transaction request.
  No implicit transaction guard or rollback/retry is introduced. Successful
  external coordinator enlistment remains unverified.
- `StreamedCalls` validates the whole batch before production/commitment and
  preserves absolute source offsets. Controlled refusal and four-mode Docker
  tests cover multiple large producers, grouped returns and a later producer
  failure with bounded cleanup/reuse. Earlier calls may have executed; batches
  are not atomic and are never replayed.
- TABNAME/COLINFO and classification v1/v2 are retained as result metadata.
  Docker checks aliases/hidden keys and named labels/types/ranks. Pure tests
  fragment every byte and refuse malformed bounded metadata and unnegotiated
  classification. Feature checks preserve downgrades/disabled UTF-8 and refuse
  invalid, duplicate and unrequested acknowledgements.
- CLR/UDT values retain named serialization bytes, assembly and wire size.
  Hierarchyid/geometry/geography round-trip as owned bytes and a source in four
  modes; assembly loading/shape interpretation are outside the client. The large
  corpus now has **24 Python cases**, including distinct CLR input/result layouts.
- Bounded variants match **56 Python cases** across fragments, including exact
  decimal, temporal, text, binary and NULL values. Corrupt bounded layouts and
  unsupported bases are refused; Docker proves native variant round trips.
- Vectors match **4 Python cases** and preserve float32/float16 bits. All 65,536
  binary16 patterns receive conversion checks; nonfinite writes and rounding are
  refused. Docker checks native float32, feature-version-sensitive float16
  behavior and character fallback without vector support. The local server does
  not establish successful native float16 acceptance.
- Native JSON matches **12 Python cases** for result encodings, NULL/empty text,
  surrogate units and strict input refusal. Malformed UTF-8 is refused. Eight
  Docker modes check negotiated UTF-8/UTF-16 rows, NULL, output parameters,
  large produced inputs and borrowed chunk reads; native-JSON opt-out also
  returns correctly decoded character text. Saved JSON metadata uses the
  current session's encoding in both clients. Header totals count wire bytes;
  Unicode chunk sizes count their owned UTF-16 payload, explicitly distinguished
  by the CLI.
- Collation views use sixteen SQL-corrected legacy pages plus UTF-8. Python
  digests cover every byte pair in sequence, canonical re-encoding and fragmented
  decoders; live bounded/max samples match SQL on all seventeen pages in all
  four modes. Unknown pages and substitution are refused. The generated source,
  1,667,248 table bytes and fixtures reproduce byte-for-byte with the
  generator source; the workspace changes themselves are not yet committed.
- The actual CLI adds `--demo-transactions`, native JSON/vector/CLR/varchar
  literals and explicit decoded varchar displays. It preserves CLR identifier
  case and refuses vector rounding. Three Docker subprocess tests pass. All
  **16 fresh CLI recordings** (4 scalar, 4 streaming, 8 transaction/special)
  replay in Python and pass LOGIN7 masking checks. Recording files are temporary.

The new replay experiment exposed Python's missing accepted-feature context and
input inspection using result layouts. The live login and replay now share
result-context interpretation. Input TYPE_INFO/values explicitly select the
JSON, CLR and legacy request formats. Fifteen NULL/empty/value cases verify
actual full recording and decoding under either result encoding; replay cases
also cover both classification versions. Both clients reject vector
count/element/width/reserved-byte contradictions. Python's live vector tests
follow negotiated capability rather than a permanent assumption about one host.
The focused shared group passes **47 tests**.

Final Rust evidence: **157 default checks** (8 rustdoc), **61 core-only checks**
(2 rustdoc), **50 serial Docker tests**, and **14 affected Docker tests** rerun
after the final JSON/CLI refinements. Both strict Clippy configurations, formatting,
rustdoc generation and the executable build pass. Full Python evidence is
recorded immediately below. Logs are under
`/private/tmp/tds-completion-*`; generation and cross-replay commands are:

```sh
clients/python/.venv/bin/python tools/generate_rust_collations.py
clients/python/.venv/bin/python tools/probe_rust_rpc_cli.py
clients/python/.venv/bin/python tools/probe_rust_streaming_cli.py
clients/python/.venv/bin/python tools/probe_rust_completion_cli.py
```

The changes remain on `rust-client`; no commit, push, tag or publication is part
of this continuation. Native Windows/Linux runtime behavior, external failover,
measured memory/throughput, exhaustive forced partial-write aborts, binary XML,
alternate compute tokens, TVP/bulk, full inspection/native replay and
Windows/Entra/encryption providers remain separate work. A1/A2 reserve the next
input ownership choices for user review rather than inventing a Rust-only policy.


Final full Python regression on the final source: **761 passed, 13 skipped**
(`.venv/bin/python -m pytest -q --tb=short`, 124.17 seconds). No Rust Docker suite
or CLI probe ran concurrently with this final Python run. The offline planning
pages regenerate; their JavaScript parses and generated source-file links resolve.
The renderer now resolves links from the Markdown source location before moving
content into `site/index.html`. `git diff --check` is clean.


## Tables and borrowed bulk continuation

Implemented following user approval of input-only TVP values and a borrowed
`BulkWriter`, with bulk sequencing an explicit D-50 exception to D-53.
This section supersedes the earlier A1/A2 pending notes.

- `ParamValue` separates scalar payloads and owned table rows. `TableType`
  retains schema/name, supplied/default columns and sort/unique/placement hints.
  Existing scalar constructors remain valid; the unpublished `Param.value`
  field now uses the enum. Unique `RowSource` bindings use the same bounded
  scheduling and partial-input cleanup as large parameter sources.
- Twelve owned TVP bodies match actual Python-generated fixtures, including
  NULL/DEFAULT/empty rows, exact UTF-16, default columns and hints. A controlled
  peer checks produced/empty tables with following parameters across batched
  call separators. Four-mode Docker tests prove real procedures, identity and
  computed columns, large cells, output values and return status.
- `SerialChannel::bulk` borrows the channel across preparation/data. It accepts
  explicit SQL and matching column metadata. Awaited owned/source finish and
  Attention abort preserve actual announced state; no SQL generation, automatic
  transaction boundary or replay is added. Pending state also protects forgotten
  writers, delegated close, pool return and recovery.
- Controlled peers prove ordinary DONE does not release a pending abort, missing
  ACK discards under the budget, and delegated close cleans a forgotten writer.
  Docker checks finish, explicit abort with a preceding live transaction,
  source failures before/after transmission, local encoding refusal, failed
  preparation, delegated close then old-writer Drop, unfinished Drop, and pool
  discard. Wide rows preserve fixed metadata, exact decimal/money/time values,
  NULL, large Unicode/binary, variants and vectors in all four modes.
- Python's prepared gap now refuses direct release/recovery, creates a private
  cancellation reader for awaited close, and discards unresolved pool returns.
  The original experiment rerun passes all four modes with regression assertions
  for safe close/replacement and different pool protocol cores. Session IDs can
  be reused and are not treated as physical identity. Full Python regression:
  **766 passed, 13 skipped**, 125.20 seconds; the focused normal-DONE-before-ACK
  addition also passes all five `test_bulk.py` cases afterward.
- `tds --demo-bulk` exercises whole-row source upload and explicit abort. All
  **20 fresh CLI recordings** (4 scalar, 4 streaming, 12 transaction/special/bulk)
  replay through Python without decode errors and pass LOGIN7 masking checks.
  This caught duplicate Rust Attention events for one packet; one event per
  message is now enforced and checked by a controlled observer test.

Final checks: **164 default** (10 rustdoc), **63 core-only** (3 rustdoc), all
**55 serial Docker tests**, plus the **8 affected live tests** after the final
Attention-event/readability correction. Both strict Clippy modes, formatting,
rustdoc and the CLI build pass. Logs are under `/private/tmp/tds-bulk-*`.
The Python full suite ran after the full Rust Docker suite; no concurrent Rust
Docker work ran during that Python regression.

Reproduce the new fixtures/experiments from the repository root:

```sh
PYTHONPATH=clients/python clients/python/.venv/bin/python clients/rust/tests/fixtures/tables/generate.py
clients/python/.venv/bin/python tools/probe_bulk_continuation.py
clients/python/.venv/bin/python tools/probe_rust_completion_cli.py
clients/rust/target/debug/tds --demo-bulk
```

The server was the existing SQL Server 17.0.5015 Docker instance, TDS 7.4/8.0 ×
plain/MARS. This does not establish Windows/Linux runtime behavior, performance,
every SQL type/server option in bulk, encrypted inputs, external failover,
external coordinator acceptance, or full Python feature parity. Saved TVP input
inspection is still missing from Python replay; bulk recordings do replay.
Native replay, field inspection/timings, binary XML, alternate compute tokens and
authentication/encryption providers remain explicit in `SUPPORT.md`. Changes
remain uncommitted on `rust-client`; no publication is implied.


## Native offline replay

Approved and implemented on 2026-10-18; [design K](../../docs/design/K-offline-replay.md)
is the representation/compatibility contract. The CLI uses the public
`replay::replay` reader before any connection/credential/CA configuration. Existing
unversioned Python/Rust JSONL captures remain readable. Recorded events/times and
decoded wire facts are separate outputs. No SQL is executed on replay.

- Requests reuse exact type/value definitions with explicit input layouts for
  JSON, CLR, legacy values, TVPs and bulk. Pure tests read the existing Python
  RPC/large/transaction/table corpora: exact flags, NULL/default/empty rows,
  omitted default columns, sort/unique/placement metadata, lone UTF-16 surrogates
  and trailing parameters/calls. Every cut within the TVP payload is refused.
- Response readers share accepted encoding/classification context while keeping
  logical channels independent. Tests distinguish final DONE from Attention ACK
  and its message boundary; unknown/duplicate negotiation retires later decoding.
  Malformed JSON/UTF-8/base64/packets, truncated tokens/messages, unknown content,
  and callback failure preserve the available prefix and located diagnostics.
  Credential packet bodies are withheld even for unmasked/partial LOGIN7 input.
  Python event text retains lone surrogates without substitution.
- Python now reads TVP inputs as `types.TableInput` (declaration plus rows),
  separate from result cells. Sixteen new Python cases cover the twelve existing
  request fixtures, batched/trailing parameters, recording fragmentation and
  malformed table metadata. The focused shared request/type/replay group passed
  **154 tests** before the final full Python regression recorded below.
- `tools/probe_offline_replay.py` creates **32 fresh physical recordings** from
  Rust/Python under 7.4/8.0 × plain/MARS: queries, transaction messages, special
  values, 2.1 MB produced input/results, table row sources, bulk finish/abort,
  interleaved MARS channels and separately saved recovery epochs. Every file
  passes both replay readers and LOGIN7 masking checks.
- The full Rust Docker run saves **16 additional Rust recovery recordings**.
  Native replay assertions check logical row attribution across all four epochs
  in each mode. Both offline readers accept those sixteen files; the independent
  Python recovery checker also verifies logical attribution and masking.
  The new live Rust TVP test checks owned/produced inputs and output values in
  all four modes. These assertions use actual recordings, not reconstructed
  request execution.

The new live fixture initially used a three-column table (identity, integer,
large Unicode), defaulted identity and reverse placement. The local SQL Server
refused it with **8037/8061**, identically through Python and Rust. An independent
Python probe accepted the four-column variant with a defaulted computed final
column. The final Rust fixture follows that already-established accepted shape.
No server refusal policy or client encoding was changed. This observation is not
proof that every table/placement/server combination is supported; its cause has
not been established.

Full Rust checks: **175 default**, **73 core-only**, **56 serial Docker tests**.
After the final malformed-UTF-8 and unsupported-token location refinements, the
affected **11 default** and **9 core-only** tests pass again. The **32 + 16**
recording checks pass; the last refinement changes only failure locations. Both strict Clippy modes, formatting, rustdoc and executable
build pass. Logs use `/private/tmp/tds-replay-*`. Commands from the repository root:

```sh
cargo test --offline --manifest-path clients/rust/Cargo.toml
cargo test --offline --no-default-features --manifest-path clients/rust/Cargo.toml
TDS_RECOVERY_CAPTURE_DIR=/private/tmp/tds-replay-recovery-iteration cargo test --offline --manifest-path clients/rust/Cargo.toml --tests -- --ignored --test-threads=1
cargo build --offline --manifest-path clients/rust/Cargo.toml --bin tds
clients/python/.venv/bin/python tools/probe_offline_replay.py
clients/python/.venv/bin/python tools/probe_offline_replay.py /private/tmp/tds-replay-recovery-iteration
clients/python/.venv/bin/python tools/replay_rust_recovery_captures.py /private/tmp/tds-replay-recovery-iteration
```

Limits: whole request inputs are materialized; zero decode issues does not prove
session closure or every obligation created by arbitrary SQL. Missing saved
NO_METADATA context, encrypted/provider content, binary XML and alternate compute
tokens remain explicit. Field trees/reference links and timing analysis remain
separate work. Local Docker evidence does not establish platform/failover parity.
This development checkpoint records the implementation on `rust-client`;
Rust release/publication is a separate task.


Final full Python regression: **782 passed, 13 skipped**, 120.60 seconds
(`.venv/bin/python -m pytest -q --tb=short` from `clients/python`). The 13 skips
remain 10 Azure, 2 Kerberos and 1 Windows certificate-store tests. No Rust Docker
suite or live probe ran concurrently with that Python run. Generated planning
pages regenerate, all site page JavaScript parses and `git diff --check` passes.

## Interrupted I/O acceptance

Approved iteration, completed 2026-10-18 on `rust-client`. The
[boundary matrix](INTERRUPTIONS.md) defines the finite acceptance scope and exact
test names. Fifteen new test functions cover submission, selected partial TCP
write offsets, short-write resumption, WouldBlock, zero/error writes, owner/driver
abortion, streamed IGNORE/drain, delegated close, partial Attention timeout and
abandonment, bulk continuation discard, MARS shared errors during a blocked write,
pool capacity/replacement, explicit recovery without SQL replay, and runtime
shutdown after borrower-endpoint rotation.

The private `cfg(test)` write control runs inside the ordinary driver loop and
retains real TCP/TLS. Peer checkpoints precede request-write fault scripts. These
checkpoints also prevent the peer's buffered login/SYN reads from invalidating a
later raw socket-tail measurement. One short-write conversation per protocol/MARS
mode is replayed natively with exactly two batches and zero diagnostics; peer
bytes independently establish delivery without duplication. No new public API,
transport abstraction, cleanup policy or production defect was established.
Python's send/undo, close/drain and canceled-close discard paths were inspected;
no shared behavioral correction was indicated and Python is unchanged.

Fresh validation, from the repository root:

```sh
cargo test --offline --manifest-path clients/rust/Cargo.toml
cargo test --offline --manifest-path clients/rust/Cargo.toml --no-default-features
cargo test --offline --manifest-path clients/rust/Cargo.toml --tests -- --ignored --test-threads=1
cargo clippy --offline --manifest-path clients/rust/Cargo.toml --all-targets -- -D warnings
cargo clippy --offline --manifest-path clients/rust/Cargo.toml --no-default-features --all-targets -- -D warnings
cargo fmt --all --manifest-path clients/rust/Cargo.toml -- --check
cargo doc --offline --manifest-path clients/rust/Cargo.toml --no-deps
cargo build --offline --manifest-path clients/rust/Cargo.toml --bin tds
```

Results: **190 default checks** (including the fifteen new tests and eleven
rustdoc checks), **73 core-only checks**, and **56 serial Docker test functions**
pass with zero failures. The default run explicitly ignores the live cases; the
separate Docker run executes all 56. Both strict Clippy modes, formatting,
documentation and executable build pass. Local command logs are under
`/private/tmp/tds-io-{default,core,live,clippy,clippy-core,doc,build}.log`.

The existing `mssql-2025` container was healthy before live validation. The suite
used `127.0.0.1:14325`, `tds_test`, ignored credentials and the existing test CA.
No Python mutation suite ran concurrently. Python's prior **782 passed, 13
skipped** result above remains prior evidence, not a fresh Python run here.

This completes the approved selected interruption matrix. Other offsets, kernel
saturation, every successful credit-update schedule, every handshake/recovery
write boundary, all type/TVP combinations, other native platforms and remote
failover remain outside this evidence. Memory, latency and throughput were not
measured. Field inspection trees and timing detail remain separate work.
