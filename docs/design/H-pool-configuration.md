# Pool configuration snapshots: shared Python and Rust design

**Where this sits:** The shared design for reading current connection configuration without replacing a pool object.
**After reading this you can** identify the configuration values, source and ownership boundaries, trace opening and recovery, and follow the implemented policies in both clients.

**Vision:** applications keep the same pool object while an application-controlled
configuration service supplies the settings for new connections. Configuration
is read when a connection must be opened. Unusable credentials cause explicit,
bounded failures. Later attempts can succeed after an operator corrects the
source. Neither client discovers an authoritative password-change event or
changes the server password on behalf of a pool.

**Status, 2026-10-17:** the user approved this design and authorized implementation.
Both clients now implement the SQL configuration source, snapshot comparison,
opening/recovery reads and retirement rules below. The source is supplied by the
application; no built-in file provider or watcher is added. Section 13 records
validation and its limits.

## 1. Agreed foundation

- A configuration service has an asynchronous `read` operation returning a
  coherent, immutable configuration value.
- A pool compares that value with its last accepted configuration. Equality
  concerns effective settings, including the credential, rather than file bytes,
  timestamps or object identities.
- The public read result needs no hash, timestamp, revision or `changed` flag.
  Each pool keeps its own comparison state.
- A read before opening discovers current configuration. No watcher, polling
  timer, notification registration or permanent monitoring task is required.
- Configuration reading and the pool's response to differences are separate
  responsibilities. Reading does not certify that the server will accept a login.
- Authentication failure is reported. It does not establish that a password
  changed. The pool remains available for later acquisitions.
- A pool does not issue password-changing SQL or a password-changing LOGIN7.
  The distinct direct-login operation is described in
  [Credential lifetime](G-login-credential-lifetime.md).
- Ordinary connection setup and application SQL have different retry semantics.
  Interrupted application SQL is never replayed by configuration handling.

## 2. Concepts, identities and ownership

| Concept | Meaning and identity | Ownership and relationships |
|---|---|---|
| Configuration service | An application-supplied reader of current settings | A pool uses one service. A service may supply several pools. Its I/O, file format, caching and secret-store access belong to its implementation. |
| Connection configuration | An immutable value describing one set of effective opening settings | A read produces one snapshot. Several pools/connections may hold equal values. Object allocation does not determine equality. |
| Configuration state | The last validated snapshot accepted for one pool | Owned independently of the pool's connection registry. Openings and recovery share access; it contains no connections or back-reference to the pool. |
| Pool | A persistent manager of capacity and whole-connection leases | Existing application references remain valid when configuration changes. Each pool has its own acceptance state. |
| Physical connection | A transport authenticated using one captured snapshot | The driver records the snapshot actually used. It is not relabeled when another read accepts different settings. |
| Logical connection/session | The application's connection identity across eligible physical recovery | Recovery preserves its existing authority, session semantics and routing identity. Configuration cannot silently substitute a different login or unrelated session. |
| Fixed bindings and pool policy | Runtime services and limits outside the initial reloadable value | These include TLS runtime objects, observer/capture factories and pool capacity. They are not compared by object identity as configuration changes. |

There is no connection-to-pool ownership cycle. A borrowed connection retains
configuration access so it can recover after the pool owner closes, as existing
pool lifetime rules permit. Closing a pool still stops acquisitions and retires
idle sessions. It does not give a borrowed connection new pool authority.

An implementation may use a private local generation to invalidate stale
openings efficiently. This is bookkeeping, not a public source revision or a
timestamp. Each physical connection must still identify the settings it used.

## 3. First reloadable value

**Initial scope:** implement dynamic SQL-login connection settings first. Keep
pool-management limits and opaque runtime services fixed. This avoids claiming
that every existing connection option can safely change on a running pool.

| Reloadable connection values | Representation and equality |
|---|---|
| Logical host and port | Validated host text and numeric port, before server routing |
| SQL login | Username and password; the password participates in equality but is hidden by diagnostic representations |
| Initial database | Explicit text, including the existing meaning of empty/default |
| Protocol and framing | TDS version and MARS selection |
| Login/session defaults | Application/host names, language, ODBC flag and read-only intent |
| Supported features | Immutable, normalized feature selection, including session-recovery opt-out |
| Routing choice | Whether the ordinary one-hop redirect is followed |

All remaining fields have an explicit fixed home; none is silently dropped:

| Fixed for the first implementation | Reason |
|---|---|
| Capacity and opening/cleanup budgets | Resizing and changing active operation deadlines require additional policy. Existing constructor arguments retain these roles. |
| TLS trust/verification bindings, including server-name override | Python's mutable `SSLContext` and Rust's TLS objects do not form a shared comparable value. Dynamic TLS requires a separate immutable trust/verification description. |
| Observer and per-physical capture factory | Executable services and resources, rather than configuration values |
| Windows/Entra provider bindings | Existing Python provider authentication continues to work through its current static path. The new dynamic path initially supports SQL credentials; Rust's missing authentication features are not implied. |
| One-time `new_password` request | A server-changing login operation, excluded from reusable pool configuration |

Both old SQL-login constructors can adapt their scalar settings into a static
service and retain their runtime bindings separately. Existing direct connection
APIs remain usable. Caller-supplied Python TLS contexts have the existing
mutability limitation: the caller must not mutate a bound context while it is in
use. Freezing an outer dataclass does not freeze that object. The new snapshot
does not contain the context.

Reject unsupported source fields and mutually exclusive construction forms
explicitly. Future dynamic TLS/provider/capacity work must define its values and
effects before being added. A file provider must resolve any reloadable external
inputs into the returned values; comparing an unchanged path alone cannot detect
a changed value behind it.

## 4. Language surfaces

These are the implemented entry points. Each language uses its existing
field vocabulary and defaults.

Python:

```python
class ConfigService(Protocol):
    async def read(self) -> ConnectionConfig: ...

@dataclass(frozen=True)
class ConnectionConfig:
    # Validated value fields from section 3; nested collections are immutable.
    # password is excluded from repr, but included in equality.
    ...

pool = Pool.from_config(source, size=10, services=services, timeout=15.0,
                        cleanup_timeout=5.0)
# Existing Pool(host, port, user=..., password=..., ...) remains supported.
```

Rust:

```rust,ignore
pub struct ConnectionConfig {
    // Owned fields from section 3; validation at acceptance, immutable shared snapshot.
    // Eq compares effective values; custom Debug hides credentials.
}

pub trait ConfigService: Send + Sync {
    fn read(&self) -> Pin<Box<dyn Future<Output = ConfigResult<ConnectionConfig>>
                           + Send + '_>>;
}

let pool = Pool::from_config(source, capacity, services, policy)?;
// Existing Pool::new(options, capacity) remains a static-source adapter.
```

`services` is a fixed binding object for the relevant runtime services above.
`policy` supplies fixed budgets; existing Rust options map to it. The initial
implementation should keep this object small rather than introduce a generic
configuration framework. The Rust source/future bounds allow the existing driver
task to await the reader; they do not create a thread. Python source access runs
on the owning asyncio loop. The same observable read/failure/acceptance contract
applies in both languages.

A source must cooperate with asynchronous scheduling and cancellation. A blocking
read or a source that suppresses cancellation can defeat an event-loop deadline;
the client cannot guarantee prompt shutdown against arbitrary blocking application
code. Offloaded filesystem work can outlive cancellation of its awaiting task,
so logical reservation cleanup must not depend on that worker having stopped.

**Startup:** preserve lazy, synchronous pool construction. The first
physical opening performs the initial read; later openings use the same operation.
An eager asynchronous startup factory can be added separately if needed. No I/O
is hidden inside a synchronous constructor.

## 5. Opening a connection

**Sequence for both clients:**

1. Obtain capacity under existing pool rules. A reserved opening does not exceed
   capacity. No source read occurs merely because an already eligible idle
   connection is borrowed.
2. Start one fixed opening deadline. It includes waiting for the configuration
   read gate, reading, validation, TCP/TLS/login and any routing hop. Capacity
   waiting keeps its existing caller-controlled timeout semantics.
3. Serialize source reading and acceptance for this pool with a separate async
   gate. Do not hold the connection registry lock while calling application code
   or doing I/O. Validate a complete snapshot before publishing it.
4. Compare with the last accepted snapshot and accept the candidate value.
   Acceptance means the settings are valid for this client, not that credentials
   have been authenticated. An invalid or failed read leaves the prior acceptance
   state intact, but fails this opening; there is no silent fallback to it.
5. Release the configuration gate. Open using that captured snapshot, outside
   the gate so independent network handshakes remain concurrent.
6. Recheck pool closure and accepted settings before lending the result. If the
   snapshot has been superseded, close the candidate and return an explicit
   configuration-superseded failure. Do not start an unbounded reopen loop.
7. Commit the lease and release the opening reservation according to the existing
   lifecycle. Cancellation/failure releases capacity and discards any uncommitted
   transport, including when waiting to commit a completed login.

One opening attempt pins one snapshot across its routing hops. A redirect changes
the physical target within that attempt, not the source's logical endpoint or
the identity being authenticated. Reading again mid-redirect could mix settings
within a single login attempt. A later replacement or recovery is a new attempt
and reads again.

Ordinary authentication receives one attempt per acquisition, apart from the
existing one-hop routing exchange. Reading fresh configuration already happened.
An authentication rejection is returned as such. The client does not immediately
repeat the same read/login or permanently blacklist the snapshot. A later
acquisition may succeed after either the source or the server is corrected.

The source does not call back into this pool's acquisition/recovery while its
read is pending. Reentrant reads could deadlock the configuration gate.

## 6. Policy for existing connections

**Implemented:** discover changes only on opening/recovery, then retire connections
known to use superseded settings at the next checkout or return. Do not interrupt
active borrowers solely because another operation accepted a different snapshot.

| Connection state when new settings are accepted | Action |
|---|---|
| Idle | Do not lend it under superseded settings. Detach and close it when considered for checkout, outside the registry lock. No background cleanup task is required. |
| Borrowed and working | Continue serving its current owner. No protocol commands are injected because configuration changed. |
| Returned | Discard if its actual snapshot differs from accepted configuration. Otherwise preserve existing proven-reuse/reset rules. Rust still requires awaited release; Drop still discards. |
| Opening under old settings | Finish/cancel within its deadline; refuse to lend the superseded result at commit. |
| Broken and eligible for recovery | Read current configuration and apply section 7's compatibility test before authentication. |

Each pool has its own accepted configuration. A shared service does not let the
first reader consume a global change indication. Recovery reads may update the
same pool configuration state; idle entries detect their obsolescence on later
checkout. State contains no idle list, so this needs no back-reference or callback
into the pool.

**Known limitation:** if no physical opening or recovery occurs, no new
configuration is discovered. An idle connection can pass the existing transport
check and then fail authentication at its next session reset. Both clients defer
reset to the next application request. That failure is reported and the unusable
connection is discarded; the client does not replay SQL. A later acquisition
reads configuration when opening its replacement. This design does not promise
seamless password rotation. Moving reset before lending would be a separate
shared protocol/pool change.

## 7. Recovery and lifetime

**Compatibility rule:** refresh the password for the same logical
connection settings. Initially require every other reloadable field to match the
logical session's captured configuration. A changed endpoint, username, database,
protocol, framing or session-default choice refuses recovery rather than silently
creating a different session behind retained handles. Additional compatibility
can be designed later with evidence.

For a compatible snapshot, use its credential with the original session recovery
data and physical routing target. Compare the original logical configuration,
not the server-selected routed host. Preserve destination certificate validation,
the recovery acknowledgement requirement, fresh SMP wire ids, logical channel
identity, retired old exchange controls and the prohibition on SQL replay.

Recheck acceptance before installing a completed recovery candidate too. If
its captured settings have been superseded, close it and report recovery failure;
do not silently install older settings or start an unbounded retry loop. Recovery
uses the borrower's existing capacity reservation, not another pool acquisition;
otherwise a size-one pool could deadlock while recovering its only lent session.

Read through shared configuration state owned independently of `Pool`. No strong
connection-to-pool link is introduced. Pool shutdown prevents acquisition but
does not cancel a borrowed connection's eligible recovery. Closing/dropping that
connection does cancel its own configuration wait and recovery candidate.

The fixed opening budget covers the configuration gate/read and the replacement
login. Do not accidentally save the remaining fraction of that budget as the
next recovery's timeout. No configuration I/O or source callbacks enter either
protocol core; both shells translate one captured value into protocol inputs.

Read/validation/compatibility failures appear as causes of `SessionNotRecovered`.
The broken connection stays broken; a failed attempt never authorizes SQL. Saved
recording failures retain their existing terminal policy and per-physical capture
factory requirement.

## 8. Failure, diagnostics and file providers

| Failure | Observable result |
|---|---|
| Source I/O or parsing failure | Configuration-read error; no login with fallback settings |
| Invalid/unsupported value | Configuration-validation error before TCP/login |
| Source/gate/opening deadline expires | Timed failure identifying its phase; capacity released |
| Login rejected | Existing authentication error, not relabeled as proof of a password change |
| Snapshot superseded before lease commit | Explicit configuration-superseded error; candidate closed |
| Pool closed during acquisition | Existing pool-closed result; a late read/login cannot become a lease |
| Recovery settings incompatible | `SessionNotRecovered` with configuration-compatibility cause |

Configuration errors expose a safe phase/reason. Preserve source causes for
inspection without automatically printing source messages or configuration values
that could contain credentials. Python exception presentation and Rust Debug
must be tested as well as ordinary logging. No configuration diff prints passwords.

There is no automatic stale-configuration fallback, password guessing or permanent
pool failure after an authentication rejection. Existing valid borrowed sessions
need not close merely because a different opening failed.

The service implementation owns file parsing, external-value resolution and
caching. A writer that uses complete temporary files and platform-appropriate
atomic replacement gives the cleanest read contract. In-place concurrent writes
cannot be made universally coherent by hashing or checking mtime twice. Invalid
or unreadable input must be reported rather than partially adopted. A relative
path's base should be fixed when the file service is constructed, rather than
change with the process working directory.

No built-in file format or filesystem watcher is selected here. This keeps the
client mechanism portable. A file provider must disclose its I/O behavior:
direct reads can block the event loop, while offloading uses worker threads.
The async interface itself guarantees neither thread-free nor nonblocking
filesystem access. Windows/Linux/macOS provider acceptance is separate from
core snapshot correctness. No watcher dependency is needed for this design.

## 9. Python change map

| File | Implementation |
|---|---|
| `tds/config.py` (new) | Immutable `ConnectionConfig`, `ConfigService` Protocol, static source, safe configuration errors and internal configuration state/read gate |
| `tds/connection/shell.py::Pool` | Source-based constructor, legacy static SQL adapter, reserved opening deadline/read flow, snapshot-tagged idle/lent connections, superseded candidate/return checks |
| `tds/connection/shell.py::Connection.recover` | Use shared configuration access, compatible credential refresh and the same deadline/lifetime rules; preserve transport pinning and failure causes |
| `tds/connection/core.py` | Accept only resolved opening inputs; no configuration I/O. Keep actual physical versus logical/routed settings distinct. Separate direct-login password promotion from pool configuration. |
| `tds/__init__.py` | Export the reviewed configuration types and errors |
| Tests and client/reference docs | Shared scenario matrix, API examples, failure boundaries and explicit lack of automatic idle monitoring |

The source-based path is opt-in. Existing provider-auth pools remain supported.
Existing task ownership, channel lifetime, observation/capture, release/reset and
response retention contracts continue to apply.

## 10. Rust change map

| File | Implementation |
|---|---|
| `src/config.rs` (new) | Owned comparable settings, redacted Debug, source trait and safe errors; separate runtime bindings |
| Optional Tokio configuration shell | Async gate/current acceptance state, budgeted source reads and static-source adapter; no I/O added to core-only builds |
| `src/pool.rs` | Source-based constructor, existing options adapter, captured configuration on idle/lease entries, stale checkout/return/late-opening checks; preserve reservation RAII |
| `src/connection/shell.rs` | Carry independent shared configuration access into the driver; translate a captured snapshot with fixed bindings into existing core inputs |
| `src/connection/shell/recovery.rs` | Resolve compatible credentials under the replacement deadline and close/revocation path; preserve logical versus routed identity |
| `src/error.rs`, `src/lib.rs` | Configuration phase/cause and reviewed public exports, with existing execution-uncertainty semantics |
| Tests, SUPPORT/ACCEPTANCE and README | Mirrored scenario tests and exact evidence limits; existing feature configurations and safe-Rust checks |

Avoid framework or dependency additions solely for this abstraction. A boxed
read future is sufficient for a dynamically supplied source; no watcher or
global configuration singleton is needed. Rust's driver requires compatible
Send/Sync ownership; that is not a requirement to create another OS thread.

## 11. Implementation order and acceptance

1. Review first-slice fields, fixed bindings, lazy startup, superseded connection
   treatment and conservative recovery compatibility.
2. Implement immutable values/source adapters and configuration error contracts
   in both clients. Test equality and credential redaction before wiring I/O.
3. Add new-opening reads and static SQL compatibility adapters. Test cancellation,
   closure, deadline and concurrency with deterministic barriers, not sleeps.
4. Add independent configuration access to recovery and snapshot checks to pool
   checkout/return/commit. Preserve all existing authority and Drop rules.
5. Implement the separate direct-login password-change correction described in G.
6. Run the shared Docker scenarios, existing full regressions and language checks.
   Add native platform/provider acceptance before claiming that coverage.

| Shared scenario | Required evidence |
|---|---|
| Equal snapshots allocated separately | No change detected; allocation identity is irrelevant |
| Credential changes, file formatting does not affect parsed values | Effective equality catches only represented value changes; credentials stay hidden |
| Read fails or returns invalid values | No socket/login/fallback, no capacity leak; later corrected read succeeds |
| Source waits; acquisition canceled/pool closes | Prompt logical shutdown, released reservations, no late lease |
| Two reads and concurrent handshakes | Ordered acceptance, concurrent network progress, superseded late result refused |
| Two pools share one source | Independent acceptance and change comparison |
| Server password A becomes B | Current borrower may work; old credential opening fails loudly; corrected source permits a later opening through the same pool |
| New config accepted while old sessions exist | Idle/returned sessions handled under reviewed policy; active owner not interrupted |
| All sessions reused without an opening | No read occurs; deferred reset failure remains visible and SQL is not replayed |
| Broken borrowed connection | Compatible new password can recover with server acknowledgement; incompatible settings refuse; pool closure does not revoke the borrower |
| Routed opening/recovery | One captured snapshot per attempt; logical/routed identities stay distinct; one original deadline |
| Direct password-changing login | Success promotes local reconnect credential once; both fields masked; lost completion reported as uncertain server-side change |
| File source/platform behavior | Atomic replacement, missing/invalid file and fixed relative-path base tested natively on Windows/Linux/macOS |

Docker protocol scenarios run under TDS 7.4/8.0 × plain/MARS where applicable.
Configuration/equality/concurrency tests require no SQL Server. Existing full
Python regression and Rust fmt, strict Clippy, core-only/all-feature tests and
rustdoc remain required. File-provider acceptance remains separate from the implemented source contract.

## 12. Evidence informing the design

Before this change, source inspection on 2026-10-17 confirmed both pools retained opening options,
both recovery paths retain a separate copy, and both defer session reset to the
next request. Existing lifecycle tests cover late-login shutdown and canceled
lease commit; adding a source read must preserve those invariants.

A direct Python options probe shows separate equivalent SSL contexts compare
unequal, while clones sharing a context remain equal after it is mutated. This
is evidence against treating current option objects as immutable snapshot values.

Earlier isolated Docker observations show: an existing borrowed connection works
after an administrator changes its login password; another opening with the old
credential fails; and returning/reborrowing the old connection then fails reset
with 18456 and 596. A separate probe confirms direct password-changing login
succeeded but Python recovery failed with retained old credentials before this correction. These
observations concern the local SQL Server and current clients, not untested
platforms or universal server behavior. G retains the reproducible probe command.

## 13. Implementation evidence and limits

`clients/python/tests/test_config.py` tests equality/redaction, invalid and failed
reads, independent per-pool state, source deadlines/cancellation and superseded
late openings with deterministic barriers. `clients/rust/tests/config.rs` covers
the matching source/deadline/late-login boundaries through controlled TLS peers.
Both clients also test root close during a borrowed recovery's configuration read.

Disposable SQL logins on the existing Docker server exercise TDS 7.4/8.0 ×
plain/MARS: an active borrower continues after rotation; a stale opening fails;
a corrected source opens through the same pool; an obsolete return is discarded;
idle reuse does not read; incompatible recovery refuses; corrected password-only
recovery preserves the original channel after pool shutdown. Direct password
change followed by transport loss/recovery passes under both protocol versions.

A controlled TLS peer accepts LOGIN7 then drops the transport before completion.
Both clients report uncertainty and make no second attempt. This tests client
handling of an unknowable outcome; it does not prove that the artificial peer
changed any password. Rust's `Error.password_change_uncertain` and Python's error
attribute/exception note distinguish this from application SQL execution.
Canceling a login likewise cannot establish whether the server changed a password.

Configuration causes are safe by default. Raw source exceptions require explicit
inspection (`ConfigurationError.source_error` / `ConfigError::source_error()`).
There is no credential diff, secret fingerprint or public generation.

These are local macOS and Docker observations. Native Windows/Linux runtimes,
remote failover, a file format/provider and atomic-file-update behavior have not
been accepted by these tests. No automatic watcher, background reload or seamless
rotation is claimed. Full regression/check commands are recorded in the Rust
acceptance log and client READMEs.
