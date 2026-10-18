# N · Encryption Policy Implementation

**Where this sits:** Implements the agreed direction in [D-66](4-decisions.md) against the [scenario plan](experiments/encryption-policy-scenarios.md). The earlier [cost/lifetime explanation](M-rust-encryption-lifetimes.md) remains the conceptual basis.

**After reading this you can** follow secret ownership, cache lookup, cancellation and timer behavior through the Rust key-policy foundation.

> Foundation design written before implementation, 2026-10-18. The policy/local-crypto service and driver lifecycle link are implemented under the optional `encryption` feature. This foundation campaign uses manual byte crypto. Transparent SQL metadata, normalization, parameter/result orchestration and independent .NET interoperability are now implemented and covered separately in [design O](O-rust-transparent-encryption.md) and its [evidence](experiments/rust-transparent-encryption.md).

## Intent and public concepts

`encryption` is an optional Cargo feature that enables `tokio`; its timer needs a time-enabled Tokio runtime. The normal non-encryption and core-only builds retain their existing behavior. The driver contains no new unsafe code. Use the existing AWS-LC backend and compiler-resistant `zeroize` buffers, not new cryptographic primitives.

- `Policy`: `Exchange`, `Transaction` (default), or `Time(Duration)`.
- `Policies`: independently selects parsed-master and working-column lifetimes, plus bounded entry counts (defaults eight and 32).
- `LocalKeyStore`: a named, fixed provider binding to a canonical directory containing PKCS#8 RSA private-key PEM files. Reads are bounded and path escape is refused.
- `ColumnKey`: complete wrapped-key metadata, including database-local identifiers and encrypted provider entries. This is ciphertext metadata, not a secret handle.
- `KeySession`: one connection/lease authority and its bank, providers, policy defaults, counters, tracked loads and timer. Clone no session owners; expose no raw key handles. Dropping or closing it revokes authority.
- `Connection::key_session`: attach one service to the real driver endpoint. Registration initializes the current transaction atomically; decoded environment records update transaction/context authority. Endpoint revocation, pool return and physical recovery revoke the service. The driver retains only a weak lifecycle link. A replacement lease/epoch attaches a fresh service. Standalone construction remains available for deterministic controller tests.
- `KeyExchange`: one non-cloneable application exchange guard. Its encrypt/decrypt operations borrow bank-owned handles briefly; dropping it clears exchange-owned keys. The later facade must own this guard alongside the response stream.
- `transaction_begin/end`, `invalidate`, and `revoke`: explicit lifecycle inputs for the adapter, never SQL-string matching. Begin always creates a new generation, even for a repeated server descriptor. Savepoints/inner commits do not emit an outer boundary. Reset, recovery, pool return and close revoke the session; the replacement creates a fresh authority.

## Cache and identity

Attachment is allowed only between protocol exchanges, with at most one live service per endpoint. The pooled connection's deferred RESETCONNECTION requires a distinction: a newly attached service already belongs to the new borrower. Its first expected reset acknowledgement clears all pre-ACK entries but keeps that new lease/guard authority alive. Other reset acknowledgements revoke the service. The SQL facade in design O obtains a fresh parameter description after reset before preparing encrypted SQL inputs. Manual byte-crypto callers may observe one extra load/unwrap when they encrypt before that first acknowledgement and decrypt after it.

Decoded database/collation changes invalidate entries and prior guards. Opaque or unannounced T-SQL security-context changes still require explicit `invalidate`; this adapter does not claim to detect every change by parsing statements. Physical break revokes the bank before recovery begins. Awaited key-session close drains tracked provider work; connection close revokes immediately but cannot interrupt an OS key-file read already running.

Master entries use provider binding + resolved key source + ownership scope. Column entries additionally compare the complete `ColumnKey`, including provider entries, path/algorithm and wrapped bytes. Numeric database/key IDs alone never select a key. Per-session storage prevents connection/borrower sharing. Policy identity partitions exchange, transaction and time entries: an exchange override cannot borrow a broader entry.

An exchange guard records its originating session/context generation and transaction generation. A transaction-policy guard whose transaction has ended can load exchange-local material for a remaining stream; it cannot join a replacement transaction. Invalidation retires all prior guards. A time-owned entry deliberately survives transaction boundaries but never a session revocation.

Each cache entry records acquisition time, immutable optional deadline, and last-use sequence. Expire at `now >= deadline`; hits never extend deadlines. Timers use Tokio's monotonic clock and run independently of traffic. Capacity eviction removes the least recently used entry and drops its secrets. A miss reloads normally. Policy changes require no active guards, clear existing entries and advance context authority.

Prepared AES/HMAC objects are boxed before entering the cache. A growable vector
must never contain those native schedules inline: reallocation and compaction
could copy them into old heap storage without running their destructor there.
Cache entries move only box pointers; dropping a victim destroys its native
objects in place. Private RSA handles already point to native owned allocations.

Capacities are session-wide. Per-exchange lifetime overrides must retain those capacities; they cannot silently increase a connection's memory budget. The maximum normalized plaintext per operation is 16 MiB. Check the decrypted length after unpadding as well as the ciphertext envelope size, since those bounds differ.

## Loading, handoff and cancellation

1. Under a short bank lock, validate the guard, remove expired entries and attempt the operation with a cached working key.
2. On a miss, acquire an owned async load gate and recheck. This coalesces concurrent first use. The gate is transferred to the worker so canceling its caller cannot release it prematurely.
3. Run bounded file reading/parsing and missing-key work in a tracked blocking worker. Do not block the async executor on provider I/O. PEM, decoded DER and RSA plaintext are immediately guarded owned allocations.
4. Never hold the bank lock during file reads/parsing. Recheck session, context, exchange and transaction authority after acquisition. An obsolete result is dropped without insertion. Record actual attempts separately from success.
5. Existing master handles may be borrowed under the bank lock for signature verification, unwrap and derivation. No raw-key borrow crosses `await`. Derive directly into guarded output; avoid copyable HMAC `Tag` objects for secret output. Erase the root as soon as derived handles exist.
6. Check acquisition deadlines before insertion. A deadline already reached is a clear error, not an unbounded retry. Insert only when the initiating guard still exists. Return ciphertext or guarded plaintext, never a key.
7. The worker sends its operation result through a one-shot channel. A canceled receiver causes that owned result to drop. Workers return no retained secret task result. Awaited close revokes first and waits for the pending-work counter to reach zero. Running blocking I/O cannot always be canceled instantly; Drop revokes synchronously and owned worker temporaries are destroyed when that finite work finishes.

Timer scheduling holds only a weak bank reference and is woken after inserts/invalidation. Its task cannot keep a dropped session alive indefinitely. Session Drop revokes synchronously; task shutdown is also a cleanup path.

A timer authority guard is captured before spawning the task. Its destructor revokes even when the task never polls or the runtime is destroyed while application session handles survive.

## Local cryptography and erasure

Parse bounded PKCS#8 through AWS-LC's native decoder and decrypting-key API. Serialize its public component into a public-only DER allocation; immediately drop the temporary reference-counted public view before retaining the private handle. Do not infer identical validation cost/policy to Python from earlier primitive measurements; record the native decoder and explicit API checks separately. Wrapped-key validation checks version, lengths, provider algorithm and signature before RSA-OAEP decryption, using the existing local-provider wire format. Derive the three Microsoft HMAC-SHA-256 working keys. The root is not retained.

Source review traced PKCS#8 decoding to `RSA_parse_private_key`, which calls `RSA_check_key` for mathematical/CRT consistency. A valid-ASN.1 key with a corrupted CRT coefficient is rejected by the implementation tests. This is stronger evidence than only observing the Rust API's additional type/size checks; it still does not establish identical validation policy to another backend.

Prepare AES/HMAC handles from guarded derived bytes, then erase those input bytes; the native handles own working copies until expiry. AES-256-CBC/PKCS#7, deterministic or random IV and HMAC authentication follow the existing Python implementation. Authenticate before decrypting. Malformed values and tampered tags return a fixed error without plaintext. Bound each operation's input size; streamed SQL value handling belongs to the later facade.

Use secret wrappers without byte-bearing `Debug`, `Clone` or serialization. Destructor instrumentation exists only in unit tests and checks owned memory after zeroing but before deallocation. Native RSA/HMAC/cipher cleanup is reviewed separately against pinned dependency sources. No claim covers all stack/register copies, custom native allocators, process abort, disk sanitization, swap or dumps. Python's immutable bytes retain their documented weaker erasure guarantee.

## Verification and reporting

Name tests by KP scenario ID. Generate synthetic fixtures using the independent Python implementation; retain only fixture metadata, public/ciphertext evidence and clearly identified disposable test secrets. Compare deterministic ciphertext and derived behavior, randomized round trips, multiple sizes and meaningful failures. Use counters for reuse/coalescing and a paused Tokio clock for exact age/idle behavior. Gates provide deterministic cancellation/revocation during loading. Tests must not sleep long enough to depend on scheduling luck.

Run feature-enabled tests, normal/default and core-only regressions, strict Clippy, formatting and rustdoc checks. Then use the existing local SQL Server to check the driver's lifecycle link under both TDS versions and plain/MARS framing: outer begin/end, savepoints, time reuse across commit, pool release and close. Keep manual byte encryption separate from transparent SQL encryption. Retain commands, counts and evidence limits in a separate experiment report. .NET interoperability and transparent encrypted SQL wire support remain explicitly outside this foundation campaign.
