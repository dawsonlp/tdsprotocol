# Python key retention: design and scenarios

**Where this sits:** Python Always Encrypted ownership and D-66 lifetime parity.
**After reading this you can** configure retention and distinguish controller, live SQL and memory-erasure evidence.

> Included in Python v0.3.0. The logs and manifest below retain the original
> implementation checkpoint, before the release commit and version update.

Intent: give Python applications the D-66 trade-offs already agreed for Rust,
without sharing plaintext keys between physical connections or pool borrowers.
Transaction retention is the default; outside a transaction it becomes exchange
retention. Exchange includes parameter preparation, streamed bulk production and
response decoding, ending at the terminal response message or failed submission.
Time retention is a fixed, non-sliding maximum age from acquisition and may span
transactions/autocommit on one lease. Idle timers remove expired entries. Expiry
reloads on demand and never limits transaction duration.

## Implementation design

`Policy.exchange()`, `Policy.transaction()` and `Policy.time(seconds)` describe
retention. Immutable `Policies` chooses master and column policies independently
and bounds their caches (8/32 entries by default, maximum 4096). `Encryption`
accepts `policies=`; an exchange may override them. Different scopes/policies have
separate cache entries, so a strict override cannot reuse a broader entry.

One `KeySession` belongs to one connection lease. An explicit `KeyExchange` pins
its initial transaction generation, not merely a reusable server descriptor. A
reader that outlives that generation can reload exchange-local keys but cannot
join a later transaction. Actual decoded ENVCHANGE records update the bank before
later values are decoded. Terminal-response callbacks end exchange authority;
connection failure, close, reset and pool return clear/revoke it synchronously.
Recovery installs a fresh bank. Pool return revokes old wrappers. Before preparing
parameters on a borrowed physical connection, flush its deferred reset with an
empty batch: describe only after the login database/collation has been restored.
Statement metadata and enclave sessions are local to that lease and cleared at
context/reset/recovery boundaries. Metadata alone contains wrapped keys, not
plaintext. The policy covers column keys and locally loaded RSA master objects,
not enclave session secrets or provider-managed remote key caches.

LocalKeyStore supplies a master-loading/unwrap split. Opaque custom, certificate
and vault providers keep their existing API: the driver controls decrypted column
keys, while provider operations retain their existing private-key ownership. No
claim is made to control a provider's internal cache. Synchronous crypto remains
synchronous in this change; no new executor/cancellation model is introduced.
Runtime cancellation revokes banks via a weakly owned lifetime task, started eagerly
so shutdown cannot cancel an unpolled cleanup guard. Event-loop scheduling and
synchronous native calls bound timer precision.

Direct `Encryption.cell_key()` is uncached unless supplied an explicit exchange;
its caller owns the returned key and should close it. Connection crypto always
uses a guarded exchange. CellKey stores its four retained byte buffers in mutable
bytearrays and overwrites them before releasing ownership. Python, HMAC, custom
backends and native libraries can create immutable/temporary copies; this is not a
process-wide erasure guarantee or Rust's native ownership model. The custom backend
API still receives `bytes` keys; its call-boundary conversion creates another such
temporary copy. A regression checks that existing bytes-only backends still work.

## Scenarios to verify

- Twenty exchanges in one transaction: default loads one master and unwraps once;
  exchange/exchange does each twenty times; independent master/column policies
  produce the expected mixed counts. Autocommit defaults to exchange retention.
- Outer commit/rollback releases transaction entries; unchanged descriptors,
  savepoints and nested commit preserve them. Reused descriptors are distinct
  generations; an old reader cannot join a replacement transaction.
- Time entries span transactions, never renew on a hit, expire without activity,
  and reload during a transaction longer than their age. Master/column ages are
  independent. An acquisition already expired is discarded.
- Strict overrides do not borrow broader keys; capacities evict/reload; invalid
  configuration fails before use. Complete wrapped evidence, provider and backend
  replacement invalidate cached authority. Failed loads do not populate caches.
- Close, pool return, context change, reset and transport loss clear keys. Escaped
  old wrappers cannot use a new borrower's bank. Recovery starts fresh.
- Parameter encryption and result/output decryption share the exchange bank;
  streamed bulk production keeps it until the actual response completes. Early
  close/cancel, failed preparation and failed send release exchange keys.
- Owned CellKey buffers are zero after close/expiry, and closed objects refuse use.
  Direct unscoped calls do not populate a context-wide plaintext cache.
- Live SQL: encrypted parameter/result round trips and policy load counts under
  TDS 7.4/8.0 with plain/MARS; transaction manager begin/commit/rollback, time
  expiry/reload, pool reuse/reset database restoration and reader cleanup.

## Observed integration correction

A source yielding one small bulk row then failing, before any packet was sent,
reproduced SQL error 4022 on the following request: the server still expected bulk
data. `ConnectionCore.exchange` had cleared the continuation before transmission,
and `_undo` treated an unsent request as having nothing to clean up. The correction
restores the prior continuation for an unsent failed BulkRows request. Pool return
and recovery refuse it; awaited channel close sends Attention and drains its
acknowledgement before a replacement channel is used. A core regression and all
four live transport variants exercise this boundary. This does not change partial
bulk abandonment or claim that a failed send proves rollback.

The first cancellation fixture also demonstrated SQL Server response buffering:
`SELECT; WAITFOR` did not make the row observable before terminal completion.
The test uses `RAISERROR ... WITH NOWAIT` between the row and delay to establish an
actual open response before asserting key retention and cancellation cleanup.

## Evidence boundaries

Tests distinguish owned mutable buffer erasure from native/library cleanup. No
fresh Windows certificate, Key Vault or enclave acceptance is claimed. Rust SQL
integration and Rust/.NET interoperability are unaffected and remain pending.
The Python full suite's Windows/Azure skips are recorded in its log. The existing
independent Python/.NET Always Encrypted interoperability test also runs in that
suite; that does not establish Rust/.NET acceptance.
Runtime cleanup tests use orderly `asyncio.run` cancellation; manually abandoning
an event loop without cancelling its tasks requires explicit bank/connection close.
No cloud resources were created, no release was made, and these changes remain
uncommitted on `rust-client`.

Final test results and source/log hashes are recorded below and in the evidence
manifest.


## Final results — 2026-10-18

- **Full Python suite: 866 passed, 13 skipped**, 153.30 seconds. The skips are
  ten Azure infrastructure checks, one Windows certificate-store check and two
  Azure Kerberos checks. The existing independent Python/.NET Always Encrypted
  interoperability test passed. [Raw full-suite log](python-encryption-retention-evidence/full-suite.log).
- **Focused core/encryption/controller suite: 77 passed**, 3.82 seconds.
  [Raw controller log](python-encryption-retention-evidence/controller.log).
- New coverage comprises **41 controller cases** (26 functions), **40 live policy
  cases** (seven functions × four transport modes, with four count profiles) and
  one bulk core regression. Existing encryption, lifecycle and interoperability
  checks remain in the complete suite.
- The [cache identity probe](python-encryption-retention-evidence/cache-probe.json)
  runs inside an actual guarded cache: different wrapped tables produce different
  keys, a repeat table hits the same cached object, the provider is called twice,
  and the second key agrees with an independent decryptor.
- All 35 site page scripts passed `node --check`; new API/scenario Markdown links
  resolve; `git diff --check` passed. These are structural documentation checks,
  not a fresh browser usability or publication claim.

### Observed loads and unwraps

Each row uses one CEK for twenty exchanges. All explicit-transaction profiles
are asserted with real local RSA in controller tests and with actual encrypted
SQL parameters/results in 7.4/8.0 × plain/MARS. The autocommit fallback count is a
controller test.

| Master policy | Column policy | Explicit transaction | Master loads | Unwraps |
|---|---|---|---:|---:|
| Transaction | Transaction | Yes | 1 | 1 |
| Exchange | Exchange | Yes | 20 | 20 |
| Transaction | Exchange | Yes | 1 | 20 |
| Exchange | Transaction | Yes | 1 | 1 |
| Transaction | Transaction | No | 20 | 20 |

Time tests separately prove reuse across commit/autocommit, a non-sliding exact
deadline, zero entries while idle, and a second successful acquisition/decryption
within the same longer transaction. Strict overrides use their own scope; they
do not retroactively erase entries authorized by earlier broader exchanges.
Changing defaults between exchanges clears those prior entries.

The [manifest](python-encryption-retention-evidence/manifest.json) retains selected
source hashes, evidence hashes, commands, counts, test-function inventory,
transport modes and evidence limits. Test-suite elapsed times are not CPU or
throughput benchmarks.


## Isolated v0.3.0 release verification

The main-based Python-only release checkout independently passed **866 tests,
13 Windows/Azure infrastructure skips** in 148.29 seconds, including the
existing Python/.NET interoperability test. [Release-checkout log](python-encryption-retention-evidence/release-main-suite.log).
Its selected source hashes match the original implementation evidence.

The first isolated run lacked ignored TLS fixtures for ten mock login/routing
tests. Existing local test certificate/key fixtures were linked into the
checkout, and the complete suite then passed; no product-code change was needed.
No key material was copied into Git or release assets.

The v0.3.0 wheel and source distribution build offline. All 34 packaged Python
modules match this checkout; an isolated installed wheel reports version 0.3.0,
imports the new API, passes CLI help and exercises all three retention options,
value encryption/decryption and owned-buffer cleanup. Checksums accompany the
GitHub release assets. Rust implementation files are absent from this release.
