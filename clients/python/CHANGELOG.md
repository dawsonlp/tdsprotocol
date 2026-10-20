# Python client release notes

## Unreleased — Azure authentication follow-ups

Live testing on the Azure campaign's deployment (see the
[follow-up plan](../../docs/design/experiments/azure-auth-followups.md)):

- The built-in `Spnego` adapter runs pyspnego's blocking calls in a bounded pool
  of worker threads, so a Kerberos KDC that never answers can no longer hold an
  opening past its deadline or stall the event loop. Live: an unreachable KDC
  returned at the 1.5 s deadline (it previously blocked for more than 4 s). A
  canceled call finishes in its worker and its result is released.

## Unreleased — GCP authentication follow-up

Rust/GCP interoperability testing exposed shared-client corrections:

- Redact incoming Windows-login payloads in default captures and SSPI copies in
  inspection/replay. Preserve safe login/feature evidence without reconstructing
  omitted authentication tokens. Sanitize provider-start/step error diagnostics.
- Process final SSPI tokens alongside LOGINACK; refuse invalid final tokens,
  output after server acceptance and duplicate challenges.
- Bound Windows authentication to 48 KiB tokens, eight provider steps including
  the initial step, and 64 KiB assembled login replies.
- On configured SQL pool opening refusal (18452/18456), reread credentials once
  and reopen only for changed settings within the original deadline. Never
  replay application SQL.

The [follow-up evidence](../../docs/design/experiments/gcp-authentication-follow-up-evidence.md)
records remaining completion/configuration/worker decisions and the failed
blocking-provider deadline case. This work is not a released version.

## 0.3.0 — 2026-10-18

Implementing explicit key ownership and lifecycle handling in Rust exposed a
necessary correction in the Python reference: decrypted keys were shared across
connections for the lifetime of an Encryption context. Python now provides the
same agreed transaction, exchange and fixed-age retention choices, with explicit
connection and pool-lease boundaries. The Rust implementation prompted this
change; this release delivers the Python implementation.

- Always Encrypted key-cache lookup now compares complete wrapped-key evidence,
  rather than database-local numeric identifiers alone. Replacing a configured
  provider or crypto backend retires cached keys. This corrects the synthetic
  collision discovered during Rust key-policy development.
- Add transaction (default), exchange and fixed maximum-age key retention, with
  independent local master/column policies, bounded caches, idle expiry and
  per-exchange overrides. Keys and statement descriptions belong to one physical
  connection and exclusive pool lease. Commit/rollback, context changes, pool
  return, reset, recovery and close enforce the agreed boundaries. A deferred
  pool reset completes before describing/encrypting application parameters.
- Overwrite the four owned CellKey buffers on release, expiry and eviction.
  Python/library temporary copies and provider-owned native secrets remain
  outside the erasure guarantee. Local RSA objects follow the selected master
  policy; opaque providers keep control of their private-key operations.
- Preserve the pending bulk continuation when row production fails before any
  data packet is sent. Awaited channel close must cancel/drain that preparation;
  unresolved connections cannot return to the pool or recover.

### Compatibility and verification

Transaction retention replaces the old shared context-wide default. Outside an
explicit transaction it falls back to exchange retention. Select `Policy.time`
for bounded reuse across transactions on one physical connection/pool lease.
A per-exchange override does not retroactively erase entries retained by earlier
exchanges; changing session defaults clears them. Direct `Encryption.cell_key`
is uncached and caller-owned; close the returned key or use explicit session and
exchange guards. Custom provider overrides and backends' bytes input contract
are preserved.

Development validation: **866 passed, 13 Windows/Azure infrastructure skips**,
including independent Python/.NET Always Encrypted interoperability. Forty new
live policy cases cover TDS 7.4/8.0 with plain/MARS. The thirteen skips are ten
Azure checks, one Windows certificate-store check and two Azure Kerberos checks.
The retained design, scenarios and raw evidence are linked from the Python README.
Python/library temporary copies are outside the owned-buffer erasure guarantee.

The isolated main-based v0.3.0 checkout independently passed **866 tests with 13
skips** in 148.29 seconds. Wheel/source builds, all 34 packaged Python modules,
isolated installed-wheel imports/version/CLI and all retention options were
verified. The release contains Python changes and their documentation.


## 0.2.0 — 2026-10-18

Developing and independently exercising the Rust client exposed defects and
missing lifetime boundaries in the Python reference. This release applies those
corrections to Python and adds regression coverage. It releases the Python
client; the Rust implementation remains development work on `rust-client`.

### Connection, channel and pool corrections

- Awaited channel close now revokes its authority and drains cancellation through
  Attention acknowledgement and the message boundary. An ordinary final DONE is
  insufficient. Cleanup uses one total budget (five seconds by default); failed
  or canceled cleanup discards the connection. Stale close controls cannot close
  a replacement channel or session.
- MARS flow control counts consumed DATA frames instead of TDS packets. Frames
  may split/combine packets. Framing, sequence wrap, credit and per-channel inbox
  checks prevent dirty reuse, deadlocks and incorrect window advancement.
- Session recovery separates stable logical channel identities from fresh wire
  identities. Existing open channel handles survive eligible recovery; closed
  channels stay closed. Commands and cleanup from the old transport cannot act
  on its replacement. An in-flight request is never replayed.
- Successful INSERT BULK preparation leaves a continuation obligation. Channel
  close now cancels/drains that gap; unresolved pool return discards it, and
  recovery refuses it. Proven cleanup preserves the server-announced transaction
  state; it does not imply commit or rollback.
- Autocommit transaction-descriptor headers now send an outstanding-request count
  of one, including with concurrent MARS requests.

### Configuration and credentials

- Add `ConfigService`, comparable immutable `ConnectionConfig`, `StaticConfig`,
  `ConnectionServices` and lazy `Pool.from_config`. Physical opening and eligible
  recovery read current configuration within their deadline. Each pool adopts
  snapshots independently and retires known stale idle/returned connections;
  current borrowers continue. No watcher is created.
- Configuration failures retain an explicit safe phase/reason. Login rejection
  fails without fallback; a later corrected source read can succeed through the
  same pool. SQL carrying a failed deferred reset is never silently replayed.
- A fully successful password-changing direct login retains its new credential
  for later recovery and clears the one-time request. Lost completion exposes
  `password_change_uncertain`; pools reject one-time password changes.
- Reject invalid routing targets before opening a redirected connection.

### Observation and saved recordings

- Optional observer failure disables that observer without stopping SQL or a
  requested recording. The exception is available as `observation_error`.
- Saved-recording write/flush failure raises `CaptureError`, retains its cause,
  discards the connection and wakes waiters. Query execution may already have
  happened; recording failure does not establish rollback.
- A Capture belongs permanently to one physical connection. `capture_factory`
  supplies distinct recordings for pool openings, routing and recovery; a direct
  capture refuses transitions that would combine physical connections.
- Replay uses accepted feature context for JSON/classification and advances past
  large rows to remaining returns/completions. Input inspection uses input layouts
  for JSON, CLR and legacy types rather than result layouts.
- Saved TVP input inspection now retains table names, default columns, sort/unique
  hints, placement and exact rows as `types.TableInput`, separate from result cells.
  Its regression fixtures are self-contained in the Python tree.

### Exact values and test evidence

- Refuse contradictory PLP totals/chunks and vector width/count/element/reserved
  bytes. Respect negotiated vector capability instead of assuming every server
  supports native float16 or the same character fallback.
- Validate UTC/local datetimeoffset range, ticks, offset and scale, including
  directly constructed exact values and aware datetimes that overflow UTC.
- Observation-level comparisons verify each connection's actual session ID before
  normalizing that incidental identity. They do not assume SQL Server reuses it.
- Development validation: **782 passed, 13 skipped** against local SQL Server
  2025 with verified TLS, TDS 7.4/8.0 and plain/MARS. The skips are Azure (10),
  Kerberos (2) and Windows certificate store (1). This does not establish full
  cross-platform/failover acceptance. Release-checkout verification is recorded
  in the GitHub release notes. The isolated `main` release checkout also passed
  **782 tests with 13 skips** in 117.39 seconds; the built wheel passed isolated
  version/import/CLI checks, and its package source matches that checkout.

### Compatibility notes

Await active channel close and handle cleanup failures explicitly. Record pooled,
routed and recovered physical connections through `capture_factory`. Optional
observer failures no longer abort database work; saved-recording failures do.
Use configuration sources for reusable pool credentials and direct login for
one-time server password changes. No implicit transaction outcome or SQL replay
has been added.

A three-column TVP with a defaulted identity and reversed placement was refused
with SQL Server errors 8037/8061 by both clients on the local server. The existing
four-column variant with a defaulted computed final column succeeds. The cause
is unresolved; this release does not change server-validation policy or claim
that every table/placement/server combination is accepted.

## 0.1.1 — 2026-10-17

Make SQL Server test setup portable: wait for and provision `tds_test`, query the
current server identity, retain captured protocol bytes and document the local
verified-TLS setup.
