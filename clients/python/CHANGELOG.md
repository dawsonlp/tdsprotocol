# Python client release notes

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
  in the GitHub release notes.

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
