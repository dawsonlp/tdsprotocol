# Rust transparent SQL encryption evidence

**Where this sits:** Acceptance for [design O](../O-rust-transparent-encryption.md), extending the earlier [key-policy campaign](encryption-policy-evidence.md). Observed on the uncommitted `rust-client` working tree, 2026-10-18.

**After reading this you can** reproduce the SQL/.NET and lifecycle checks, inspect measured counters and distinguish local Rust completion from the remaining Windows/GCP campaign.

Verification complete: all configurations, strict checks, serial live campaigns
and local package verification passed. Results apply to the retained working-tree
source hashes. This is not a Rust release or Windows-authentication acceptance
claim.

## Scenarios and independent implementation

`clients/rust/tests/transparent_encryption.rs` exercises the real Rust adapter
against SQL Server 2025 and runs Microsoft's SqlClient directly through the
existing `.NET SDK 10.0` test container. `Microsoft.Data.SqlClient` is pinned by the
existing test project. Python generates application-value/normalization fixtures;
it performs no encryption or SQL orchestration during this Rust live test.

- 28 SQL type cases, two non-NULL edge values and NULL each: 84 Rust inserted rows
  and 84 Rust bulk-loaded rows, with deterministic/randomized columns in each.
- SqlClient reads both Rust paths and checks deterministic lookups. Rust reads
  SqlClient's writes and performs deterministic lookups against those rows.
- SqlClient's known `time(0)` parameter behavior prevents its writes to that one
  declared type; its reads/lookups of Rust's `time(0)` values are still checked.
  Thus mutual writes cover 27 types, with independent reads covering all 28.
- Exact values include decimal(38,s), tiny/small/big integer boundaries, money,
  floating-point bits, temporal scales/offsets, GUIDs, Latin-1, Unicode (including
  the known SqlClient surrogate replacement), fixed padding, binary and max data.
- The interoperability function records 165 successful master loads and CEK
  unwraps, 221 working-key hits, and zero retained masters/working keys after its
  final exchange. These are operation counts, not elapsed crypto CPU times.

## Lifetime, failure and diagnostic boundaries

The live lifecycle function covers TDS 7.4/8.0 × plain/MARS, independently of the
single .NET interoperability session:

| Scenario | Observed assertion |
|---|---|
| Transaction default | Two value-reading exchanges share one unwrap and one retained working key |
| Exchange overrides inside that transaction | Two overrides add two unwraps; neither borrows nor erases the transaction's entry |
| Outer rollback | Transaction-retained keys are gone |
| Fixed-age autocommit reuse | Two exchanges share one acquisition; after idle expiry, a still-open transaction reacquires successfully |
| Encrypted output | `sp_executesql` output authenticates and returns the integer 42 |
| Cancellation | Consume a decrypted row from a result large enough to force packets, cancel, observe completed/canceled cleanup, then reuse the channel |
| Large value | A 1 MiB + 17 byte encrypted max value authenticates and reads back exactly |
| Pool return/reborrow | Awaited release reuses the connection; a new adapter completes deferred reset before discovery/key use |
| Missing configured provider | Explicit `NotDecrypted` cell; readable response completion |

Controlled TLS acceptance sends authenticated/corrupted/NULL/authenticated cells
and verifies that the corrupted cell exposes no plaintext and later cells remain
readable. It also verifies:

- Discarding unread rows causes no extra unwrap/decryption.
- Invalid input is refused before discovery/application send.
- A discovery error marks application SQL `NotSent`, sends no application UPDATE,
  and permits subsequent channel reuse.
- Bulk returned result sets authenticate through the same adapter, under the
  input's exchange guard.
- Full observation and capture/replay contain ciphertext, no decrypted canary or
  private PEM. Native replay decodes version-one metadata without a key provider.

Three core wire tests run without the encryption feature: every valid metadata
and RETURNVALUE split, explicit cipher RPC bytes/negotiation and raw replay,
plus malformed key counts/ordinals/cipher types. Normalization separately matches
56 Python edge-value fixtures and checks invalid range/boolean cases.

## Reproduce

```sh
python3 tools/check_rust.py --live --output /private/tmp/tds-rust-acceptance
```

It runs locked/offline default, core-only and all-feature tests, strict Clippy in
all three configurations, formatting, rustdoc with warnings denied and the serial
Docker suite. Docker and the existing SQL fixture/CA/ignored credentials are
required for `--live`; Windows/GCP tests are not silently substituted or skipped
into acceptance. Run Python and Rust mutation campaigns sequentially.

| Check | Result |
|---|---|
| Default | 209 passed; 57 live functions explicitly ignored in this unit/controlled run |
| Core only | 90 passed |
| Encryption enabled | 240 passed; 61 live functions explicitly ignored in this unit/controlled run |
| Encryption-enabled Docker/.NET | 61 live functions passed, serially (45.29 s) |
| Default Docker | 57 live functions passed, serially |
| Format / Clippy (all 3 configurations) / rustdoc | Passed, warnings denied |
| Package | Local source archive built and verified with all features; not published |

Retained [summary and exact commands](rust-transparent-encryption/summary.json),
[source hashes](rust-transparent-encryption/source-sha256.json),
[package hash](rust-transparent-encryption/package-sha256.json),
[default log](rust-transparent-encryption/default.log),
[core log](rust-transparent-encryption/core.log),
[encryption log](rust-transparent-encryption/encryption.log),
[live counters/results](rust-transparent-encryption/live.log),
[default live results](rust-transparent-encryption/default-live.log),
[package verification](rust-transparent-encryption/package.log).
No ignored-configuration credential appears in the retained logs.

The live log's `time_reacquisitions=2` denotes two acquisitions in that measured
window: the initial load and one replacement after expiry. Four identical
transport-mode results were observed. Test databases from successful runs were
dropped by their fixtures. Four abandoned databases from development failures
were separately identified by exact timestamps, public CEK fixture and complete
table lists before deletion; final read-only inventory found no campaign database.
No SQL data volume was recreated.

## Readiness and limits

The initial tested Rust minimum is 1.99.1 on macOS ARM64. Cargo.lock pins the
resolution; the optional crypto reuses the existing AWS-LC dependency and
zeroize. Dependency-tree review found no duplicate resolved package versions on the inspected macOS target.
This is not a fresh vulnerability-database audit; `cargo-audit` was unavailable.
The crate forbids unsafe Rust in its own source; its dependencies include native
crypto and are outside that source-level guarantee.

The example `always_encrypted` compiles under the optional feature. The MIT notice
is included in the local unpublished crate archive. A local package verification
is recorded separately from publication. No release/tag/main update is implied.

The supported adapter covers owned scalar/max values and owned bulk rows, with a
16 MiB crypto bound per value. Encrypted producer APIs and borrowed plaintext
chunk readers are not provided. Applications close/drop and reattach the adapter
after physical recovery; old guards cannot migrate. Ordinary returned values are
application-owned allocations; the key/work-buffer erasure guarantee does not
extend to arbitrary application copies. Captures can still contain ordinary
unencrypted SQL/data under their existing policy.

Native Windows authentication, actual Browser behavior, native Windows builds,
GCP permissions/quotas/cost and verified lab teardown remain unaccepted. See the
[provider/lab proposal](../P-windows-authentication-campaign.md). No GCP resource
was created during this local campaign.
