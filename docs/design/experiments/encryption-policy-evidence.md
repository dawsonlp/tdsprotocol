# Encryption policy acceptance evidence

**Where this sits:** Results for the [scenario plan](encryption-policy-scenarios.md) and [implementation design](../N-encryption-policy-implementation.md), observed on 2026-10-18.

**After reading this you can** reproduce the policy campaign, inspect actual counters and distinguish foundation, driver-boundary and transparent SQL encryption evidence.

> Implemented on the uncommitted `rust-client` working tree. No release, remote Windows test or cloud deployment is claimed. This is the earlier foundation checkpoint; transparent SQL integration is now covered by [design O](../O-rust-transparent-encryption.md) and [its independent SQL/.NET evidence](rust-transparent-encryption.md).

## Delivered behavior

The optional Rust `encryption` feature supplies local PKCS#8 RSA master loading, signed RSA-OAEP unwrap, derived AES/HMAC handles and authenticated byte encryption/decryption. Transaction is the default lifetime; exchange and absolute time lifetimes are independent choices for master and working keys. Fixed deadlines do not slide. Idle timers erase expired entries. Owned input/root/derived buffers zero on Drop; default native destruction paths were source-reviewed separately.

`Connection::key_session` binds one service to decoded transaction/database/collation changes, pool return, physical break/recovery and close. An application-owned exchange guard encloses manual byte processing. These foundation tests intentionally exercise byte operations; the subsequent SQL adapter automatically transforms encrypted columns/parameters in its separately retained campaign.

## Scenario results

All **30 named scenarios** pass through **31 test functions**: 28 foundation/controller tests, one controlled TLS recovery matrix, and two live SQL lifecycle matrices. KP01–KP24 were specified first; KP25–KP30 extend the plan with issues found during review and driver integration.

For twenty exchanges with one key, each performing a successful encrypt/decrypt round trip:

| Master / column lifetime | Actual master loads | Actual unwraps | Retained after exchange guards end |
|---|---:|---:|---|
| Transaction / transaction | 1 | 1 | One master and one column entry until transaction end |
| Exchange / exchange | 20 | 20 | None |
| Transaction / exchange | 1 | 20 | One master |
| Exchange / transaction | 1 | 1 | One column entry; no private master retained |
| Default, outside a transaction | 20 | 20 | None |

Raw [scenario output](encryption-policy-evidence/scenarios.log) records the counters. Additional observed results include:

- A hit at 59 seconds does not extend a 60-second deadline. The exact deadline forces a second load/unwrap.
- The idle timer leaves **zero** live master/column entries with no lookup; statistics do not perform lazy expiry.
- Eight concurrent first uses produce **one** master load/unwrap and **seven** coalesced followers.
- Cancellation during a gated load leaves **zero** entries and records **one** discarded late result. Transaction/epoch revocation also prevents late insertion.
- Five owned secret-buffer stages (PEM, encoded PEM body, DER, RSA plaintext and derived bytes) are observed entirely zero while still allocated, before deallocation. This is not an inspection of freed memory or native/register state.
- **537** truncated wrapped-key prefixes, inconsistent RSA CRT parameters, oversized PEM, invalid root length and path escapes are refused. A correctly authenticated ciphertext whose unpadded plaintext exceeds the operation limit is also refused.
- A session moved out of its Tokio runtime is revoked when the timer task is destroyed: zero live entries remain.
- A retained prepared key object stays at the same address while the cache grows to seventeen entries and its backing-vector capacity grows from four to 32. Boxed ownership prevents vector growth/compaction from copying inline native schedules into old heap storage.

## Actual driver and SQL observations

The [live SQL output](encryption-policy-evidence/live-final.log) covers TDS 7.4/8.0 × plain/MARS. It establishes:

- Actual outer begin/commit/rollback announcements control transaction retention. Savepoint rollback and an inner commit retain the same key. Attaching inside an existing transaction initializes from the server's current descriptor.
- Fixed-age keys survive commit/rollback and subsequent autocommit exchanges on the same lease, with one load/unwrap.
- Binary ciphertext sent to SQL Server returns unchanged and decrypts correctly in the service. This is manual byte encryption over an ordinary binary SQL expression, not Always Encrypted SQL metadata support.
- Pool return clears the old service. The next borrower reuses the same SQL session ID but loads keys independently. Its first RESET acknowledgement clears pre-ACK material, including when restoring a different database context.
- Decoded `USE master` invalidates prior guards and entries. Physical close revokes the service.

The [controlled recovery output](encryption-policy-evidence/recovery.log) separately covers all four modes: TLS peers break the original transport, acknowledge a real recovery login, and observe one successful recovery. Old key authority is closed; a fresh attached service loads once. These are actual driver/TLS recovery checks, not SQL Server recovery evidence.

## Findings and corrections

The first live adapter incorrectly revoked a newly borrowed service on the first deferred RESET acknowledgement. The [pre-fix output](encryption-policy-evidence/live-before-fix.log) retains the failure. The correction clears pre-ACK keys while preserving the new lease's authority. Old borrower authority was already revoked at return and never participates.

The initial MARS test used T-SQL `BEGIN TRANSACTION` in a batch. SQL Server returned 3997 and rolled it back at batch end. The test now uses the existing TDS transaction-manager API for outer transactions. This corrects the test setup; it is not a driver transaction workaround.

Review also added runtime-destruction cleanup and a decrypted-length check after PKCS#7 removal. A ciphertext envelope size alone cannot establish the maximum plaintext length.

Final ownership review found that inline native key objects in a growable cache
could leave old heap copies on reallocation/compaction. The cache now owns boxed
AES/HMAC objects, so it moves pointers rather than schedules. KP30 checks stable
pointee addresses during real capacity growth. Compiler-created temporary copies
remain a separate limitation, not something this test claims to erase.

The shared Python key-cache collision is corrected: complete wrapped-key evidence participates in lookup, and provider/backend object replacement clears entries without requiring hashable providers or relying on reusable numeric object IDs. The same [synthetic probe output](encryption-policy-evidence/python-cache-probe.json) changed from `true / 1 / false` to **`false / 2 / true`**. At this checkpoint Python still had context-wide retention. The subsequent [Python retention implementation](python-encryption-retention.md) replaces that lifetime; Python's erasure limits remain distinct from Rust's.

## Regression checks

Run Rust commands from `clients/rust/`, Python commands from `clients/python/`:

| Command | Observed result |
|---|---|
| `cargo test --offline --all-features` | **235 passed**, 59 live tests explicitly ignored |
| `cargo test --offline` | **206 passed**, 57 live tests explicitly ignored |
| `cargo test --offline --no-default-features` | **87 passed** |
| `cargo test --offline --all-features --tests -- --ignored --test-threads=1` | **59 passed**, zero failures/skips |
| `cargo test --offline --all-features --lib encryption:: -- --nocapture --test-threads=1` | **28 passed**, actual counters retained |
| `cargo test --offline --all-features --test encryption_live -- --ignored --nocapture --test-threads=1` | Both strengthened live functions pass, each exercising all four modes |
| `cargo clippy --offline --all-features --all-targets -- -D warnings` | Pass |
| `cargo clippy --offline --all-targets -- -D warnings` | Pass |
| `cargo clippy --offline --no-default-features --all-targets -- -D warnings` | Pass |
| `cargo fmt --all -- --check` | Pass |
| `cargo doc --offline --all-features --no-deps` | Pass |
| `.venv/bin/python -m pytest tests/test_encryption.py tests/test_encryption_live.py -q` | **96 passed**, including both new cache regressions and live encrypted SQL coverage |

Retained raw logs, source hashes, exact counts and native-source review notes are indexed by [the evidence manifest](encryption-policy-evidence/manifest.json). Default/core checks preserve the existing non-encryption build paths. This does not establish a minimum Rust version or another operating system.

## Implemented service cost

Run `cargo run --offline --release --features encryption --example key_policy_cost`. It reads intentionally public synthetic fixtures and measures the actual service, including warm PEM file reads, worker scheduling, guarded memory, key/value crypto and exchange/transaction cleanup. Each transaction contains twenty exchanges, each with a deterministic encryption and authenticated decryption of a 64-byte value. Five batches of ten transactions follow a warmup.

The [retained service results](encryption-policy-evidence/service-cost.json) give median wall time and batch-mean range. The concurrent-build run is retained separately to show scheduling variance. These are not CPU utilization, SQL latency or a guaranteed throughput distribution. Every profile has zero retained keys at transaction end, and measured load/unwrap counts agree with its policy.

| Master / column lifetime | Median per twenty-exchange transaction | Five batch means, range |
|---|---:|---:|
| Exchange / exchange | 10.745 ms | 10.729–10.789 ms |
| Transaction / exchange | 5.856 ms | 5.841–5.996 ms |
| Transaction / transaction | 0.563 ms | 0.560–0.567 ms |

The final run launched no other build/test commands concurrently from this task.
Other activity on the machine was not controlled. The earlier concurrent-build
run measured 14.143 ms for strict exchange scope, illustrating scheduling noise.

## What the erasure evidence means

Owned-buffer instrumentation proves clearing of the specific live allocations controlled by this crate. Native source review for aws-lc-rs 1.18.2 / aws-lc-sys 0.46.0 / zeroize 1.9.1 traced:

- Cipher input buffers and both expanded AES schedules to compiler-resistant zeroization on destruction.
- HMAC native contexts to `HMAC_CTX_cleanup` / `OPENSSL_cleanse`. Secret derivation uses `sign_to_buffer`, avoiding the copyable `Tag` output.
- Private-key destruction through EVP ownership, RSA components/BIGNUM cleanup and default `OPENSSL_free`, which cleanses before freeing.
- PKCS#8 parsing through native RSA consistency checks, also exercised with a corrupted CRT fixture.

The manifest records reviewed source-file hashes. This applies to the tested locked/default-allocator build. It is not proof of all compiler moves, stack/register copies, a custom native allocator, process abort, swap/dump protection or disk sanitization. Revisit the review if native versions/features/allocator configuration change.

Transparent encrypted SQL metadata, normalization, automatic parameter/result handling and independent Rust/.NET interoperability remain subsequent integration work. Opaque security-context changes require explicit invalidation. No GCP resources were created.
