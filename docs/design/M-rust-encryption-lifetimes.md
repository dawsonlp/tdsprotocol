# M · Rust Encryption Lifetimes and Cost

**Where this sits:** The local-key Always Encrypted portion of [Rust completion](J-rust-completion.md), before the temporary Windows lab in the [roadmap](C-roadmap.md).

**After reading this you can** choose key reuse boundaries, follow ownership and erasure through an exchange, and estimate the client cost for a particular workload.

> **Status: policy/local-crypto foundation implemented, 2026-10-18 (D-66).** Transaction reuse is the default, with application-selected exchange or broader time-based reuse on one connection/lease. [Design N](N-encryption-policy-implementation.md) describes the implemented service, bounds and lifecycle link. Transparent SQL integration is now implemented in [design O](O-rust-transparent-encryption.md), with [separate SQL/.NET evidence](experiments/rust-transparent-encryption.md). The primitive costs below remain historical measurements, not an end-to-end SQL encryption benchmark.

## 1. Intent and concepts

The client should decrypt protected SQL values correctly, make secret retention an explicit choice, and erase owned key material when that retention ends. The application should be able to select a shorter retention window at a measurable cost.

| Concept | Meaning | Secret material and lifetime |
|---|---|---|
| Master key | A local RSA private key used to unwrap column keys | The PEM/DER input and parsed native private-key object are secrets. The file remains the configured source. |
| Wrapped column key | The encrypted column key, signature and provider metadata supplied by SQL Server | May remain in protocol metadata. It is not a usable plaintext key. It still belongs under ordinary diagnostic masking rules. |
| Root column key | The 32-byte key recovered by RSA unwrap | Use only to derive working keys. Erase immediately after derivation; Rust enclaves are outside this scope. |
| Working keys | AES, authentication and deterministic-IV keys derived from one root key | Three 32-byte secrets, plus any backend key schedules or copies. Retain according to the selected window. |
| Exchange | One application request and its full response, including streaming | Includes the whole stream, not each packet, row, cell or socket read. Internal describe requests do not start another application key window. |
| Transaction window | Reuse within one server-confirmed transaction on a physical connection and pool lease | Begins and ends from server transaction state. Never create a transaction merely to retain keys. |
| Time window | Reuse across transactions/autocommit exchanges on the same physical connection and exclusive lease, subject to an application-selected maximum age | Survives transaction end but never pool return, reset, recovery, close or explicit invalidation. |
| Parameter description | The server's description of how RPC parameters must be encrypted | Has a separate correctness and invalidation problem. It does not contain an unwrapped key. |

One key can protect many columns and values. A result with 1,000 rows and three encrypted columns sharing a key requires 3,000 value decryptions but only one key unwrap within a reuse window. Plain values, NULL values and transaction-control messages require no column-key unwrap. Description work may still be needed to discover the parameter contract.

The wrapped key already exists in server metadata. Releasing its plaintext working keys means erasing them. It does **not** require encrypting and saving them again. Column-key wrapping is provisioning work, outside the normal exchange path.

### Unwrapping, derivation and value decryption are different stages

Unwrapping is decryption whose plaintext is another key. In this local provider, provisioning generates a random 32-byte column encryption key (CEK), encrypts it using the RSA master key's public component, and signs the wrapped-key metadata. SQL Server stores the wrapped CEK. The CEK is **not derived from the master key** or regenerated for each exchange.

On first use, the client verifies the wrapped metadata's signature and uses the private RSA master key to recover that same CEK. It then derives three working keys:

```text
AES key = HMAC-SHA-256(CEK, UTF-16LE(fixed encryption-key label))
MAC key = HMAC-SHA-256(CEK, UTF-16LE(fixed authentication-key label))
IV key  = HMAC-SHA-256(CEK, UTF-16LE(fixed IV-key label))
```

The fixed Microsoft labels include their distinct purpose, algorithm name and 256-bit length. Each output is 32 bytes. The labels are public constants. Three labeled outputs separate the roles without generating three unrelated random keys. The resulting working keys can be retained while the root CEK is erased.

For every non-NULL value, encryption uses AES-256-CBC with PKCS#7 padding, followed by an HMAC authentication tag. Deterministic encryption first derives the 16-byte IV from an HMAC of the plaintext using the IV key. Randomized encryption instead generates a random IV. Decryption verifies the tag before AES decryption and unpadding, using the IV carried in the ciphertext. Both forms have the same decryption path.

The earlier 0.267 ms "unwrap" measurement includes signature verification, RSA decryption, derivation and buffer cleanup. It is not a measurement of RSA alone. A separate measurement below isolates the three HMAC derivations.

## 2. Agreed direction and proposed policy details

The application chooses the reuse policy; transaction lifetime is the agreed default. Exchange scope and time-based reuse across transactions are available alternatives. The implemented `encryption::Policies` selects parsed-master and working-column lifetimes independently using `Policy::Exchange`, `Policy::Transaction` or `Policy::Time(Duration)`.

| Profile | Parsed private master key | Working column keys | Consequence |
|---|---|---|---|
| Strict exchange | Exchange | Exchange | Shortest reuse window. Repeat private-key load and column-key unwrap on each exchange that needs them. |
| Exchange column keys | Transaction | Exchange | Repeat column-key unwrap on each exchange; amortize private-key parsing across the transaction. |
| Transaction, agreed default | Transaction | Transaction | Load and unwrap on first use, then reuse until the transaction ends. |
| Time-based, explicit choice | Time(max_age) | Time(max_age) | Reuse across transactions and autocommit exchanges until a fixed per-key age limit, within the same connection and lease. |

Other combinations, such as exchange master keys with transaction working keys, are also coherent: discard the parsed master after the exchange that first derives working keys. Later exchanges reuse the working keys and reload the master only if another key needs it. The two settings should remain independent.

Without a live explicit transaction, `Transaction` falls back to `Exchange`. This includes ordinary autocommit work. The setting does not silently expand into connection-wide retention. An application needing a stricter boundary can select exchange lifetimes without changing its SQL transaction behavior.

A policy lifetime is a ceiling on reuse, not a requirement to retain every key. Proposed configurable limits are 32 distinct column-key entries and eight parsed master-key entries per window. Evict the least recently used idle entry, erasing it; a later use reloads it. These are provisional memory bounds, not measured workload requirements. A single exchange can use more distinct keys sequentially. Record evictions so their additional cost is visible.

Long transactions and slowly consumed streams retain keys longer. An application-selected maximum key age can force earlier erasure and reload; the transaction default has no age limit. A time limit does not make a still-open transaction short. No cache policy protects against an attacker who can already read the configured private-key file.

### Time-based handling: broader reuse, with a fixed maximum age

Use an absolute maximum age measured by a monotonic clock from acquisition of the secret material. Reuse does not restart the clock. This provides an upper bound on reusable secret age even under continuous traffic. Sliding idle expiry could otherwise keep a frequently used key indefinitely and is not the recommended initial interpretation.

The user selected the broader time-window interpretation, intended to permit more retention and save repeated setup. Transaction completion does not clear a valid time-owned entry. Autocommit exchanges can reuse it too. A duration is required when selecting `Time`; there is no implicit indefinite or sliding cache.

For example, a key acquired at 12:00 with `Time(60 seconds)` may serve several transactions on the same lease until 12:01. Reuse at 12:00:59 does not extend the deadline. Returning the lease at 12:00:20 clears it immediately. A value needed after expiry requires reload/unwrap, even if its transaction is still running. Long transactions continue under this policy; expiry does not abort them.

This is the option with broader retention authority, rather than an extra age cap on transaction scope. Actual exposure also depends on duration: a short time limit can expire before a long transaction ends. No policy permits reuse across pool borrowers, recovery epochs, reset, close, explicit invalidation or incompatible provider/context changes.

Expiry revokes reuse and triggers erasure of idle entries even if no further request arrives; checking age only on the next lookup is insufficient. A synchronous crypto operation already in progress finishes and drops its guard promptly. The next use reloads or unwraps the required key; it does not end the SQL transaction. Reject a nonpositive duration and fail clearly if acquisition cannot complete within the configured lifetime rather than retrying forever. Master-key and working-key clocks are independent; reloading a master does not refresh existing working-key deadlines.

Policy selection must not silently weaken another operation's policy. A strict exchange operation does not borrow a previously time-owned entry; it gets its own owner. Such an override does not erase time-owned entries retained for other operations. To tighten the whole lease's exposure, change its policy while idle and explicitly revoke the broader entries. Do not extend a live entry's deadline or ownership by mutating policy in place. Connection/lease defaults and per-exchange overrides are implemented by the SQL adapter in design O.

Keep parameter-description caching disabled initially. Describe each eligible parameterized call afresh, preserving the required encryption contract even for NULL parameters. Reusing keys does not automatically make a statement's description safe to reuse after schema or execution-context changes. A later metadata cache needs its own design and evidence.

## 3. Scenario: twenty exchanges in one transaction

Assume one physical connection, one exclusive application lease, one master key, and one column key used in each exchange.

1. The application begins a transaction. The driver observes the server's transaction descriptor and creates a local transaction generation. No key is loaded merely because a transaction began.
2. The first encrypted RPC obtains a fresh parameter description. A plain batch that only returns encrypted results instead gets key metadata in the result; it does not require a parameter-description RPC.
3. On the first non-NULL encrypted value, the provider reads the private PEM into owned, erasable storage. Decode into erasable DER storage, parse the native private-key object, and erase the input buffers after parsing, including failure paths.
4. Verify the wrapped key's signature, unwrap its 32-byte root into guarded storage, derive the three working keys, and erase the root immediately. Move ownership of the resulting handles into the chosen window; do not clone secret byte arrays between layers.
5. Normalize and encrypt input values, or authenticate and decrypt returned values. Borrow working-key handles only for the synchronous crypto operation. Do not hold a raw-key borrow across an async suspension. Backend contexts must also erase their owned copies on destruction.
6. At the end of each complete exchange, erase exchange-owned master/working keys. With the transaction profile, the transaction owner retains them for exchanges 2–20. RPC descriptions still occur independently.
7. An inner commit or rollback to a savepoint retains the transaction window. An outer commit or rollback ends it when the server confirms the end. Revoke lookup access, erase idle entries, and finish erasing active operation state as described below.
8. Release of the pool lease, session reset, recovery or physical close also revokes the owner. No later borrower or replacement connection inherits the keys. A new transaction starts a new generation even if a server descriptor is reused.

The transaction profile performs one master load and one column-key unwrap in this scenario. Strict exchange performs twenty of each. Both still encrypt/decrypt every protected non-NULL value.

## 4. Server state, concurrency and identity

Use decoded server transaction announcements, not matching `BEGIN` or `COMMIT` strings. The existing Rust session state tracks begin and end ENVCHANGE tokens. The implementation must cover T-SQL and transaction-manager requests, rollback after errors, chained transactions and reset. If a boundary cannot be established safely, use exchange-local keys rather than extending reuse.

| Event | Proposed behavior |
|---|---|
| Savepoint rollback or inner nested commit | Retain the outer transaction window. |
| Canceled exchange or failed commit | Do not assume rollback. Revoke the exchange owner and follow actual server transaction state. |
| Outer transaction end | Revoke transaction-owned reuse as soon as the end announcement is decoded. Valid time-owned entries survive within the same lease and context. |
| Database, provider configuration or security-context change | Partition or invalidate affected entries. Do not assume every T-SQL context change can be detected; full wrapped-key/provider identity is still required. |
| Recovery, reset, lease release or physical close | Retire all reuse authority, even when the server session or a handle survives. |
| Unread stream dropped | Revoke its exchange owner and follow the existing drain/discard connection contract. Retain transaction reuse only if session state remains authoritative. |

MARS permits interleaved batches. Channels may share the transaction window only when they belong to the same physical connection, lease and live transaction generation. They may share time-owned entries only within that connection/lease, policy owner and unexpired key identity. A channel never owns an application-global key cache. A transaction-scoped result already in progress when the transaction ends cannot keep or repopulate the retired transaction bank. If it later needs to decrypt another value, it may create an exchange-local entry from its pinned wrapped-key/provider metadata while its lease and connection epoch remain valid. Otherwise it fails with a context-expired error. This preserves streaming where the key context is still known and makes later key work visible in the counts.

Revocation prevents new reuse immediately. Erasure completes when active crypto operations release their handles. Keep these operations short; expose no public cloneable secret handles. A provider task already running in a blocking worker cannot always be canceled immediately. Its result must check the epoch, lease and generation before insertion; an obsolete result is erased. Own and drain pending work during shutdown rather than detaching secret-owning workers. Do not claim all key memory is gone at the instant a network transaction-end token arrives.

Lookup identity includes the connection epoch, lease, policy owner/generation, database context, exact wrapped-key evidence and selected provider binding/configuration generation, algorithm and key path. A transaction owner additionally includes its local transaction generation; a time owner deliberately does not partition by transaction and must check its fixed deadline. Exchange owners are isolated from both. A hash may index candidates, but exact identity must be checked. Database-local numeric key IDs alone are insufficient. The [synthetic Python reproduction](experiments/encryption-cache-identity.md) demonstrates that defect without claiming a live cross-server collision.

For a given parsed-master window, the provider binding and resolved key source are fixed. Replacing a private-key file in place is not an automatic notification. Existing handles remain usable until expiry or explicit invalidation; later loads read the replacement. Rotation and provider reconfiguration must invalidate or advance the binding generation. Never return a successful old cache entry for different wrapped-key evidence.

## 5. RAII and erasure contract

| Stage | Owner | Required erasure |
|---|---|---|
| PEM read / DER decode | Temporary provider input guards | On parse success, parse failure, cancellation or scope exit. Guard every allocated plaintext representation. |
| Parsed private master | Native handle owned by the selected master-key window | Explicit invalidation or expiry drops it; native destruction must cleanse private components and allocations before freeing. |
| Unwrapped root | Temporary guarded 32-byte allocation | Immediately after deriving working keys, or on any earlier failure. |
| Derived keys | Private, non-`Clone`, non-`Copy` window-owned key handle | Eviction, expiry, failure or owner destruction wipes all three keys. |
| AES/HMAC state and expanded schedules | Short-lived native crypto contexts | Backend cleanup must cleanse key copies, schedules and secret temporary state. |
| Late provider result | Tracked pending-operation owner | Erase if its originating authority was revoked; never reinsert into a retired window. |
| Decrypted application value | Response/application data owner | Separate from keys. The driver does not erase a returned value while the caller owns it. Temporary plaintext buffers should be guarded where practical. |

Use compiler-resistant zeroization and `Drop` as the fallback, with explicit clear/revoke operations at lifecycle boundaries. Allocate stable, pre-sized secret buffers and avoid reallocations or by-value secret copies. A wrapper around the original bytes does not erase copies made by parsers or crypto libraries. Exclude secret contents from `Debug`, errors, tracing, capture, serialization and panic messages.

`zeroize` provides compiler-resistant clearing and `Zeroizing` drops its wrapped value. Its documented limitations include old copies from moves/reallocations and register state. RAII also cannot promise cleanup after process abort, forced termination or deliberately leaked ownership. Memory locking, dump policy and swap protection are separate platform controls, outside this first contract.

### Backend evidence and ownership limits

The locally available candidate is `aws-lc-rs 1.18.2` / `aws-lc-sys 0.46.0`, already present through TLS. Inspecting the pinned source on 2026-10-18 found:

- Owned cipher-key `Buffer` storage calls `zeroize()` on drop. Cipher construction copies key bytes, so this backend cleanup matters.
- HMAC context cleanup calls `OPENSSL_cleanse`.
- HMAC derivation can write directly into guarded output using `sign_to_buffer`. Avoid the ordinary `sign` return type for secret derivation: its `Tag` is `Copy` and has no zeroizing destructor. Native private handles are also cloneable internally; the driver wrapper must not expose that ownership escape.
- Private-key ownership releases `EVP_PKEY`; RSA destruction releases its BIGNUM components. The default `OPENSSL_free` implementation cleanses its allocation before deallocation. Its custom allocator hooks take separate branches and cannot inherit that conclusion without inspection.

These observations support using a native backend with an audited destruction path. They do not prove every parser temporary, stack copy or error path is wiped. Before selecting the production APIs, inspect the full PEM/DER, RSA, AES and HMAC paths and test the wrapper's ownership/cleanup behavior. Pin the relevant versions/build configuration; repeat the review when it changes. Prefer using one existing crypto backend over implementing primitives in the driver.

The subsequent [implementation/evidence](experiments/encryption-policy-evidence.md)
traces the selected paths, including native RSA consistency checks and expanded
AES schedule destruction. Cache-owned native objects are boxed to avoid copies
from vector growth/compaction. Owned-buffer tests and native source review are
distinct forms of evidence; neither proves every compiler temporary is erased.

Python currently retains immutable `bytes` for root and working keys. Changing cache boundaries there will reduce retention but cannot honestly guarantee deterministic erasure of every copy. Apply the identity/lifetime correction in both clients; document the Python erasure limitation. Providing the same stronger guarantee in Python would require a separate native-owned secret API and is not silently included in this Rust slice.

## 6. Measured costs and limits

### Candidate Rust key work

An optimized [standalone Rust probe](../../tools/benchmark_rust_key_cost.rs) uses the cached `aws-lc-rs 1.18.2` and `zeroize 1.9.1` libraries, compiled with rustc 1.99.1 on this arm64 development machine. The [retained results](experiments/encryption-cost-rust-20261018.json) contain five-batch median wall times. An independent Python fixture generator creates a temporary synthetic RSA-2048 key and checks that all 96 derived working-key bytes match. No key or plaintext bytes are printed or retained in the results.

| Candidate operation | Wall time |
|---|---:|
| Parse a PKCS#8 DER private key through the backend API, then destroy it | 0.078 ms |
| Verify wrapped-key signature, unwrap, derive and erase; master already loaded | 0.267 ms |
| Warm DER-file read, parse, first unwrap/derive and cleanup | 0.465 ms |

These measurements include guarded root/working buffers and native object destruction. They exclude PEM decoding, SQL, network, value crypto, driver cache lookup and orchestration. They do not establish a completed backend erasure audit. The backend's additional `validate_rsa_key` routine checks key type and bit size; decoder checks and equivalence to Python's private-key validation still need review. Do not attribute the large parse-time difference solely to language speed, or assume identical validation policies. Production validation requirements must be settled before accepting its cost.

The probe also directly times the **key operations for twenty exchanges**, not twenty real SQL exchanges:

| Master / working-key lifetime | Loads | Unwraps | Measured key work over the twenty uses |
|---|---:|---:|---:|
| Exchange / exchange | 20 | 20 | **9.282 ms** |
| Transaction / exchange | 1 | 20 | **5.469 ms** |
| Transaction / transaction | 1 | 1 | **0.466 ms** |

Each case loads its own master from the warm DER file. The final case borrows the derived keys twenty times, then destroys them. The reduction is about **8.816 ms per transaction**, or **0.441 ms per exchange** averaged across twenty uses. No-cache key work is small for one low-rate exchange, but repeated work accumulates at higher rates. For 200 encrypted exchanges/s in groups of twenty, the measured profiles imply about **92.8 versus 4.7 ms/s of serial wall work**. These are elapsed-work estimates, not process-CPU utilization or measured driver throughput.

Freshly loaded RSA objects can have first-use work that a warmed object has already done. Use the directly measured profiles rather than assuming independent parse and warmed-unwrap medians add up exactly to a full path. Do not combine Rust key measurements with Python per-value measurements to claim Rust end-to-end latency.

### Materiality relative to actual value encryption

The extended probe measures both key setup and value work through the same candidate Rust backend. Its [additional retained run](experiments/encryption-values-rust-20261018.json) checks exact deterministic ciphertext equality with independent Python fixtures, decrypts both Python deterministic and randomized ciphertext, and rejects modified tags. No SQL round trip is involved.

| Operation | 64-byte plaintext | 1 KiB plaintext | 64 KiB plaintext |
|---|---:|---:|---:|
| Deterministic encryption + authentication | 0.365 µs | 1.626 µs | 84.869 µs |
| Randomized encryption + authentication | 1.764 µs | 2.717 µs | 66.734 µs |
| Authentication + decryption | 0.202 µs | 0.765 µs | 39.712 µs |

Master-already-loaded setup was **266.898 µs** in this run. The three HMAC derivations alone took **0.609 µs**, about **0.23%** of that setup. Preparing retained AES/HMAC value handles took another **0.666 µs** per key. Value timings assume those handles are already prepared; they include allocation, buffering, authentication and the appropriate IV work, and guarded plaintext-buffer cleanup. Random-IV acquisition costs more than deterministic IV derivation for the small values in this run; deterministic IV derivation also scans the entire plaintext, so randomized encryption becomes cheaper for the large values here.

One loaded-master setup therefore costs approximately as much as:

| Plaintext size | Deterministic value encryptions | Randomized value encryptions | Value decryptions |
|---|---:|---:|---:|
| 64 bytes | 731 | 151 | 1,321 |
| 1 KiB | 164 | 98 | 349 |
| 64 KiB | 3.1 | 4.0 | 6.7 |

These are ratios of measured median wall times, not universal algorithm constants. The private-key load is excluded from this ratio. Including a fresh warm DER master load raises setup to about 471 µs in this run.

For `N` protected values under one key, using loaded-master setup `S` and measured per-value cost `v`:

```text
key setup's share of crypto work = S / (S + N*v)
```

The denominator is measured key/value crypto work. It is not complete request latency or the difference from an unencrypted request.

| Protected 64-byte values per exchange | Deterministic encryption work | Setup share with one unwrap | Decryption work | Setup share with one unwrap |
|---|---:|---:|---:|---:|
| 10 | 0.00365 ms | 98.7% | 0.00202 ms | 99.2% |
| 1,000 | 0.365 ms | 42.2% | 0.202 ms | 56.9% |
| 10,000 | 3.650 ms | 6.8% | 2.020 ms | 11.7% |

For a result with 1,000 rows and three protected 64-byte columns sharing one key, value decryption is about **0.606 ms** and loaded-master setup adds **0.267 ms**, about **31% of the combined crypto work**. This can be significant within the encryption layer even though its absolute cost remains below one millisecond. A slow network/database request can hide that fraction in end-to-end latency; no live workload has yet measured it.

Transaction reuse pays setup once over all its values. At twenty exchanges of ten 64-byte deterministic input values, the measured key profiles plus the per-value component model give about **9.503 ms** with exchange lifetimes for both keys, **5.560 ms** with a transaction master and exchange working keys, and **0.538 ms** with both transaction-scoped. The value component is only `200 × 0.365 µs = 0.073 ms`; the profile difference dominates. These are composite estimates, not executed SQL timings; per-profile value-handle preparation adds about 0.0133/0.0133/0.0007 ms respectively and does not change the conclusion.

Thus repeated setup is proportionally material for small exchanges. For large values or many values per key, AES/HMAC processing takes a larger share. Reuse policy changes the frequency of setup; it never removes the per-value cost. Changes to transport size and parameter-description round trips are additional sources of overhead relative to plaintext SQL, outside these crypto ratios.

For example, the measured 64-byte plaintext produces a 129-byte encrypted value: one version byte, 32 tag bytes, 16 IV bytes and 80 padded ciphertext bytes. That approximately doubles the value bytes before TDS framing. This expansion is paid per value regardless of key reuse. It can be more important than sub-millisecond key setup when transporting large numbers of small fields; actual bandwidth and request-latency effects remain unmeasured.

### Existing Python baseline

The reproducible [Python benchmark](../../tools/benchmark_encryption_cost.py) uses temporary synthetic RSA-2048 keys, warm local files and the current Python implementation. There is no SQL Server or network work. The retained [aggregate results](experiments/encryption-cost-python-20261018.json) are medians of five batch means, on arm64 / Python 3.14.8 / cryptography 50.0.2. Key generation and wrapping are outside the timed loops. Provider timing includes reading the warm file; parse timing uses PEM already in memory. Do not predict Rust RSA cost from these measurements.

| Operation | Wall time per operation | Process CPU per operation |
|---|---:|---:|
| Parse/validate one RSA private key | 18.776 ms | 18.759 ms |
| Verify wrapped key, unwrap, derive working keys; master already parsed | 0.341 ms | 0.340 ms |
| Full existing local-provider path, including parse | 19.956 ms | 19.945 ms |
| Authenticate/decrypt one 64-byte value | 2.799 µs | 2.797 µs |
| Deterministically encrypt/authenticate one 64-byte value | 3.619 µs | 3.612 µs |
| Authenticate/decrypt one 1 KiB value | 3.320 µs | 3.312 µs |
| Deterministically encrypt/authenticate one 1 KiB value | 4.970 µs | 4.864 µs |
| Authenticate/decrypt one 64 KiB value | 38.353 µs | 38.294 µs |
| Deterministically encrypt/authenticate one 64 KiB value | 93.434 µs | 85.710 µs |

The full-provider measurement is independent; it need not equal the sum of two other medians. The 64 KiB encryption batches ranged from 80.983 to 142.890 µs wall time. These are local baselines, not latency distributions or cross-machine capacity guarantees. Value normalization, SQL execution, transport, orchestration and secure secret-storage overhead are not included in the Python primitive measurements.

A separate optimized [Rust buffer probe](../../tools/benchmark_key_zeroization.rs), using `zeroize 1.9.1`, measured allocation + initialization + zeroizing drop + free. Its [aggregate results](experiments/encryption-zeroization-20261018.json) were 37.794 ns for 32 bytes, 46.653 ns for 96 bytes and 505.377 ns for 2 KiB. This supports the narrow conclusion that clearing these small buffers is cheap on this machine. It does not measure native RSA-object cleanup or prove secure erasure throughout a crypto backend.

### Operation counts

Let `K(e)` be the set of distinct column-key identities actually used by non-NULL protected values in exchange `e`.

```text
U_exchange    = sum over exchanges of |K(e)|
U_transaction = sum over transactions of |union of K(e) in that transaction|
                + sum over exchanges outside transactions of |K(e)|
```

These are successful unwrap counts assuming no eviction, rotation, failures or concurrent duplicate loads. Count those extra attempts separately. Coalesce simultaneous first loads for the same identity within a window. Define master-load count `M` the same way, using distinct master bindings needed for those unwraps and the selected master lifetime. Reusing a working key does not require loading a master key at all.

| Workload | Exchange unwraps | Transaction unwraps |
|---|---:|---:|
| Twenty exchanges, same key in all twenty | 20 | 1 |
| Twenty exchanges, only three use the same encrypted key | 3 | 1 |
| Twenty exchanges use A; one also uses B | 21 | 2 |
| Ten exchanges each use a different key once | 10 | 10 |
| Twenty independent autocommit exchanges, same key | 20 | 20 |
| One exchange returns 3,000 non-NULL cells sharing one key | 1 | 1 |

### Time and capacity math

For value-size groups `b`, the component model is:

```text
client CPU = M * private_load_CPU
           + U * verify_unwrap_derive_CPU
           + sum_b(input_values[b] * encrypt_CPU[b])
           + sum_b(output_values[b] * decrypt_CPU[b])
           + allocation/erasure, metadata and orchestration CPU

extra serial describe wait = D * (network round trip + server describe time)
```

Use process-CPU measurements for aggregate capacity. Use wall times for a serial critical path, including its waits. Overlapped requests do not make CPU work disappear, and summed wall times are not an end-to-end latency prediction.

For comparison, using the **Python** component wall times for the twenty-exchange scenario:

| Master / working-key lifetime | Loads `M` | Unwraps `U` | Component key work over the transaction |
|---|---:|---:|---:|
| Exchange / exchange | 20 | 20 | `20 × (18.776069 + 0.340805)` = **382.337 ms** |
| Transaction / exchange | 1 | 20 | `18.776069 + 20 × 0.340805` = **25.592 ms** |
| Transaction / transaction | 1 | 1 | `18.776069 + 0.340805` = **19.117 ms** |

This model excludes the provider's other overhead. With the master already available, column-key work alone falls from **6.816 ms to 0.341 ms**, a 95% reduction. Choosing exchange-scoped column keys can therefore be affordable while retaining the master briefly, even when repeatedly loading the master is expensive. The exposure differs: a live private master can unwrap other column keys encrypted for it, so retaining it is a substantive choice.

At **200 encrypted exchanges/s**, one key per exchange, grouped into transactions of ten such exchanges using the same key, successful unwraps fall from **200/s to 20/s**. With already-parsed masters, the observed unwrap CPU is `200 × 0.340379 = 68.076 ms/s`, about **6.8% of one core**, versus **0.68%**. Repeating the full existing Python provider path instead costs `200 × 19.945333 = 3,989.067 ms CPU/s`, about **four cores** of aggregate demand. These are workload calculations from this Python baseline, not measured Rust throughput.

Returning 3,000 protected 64-byte cells adds `3,000 × 2.799 µs = 8.397 ms` of measured primitive decryption wall work under either policy. Larger values cost more. Key reuse removes repeated unwraps, not this per-value work.

Description latency can dominate independently. If twenty sequential calls each need a fresh description and the extra round trip plus server time is **assumed** to be 5 ms, the additional wait is **100 ms**, regardless of key lifetime. The 5 ms is illustrative, not measured. Record actual describe counts and durations before designing a metadata cache.

Key memory and exposure also differ. Three working keys require at least `96 × active distinct keys` bytes, excluding schedules, backend copies, metadata and allocator overhead. The proposed 32-entry bound gives 3,072 bytes of raw working secrets per window, plus those other allocations. A parsed private key needs more than its serialized RSA modulus size; measure it separately. Transaction reuse extends exposure from first use to transaction expiry; exchange reuse extends it from first use through the complete response stream.

## 7. Evidence required before calling this complete

1. Correctness: fixed normalization/cipher vectors and mutual .NET read/write, deterministic lookups, randomized values, NULL and tampered values. Authentication failure must expose no decrypted value.
2. Identity: the reproduced Python collision fails safely after the shared correction; different providers, wrapped values, databases, leases, rotations and recovery epochs never reuse the wrong handle.
3. Lifecycle: operation counts match the scenario table. Test savepoints, nested commits, server rollback, failed commit, autocommit, chained transactions, MARS interleaving, readers spanning transaction end, cancellation, pool release/reset/recovery and obsolete provider completions. For time policies, use a controlled monotonic clock to test the exact deadline, no refresh on hits, idle erasure, independent key ages, expiry during long streams/transactions, in-flight provider results and policy durations shorter than acquisition.
4. Erasure: instrument owned-buffer clearing before deallocation, including errors and eviction. Verify native cleanup paths and all backend copies by source/build review. Do not read freed memory in a test or claim a wrapper test proves register erasure.
5. Cost: extend the isolated Rust probe through the selected production APIs, including PEM, agreed private-key validation, value crypto, master destruction and secret buffers. Then measure complete SQL workloads with one/three/ten keys, 1/10/20 exchanges per transaction, 64-byte/1-KiB/64-KiB values, and both lifetime settings. Report throughput, CPU, p50/p95 latency, load/unwrap/describe counts, evictions and peak live key entries. Keep paths, values and key bytes out of observations.

Instrumentation should distinguish private loads, unwrap attempts/successes, coalesced loads, reuse hits, values/bytes processed, describes, evictions, revocations and pending cleanup. Driver durations are elapsed wall time; obtain process CPU in the benchmark rather than labeling elapsed time as CPU.

## 8. Agreement and remaining choices

The user agreed transaction scope as the default and application control over exchange or broader time-based handling across transactions (D-66). Independent settings, bounded entries, guarded buffers, idle expiry and the driver lifecycle link are implemented in [design N](N-encryption-policy-implementation.md). Python now also implements the agreed retention policies in its transparent SQL facade; see its [design/scenarios/evidence](experiments/python-encryption-retention.md). Python overwrites owned mutable key buffers but retains weaker guarantees for library/immutable copies. Transparent SQL encryption, fresh parameter-description orchestration and independent .NET interoperability are now accepted separately in design O. A stronger native Python secret API remains separate work. Validate the configurable bounds against the application workload.

After resolving the affected choices, implement and measure these contracts before opening the paid Windows lab window. Adjust cost expectations from actual Rust evidence rather than assuming Python's parse cost carries across.

## Sources

The local implementation evidence is in `clients/python/tds/encryption/{keys,cell,context,backend}.py`, `clients/rust/src/session.rs`, and the pinned crypto source named above. Reproduce the probes with:

```sh
clients/python/.venv/bin/python tools/benchmark_encryption_cost.py
# Select the zeroize rlib built for this checkout/toolchain; its hash is not fixed.
rustc -O --edition=2024 tools/benchmark_key_zeroization.rs \
  --extern zeroize=<release-deps/libzeroize-HASH.rlib> \
  -L dependency=clients/rust/target/release/deps \
  -o /private/tmp/tds-benchmark-key-zeroization
/private/tmp/tds-benchmark-key-zeroization
# Use the same release dependency directory and the matching aws-lc-rs rlib.
rustc -O --edition=2024 tools/benchmark_rust_key_cost.rs \
  --extern aws_lc_rs=<release-deps/libaws_lc_rs-HASH.rlib> \
  --extern zeroize=<release-deps/libzeroize-HASH.rlib> \
  -L dependency=clients/rust/target/release/deps \
  -o /private/tmp/tds-benchmark-rust-key-cost
clients/python/.venv/bin/python tools/benchmark_encryption_cost.py \
  --rust-probe /private/tmp/tds-benchmark-rust-key-cost
```

Primary references: [zeroize guarantees and limitations](https://docs.rs/zeroize/1.9.1/zeroize/), [aws-lc-rs private-key API](https://docs.rs/aws-lc-rs/1.18.2/aws_lc_rs/rsa/struct.PrivateDecryptingKey.html), [MARS transaction behavior](https://learn.microsoft.com/en-us/sql/relational-databases/native-client/features/using-multiple-active-result-sets-mars?view=sql-server-ver15), [rollback/savepoint and nested transaction semantics](https://learn.microsoft.com/en-us/sql/t-sql/language-elements/rollback-transaction-transact-sql?view=sql-server-ver17), and [SqlClient's separate key and metadata performance considerations](https://learn.microsoft.com/en-us/sql/connect/ado-net/sql/sqlclient-support-always-encrypted?view=sql-server-ver17#controlling-the-performance-impact-of-always-encrypted).

Key hierarchy, derivation and per-value algorithm reference: [Microsoft's Always Encrypted cryptography](https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/always-encrypted-cryptography?view=sql-server-ver17). This project's local provider uses its existing signed RSA-OAEP wrapped-key format; provider-specific OAEP parameters must not be inferred to be universal.
