# Encryption lifetime scenarios

**Where this sits:** The executable acceptance plan for [D-66's key policies](../M-rust-encryption-lifetimes.md), before transparent Always Encrypted wire/orchestration support.

**After reading this you can** distinguish tested key-policy behavior from future SQL encryption integration and reproduce each named scenario.

> KP01–KP24 were written before implementation, 2026-10-18. KP25–KP30 extend the plan during review/driver integration. Tests use real RSA-wrapped synthetic column keys and actual authenticated value encryption where applicable. No production keys, cloud resources or paid services are needed. Synthetic controller events are not SQL Server evidence. See the [retained results](encryption-policy-evidence.md).

## Scope and intent

Implement the reusable Rust key-policy and local cryptographic foundation. Applications choose transaction (default), exchange or fixed-age time reuse. Parsed master and working column keys have independent settings. A session owns keys; an exchange guard holds authority, never raw key bytes. An idle timer erases expired entries. The later SQL facade must supply server-confirmed transaction/context events and own exchange guards for response lifetimes. This acceptance campaign does not claim that facade or transparent SQL Always Encrypted exists.

## Scenarios and observable outcomes

| ID | Scenario | Required evidence |
|---|---|---|
| KP01 | Twenty exchanges in one transaction, one key, default policies | One master load and one unwrap; twenty successful value round trips. |
| KP02 | Exchange policies for both key classes | Twenty loads/unwraps; no cached secrets after each guard ends. |
| KP03 | Transaction master, exchange column keys | One load, twenty unwraps. |
| KP04 | Exchange master, transaction column keys | One initial load/unwrap; master erased after first exchange while derived keys remain usable. |
| KP05 | Default policy outside explicit transactions | No cross-exchange reuse; twenty loads/unwraps. |
| KP06 | Savepoint rollback / inner commit represented by an unchanged server transaction | Retain entries; outer end clears transaction-owned secrets. |
| KP07 | Transaction descriptor reused after end; end immediately followed by begin | New local generation; old entries cannot be selected. |
| KP08 | Time policy across multiple transactions/autocommit exchanges | Reuse within one session; commit does not clear time-owned entries. |
| KP09 | Exact fixed deadline and a hit just before it | Reuse before deadline; miss at deadline; hits never extend expiry. |
| KP10 | Idle time expiry | Timer clears entries with no subsequent encryption/decryption call. |
| KP11 | Long transaction / response stream spans time expiry | Later value reloads and succeeds; expiry does not end the transaction. |
| KP12 | Separate master/working ages | Expiring or reloading one does not restart the other's deadline. |
| KP13 | Reset, recovery, pool return, close and explicit invalidation | Revocation clears entries; retired exchange guards cannot repopulate them. New sessions never inherit secrets. |
| KP14 | Same database-local numeric IDs, different wrapped values/provider binding | Distinct keys yield correct independent ciphertext; no lookup collision. |
| KP15 | Bounded entries and eviction | Evicted keys are erased; later use reloads; correctness survives more keys than the capacity. |
| KP16 | Multiple concurrent first uses of one key | Coalesce successful load/unwrap; no duplicate cache insertion. |
| KP17 | Request canceled while provider load is running | No late insertion into canceled exchange; tracked work finishes with owned secrets dropped. |
| KP18 | Transaction/session authority revoked during provider load | Late result rejected and erased; new transaction/epoch unaffected. |
| KP19 | Provider failure, malformed/wrongly signed wrapped key, missing/replaced master file | Clear error, no success cache entry, retry only on explicit later use. |
| KP20 | Time expires during acquisition, zero/unrepresentable duration | No stale result inserted; no retry loop; invalid configuration refused. |
| KP21 | Cipher compatibility and authentication | Exact deterministic ciphertext/working keys match independent Python fixtures; randomized round trips work; tampered tag/version/padding/layout fail without plaintext. |
| KP22 | Secret ownership and diagnostics | Owned root/derived/input buffers are zero before deallocation; Debug/errors contain no secret values. No raw-key public clone/serialization surface. Native destruction is separately source-reviewed. |
| KP23 | Strict exchange overrides a broader default | Uses its own scope; no borrowing of time-owned entries. Tightening the entire session explicitly clears broader entries. |
| KP24 | Drop and awaited shutdown | Drop revokes cached authority; awaited close waits for tracked provider work; no detached task retains a successful secret result. |
| KP25 | Runtime destroyed while a session handle survives | Timer-task destruction revokes the bank and clears retained keys; moving the session out of its runtime cannot bypass expiry cleanup. |
| KP26 | Actual driver lifecycle link against local SQL Server | Across 7.4/8.0 × plain/MARS: decoded outer begin/commit/rollback clear transaction entries, savepoints retain them, time entries survive commit, pool return and physical close revoke. This tests real boundaries with manual byte crypto; it does not claim transparent encrypted SQL metadata or .NET interoperability. |
| KP27 | Provider/input hardening | Inconsistent RSA CRT parameters, oversized PEM, every truncated wrapped-key prefix, invalid root length, absolute/symlink path escapes, duplicate provider names and zero capacity are refused. |
| KP28 | Actual physical recovery with a controlled TLS peer | Across 7.4/8.0 × plain/MARS: disconnect clears old bank; authenticated recovery succeeds; old guard fails and a newly attached service loads independently. Peer evidence is not SQL Server recovery evidence. |
| KP29 | Ciphertext size boundary after PKCS#7 removal | A valid authenticated ciphertext within the wire-size cap whose plaintext exceeds the operation limit is refused. |
| KP30 | Native key storage survives cache growth/compaction without copying schedules | Prepared AES/HMAC objects live in stable boxed allocations. Cache growth and eviction move pointers only; a live object's address remains unchanged across capacity growth. This avoids old heap copies without claiming to inspect compiler temporaries. |

## Evidence boundaries

Controlled monotonic clocks establish exact deadline behavior. A Tokio timer test separately proves idle expiry. Counters establish loads, unwraps, hits, evictions and live entries. Test-only destructor instrumentation reads live allocations after zeroing and before deallocation; it never reads freed memory. Native backend destruction, stack/register copies, process abort, swap and memory dumps are not proved by that instrumentation.

Future integration must repeat relevant scenarios through decoded SQL transaction announcements, MARS, pooled connection reuse/reset/recovery, encrypted RPC/result metadata, normalization and independent .NET read/write. A passing foundation test must never be reported as that integration evidence.
