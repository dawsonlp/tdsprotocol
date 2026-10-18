# Always Encrypted cache identity: synthetic reproduction

Observed 2026-10-18 during preparation for Rust local-key Always Encrypted.
This is an isolated cache-lookup experiment, not a live SQL Server or RSA test.

## Observation

Python `Encryption` can open/wrap more than one connection and retains decrypted
column keys for its own lifetime. `cell_key()` indexes its cache by database id,
key id, key version and metadata version. It does not include a server identity,
provider identity or the encrypted key entries in that lookup.

The probe constructs two artificial key tables with the same four identifiers
but different synthetic key values. A synthetic provider returns those values
directly so the test isolates cache behavior. It prints only booleans/counts.

```sh
clients/python/.venv/bin/python tools/probe_encryption_cache_identity.py
```

Observed output on the existing Python source:

```json
{
  "different_key_table_returned_same_cached_object": true,
  "provider_lookups_for_two_tables": 1,
  "second_result_matches_independent_second_key": false
}
```

Thus a different key table can receive the already cached key without consulting
its provider. This establishes an in-process lookup collision. It does not claim
that two independent live servers were provisioned with colliding metadata or
that a deployed application experienced it.

Source review also finds describe-plan lookup keyed only by statement and
declarations. A database/security/schema context is not part of that key. That
is a separate scope concern; no live describe-plan collision is claimed here.

## Decision needed before the encryption port

The existing shared design D-60 gives the encryption context long-lived keys and
describe plans. Copying that lifetime and cache identity into Rust would preserve
the defect. Changing those semantics requires agreement for both clients.

Initial recommendation, before the user's transaction-lifetime discussion:
share configured key providers and the crypto
backend, but retain decrypted keys only within an exchange and describe each
parameterized operation afresh. Do not retain cross-exchange key/describe caches.
Owned decrypted application values remain application data; they are distinct
from retained key material. A future cache would need its own bounded identity,
invalidation and secret-lifetime contract. The cost is repeated key-provider work
and describe exchanges.

Alternative: design bounded shared caches now, explicitly accounting for server,
database and execution context, exact key-table/provider identity, session reset,
configuration changes, schema changes and metadata invalidation. This preserves
the opportunity to reuse work but expands the architecture and its acceptance
requirements before the first Rust encryption implementation.

The subsequent [lifetime and cost proposal](../M-rust-encryption-lifetimes.md)
recommends configurable transaction/exchange lifetimes with exact identity,
RAII erasure and independent master-key policy. It supersedes the recommendation
above, not this reproduction's evidence. It remains a proposal.

The original recommendation and result above are historical. D-66 subsequently
agreed transaction defaults with exchange and broader time-based options.
The Rust policy/local-crypto foundation and lifecycle adapter are implemented in
[design N](../N-encryption-policy-implementation.md); transparent encrypted SQL
wire support remains separate work.

The Python identity correction now compares the full wrapped-key/provider
evidence and retires entries on provider/backend object replacement. Re-running
the same probe produces `false`, `2`, `true` for the three fields shown above:
the second table gets its own correct key. Two independent Python regressions
also cover cache hits and deliberately unhashable provider replacements. This
does not claim Python has Rust's new policy lifetimes or erasure guarantees.
