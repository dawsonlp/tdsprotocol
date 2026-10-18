# O · Rust Transparent Always Encrypted

**Where this sits:** Extends [the key-service design](N-encryption-policy-implementation.md) into the local SQL acceptance scope in D-65.

**After reading this you can** follow the wire/value/key ownership boundaries, use the implemented adapter and reproduce its finite acceptance scenarios.

Intent: complete the agreed local-key Rust encryption scope using the same SQL
value meanings and retention policies as Python, with independent interoperability
evidence. Windows authentication remains a separate lab acceptance campaign.

## Representation and ownership

- A declared SQL type describes the application value. Wire `TypeInfo` separately
  carries optional crypto metadata: ciphertext framing, original type, algorithm,
  normalization version, and the complete wrapped column-key identity.
- Without a crypto adapter, encrypted values are explicitly marked ciphertext.
  No ciphertext is presented as an ordinary application binary value.
- The protocol core owns negotiation, framing and raw observations. The optional
  encryption adapter owns normalization, parameter discovery and value crypto.
  Crypto work uses the existing tracked workers and zeroizing key service.
- One application exchange owns its guard, including parameter discovery and
  response consumption. Transaction, exchange and fixed-age policy semantics
  remain those agreed in D-66. A failure must not silently replay application SQL.
- Authenticated ciphertext is collected before releasing any plaintext. Encrypted
  large values are bounded by the crypto service's 16 MiB limit.

## Acceptance scenarios

1. Feature version one is requested and acknowledged; unsupported/downgraded
   negotiation fails before encrypted application SQL is sent.
2. Key tables and encrypted column/output metadata decode under every input
   split; invalid ordinals, counts and ciphertext framing fail explicitly.
3. Every supported scalar normalizes to SqlClient-compatible bytes, including
   integer widening, decimal(38,s), temporal scale seven and fixed padding.
   Values outside their declared range/scale fail before send.
4. Rust writes deterministic/randomized/NULL values; .NET reads them. .NET writes
   values; Rust reads them. Include Unicode, binary, decimal, temporal, integer,
   money and floating-point cases and encrypted output parameters.
5. Raw reading returns marked ciphertext. Like Python, per-cell authentication,
   missing-key and normalization failures return an explicit `NotDecrypted` value
   and preserve stream readability. Revoked session/exchange authority fails the
   exchange. Wrong keys/tampering never yield
   plaintext. Private-key and decrypted-value buffers do not cross into protocol diagnostics.
   Ordinary unencrypted SQL/parameters follow the existing capture policy.
6. Repeated values demonstrate retention counts at exchange/transaction/age
   boundaries. Long transactions remain usable after idle expiry (reacquisition).
7. Cancellation/drop/SQL errors/pool return/context changes revoke ownership;
   connection reuse obeys existing drain/reset rules. Discovery failure sends no
   application request. No SQL is replayed automatically after uncertain errors.
8. Default, encryption-enabled and no-default-feature builds, meaningful unit
   and live suites, formatting, Clippy and rustdoc pass. Record exact commands,
   versions and limitations in acceptance evidence.

## Implementation order

Wire vocabulary and negotiation; normalization; explicit encrypted RPC metadata;
composed encrypted channel/response API; live independent interoperability;
readiness and documentation. Then prepare/deploy the transient GCP lab once its
project, budget and lifetime are supplied, validate Windows authentication, export
evidence and destroy all lab resources.

## Implemented API and limits

`Connection::encrypted(providers, policies)` checks version-one agreement, attaches
one service for the physical epoch/lease and completes a bootstrap exchange
before any key preparation. Its channels expose `execute(sql, declarations,
named_params)`, `execute_with`, `exchange`, `exchange_with` and owned-row `bulk`.
SQL `EXEC` supports explicit stored-procedure statements. Parameter discovery is
fresh for each execute: there is no stale-plan cache and no automatic replay.
A discovery error is labelled application-SQL `NotSent` even if discovery itself
reached the server. Bulk returned result sets also cross the adapter's
authentication boundary.

A response owns its guard through discovery/input crypto and output consumption,
including fetched bulk returns. It offers `next`, `fetch`, `finish`, `snapshot`,
timing, cancellation and awaited close. Retained rows are independent application
values. `finish` skips decryption of discarded rows while preserving outputs;
it does not invent a need to load a private key for discarded data.

`TypeInfo.sql_type` preserves ciphertext framing; `value_type()` gives the
application type. `Value::Encrypted` and `Value::NotDecrypted` make raw and failed
values explicit. Captures/replay remain raw, without a key provider. The wire
vocabulary is available even with the crypto Cargo feature disabled.

Owned scalar/max values and owned bulk rows are supported. Encryption source
producers and borrowed plaintext chunk readers are not provided. Each encrypted
value has a 16 MiB operation bound; max-valued rows collect/authenticate one cell
at a time before emitting it. The adapter closes before pool release; after
physical recovery callers attach a fresh adapter. `invalidate_keys()` handles
application-controlled provider/master-file/security changes that SQL does not
announce. Returned application values retain the ordinary Rust value API's
memory ownership; only crypto secret/work allocations promise erasure on Drop.

See [retained acceptance evidence](experiments/rust-transparent-encryption.md).
