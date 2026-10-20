# Rust Azure key providers and enclave ownership: approved contract

**Where this sits:** the approved key-provider and enclave boundaries after the approved authentication slice.

**After reading this you can** understand the agreed opaque key capabilities, async acquisition and session ownership.

Status: approved by the owner on 2026-10-19; implementation and development
verification are in progress. Authentication's public contract was approved
separately. This contract covers the next significant boundary in the
[Azure plan](rust-azure-integration-plan.md). Approval is not Azure/native
interoperability acceptance.

## Intent and observed constraints

Use local RSA, Azure Key Vault and non-exportable Windows certificate keys for
the same transparent SQL behavior and retention policies. A master-key reference
is not private key material. Preserve provider-specific envelopes, signature
checks, operation ordering and exact normalized plaintext. Match Python's
explicit `none` enclave mode and authorized-key release; no new attestation mode.

Before this change Rust `KeySession` accepted `Vec<LocalKeyStore>`, caches private local `Master`
objects and `Cell` keys, and runs acquisition/crypto in a counted blocking worker
under a serial async gate. Cancellation drops the reply receiver; bank checks
prevent a late load from installing revoked material. That baseline could not await
a remote provider. Extending the local private `Master` to contain a vault key
would conflate different capabilities.

Python's public key stores wrap/unwrap column keys and sign/verify master-key
metadata. Key Vault verifies the envelope before unwrap and keeps the private
key in the service. Certificate-store operations use native handles.

## Agreed operations and ownership

Introduce a named async provider that opens an opaque master-key capability:

```rust,ignore
trait KeyProvider: Send + Sync {
    fn name(&self) -> &str;
    fn open<'a>(&'a self, path: &'a str, operation: KeyOperation) -> KeyFuture<'a, Arc<dyn MasterKey>>;
}
trait MasterKey: Send + Sync {
    fn wrap<'a>(&'a self, column_key: &'a Plaintext, operation: KeyOperation) -> KeyFuture<'a, Vec<u8>>;
    fn unwrap<'a>(&'a self, evidence: &'a WrappedKey, operation: KeyOperation) -> KeyFuture<'a, Plaintext>;
    fn sign_metadata(&self, enclaves: bool, operation: KeyOperation) -> KeyFuture<'_, Vec<u8>>;
    fn verify_metadata<'a>(&'a self, enclaves: bool, signature: &'a [u8], operation: KeyOperation)
        -> KeyFuture<'a, bool>;
}
```

The handle binds its provider and exact path/version. Local handles own the
loaded private key; vault handles own a remote key reference/client; native
handles own a non-exportable OS key. Remote `unwrap` returns only the owned
column-key bytes. The provider retains its envelope parsing and verify-before-
unwrap ordering. Errors expose categories and deliberate protected causes.
`Plaintext` owns erasing buffers. The facade releases keys to an enclave only
after the matching master-key authorization signature verifies.

`KeyOperation` counts native/local blocking work and exposes `drain` for standalone canceled operations. The session controller owns cancellation and the finite budget.

Keep the existing local-key constructor as an adapter. Add a mixed-provider
constructor accepting named providers, rejecting duplicate names as today.
An application's fixed provider binding belongs to its service owner; cache
identity includes the provider binding and complete wrapped-key evidence.

Move acquisition coordination into an async controller under the current serial
gate. Hold no bank lock across provider I/O or crypto. Local/native blocking
operations retain counted worker ownership and late-result cleanup; remote SDK
operations are awaited directly. Do not run async provider futures through
`Handle::block_on` inside a blocking worker. Keep synchronous value crypto on
the existing bounded worker path.

At every await/result installation, recheck epoch, lease, exchange/transaction,
revocation, fixed-age deadline and receiver authority. Preserve separate master
and column policies, fixed-age non-renewal, capacity and idle expiry. Cached
master entries now hold opaque capabilities, not necessarily private keys.
Dropping a caller must not leave a reusable late key. Any ongoing native call
owns its eventual handle/buffer cleanup and cannot authorize later SQL.
Define a finite provider-operation timeout in the mixed-provider constructor;
its exact value is a documented option rather than an HTTP SDK retry default.
SDK internal retries consume this same outer budget; no driver-level replay of
application SQL is introduced.

For Key Vault, use the official pinned Rust key client and an explicitly bound
credential. Preserve Python's requested key URL/version and lowercase envelope
path encoding. Add no domain/tenant allowlist by assumption. Record logical
provider and physical SDK operation counts separately. Native Windows code stays
in a companion crate so the main crate retains `forbid(unsafe_code)`.

Alternative: introduce a separate remote-only key service and keep the present
local `KeySession` untouched. It reduces the initial refactor, but duplicates
retention/revocation machinery and complicates statements that reference keys
from more than one provider. The common capability boundary is recommended.

## Agreed enclave session scope and current Python evidence

One enclave session/key/counter belongs to the encrypted facade for one physical
epoch/lease. Channels on that facade share the session and use a serial package
counter; pool return/reset, recovery, close and security-context invalidation
retire it. A session is never transferred to another identity or physical epoch.
Counter exhaustion refuses an operation before reuse. Keep statement/key binding,
explicit no-attestation trust, and Python's bounded metadata/session retry rules.

The first source inventory saw `Encryption._sessions` keyed by server. Inspection
of `EncryptedConnection.__init__` also shows a per-wrapper copy with fresh
`_plans`/`_sessions`; `_clear_metadata` closes session keys and `_lifecycle` clears
them on relevant transitions. Therefore the server-keyed dictionary alone does
not establish a server-global session-sharing defect. The proposed owner aligns
with this connection-wrapper boundary. Test concrete reuse/reset/recovery cases
before claiming complete parity or identifying a remaining Python weakness.

Alternatives are sharing sessions across physical connections or making every
SQL exchange establish a new session. Neither is required by the observed
wrapper design; both change lifetime/reuse behavior and would need evidence.

## Evidence before acceptance

Cross-wrap/unwrap and cross-sign/verify using Python and fixed public test keys;
record fake-vault arguments and verify-before-unwrap; test denials, cancellation,
timeouts, revocation and operation counts under every existing retention policy.
Compare enclave P-384 blobs/shared secrets and mutually decrypted packages with
Python; test authorization refusal, counters, statement binding and session
invalidation through controlled SQL metadata. Native execution and actual Azure
interop follow code completion and remain separate acceptance gates.
