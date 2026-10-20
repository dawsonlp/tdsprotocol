# Rust Azure key-provider and enclave development evidence

**Where this sits:** implementation of the owner-approved [key-provider/enclave contract](rust-azure-key-provider-contract.md), after the [authentication slice](rust-azure-authentication-evidence.md).

**After reading this you can** distinguish implemented behavior, paired development checks, native compilation and the still-deferred live acceptance campaign.

Development branch: `rust-azure-integration`, based on `f45aa43`, committed in
`6270814`. The owner approved the common async provider boundary and
facade/physical-epoch enclave ownership on 2026-10-19. This slice is not itself
the full-scope checkpoint; that is the [code-complete checkpoint](rust-azure-code-complete.md).
The [ticket-cache provider](rust-azure-ticket-cache-contract.md) and
[feature policy](rust-azure-feature-probe-contract.md) were later approved and implemented.

## Implemented behavior

- `KeyProvider` opens an opaque `MasterKey`; async wrap, unwrap and metadata
  sign/verify preserve provider-owned private keys. Local RSA remains an adapter
  of the same service. Unicode provider/algorithm comparison follows Python.
- An async controller coordinates acquisition under the existing serial gate.
  Bank locks cover authority/cache changes, not provider I/O or value crypto.
  Exchange/transaction/fixed-age policies, separate master/column capacities,
  fixed-age non-renewal and idle expiry remain. A finite total operation budget
  includes queueing and SDK retries. The mixed constructor takes it explicitly;
  the legacy local constructor uses 30 seconds.
- `KeyOperation` counts blocking work. Canceling a caller drops remote futures;
  a running local/native call owns cleanup and rejected output. Revocation
  prevents later insertion, and awaited close drains the controller/workers.
  Standalone callers can drain their context after cancellation.
- Optional `azure-keyvault` pins official Keys 1.0.1, Core/Identity 1.0.0. Private
  vault keys stay remote. RSA-OAEP SHA-1 wrapping, RS256 signing and metadata
  signatures match Python's envelope construction and verify-before-unwrap
  order, including exact requested versions and lowercase embedded paths.
  Protected provider causes do not appear in ordinary Debug/Display.
- Optional `certificate-store` implements Python's certificate path/provider
  name, RSA envelope and metadata operations. A companion crate owns Windows
  store/context/private-key handles. Public operations use certificate RSA;
  private operations use silent CNG acquisition without private-key export.
  Main driver Rust remains safe. Non-Windows execution reports unavailability.
- Explicit `EnclaveAttestation::None` requests version two. P-384 blobs,
  SHA-256 shared-secret derivation, session handles, UUID/counter/statement/key
  package layout and randomized cell encryption match Python. This mode trusts
  the server; no attestation signature is verified. Other modes are absent.
- The transparent facade reads the third description result, sends
  `varbinary(116)` attestation input and requires signed master authorization
  before releasing each requested column key. Only enclave-enabled cells retain
  raw roots, under their column policy. One facade owns the session/counter for
  its physical epoch/lease; context transitions retire it. Each version-two
  batch/call has the Python-compatible u16 package slot, including empty slots.
- Stale enclave refusals retry only when the first record is error 206, 33514 or
  33195: fully drain, forget the session, describe again and submit once more.
  Second refusals are returned. Successful statements and arbitrary errors are
  not replayed. Plaintext remains on the facade side of raw capture/replay.

`Statistics` counts logical loads/unwraps, metadata verifications, authorized
keys and generated packages. SDK challenges/retries are physical operations;
transport hooks can observe those independently. SDK credential/request/response
buffers and native-library allocations are outside driver-owned buffer-erasure
instrumentation.

## Verified checkpoint — 2026-10-19

Rust 1.99.1 on macOS ARM64: core-only **102 passed**, default **231 passed / 57
ignored**, and final all-features **289 passed / 62 ignored**. Ignored cases need
Docker, Windows or other explicit environments; they did not run. Final strict
Clippy across all targets/features, strict rustdoc, formatting and the Windows
companion cross-target Clippy check passed. The compiled Azure encrypted example
is included in all-target checks. Development source/command evidence is retained
in [the check report](rust-azure-key-enclave-checks.json); its final paired snapshot
includes the source-stability check. Default/core runs preceded the final
encryption-only review; the final all-feature run and affected core wire vectors
cover that review and the version-two size-bound correction.

## Development comparisons

The finite runner is `python3 tools/check_rust_azure.py`. It checks saved Python
fixtures without regenerating their random values, runs Rust tests, then uses
Python's production providers/session cipher to read Rust exports. Exact current
source/dependency hashes and command outcomes are retained in the accompanying
check report after the final run; logs remain in its temporary evidence folder.

| Evidence | What is established |
|---|---|
| Existing 28 encryption-policy tests | Original local behavior, coalescing, independent clocks, expiry, capacity, cancellation, revocation and owned-buffer audits remain |
| Seven async-provider tests | Mixed fallback/coalescing, nine retention combinations, timeout, invalidation, cancellation, local wrap/sign operations and standalone late-worker cleanup |
| Two official Key Vault SDK tests | Authentication challenge and scope, exact key/version/algorithm/JSON arguments, operation order, envelope/signature comparisons, denial and protected diagnostics; physical requests counted separately |
| Python reads Rust exports | Mutual local/vault envelope and metadata verification; Python decrypts Rust's random enclave package and checks its statement/key/counter content |
| Enclave primitive/wire tests | Fixed P-384 agreement, Python package authentication, advancing counter, UUID layout, statement binding, malformed/truncated data, tampering, exhaustion, batch/RPC framing and inspection |
| Three controlled TLS enclave tests | Authorized transparent execution and encrypted parameters, shared counter/recreation, refusal before SQL for unsigned keys, exactly bounded stale-refusal retry |
| Lifecycle unit test | Session ownership retires on pool return, recovery, close, reset, database/collation change and explicit invalidation |
| Authority/age review regressions | Queued acquisition keeps its original transaction scope; collecting other enclave keys cannot extend an earlier column key's fixed-age deadline |
| Four SDK credential tests | Scope/expiry boundary, service-principal tenant/form/cache, CLI tenant/scope invocation, and owned subprocess termination/reaping after cancellation |
| Windows companion cross-check/strict Clippy | Native Windows FFI code compiles for `x86_64-pc-windows-gnu`; this is not CNG runtime execution |

The ignored `certstore_native` test is prepared for later Windows acceptance.
Set `TDS_CERTSTORE_TEST_KEY_PATH` to a dedicated non-exportable CNG RSA fixture
and `TDS_CERTSTORE_TEST_PYTHON` to Python with the repository's encryption
dependencies, then explicitly run that test with `--ignored`. It mutually
wraps/unwraps and signs/verifies through the production Python and Rust providers,
and refuses tampering. It provisions or deletes no certificate. The fixture's
non-exportable configuration must be established by the later lab setup; this
test was compiled but not executed here.

The controlled SQL peer does not execute LIKE/range queries or run protected
enclave memory. The fake vault is not an Azure vault. Public disposable keys and
tokens are test inputs, never deployment credentials.

## Remaining gates

Complete the two pending provider/feature decisions, their implementation and
remaining cross-feature/adversarial comparisons before claiming full-scope code
completion. Native CNG handle behavior and non-exportable keys require Windows
runtime evidence. Managed/workload identity and actual Azure authentication,
Key Vault, routing, enclave computation and campaign interoperability remain
later acceptance gates. No cloud resources were provisioned.

Python production behavior and the independently added enclave-completion
backlog were not changed. Its broader attestation/completion work stays outside
this activity.
