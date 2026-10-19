# Rust Azure integration: development plan

**Where this sits:** follows the Rust client merged into `main` through PR #1
(`f45aa43`). Development branch: `rust-azure-integration`, created 2026-10-19.
This opens a new phase; it does not retroactively expand D-65's completion scope.

**After reading this you can** identify the Python behavior to preserve, the
proposed Rust boundaries, the implementation iterations and the later live
acceptance campaign.

**Status:** the owner confirmed full Python Azure-integration parity as the goal;
the authentication contract has been approved and its implementation is in
progress. Key-provider/enclave architecture is approved and in development. No resource
provisioning has started. Actual Azure testing and
its infrastructure are deferred until code completion.
Unit, fixture and controlled-peer tests belong to development; Azure deployment
and live interoperability acceptance follow code completion.

## Development checkpoint — 2026-10-19

The owner approved the [concrete authentication contract](rust-azure-authentication-contract.md).
The branch implements the unified SQL/Windows/Entra selection, async provider
boundary, both federated paths, masking/replay missing-evidence handling and an
optional official SDK adapter. The finite [paired runner](../../../tools/check_rust_azure.py)
checks Python-generated wire/decoding vectors and controlled TLS peers. This is
an initial authentication slice, not completion of iterations 1–5: remaining
negotiation, cross-feature/adversarial/provider-environment cases stay explicit.
The [key-provider/enclave contract](rust-azure-key-provider-contract.md) is approved.
Async opaque providers, Key Vault, the native certificate boundary and transparent
version-two enclave execution now have development implementation. Full Azure parity, native
runtime acceptance and actual Azure testing remain open.

## Vision and agreed scope

Enable the **full set of Azure integration behaviors already implemented in the
Python client** in Rust. Python is the guide for behavior, wire formats and
scenarios; comparison with Python is the primary development test method. This
includes both Entra login paths and credential adapters, Azure SQL routing and
feature negotiation, Azure Key Vault key operations and transparent encryption,
and Python's supported enclave operation. Include the Windows certificate-store
provider and ticket-cache Kerberos paths exercised by Python's Azure campaign;
retain its existing Windows login and Browser behaviors as regressions.

Entra, Key Vault, certificate-store and enclave work are required parts of this
branch's goal, not optional follow-ons. They may be implemented in dependency
order; completing login alone does not reach code completion for this phase.

The parity boundary is actual Python functionality, not every feature offered by
Azure. Python implements only explicit `enclave_attestation="none"`; it rejects
Microsoft Azure Attestation and HGS modes. Rust must match that capability and
its explicit trust assumption, without calling it an attested session. Existing
Extended Protection and portable NTLM dependency limitations are unchanged.

The protocol core implements TDS, credential providers obtain OAuth tokens, key
providers perform key operations and the encryption facade orchestrates encrypted
SQL. Token refresh must never replay application SQL or change an active identity.

## Observed Python guide and Rust gaps

| Concern | Python guide | Current Rust / proposed work |
|---|---|---|
| Token before login | `tds/logins.py`: `EntraToken`, `fed_auth_feature`; `connection/core.py` | Add a federated LOGIN7 feature distinct from SQL/Windows credentials, with PRELOGIN negotiation and required nonce handling |
| Token during login | `EntraLogin`, `Workflow`, `fed_auth_token`; `tokens.py`: `FEDAUTHINFO` | Add bounded FEDAUTHINFO decoding, explicit token request/supply and packet type 0x08; current Rust handles SSPI, not this exchange |
| Credential adapter | `tds/adapters/entra.py`: token/fetch adapters over sync or async Azure credentials | Optional adapter over the official Rust SDK credential abstraction; no OAuth implementation in the protocol core |
| Routing | `test_azure_live.py`: both Entra paths and redirect assertions | Reuse Rust's one-hop route handling and absolute opening deadline; obtain a token for every new physical attempt |
| Azure feature negotiation | `login7.py`: Azure SQL support, DNS caching, enhanced routing and global-transaction flags | Explicit request/acknowledgement support after reviewing each feature's actual obligations; an ACK does not implement DNS caching or distributed transactions |
| Capture/replay | `capture.py`, `test_logins.py`: upfront and deferred tokens masked | Extend existing Rust masking to new token paths, safe typed metadata and replay without authenticating from omitted bytes |
| Key Vault | `encryption/keyvault.py`, `test_azure_live.py` | Required: add remote wrap/unwrap/sign/verify and master-key metadata operations without exporting the private key; generalize the local-only provider boundary |
| Windows certificate store | `encryption/certstore.py`, `test_certstore_windows.py` | Required companion parity: certificate/key-path resolution, non-exportable native-key operations and owned-handle cleanup |
| Enclaves | `encryption/enclave.py`, `context.py`, `test_encryption.py`, Azure enclave scenario | Required: version-two negotiation, P-384 exchange, session key, counters, key authorization, enclave packages and transparent call orchestration; explicit `none` attestation only |
| Linux ticket identity | `test_kerberos_azure.py`, `infra/azure/kerberos.sh` | Approved optional system GSSAPI now consumes native cached credentials; actual Azure identity/auth-scheme acceptance remains pending |
| Windows/Browser baseline | `test_azure_live.py`: local/domain NTLM, bad password and Browser | Preserve implemented Rust behavior and compare outcomes with Python; Azure hosting alone does not require a new authentication method |

Use `clients/python/tests/test_logins.py` for deterministic wire examples and
`test_azure_live.py` for the future independent behavioral comparisons. Python's
Azure SDK credential selection is not a requirement to duplicate class names or
implement every credential flow in the driver.

## Evidence rule for this phase — agreed 2026-10-19

Python has been tested against real services; the new Rust Azure work will not
yet have that evidence. Preserve Python's observed behavior as the baseline.
Static inspection, a model or a controlled test may identify a concern, but does
not establish that a proposed change is correct against Azure.

Put suspected Python weaknesses in the
[review backlog](python-azure-review-backlog.md), recording the observed code,
hypothesis, possible impact and later real-service comparison needed to decide
it. Do not change Python production behavior during this phase. Do not silently
turn a suggested Python correction into a new Rust compatibility policy either.
Rust memory safety and explicit ownership remain requirements; distinguish those
implementation constraints from proposed changes to accepted input or behavior.

For example, the FEDAUTHINFO helper uses slicing and replacement decoding, generic
token errors include exception text, and enclave sessions are cached by server.
Those are observations; service impact and the suitability of stricter parsing,
different error reporting or narrower session reuse remain hypotheses. The
previously reproduced Python Kerberos deadline defect is separately backlogged;
it does not validate every proposed Azure callback change.

## Concepts and ownership before the API

| Concept | Meaning and owner |
|---|---|
| Authentication selection | Exactly one SQL, Windows or Entra mode for an opening; conflicting credentials are refused before transmission |
| Credential source | Application/SDK object that may cache and renew OAuth tokens; distinct from a particular token and physical connection |
| Token request | Audience/resource, login workflow and validated authority hints for one physical opening attempt |
| Access token | Opaque bearer secret with optional provider-supplied expiry metadata; not parsed as a JWT to invent identity or expiry |
| Identity configuration | Comparable tenant/principal/credential-source identity and relevant options; runtime credential objects and bearer-token bytes are not compared as configuration |
| Physical attempt | One verified TCP/TLS login, including a routed or recovery login; an abandoned attempt cannot install a late result |
| Accepted SQL session | Server authentication and login completion have succeeded; token expiry alone is not evidence that the current SQL transaction failed |
| Key provider | Named local, vault or certificate-store capability; a remote/native private key remains with its provider |
| Wrapped column key | Provider/path/algorithm plus versioned envelope and signature; distinct from the plaintext column key retained under the chosen policy |
| Enclave session | Explicit mode, endpoint/session identity, owned session key and monotonic package counter; not a server-global cache |
| Enclave package | Statement-bound encrypted payload containing authorized column keys and session ordering evidence |
| Saved evidence | Non-secret negotiation, ordering and lengths; omitted token/key bytes remain missing evidence in offline replay |

The sans-I/O core owns encoding, parsing, negotiation and state transitions. The
async shell owns token-provider invocation, deadlines, cancellation and connection
installation. The credential library owns OAuth acquisition and its cache. Pool
configuration owns identity changes and stale-session retirement. Azure control
plane operations and test resources remain outside the client.

## Decisions to settle before affected implementation

1. **Public authentication representation.** Recommend a single explicit login
   selection with SQL, Windows and the two Entra variants, preserving existing
   constructors where practical. Compare this with an additive Entra option;
   avoid independently selectable fields that admit contradictory states.
2. **Token/provider and SDK boundary.** Recommend an SDK-independent async token
   provider contract, plus optional official Azure Identity integration. Keep
   runtime providers in services and comparable identity settings in snapshots.
   Define owned secret/expiry types, cancellation and error contracts before code.
3. **Audience and authority representation.** Preserve Python's provider inputs
   and its adapter behavior: the adapter uses the resource for a scope and does
   not use the supplied STS URL to choose its authority. Represent configured
   tenant/authority explicitly. Additional validation/restriction policies remain
   proposals needing compatibility evidence and agreement, not assumed fixes.
4. **Key-provider representation.** Define common operations with local, remote
   and native implementations while retaining existing policy, capacity and
   revocation contracts. Do not model a vault key as a local private `Master`.
5. **Enclave ownership.** Agree session/counter identity, concurrency, invalidation
   and authorized-key release. Compare Python's session caching with Rust's
   physical connection/lease boundaries. Backlog suspected weaknesses and the
   service tests needed to decide them; do not label another scope a correction
   before that evidence exists.

Scope and decisions 1–5 above are agreed. The [system ticket-cache
provider](rust-azure-ticket-cache-contract.md) is now also approved and implemented
behind the existing authentication context. The [unsupported-feature policy](rust-azure-feature-probe-contract.md) is also
owner-approved and implemented: explicit unsupported requests warn; enabled
ACKs fail opening before SQL or pool admission, without automatic downgrade.
Python's correction remains backlogged as PY-AZ-06.
Scope and the above decisions are agreed; additional operational capabilities
need their own requirements and acceptance.

## Iterations to code completion

Each numbered item is approximately one development iteration; split it if its
observed complexity warrants it. No cloud resources are needed for these steps.

1. **Establish the complete parity inventory, harness and contracts.** Review the above decisions and
   map Python examples to Rust types, ownership and error behavior. Review/pin
   candidate SDK dependencies, features, platform support and async/process
   behavior. Map every Python Azure test and adapter/provider capability to Rust
   work and comparison evidence. Build a small paired-runner/fixture format, not
   a new general testing framework. Exit: agreed API sketches, traceable parity
   cases and an executable comparison path.
2. **Implement federated wire definitions and upfront-token login.** Add typed
   PRELOGIN federated negotiation/nonce evidence, FEDAUTH LOGIN7 encoding,
   acknowledgement validation and explicit incompatible-option checks. Validate
   lengths before allocation and use zeroizing driver-owned secret buffers.
   Match Python's deterministic wire fixtures. Exit: controlled TDS 7.4/8.0
   login success/refusal, fragmentation, nonce and malformed-input cases.
3. **Implement server-directed token acquisition.** Decode FEDAUTHINFO and its
   bounded UTF-16 fields, validate the request, invoke the token provider and send
   the FEDAUTH message. Enforce legal message ordering, finite rounds and explicit
   completion. Exit: both login paths work against controlled peers, including
   late/duplicate/malformed requests, provider refusal, timeout and cancellation.
4. **Integrate Azure Identity, routing, pools and recovery.** Add the optional
   official SDK adapter and documented application-provider examples. Exercise
   Azure CLI and service-principal credential shapes with controlled fakes;
   list managed/workload identity as SDK credential paths whose environment
   acceptance comes later. Route/recovery/new pool openings ask the credential
   source again; it may return a still-valid cached token. Bound any opening retry
   and configuration reread under the original deadline, with no SQL replay.
   Exit: slow/canceled/expired providers, identity changes, routed TLS refusal,
   recovery refusal and late results leave no reusable partial connection.
5. **Complete feature negotiation, diagnostics and user entry points.** Add only
   Azure feature flags whose handling has been reviewed, preserving non-default
   opt-in behavior. Reject capabilities whose ACK would require missing runtime
   behavior. Extend CLI/examples, field inspection and cross-language replay.
   Exit: bearer tokens, authentication headers and provider exception secrets are
   absent from ordinary Debug/errors/captures/inspection, including malformed
   messages and provider failures; no token command-line arguments are required.
6. **Generalize key-provider ownership without regressing local keys.** Introduce
   the agreed local/remote/native operation boundary. Preserve transaction,
   exchange and fixed-age policies, separate master/column settings, bounded
   capacity, revocation, deadlines and late-result cleanup. Compare local-key
   behavior with Python before adding provider-specific implementations.
7. **Implement Azure Key Vault integration.** Match Python's wrapped-column-key
   layout, provider/path handling, RSA-OAEP operations, signature verification and
   master-key metadata signing/verification. Compare using recorded mock vault
   requests and shared test keys; cross-wrap/unwrap in both directions. Check
   denials, key versions, malformed envelopes, cancellation and operation counts.
8. **Implement Windows certificate-store parity.** Match Python's provider name,
   certificate paths, wrapping/unwrapping and metadata signatures through native
   key handles. Keep private keys non-exportable and handle retirement explicit.
   Compare through controlled provider fixtures; separate native runtime evidence
   from cross-compilation when Windows is unavailable during development.
9. **Implement enclave session/package primitives.** Match Python's explicit
   `none` mode, negotiation, P-384 public blobs/shared-secret derivation, session
   handle, statement hash, package counter and encrypted key payload. Use fixed
   test inputs for layout comparisons and mutual decrypt/verify checks for random
   cryptography. Reject unsupported attestation modes rather than downgrading.
10. **Integrate enclave operations into transparent SQL.** Match Python's
    parameter-description call, third-result-set session information, enclave
    column/key metadata, signed master-key authorization and batch/RPC package
    insertion. Compare cache invalidation and session recreation after errors,
    and SQL retry behavior with `context.py`; never add arbitrary SQL replay.
    Exercise local, Key Vault and certificate-backed metadata operations through
    the common provider contract.
11. **Close the campaign's ticket-cache and cross-feature parity.** Add the
    supported ticket-cache Kerberos/Negotiate path needed by Python's Azure runner
    scenarios, with a provider/dependency decision if the current library cannot
    supply it. Exercise identity changes, routing/recovery, pools, MARS and key
    policies across the completed features. Existing explicit/native Windows
    logins and Browser remain regressions. Report unsupported SDK credential modes
    as unresolved parity work, not silently deferred capabilities.
12. **Review and establish the full-scope code-complete checkpoint.** Run supported core,
   default/all-feature and optional-adapter checks, strict Clippy, formatting,
   rustdoc/examples and meaningful regression coverage. Update the support matrix
   and record exact source/dependency hashes. Review remaining limitations and
   prepare the live acceptance scenarios. Exit: every in-scope Python Azure
   behavior is implemented with paired development evidence, or an explicit
   owner-agreed exception. Azure interoperability is still unproven; missing cloud
   access is not a reason to call unfinished implementation code complete.

## Scenario evidence required during development

| Group | Minimum scenarios |
|---|---|
| Wire parity | Upfront and deferred tokens, UTF-16 lengths, workflow values, FEDAUTH echo/nonce handling, acknowledgement; byte comparisons with Python fixtures |
| Parsing and ordering | Every fragmentation boundary; truncated/overflowing/overlapping fields; duplicate/missing SPN/STS data; unexpected FEDAUTHINFO/LOGINACK/DONE; excessive token/message sizes and rounds |
| Provider behavior | Async success/refusal, empty/oversized token, known-expired token, expiry absent, slow acquisition, caller cancellation, late result and sanitized errors |
| Identity and routing | Token requested for every physical attempt; wrong route certificate; repeated route refusal; configured identity change retires stale pool sessions; no SQL or Windows fallback |
| Pool/recovery | Original opening budget, changed/unchanged credential-source outcomes, capacity restored after failure, closed-pool late completion, fresh recovery token and no application replay |
| Privacy/lifetime | Upfront/deferred/canceled token copies absent from ordinary output; driver-owned secret disposal; explicit limits on SDK/OS-managed copies; safe replay preserves missing-evidence distinctions |
| Vault/certificate providers | Cross-language envelope, unwrap and signature checks; remote operation arguments/counts; non-exportable key/handle ownership; wrong algorithm/path/key/signature; denial, timeout, cancellation and revoked result |
| Enclave cryptography | Protocol/curve/blob agreement, mutual shared-secret derivation, handle/counter/statement/key bindings, malformed fields, counter overflow and package tampering |
| Enclave SQL integration | Version-two negotiation, description metadata and session creation, CMK authorization refusal, needed-key selection, package framing, stale metadata/session invalidation and bounded documented retry behavior |
| Ticket identity | Ticket-cache principal and service identity, Kerberos-required refusal without fallback, Negotiate result classification and expired/missing ticket behavior |
| Regression | Existing SQL/Windows authentication, MARS, local-key AE and its retention policies, cancellation/cleanup, configuration and recovery |

The [paired scenario plan](rust-azure-parity-scenarios.md) defines comparison
levels, normalization rules, evidence records and the source-test inventory.
Use deterministic peers/fakes to prove the client contract. SDK credential paths
that compile with a fake are not described as working against Entra. Access-token
renewal and Always Encrypted key-retention policies are separate mechanisms.

## After code completion: set up Azure testing

Only after the code-complete review, agree tenant/subscription access, identities,
region, budget and deletion deadline, then design the smallest transient fixture.
Use the historical `infra/azure/` as a scenario guide. Plan the resources needed
for Azure SQL, Key Vault, VBS enclave behavior, Windows certificate keys and the
ticket-cache/domain scenarios, reusing shared fixtures where possible. Review
current Terraform, secrets and teardown behavior before reuse. Do not recreate GCP.

The later campaign should independently compare Python, Rust and an established
Microsoft client against Azure SQL: both Entra paths, SQL-login baseline,
actual principal/database, gateway redirect with verified destination TLS,
TDS/MARS combinations offered by that service, configured identity/token refusal,
pool/recovery/lifecycle behavior and reviewed opt-in feature acknowledgements.
Add paired Python/Rust encrypted read/write and provider operation checks against
Key Vault; non-exportable certificate-store keys on Windows; enclave LIKE/range
results matching the Python fixture; and ticket-cache Kerberos/Negotiate with
the same principal/service. Use a Microsoft client as an independent tie-breaker
when Python and Rust disagree or share an assumption.
Managed identity requires a suitable hosted identity environment; a CLI login
does not validate it. Provider-specific claims need their actual environment.

Retain the fixture through result review, fixes and retesting, then preserve
redacted evidence and verify full teardown. **Code complete** and **live accepted**
are separate checkpoints; neither means a crate has been published.

## Required provider/enclave integration boundaries

First propose an async remote/native key-store boundary that can coexist
with local-key providers while retaining the existing transaction/exchange/time
policies, capacity, cancellation and revocation rules. Do not force remote
operations through a local `Master` abstraction or download a vault private key.

Python guides the `AZURE_KEY_VAULT` identity and wrapped-column-key format,
RSA-OAEP wrapping/unwrapping, signature verification and master-key metadata.
Agree permitted key URLs/versions, credential-service binding, remote retry and
deadline policy, and cost counters. Verify malformed envelope/path/signature and
late-result behavior locally; require independent Python/.NET encrypted-value
interoperability and retained remote-operation counts in a later live campaign.
Enclave metadata helpers alone do not establish enclave operation. Session
establishment, transparent packages, permission checks and invalidation are also
required. The only attestation mode required here is Python's explicit `none`;
MAA/HGS implementation would be new scope beyond Python parity.
Fuller attestation and enclave behavior beyond Python's current implementation
remain separate future work, outside implementation for this phase.

## Sources checked 2026-10-19

The source inventory above is from this repository. External API/protocol
references are evidence for implementation planning, not live acceptance:

- [MS-TDS FEDAUTHINFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/0e4486d6-d407-4962-9803-0c1a4d4d87ce)
  and [federated token message](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/827d9632-2957-4d54-b9ea-384530ae79d0).
- [Microsoft Rust authentication overview](https://learn.microsoft.com/en-us/azure/developer/rust/sdk/authentication/overview)
  and [official Azure Identity Rust API](https://docs.rs/azure_identity/latest/azure_identity/).
  The reviewed API lists Azure CLI, service-principal, managed-identity and
  workload-identity credentials. Dependency versions/features remain subject to
  iteration 1's source review; Python's credential class names are not assumed.
