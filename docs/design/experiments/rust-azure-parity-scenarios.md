# Rust/Python Azure parity: development test plan

**Where this sits:** the comparison contract for the
[full Azure integration plan](rust-azure-integration-plan.md).

**After reading this you can** trace Python's Azure behaviors to paired Rust
scenarios, select the appropriate comparison and identify what remains unproved
until the deferred Azure campaign.

Status: planned scenarios, not tests already implemented or passed. The owner
requires Python-guided full Azure integration, local comparison during
development, and actual Azure testing only after code completion.

## What counts as comparison

Run the same semantic inputs through Python and Rust using shared artificial
credentials, keys, metadata, clock values and scripted server/provider replies.
Keep each client's setup thin and use its public surface where possible. Prefer
reusing Python's current fixtures and tests over reimplementing the protocol in
the comparison harness.

Compare at four levels:

1. **Wire:** exact bytes for deterministic PRELOGIN/LOGIN7/FEDAUTH features,
   metadata and package layouts, including lengths, offsets and flag values.
2. **Cryptography:** Python wraps/encrypts and Rust unwraps/decrypts, then reverse
   the direction; cross-verify signatures. For randomized encryption and ECDH,
   compare decoded content and algebraic results, not incidental ciphertext.
   Fixed entropy/keys are allowed only in test fixtures, never as a production
   entropy downgrade.
3. **Behavior:** compare provider requests, accepted/refused authentication,
   negotiated capabilities, plaintext values, key authorization, invalidation,
   retry counts and physical connection reuse/discard decisions.
4. **Privacy and lifetime:** assert absence of secret markers in ordinary output,
   bounds on provider calls, cancellation authority, late-result disposal and
   permitted retained-key counts. Language runtime cleanup mechanisms can differ;
   state exactly what each test observes.

Normalize only irrelevant nondeterminism such as fixture host names, trace IDs,
wall-clock timestamps and deliberately generated random values. Never normalize
away audience, tenant/principal, nonce, key path/version, encryption algorithm,
statement hash, enclave counter, returned rows or failure stage. Do not require
identical exception wording when comparing failure categories and protected
causes, but preserve that distinction in the evidence. Potential diagnostic
disclosure belongs in the review backlog; static suspicion is not a confirmed
real-service defect or permission to change Python in this phase.

## Trace the whole existing Azure campaign

| Python source scenario | Rust parity requirement | Development comparison before Azure |
|---|---|---|
| `test_azure_live.py::test_an_entra_token_up_front` | Upfront token, fresh provider request per physical attempt and redirect | Controlled gateway/destination peers; compare token feature, nonce and route trace |
| `test_an_entra_token_fetched_mid_login` | FEDAUTHINFO resource/authority inputs and deferred token | Same server transcript and fake credential; compare callback request and FEDAUTH bytes |
| `test_a_sql_login_on_azure_sql` | Preserve SQL login baseline | Same controlled peer, negotiated capabilities and observed query result |
| `test_the_azure_only_features` | Same opt-in request bytes, acknowledgements and exposed context | Feed identical ACKs; distinguish advertised feature support from unimplemented service semantics |
| `test_ntlm_with_a_local_windows_account` | Preserve explicit local principal behavior | Existing Rust Windows-auth fixtures plus paired principal/scheme expectations |
| `test_ntlm_with_a_domain_account` | Preserve explicit domain principal behavior | Same identity and provider/server outcomes; no relabeling as Kerberos |
| `test_a_wrong_windows_password_is_refused` | Matching refusal category/stage, no SQL | Script the refusal; compare connection retirement and zero application requests |
| `test_the_browser` | Same instance/port discovery | Paired UDP fixture; compare selected instance and port |
| `test_always_encrypted_with_a_key_vault_master_key` | Vault envelope, remote operations and transparent encrypted values | Fake vault plus shared RSA key; bidirectional envelopes/value encryption and controlled SQL metadata |
| `test_always_encrypted_with_an_enclave` | Explicit `none` mode, session/packages, signed key authorization and encrypted LIKE/range inputs | Python enclave primitives and scripted metadata/SQL peers; live LIKE/range execution itself stays unproved |
| `test_kerberos_azure.py::test_kerberos_with_the_tickets_user` | Use the existing ticket-cache identity, not a substituted explicit password | Controlled cache/provider fixture; preserve principal/service and failure classification |
| `test_negotiate_chooses_kerberos` | Negotiate selects Kerberos with the available ticket | Same supported credential context and scheme expectations; refuse forbidden fallback |
| `test_certstore_windows.py::test_always_encrypted_with_a_certificate_store_master_key` | Native non-exportable key operations and transparent encryption | Shared provider vectors; platform-gated Windows certificate/native-handle tests when a local environment exists |

The unqualified names in the first column refer to `test_azure_live.py` until a
new file is named. Inventory the supporting adapter/provider APIs too: these 13
integration tests are the starting coverage, not proof that every API edge is
already tested in Python.

## Additional paired scenarios

| ID | Scenario and comparison |
|---|---|
| A01 | Upfront and deferred tokens: same workflow, echo/nonce, UTF-16 encoding and feature ACK; no SQL/Windows fallback |
| A02 | Token callback per initial/routed/recovery attempt; credential source may return a valid cached token; compare provider calls separately from actual OAuth requests |
| A03 | Generic application credentials and SDK adapters: same resource-to-scope conversion and credential selection; inventory Python-supported credential modes and record SDK gaps rather than silently omitting them |
| A04 | Missing/duplicate/overlapping/truncated FEDAUTHINFO fields, invalid UTF-16 and unexpected ordering: compare actual outcomes and bounds; backlog discrepancies and required service tests without presuming stricter Rust rejection is a Python correction |
| A05 | Provider refusal, empty/oversized/known-expired token, no expiry metadata, timeout and late completion: compare failure stage, cleanup, deadline and absence of application SQL |
| A06 | Route identity/TLS failure, repeated redirect, changed/unchanged configuration and closed pool: compare retry budget, token requests, physical candidates and no stale-session installation |
| A07 | Capture, full inspection, Debug and provider-error paths: artificial bearer/token/key markers absent; safe replay retains negotiation but cannot reconstruct omitted authentication |
| K01 | Vault provider/path/algorithm and wrapped-key envelope: cross-wrap/unwrap, lowercase encoded path behavior, length fields, RSA-OAEP and RS256 verification |
| K02 | Master-key metadata signature: Python signs/Rust verifies and reverse; changing provider/path/enclave permission refuses verification |
| K03 | Vault operation recording: same key/version and algorithm, verify before unwrap, signature refusal prevents key use; no private-key export |
| K04 | Denied/missing/version-changed key, wrong algorithm, malformed envelope/signature, timeout and canceled late unwrap: fail without retaining usable unauthorized material or leaking provider secrets |
| K05 | Local/vault/certificate providers under transaction/exchange/fixed-age policies: compare values and logical unwrap counts, fixed-age non-renewal, capacity, pool return/reset/recovery/close revocation |
| C01 | Certificate location/store/thumbprint resolution and wrong/missing certificate: equivalent lookup/operation outcomes; native private key remains non-exportable |
| C02 | Certificate wrap/unwrap and metadata signatures: mutual vectors where supported; native handles retire on success, refusal and cancellation; platform runtime evidence separately identified |
| E01 | `none` attestation parameters: protocol 2, empty input and P-384 public-key blob match Python's fixture layout; unsupported modes refused |
| E02 | Session establishment: matching shared-secret-derived session key, handle and initial counter; malformed blob/curve/length/truncation refused |
| E03 | Package content: GUID layout, advancing counter, UTF-16 statement hash, database/version/key identifiers and exact authorized column keys; mutual decrypt under fixed test keys |
| E04 | Wrong session/statement/key metadata, tampered package, counter exhaustion and concurrent requests: no counter reuse or cross-session key authority |
| E05 | `sp_describe_parameter_encryption`: same version-two metadata, attestation parameter, third result set, requested-key selection and CMK signature validation |
| E06 | Batch/RPC enclave package placement and encrypted parameter/value results: compare deterministic layouts and randomized decoded content across supported transports |
| E07 | Invalid enclave authorization signature prevents sending a key; ordinary AE remains usable without silently granting enclave permission |
| E08 | Stale metadata/session errors: compare invalidation, new description/session and exactly which bounded operation Python retries; no broad application SQL replay |
| E09 | Pool return/reset, recovery, endpoint/identity changes and close: compare authority revocation; review Python's shared session cache before choosing a Rust scope |
| W01 | Ticket-cache Kerberos/Negotiate: principal/service, expired or absent ticket, KDC/provider timeout, no hidden explicit-password substitute and no forbidden NTLM fallback |

Start enclave fixture work from
`test_encryption.py::test_an_enclave_session_and_package` and
`test_a_master_key_signs_whether_its_keys_may_go_to_an_enclave`. Reuse Python's
local crypto and metadata APIs as an independent implementation for Key Vault
and certificate operation vectors, with fake service transport where necessary.

## Evidence and completion rules

For each case record the scenario ID, Python/Rust commit plus dirty-source hashes,
fixture hash, relevant features/platform, comparison level, expected/actual
outcome and exit code. Retain finite redacted summaries in the repository;
credentials, real tokens, raw sensitive artifacts and Terraform state stay out.

Classify discrepancies by observed evidence: Rust mismatch with the Python
baseline, suspected Python weakness, proposed language/API difference,
dependency/platform gap, fixture error or unresolved. Record confidence and what
would distinguish the competing explanations. A local comparison can demonstrate
a mismatch; it cannot alone establish that Rust's alternative is the correct
service behavior. Matching both clients likewise does not prove compatibility.

Suspected Python weaknesses go to the
[review backlog](python-azure-review-backlog.md), not into Python production fixes
or unannounced Rust policy changes. Keep proposed remedies unverified until the
later actual Azure/native campaign can test their compatibility and consequences.
Compare with the specification and a Microsoft client where useful, and seek
agreement on significant behavioral differences. Rust memory safety/ownership
constraints remain explicit; do not mislabel them as proof of a Python defect.

Full-scope code completion requires the complete capability inventory and paired
scenarios implemented/passing, or specific owner-agreed exceptions. A skipped
Windows runtime test is not a passing native-provider check; preserve that as
pending platform acceptance while distinguishing implemented code from runtime
evidence. No Azure-hosted resource or real Azure request is needed to run the
development comparisons.

## Deferred actual Azure acceptance

After code completion, run both clients against the same transient fixture and
compare actual principal, selected authentication scheme, redirect destination,
feature ACKs, values, permission failures and cleanup. Include:

- Both Entra flows and the agreed credential-source environments.
- Key Vault requests and mutual encrypted read/write, including metadata signatures.
- The enclave fixture's expected rows: `A%` returns Ada/Alan; salary above 50000
  returns Alan/Grace, under explicit no-attestation mode.
- Non-exportable Windows certificate keys and ticket-cache Kerberos/Negotiate.
- Existing Windows logins, Browser, pools/recovery and key-retention integration.

Use a Microsoft client for independent interoperability checks, especially for
cryptography and disagreements. Resource selection, access, budget and Terraform
setup/teardown are a later campaign decision. Development evidence alone must
never be labeled successful live Azure acceptance.
