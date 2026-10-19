# Development plan: corrections following the GCP authentication campaign

**Where this sits:** follows the [Windows campaign](../P-windows-authentication-campaign.md),
[runtime evidence](rust-gcp-authentication-evidence.md) and
[cross-client findings](rust-python-authentication-limitations.md).

**After reading this you can** distinguish confirmed defects from remaining
acceptance work, implement the corrections in bounded iterations and identify
the public API decisions needed before coding those changes.

Status: approved and in progress, recorded 2026-10-19 UTC. The
[follow-up evidence](gcp-authentication-follow-up-evidence.md) distinguishes
implemented corrections, tested scenarios and the remaining API/worker decisions.
No dependency fork or upstream issue submission is part of this execution.

## Vision and scope

Deliver Python and Rust clients whose supported Windows logins complete and
validate authentication before granting SQL access, keep authentication material
out of ordinary diagnostics, and handle credential changes without replaying
application work. Prove the supported behavior against the Windows fixture, then
close the transient campaign with retained evidence and verified cleanup.

The owner chose to document the dependency limitations rather than maintain
forks/patch sets or introduce TLS backends. **Extended Protection implementation
and dependency-owned secret-erasure changes are excluded from these iterations.**
The [provider review](rust-authentication-provider-review.md) records those limits.
[rustls #995](https://github.com/rustls/rustls/issues/995) is an existing closed
request; the [rustls follow-up](upstream-rustls-channel-binding.md) and
[sspi cleanup report](upstream-sspi-ntlm-zeroization.md) remain unsubmitted drafts.
No verified upstream ticket is recorded for the sspi erasure finding.

Entra, new key providers, new TLS stacks and new convenience/application-driver
features remain outside this correction plan. Always Encrypted retention policy
is unchanged; its tests are regression checks for authentication integration.

## Concepts and ownership

| Concept | Required meaning |
|---|---|
| Opening operation | One requested connection acquisition under one absolute deadline, including configuration reads and any permitted retry |
| Physical opening attempt | One new TCP/TLS connection and its authentication; a permitted retry creates a different connection and security context |
| Security context | One provider-owned authentication exchange for one opening attempt; completion is explicit and a new attempt gets a fresh context |
| Server acceptance | LOGINACK establishes server acceptance; it does not substitute for provider validation of the final token |
| Credential snapshot | Comparable application-owned settings; a failed login may trigger one fresh read, without changing an active borrower's identity |
| Pool lease | Exclusive borrower authority; no failed/late opening or previous lease can install or operate the replacement connection |
| Saved evidence | Redacted packets and safe typed records; absent token bytes are unavailable evidence and cannot be reconstructed by replay |

The protocol core owns token sequencing and limits. The provider owns NTLM/
Kerberos validation and completion. The async shell owns I/O, deadlines and
late-result cleanup. Configuration owns selection of current credentials; the
pool owns retry and session installation. No layer retries application SQL.

## Iteration 1 — protect Python authentication diagnostics

Priority: required security correction. The confirmed default-capture retention
of incoming authentication tokens is independent of the deferred dependency work.

- Add failing regressions using artificial token markers for incoming SSPI in
  standalone, fragmented and coalesced SSPI/LOGINACK replies.
- Redact incoming authentication payloads in default captures and full live/
  replay inspection, including raw bytes, child fields and malformed-input
  diagnostics. Preserve safe token types, lengths, ordering and useful errors.
- Preserve compatibility with older captures. Redacted exchanges must report
  missing authentication evidence rather than decode zeros as genuine tokens.
  Review the existing explicit secret-capture option; ordinary capture remains
  safe by default and this iteration adds no new secret-recording option.
- Use the same scenarios to check Rust masking and replay for regressions.

Exit evidence: artificial tokens are absent from default JSON capture, decoded
packet bodies, full inspection and diagnostic text across the tested paths;
legitimate non-secret login records remain usable. Outgoing SQL/Windows/Entra
credential masking and capture-failure cleanup still pass their existing tests.

Targets: Python `capture.py`, `tokens.py`, `connection/core.py`, inspection/replay
and their tests; Rust authentication/capture/replay regression tests.

## Iteration 2 — complete and bound Python provider exchanges

Priority: required authentication correctness. Use the existing loopback TLS
fixture to reproduce skipped final SSPI and accepted early LOGINACK first.

- Define an explicit provider-completion contract. Adapt pyspnego's completion
  state; do not infer completion merely from a nonempty or empty output token.
- Process a final SSPI token even when it shares a response with LOGINACK. Make
  provider failure or incomplete state refuse the connection before SQL access.
- Distinguish a final server token requiring no response from a continuation
  requiring an outgoing token; do not send an authentication packet after the
  server has already completed the login.
- Add token-size and round bounds. Start from Rust's 48 KiB token and eight-step
  limits, define exactly which provider calls count, and test the same boundary
  semantics in both clients. Enforce bounds before unbounded accumulation or
  provider invocation. The limits are driver policy, not TDS maxima.
- Keep all awaited work under the original opening deadline. Fresh opens,
  routing and recovery must create fresh provider contexts.

Exit evidence: valid final-token handling succeeds; invalid final tokens,
premature LOGINACK, missing completion, excess rounds, oversized/truncated input,
provider exceptions and delayed/canceled operations fail without installing a
session or sending SQL. Boundary-valid fragmented tokens still succeed.

**Design checkpoint before implementation:** agree the compatibility behavior for
application-written `SecurityProvider`/`SecurityExchange` adapters that currently
have no completion contract. The proposed direction is explicit completion with
clear migration guidance and early refusal of unsupported adapters, rather than
silently treating them as complete. Approval of this plan does not silently
settle that public API behavior.

Synchronous provider calls currently run inline. Evaluate their scheduling and
cancellation separately: an asyncio timeout cannot preempt a blocking call.
If worker isolation is needed, specify serialization, retained context ownership
and late-result cleanup before changing it. Do not claim forced cancellation of
an operating-system provider call.

## Iteration 3 — refresh Python SQL credentials on pool opening refusal

Priority: required behavior parity within the existing SQL configuration model.

- For recognized authentication refusal, including SQL 18452/18456 where
  applicable, reread the configuration source exactly once. Use structured
  failure classification, not matching exception text or retrying every error.
- Retry opening once only when the accepted configuration changed. Unchanged
  credentials preserve the refusal; source errors fail clearly without stale
  fallback. A second refusal stops the attempt.
- Share one opening deadline across both reads and both connection attempts.
  Retire obsolete idle sessions according to the existing snapshot rules.
- Keep direct one-time password changes, active transactions, query execution
  and application SQL outside this retry mechanism.

Exit evidence: controlled tests cover changed/unchanged snapshots, both SQL
codes, unrelated refusals, a second failure, source failure/timeout, pool closure,
concurrent opens and cancellation. Assert source reads and opening counts,
original-deadline use, slot cleanup and zero application SQL replay. Add live
SQL-login password rotation during the final Windows campaign.

Targets: Python `connection/shell.py`, `config.py`, `test_config.py`, pool/lifecycle
tests and live configuration tests. Preserve Rust's already implemented handling.

## Iteration 4 — resolve Windows credential-source parity

Priority: gated extension needed for comparable Windows rotation behavior.
Python's `ConnectionConfig` currently represents SQL credentials; the correction
in iteration 3 must not be described as Windows configuration support.

- Propose an immutable representation separating authentication method,
  credential source and target service identity. Keep provider factories/runtime
  services distinct from comparable values and never compare live contexts.
- Compare extending configuration with authentication values against a separate
  Windows credential-source interface. Explain migration of existing `login=`
  providers and how signed-in identity changes retire the appropriate pool.
- Specify which changes permit recovery and which require a new session.
  Password refresh cannot silently change principal, SPN or fallback policy.
- Implement only after the owner selects the representation and compatibility
  policy. This decision can remain deferred while iterations 1–3 and 5 proceed.

Exit evidence if approved: local/domain credential changes are reread as
specified; unchanged/bad replacements stop cleanly; native signed-in operation
needs no application password; no active borrower changes identity. Live domain
rotation and recovery results assert the actual principal and auth scheme.
Explicit recovery retains its own refusal/uncertainty rules and never replays
application requests.

## Iteration 5 — close remaining Rust platform acceptance gaps

Priority: required validation, with code changes only for reproduced defects.
The GCP-discovered direct-Kerberos package-query error and missing 18452 refresh
classification are already corrected; retain their tests rather than reimplement
the fixes. The RTM strict-mode RPC defect was a server issue, corrected by CU27.

- Exercise native provider cancellation/late completion: caller timeout returns,
  no late connection is installed, and handles/workers eventually retire when
  the underlying operation finishes. Use a controllable worker for deterministic
  ownership tests; report real Windows behavior separately.
- Test live credential rotation/recovery and duplicate-SPN failure in isolated
  fixture accounts, restoring account/password/SPN changes in `finally`.
- Expand the authentication privacy/replay corpus to cover fragmentation,
  coalesced final tokens, provider failures and cancellation across both clients.
- Reconfirm that mandatory Kerberos cannot pass through NTLM fallback, permitted
  fallback is reported as NTLM, and physical connection/lease cleanup preserves
  authority boundaries.

Exit evidence: each scenario has a named result, tested platform, exact source
revision/hash and recorded limitation. Controlled and real-platform evidence
remain distinct. A new defect gets a minimal regression before correction.

## Iteration 6 — run cross-client Windows acceptance and close the campaign

Priority: final acceptance and cost/resource closure. Prepare controlled tests
and runner builds before allocating another paid test window.

- Check actual inventory, expiry, ledger and remaining budget first. Existing
  deployment descriptions are historical evidence, not proof the lab is still
  available. Reuse retained infrastructure only within its safety window; do
  not silently extend expiry, reset the paid clock or recreate deleted VMs.
- Retain SQL Server CU27-or-reviewed-successor verification and strict test CA
  validation. Preserve the independent Python/SqlClient RPC witness so the RTM
  defect is not mistaken for a client wire regression.
- Run corresponding SQL/local NTLM/domain NTLM/Kerberos/Negotiate cases from
  supported client locations under TDS 7.4/8.0 and MARS off/on. Provider
  implementations differ: compare semantic identity, scheme and lifecycle
  behavior, not token bytes or an assumed equal case count.
- For changed paths assert successful/refused login, final provider completion,
  structured transaction rollback, Attention/drain and reuse, pool reset/lease
  revocation, actual Browser discovery and local-key AE retention/round trips.
  Keep fixture mutations sequential; independent read-only probes may run together.
- Run relevant local Python/Rust regressions and native Windows Rust checks.
  Record skips explicitly; passing local suites does not replace live evidence.
- Retain the lab through review/fix/retest, as requested. Export sanitized
  evidence after acceptance, then destroy and verify scoped resources, state,
  project shutdown and billing detachment. VM expiry alone is insufficient.

Exit evidence: a per-client acceptance matrix with explicit failures/deferrals,
redacted results, source manifests, support/migration notes and verified cleanup.
The **$10 total campaign ceiling includes previous allocations and retries**;
the $1 efficiency target is not a renewed allowance. If the remaining campaign
cannot fit, report the cost constraint before further provisioning. Normal review
does not override absolute expiry or budget safety limits.

## Completion and release boundary

Iterations 1–3 are the immediate correction sequence. Iteration 4 needs an owner
API decision; iteration 5 can proceed independently of it. Iteration 6 validates
the implemented scope and records any agreed deferral. No calendar estimate is
promised for public API decisions or Windows authentication failure cases.

Extended Protection and complete dependency-key erasure remain documented
limitations at completion. Upstream draft submission, commits, merge and release
are separate actions. Before any Rust publication, resolve the unpublished native
companion crate's packaging strategy; successful MSVC builds do not prove that
the current workspace can be published.
