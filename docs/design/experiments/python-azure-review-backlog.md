# Python Azure integration: review backlog

**Where this sits:** concerns raised while planning
[Rust Azure parity](rust-azure-integration-plan.md), not an implementation task list
for changing Python during this phase.

**After reading this you can** distinguish inspected code from a suspected
weakness and identify the real-service evidence needed before accepting a remedy.

## Agreed handling

Python is the real-service-tested baseline; new Rust Azure work has no live Azure
evidence yet. Record concerns and comparison outcomes here. Do not assume a
suggested improvement is correct, change Python production behavior, or silently
implement a divergent Rust compatibility policy on that basis. Keep proposed
remedies provisional until they can be tested against actual Azure/native
behavior, including regressions of valid Python scenarios.

For each entry retain: source revision, observed code/behavior, hypothesis,
possible consequence, local reproducer if any, proposed alternatives, missing
evidence and later paired acceptance scenario. Labels such as "defect" or "fixed"
require evidence appropriate to the claim. Static observations below do not
establish failures against Azure.

## Initial concerns from source inspection

These entries are **unverified review candidates**, not confirmed Azure defects.
Source baseline: Python at `f45aa43`, inspected 2026-10-19.

| ID | Observed source | Hypothesis / proposed alternatives | Evidence needed before a fix decision |
|---|---|---|---|
| PY-AZ-01 | `tds/tokens.py::_fed_auth_info` slices fields and decodes UTF-16 with replacement | Stricter offset/length/duplicate/text checks may reject malformed metadata more clearly; strictness may also reject an actual supported server response | Shared malformed-input fixtures, actual FEDAUTHINFO layouts from supported Azure paths and paired regression of valid sessions; compare specification/Microsoft client before changing acceptance |
| PY-AZ-02 | `connection/core.py::_obtain` includes callback exception text; `encryption/keyvault.py` includes a shortened SDK error | Some credential/provider exception messages may contain sensitive information; a generic public failure with explicit protected cause may be preferable | Artificial secret-marker cases establish local output; inspect real SDK refusal categories with safe fixtures and compare diagnostic utility/compatibility before choosing a replacement contract |
| PY-AZ-03 | `tds/adapters/entra.py` and generic callback dispatch may invoke synchronous credential work inline | A slow synchronous Azure credential may delay event-loop deadlines; async-only or serialized-worker alternatives have different cancellation/shutdown behavior | Controlled blocking callback, actual Azure credential failure/latency scenarios, cleanup and runtime-shutdown evidence. The existing Linux Kerberos 1500/4010 ms failure is separate evidence, not an Azure reproduction |
| PY-AZ-04 | `encryption/context.py` caches enclave sessions by server identity | That scope may need review across physical connections, identities, pool return and recovery; narrower scope might instead break useful/valid reuse | Paired actual enclave session reuse/rejection, stale-session handling, concurrency and identity/connection transitions; compare permitted behavior before changing cache identity/lifetime |
| PY-AZ-05 | `encryption/keyvault.py` parses an envelope before remote verify/unwrap; `enclave.py` parses session fields under explicit no-attestation mode | Additional structural checks may improve handling of malformed inputs; their compatibility and appropriate failure contract remain unverified | Local adversarial vectors plus valid Key Vault/enclave service responses and mutual Python/Rust/.NET checks; retain the explicit `none` mode's trust assumption |

Add actual comparison results to the relevant row or a linked evidence record.
Do not count these candidates as required Python fixes for Rust code completion.
If a discrepancy prevents faithful Rust implementation, surface the specific
conflict and evidence instead of silently deciding that Python is wrong.

The independently reproduced Python Kerberos deadline defect remains in the
[existing roadmap backlog](../C-roadmap.md#backlog--python-kerberos-opening-deadline).
It is not newly classified as speculative by this document; implementation of its
proposed remedy is still deferred.

## PY-AZ-06 — owner-directed unsupported-feature negotiation policy

Decision accepted 2026-10-19. This explicit owner direction supersedes the
provisional-remedy rule above for this item. Python implementation remains
backlogged; no Python production code is changed in the Rust phase.

Observed at baseline `f45aa43`: `tds/login7.py::feature_list` permits Azure SQL
support (8), DNS caching (11), enhanced routing (15) and global transactions (5).
`tests/test_azure_live.py::test_the_azure_only_features` requests all four and
collects ACKs; its assertion only requires at least one acknowledgement. The
retained campaign reports 1/1/0/1 without demonstrating operational effects.
This establishes permissive negotiation, not a reproduced server-side
corruption/failover/transaction failure.

Required correction for each requested feature whose behavior is unimplemented:

| Situation | Required result |
|---|---|
| Explicit request | Warning naming the unimplemented feature; all switches remain off by default |
| No ACK | Warning remains; no inference of enabled support; login may finish |
| Valid disabled ACK (`0`) | Retain disabled evidence; login may finish |
| Valid enabled ACK (`1`) | Named error; stop physical opening, close/discard it, allow no application SQL or pool admission |
| Malformed/duplicate/unrequested ACK | Protocol error; stop opening |

No automatic flag removal/retry. Actual implementations need their own
acceptance before leaving this policy. Ordinary supported Azure routing and
local SQL transactions are unaffected. The rule is deliberately conservative
for DNS caching: its server ACK permits caching, and unused permission can be
harmless. Enhanced routing advertises an ability to act on server instructions.
Apply the owner's uniform refusal policy; calling a request a probe does not
change its on-wire meaning.

Acceptance: Python-produced wire vectors; absent/0/1 ACKs for all four switches
under TDS 7.4/8.0 and plain/MARS, warnings, malformed/duplicate replies, socket
close, no SQL/pool admission and no silent retry. Change the Azure test to expect
the named refusal if any requested unimplemented feature is enabled. Later run
both clients against the same Azure fixture. Rust implements this approved
difference now under the [feature policy contract](rust-azure-feature-probe-contract.md).

## Source clarification during Rust authentication development — 2026-10-19

For PY-AZ-04, `EncryptedConnection.__init__` copies the `Encryption` context and
creates fresh `_plans`/`_sessions` dictionaries per wrapper. `_clear_metadata`
closes enclave session keys, while `_lifecycle` clears metadata on return/close
and database/collation/reset events; `_ready` handles physical core replacement.
Therefore the server-keyed dictionary alone is not evidence of cross-connection
session sharing. Review direct-context usage and actual wrapper lifecycle cases
before asserting a defect or changing Python behavior. No Python production
change was made. This clarification does not expand the separate enclave
completion backlog into the current parity activity.
