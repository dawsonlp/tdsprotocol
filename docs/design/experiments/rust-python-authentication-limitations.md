# Authentication limitations and follow-up findings

Recorded after the October 19 UTC GCP campaign and cross-client review. Owner
direction: document the findings and prepare potential upstream reports.
Dependency forks, local security patches and TLS backend changes are deferred.
The initial record below is supplemented by the approved implementation in the
[follow-up evidence](gcp-authentication-follow-up-evidence.md). No upstream issue
has been submitted.
The [follow-up development plan](gcp-authentication-development-plan.md) orders
the corrections, design checkpoints and remaining campaign acceptance work.

## Accepted dependency limitations

- **Rust portable NTLM:** retained session-key/RC4 state in pinned `sspi` 0.23.0
  does not satisfy our complete retained-key erasure goal. Our own buffer
  zeroization does not clear private dependency state. Portable NTLM remains
  available with this explicit limitation; no complete erasure claim is made.
- **Rust Extended Protection:** the tested Required policy rejects both provider
  paths. Allowed policy also rejected portable NTLM. These configurations are
  unsupported; verified TLS encryption and hostname/CA validation remain on.
- **Python Extended Protection:** `Spnego.begin(host, port)` supplies no TLS
  channel binding. Python uses a different TLS stack but has not already solved
  the shared integration problem. No dependency fork requirement is established
  for Python.
- **Python secret erasure:** provider-owned authentication state has not had the
  equivalent audit. Python-managed strings/bytes cannot be assumed to satisfy
  the Rust zeroization contract. The confirmed Rust `sspi` finding is not proof
  of the same implementation defect in pyspnego.

These are authentication secrets and transport bindings, separate from Always
Encrypted column-key retention and per-value encryption.

See the [provider source review](rust-authentication-provider-review.md),
[sspi report draft](upstream-sspi-ntlm-zeroization.md) and
[rustls discussion draft](upstream-rustls-channel-binding.md). Drafts are not
submitted reports or promises of upstream acceptance. Documentation resolves the
owner's scope decision; it does not resolve the technical limitations.

## Python follow-up backlog: controlled observations

These findings use the existing `tests/test_logins.py` loopback TLS fixture with
artificial tokens and a stubbed pool connector. They are separate from live
Microsoft interoperability; no production credentials or client source changes
were used for these checks.

| Finding | Observed behavior | Future correction/acceptance |
|---|---|---|
| Final SSPI alongside LOGINACK | A single response containing `SSPI(FINAL-SERVER-TOKEN)` followed by LOGINACK was accepted, but the provider received only its initial `None` call | Process the final token and verify provider completion before installing the session; test valid and invalid mutual-authentication completion |
| Early LOGINACK | A scripted provider with no completion contract was accepted after its initial token | Define completion semantics and reject server acceptance while the provider remains incomplete |
| Incoming capture privacy | Default `Capture` retained the artificial server challenge in received packet bytes | Redact incoming authentication material, including fragmented/coalesced replies; preserve useful typed diagnostics and explicit replay limitations |
| Authentication round bound | Nine server challenge/response rounds followed by LOGINACK were accepted | Add explicit round/token bounds and boundary/failure tests under the original opening deadline |
| Credential-source refresh | A configured pool read its source once, attempted opening once and propagated `LoginRejected`, despite a second source read being able to return a new value | Reread once on recognized authentication refusal, retry opening only on changed configuration within the original deadline, and never replay application SQL |

Follow-up disposition: incoming capture/inspection/replay privacy, provider-error
masking, token/round/message bounds and configured SQL opening refresh are
implemented. Final SSPI routing alongside LOGINACK, invalid-final-token refusal
and duplicate-challenge refusal are also implemented. Explicit provider
completion and Windows credential-source values remain gated on the owner API choices. A live unreachable-KDC test also confirmed
that synchronous pyspnego startup can outlive the opening deadline; the built-in
provider worker-lifetime design is awaiting the owner. See the
[concrete API proposal](python-windows-authentication-contract.md).

Source locations: [`ConnectionCore.connect`](../../../clients/python/tds/connection/core.py),
[`Pool._open`](../../../clients/python/tds/connection/shell.py),
[`SecurityExchange`](../../../clients/python/tds/logins.py),
[`Spnego`](../../../clients/python/tds/adapters/spnego.py) and
[`Capture.packet`](../../../clients/python/tds/capture.py).

The pool probe used the refusal exception class, not a fresh live credential
rotation. A future fix should cover actual SQL 18452/18456 and provider failures
where appropriate. Python's configuration value currently models SQL logins;
Windows credential-source parity requires explicit design rather than assuming
the existing SQL configuration already represents those identities.

## Corrections already present and evidence limits

Rust's direct Kerberos adapter no longer invokes a Negotiate-only package query.
Rust opening refresh recognizes SQL 18452 as well as 18456, with controlled tests
for changed and unchanged configuration. These corrections are implemented; the
dependency limitations above remain.

SQL Server RTM's strict-mode RPC defect affected both clients and was corrected
by updating the fixture to CU27, without a client encoding workaround. The
[campaign evidence](rust-gcp-authentication-evidence.md) records 64 Rust login
combinations and narrower independent Python witness coverage. Passing those
checks is not proof that the backlog above, provider erasure, cancellation stress
or all other campaign gates have passed.
