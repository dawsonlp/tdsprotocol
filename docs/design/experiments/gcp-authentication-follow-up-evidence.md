# GCP authentication corrections: implementation and evidence

2026-10-19 UTC, development checkpoint on `rust-client`. The
[approved plan](gcp-authentication-development-plan.md) is **partially complete**.
Two architecture choices remain pending; synchronous provider isolation is now
deferred to the backlog. The
[API proposal](python-windows-authentication-contract.md) describes all three.
This report does not claim Rust completion or full Python parity. The owner
subsequently authorized teardown; verified closure is recorded below.

## Campaign closure — 2026-10-19 04:29 UTC

Terraform destroyed 11 lab resources, then the dedicated project and its five
service-state entries. Independent inventory before project shutdown confirmed
zero VMs, disks, reserved IPs, snapshots, forwarding rules, routers, firewalls,
subnets, VPCs and storage buckets. The campaign service account was gone; Google's
default Compute service account remained until project shutdown. Cloud DNS's API
was disabled, so its zone inventory was unavailable, not a passing empty query.
Both Terraform roots and the earlier default-network cleanup state were empty.

At **04:29:52 UTC**, Google's APIs confirmed `DELETE_REQUESTED`,
`billingEnabled=false` and no attached billing account for
`tds-rust-auth-77681f69a4`. This verifies shutdown, not immediate permanent
deletion or the actual billed total. Protected artifacts retain
`teardown-resource-verification.json`, `teardown-final-verification.json`,
reviewed plan summaries and apply logs alongside the test evidence. The lab is
unavailable for further tests; unresolved defects and acceptance work remain open.

## Implemented corrections

- Python omits incoming Windows-login raw payloads from default captures and
  removes SSPI payload copies from full inspection and legacy replay. Malformed
  authentication replies and provider-start/step exceptions do not echo their
  payloads or private provider exception messages. The original provider error
  remains available only by explicit inspection.
- Valid login capture events retain `safe_login_tokens`: SSPI payload bytes are
  zeroed before serialization, while non-secret LOGINACK/feature records remain.
  Python and Rust replay restore negotiation context from this supplemental
  evidence and still report that the authentication payload is unavailable.
- Python now dispatches final SSPI tokens even alongside LOGINACK, refuses
  invalid final tokens before returning a connection, and refuses duplicate
  challenges or provider output after server acceptance. This correction uses
  the existing step interface; it does not decide the new completion contract.
- Python enforces 48 KiB input/output tokens, eight provider steps including the
  initial step, and a 64 KiB assembled Windows-login message limit. Exact-size
  boundaries and fragmented messages are tested. These are driver limits, not
  protocol maxima.
- Configured Python SQL pools reread their source once after recognized SQL
  18452/18456 authentication refusal. Only a changed snapshot permits one new
  opening attempt. Both reads/attempts share the original deadline; unchanged
  values, second refusal, source failure, cancellation and pool closure stop
  cleanly. Application SQL and one-time password changes are not retried.
- Rust's native worker/reaper path has a deterministic late-owned-result test.
  The live probe can separately abandon an opening after observing an actual
  native worker, without opening an application SQL channel.
- The Windows Python campaign now invokes Python, rather than falling through
  to its independent SqlClient branch. Evidence records pyspnego's actual
  implementation class and completion state. This corrects the harness; older
  SqlClient witnesses are not relabeled as Python acceptance.

## Local regression evidence

| Check | Observed result |
|---|---|
| Python suite, `-m 'not live and not azure'` | **532 passed**, 379 deselected |
| macOS Rust, all features | **253 passed**, 61 live checks ignored |
| Native MSVC Windows Rust, all features | **254 passed**, 61 live checks ignored; includes the late-result cleanup test |
| macOS all-feature/all-target Clippy | Passed with warnings denied after the final test-fixture edits |
| Native Windows workspace/all-feature/all-target Clippy | Passed with warnings denied |
| Local GCP cost/plan/configuration/certificate tests | **13 passed** |

The Python controlled cases include coalesced/fragmented incoming privacy, old
recordings, malformed replies, explicit secret-capture opt-in, preserved feature
negotiation, provider error masking, exact/oversized tokens, round limits and
pool failure/cancellation boundaries. The custom-provider completion correction
is not included in the implemented claims.

## Windows SQL runtime evidence

SQL Server remains the same Developer fixture updated to CU27, 16.0.4295.3.
The [original campaign](rust-gcp-authentication-evidence.md) records the RTM RPC
defect and server update, not a client wire workaround. Verified CA/hostname TLS
and the recorded ExtendedProtection=0 baseline remain the test conditions.

| Scenario | Observed result and boundary |
|---|---|
| Python login matrix | 64 current-source semantic login/transport/credential-source cases repeated after the final-token routing fix across macOS, Linux and Windows; actual pyspnego provider, completion and default capture redaction asserted |
| Rust native signed-in regression | 12 Windows NTLM/Kerberos/Negotiate transport cases passed again after the worker/reaper refactor, with zero pending workers after close |
| Python SQL refresh | Four TDS/MARS profiles passed both changed-source success and unchanged-source 18456 refusal; each source was read twice; disposable logins removed |
| Existing Python live configuration suite | **8 test functions passed** against GCP through a verified-TLS SSH tunnel, including rotation, eligible recovery, root closure and superseded candidates |
| Existing Rust live recovery suite | **5 test functions passed**, including SQL password rotation, direct password change, repeated recovery and refusal/no-replay scenarios; runs from macOS against Windows SQL, not native Windows account rotation |
| Actual native Rust cancellation | Four opening profiles observed an outstanding native Kerberos worker, abandoned opening before SQL, and returned to zero workers. Cancellation was observed at 96–156 ms and cleanup at 115–185 ms from opening start |
| Duplicate SPN | AD refused adding the already-owned SQL SPN to an isolated account; owner count remained one and the owner was unchanged |
| Python authenticated lifecycle/AE | macOS NTLM and Linux Kerberos passed all four profiles. Windows signed-in Kerberos also passed all four profiles and repeat runs, with initial harness timeouts retained below |

The lifecycle probe checks structured rollback and descriptor reset, Attention/
drain followed by reuse, pool reset on the same physical SPID, temporary-table
removal, old-channel revocation and preserved principal. The local-key AE probe
uses the public RSA fixture and value 42: encrypted insert/decrypted select,
one unwrap within the transaction, zero live column/master keys after commit,
and disposable database cleanup. Fixture mutations run sequentially.
After the final-token routing correction, representative lifecycle/encryption
profiles were repeated successfully from macOS NTLM, Linux Kerberos and native
signed-in Windows Kerberos. Both runner manifests matched the current `.py` and
`.rs` source files. The final server check found zero smoke databases and zero
disposable SQL logins; ForceEncryption remained 1 and ExtendedProtection 0.

Duplicate-SPN registration refusal does not simulate an AD forest accepting
ambiguous SPNs and then refusing authentication. Forest uniqueness protection
was not disabled. Native worker retirement likewise does not prove forced OS
call cancellation or erasure of OS-managed secrets.

## Failures retained and architectural work still open

**Python opening deadline is not reliable for synchronous provider startup.**
A Linux Kerberos probe used an isolated temporary KRB5_CONFIG pointing to an
unreachable private KDC. With a 1500 ms opening deadline it remained inside
provider startup until the test's independent four-second process limit killed
it, measured at **4010 ms**. The temporary configuration was removed; the machine
Kerberos configuration was unchanged. This is a failed driver deadline case,
not a passing timeout test.

The proposed correction is serialized worker execution for the built-in Spnego
adapter, with a reaper owning eventual context/results after caller cancellation.
It preserves the begin/step interface and distinguishes caller timeout from
eventual native cleanup. The owner deferred this fix to the
[roadmap backlog](../C-roadmap.md#backlog--python-kerberos-opening-deadline);
no thread-isolation correction is claimed yet.

**Windows lifecycle harness had two 90-second task timeouts.** Both occurred
while native build/check work was also active; neither retained enough phase
information to identify the cause. The harness now retains non-secret phase
markers and Scheduler status on timeout. The diagnostic rerun and subsequent
Windows lifecycle/encryption matrix/repeats passed without a client correction
for those timeouts. Resource contention is a hypothesis, not an established
cause. Keep the original failures and separate idle-run checks from compilation.
After verifying that no cargo/rustc/clippy process was active, all four Windows
profiles passed again in **5.874–12.221 seconds** including controller/task
overhead. These idle runs are retained separately. The slower successful loaded
runs and the original timeouts remain part of the evidence, not discarded retries.

The first AE smoke also combined key creation and table creation in one SQL
batch; table compilation could not resolve the newly created key. Separating
the fixture batches corrected it. This was a harness/setup issue, not a client
encryption defect. The failed smoke's cleanup path removed its database.

Remaining choices/work:

1. Require explicit provider completion, or provide an explicit legacy wrapper.
   Early server acceptance with an incomplete/missing-completion provider remains
   unfixed; final SSPI routing itself is corrected and tested.
2. Extend comparable Python configuration with Windows values, choose a separate
   type, or defer it. Current refresh acceptance covers SQL configuration only.
3. Deferred backlog: isolate built-in synchronous provider calls in workers,
   with the blocking-deadline limitation retained until fixed. Re-test the failed
   KDC case when implementing the correction.

Windows account rotation across both clients, the full completion/cancellation
corpus, reviewed final acceptance and a clean deployment/expiry rehearsal remain
open. Campaign teardown is verified in the closure record above.
Dependency forks, Extended Protection implementation and complete provider-key
erasure remain deferred as agreed. Upstream drafts remain unsubmitted.

## Reproduction and protected evidence

Local regression commands:

```sh
clients/python/.venv/bin/python -m pytest clients/python/tests -m 'not live and not azure' -q
cargo test --manifest-path clients/rust/Cargo.toml --offline --all-features
cargo clippy --manifest-path clients/rust/Cargo.toml --offline --all-features --all-targets -- -D warnings
clients/python/.venv/bin/python -m unittest discover -s infra/gcp/tests -q
```

On the existing dedicated lab, `infra/gcp/followup.py` has `sql-refresh`,
`sql-lifecycle` and `rust-lifecycle` commands. `campaign.py --client python --full`
runs the per-location login matrix; Windows defaults to signed-in identity and
`--portable` selects explicit credentials, with pyspnego's actual backend named
in evidence. Set the probe's `lifecycle`/`local_key_ae` flags for the focused
authenticated checks. `runner.py --source-only` updates a snapshot without
compiling Rust. Keep Windows scheduled probes sequential and run timing checks
without concurrent native builds.

Ignored, private `infra/gcp/artifacts/` retains source manifests, raw redacted
per-case results, the initial lifecycle failure, diagnostic reruns, native worker
timings, full suites, the failed Python KDC deadline and SQL rotation/recovery
reports. Test input/credentials/state stay under ignored protected paths.

The owner authorized teardown and PR submission after this implementation
checkpoint. The lab is closed; further live tests require a new campaign.
Rust crate publication and upstream submissions have not occurred. The original
paid clock and protected evidence are retained. The historical full-window guard
was $6.9369 including reserves, not actual billing or a cloud hard cap. Posted
project charges were unavailable at the first billing check; reconciliation is
scheduled to inform future estimates.
