# Azure authentication follow-ups: plan and checklist

**Where this sits:** after the [Rust Azure live campaign](rust-azure-live-evidence.md).
The owner lifted the Python production freeze on 2026-10-20 and asked for every
follow-up that can use the running `infra/azure` deployment (a domain, Kerberos,
NTLM, Azure SQL with Entra, Key Vault and a VBS enclave).

**After reading this you can** see what is being done, in which order, on which
branch, and which steps wait for an owner decision.

## Git

1. Merge `rust-azure-integration` into `main` through a pull request (PR #2),
   with GitHub's default merge.
2. Do all of this work on one new branch from `main`, `azure-auth-followups`, in
   logically grouped commits. One branch avoids merge friction between the
   Python fixes and the live tests, which share `infra/azure` and the test
   harnesses.
3. Finish with a second pull request, merged after the evidence is recorded.
   Releasing Python or publishing Rust stays a separate action.

## Order, and why

The deployment deletes itself at **2026-10-21 18:59 UTC**, and its VMs shut down
at 05:00 UTC (restart them if needed). Steps needing the VMs or Azure come
first; local design work fills waits for builds and remote runs. The Python
fixes are developed locally with controlled tests, then confirmed live while
the deployment is still up.

## Checklist

### A. Git
- [x] A1. PR #2: `rust-azure-integration` → `main`, merged (`1bf1493`)
- [x] A2. Branch `azure-auth-followups` from the new `main`

### B. Live session recovery on Azure SQL (Rust and Python) — done
Not shown live in the campaign: under the Redirect policy clients bypass a relay.
- [x] B1. Switched the connection policy to Proxy (`az sql server conn-policy update`)
- [x] B2. A local relay reached Azure, but the gateway routes by LOGIN7's server name, and both clients send the TCP host there (40532: "cannot open server 127.0.0.1"). Instead, the session is ended server-side with `KILL` from an admin connection, which needs no relay and works under both policies
- [x] B3. Rust (`mac_recovery_after_the_server_ends_the_session`): Azure resets the transport at once; explicit recovery makes one new token request (under Redirect it reconnects to the routed node directly) and restores `DATEFIRST`/`TEXTSIZE`, in both Entra flows and under both policies
- [x] B4. Python (`paired.py recovery`): identical results
- [x] B5. Restored Redirect

### C. Windows account rotation across both clients (GCP open item)
- [x] C1. Rotate a throwaway account's password during a run (`scripts/rotation.ps1`; local on the SQL VM and in the domain; a new name each run, because a reused name can map to the deleted account's cached SID)
- [x] C2. Rust (`mac_windows_password_rotation_during_a_pool`): local old password refused (18452) and not retried; domain old password **still accepted** right after the change (AD's NTLM grace period); re-read once, reopen with the new password; old-password sessions discarded on return
- [x] C3. Python: `ConnectionConfig(windows=...)` (owner decision); a live pool re-reads the rotated password
- [x] C4. Throwaway accounts and logins removed after each run; Python explicit connections (`paired.py rotation`) match Rust

### D. Python Kerberos opening deadline (roadmap backlog)
- [x] D1. Isolate the built-in Spnego adapter's native calls in bounded, serialized workers, with a reaper owning late results ([design](python-windows-authentication-contract.md#3-built-in-provider-worker-ownership))
- [x] D2. Deterministic tests: timeout within tolerance, event loop stays responsive, cancellation, late success and error cleanup, worker-capacity bounds
- [x] D3. Live on the runner: an unreachable KDC returned at **1.50 s** for a 1.5 s deadline, the event loop ticking throughout (GCP: over 4 s); real Kerberos logins still pass
- [x] D4. Move the roadmap backlog entry to done

### E. Python Azure review backlog (PY-AZ-01 to 06)
Each item names the real-service evidence it needs; collect it, then decide
and fix. Evidence collected 2026-10-20 (`paired.py review` and a capture):
- **PY-AZ-01:** Azure's FEDAUTHINFO (sent only by the routed destination) is fully well-formed: two options, SPN then STS URL, in bounds, even lengths, valid UTF-16, no duplicates, data region exactly covered. Rust's parser deliberately mirrors Python's lenient slicing, so tightening changes both clients.
- **PY-AZ-02:** real refusals (wrong service principal secret, managed identity off the VM, a vault key that cannot verify) carry descriptive Azure codes but no secret and nothing token-like.
- **PY-AZ-03:** a synchronous Azure CLI credential stalls Python's event loop for 0.42 s per login; the asynchronous credential stalls it 0.015 s.
- **PY-AZ-04:** each encrypted connection already starts with fresh sessions; two connections from one context and four concurrent MARS channels on one connection all return correct enclave results.
- [x] E1. PY-AZ-06: implement the owner-approved unsupported-feature policy in Python (warn on request; fail on an enabled ACK before SQL or pool admission; no retry without the flag). Live: ACKs 1/1/0/1 refused as in Rust
- [x] E2. PY-AZ-01 (strict in both clients, owner decision): capture Azure's real FEDAUTHINFO layouts (deferred flow) with both clients; tighten Python's parsing (offsets, lengths, duplicates, UTF-16) only as far as real layouts and shared malformed fixtures support
- [x] E3. PY-AZ-02 (no change: no leak found): collect real SDK refusals (wrong service principal secret, managed identity off-VM, Key Vault denial); keep provider text out of ordinary Python errors, with an explicit protected cause, as Rust does
- [x] E4. PY-AZ-03 (fixed; live stall 0.42 s → 0.015 s): measure a synchronous Azure credential blocking Python's event loop; run synchronous credential work in a worker, sharing D's worker design where it fits
- [x] E5. PY-AZ-04 (no change: no defect): paired evidence on enclave session reuse across connections, identities and pool return; scope Python's sessions per lease if the evidence supports it
- [x] E6. PY-AZ-05 (fixed): add the structural checks Rust has (such as the 32-byte root) where valid vault, enclave and SqlClient responses still pass; raise a typed error for a bad key path
- [x] E7. Update the review backlog with each result

### F. Credential-mode gaps
- [x] F1. Client assertion: a disposable certificate on the app registration, an application-signed assertion; Rust and Python log in, both flows
- [x] F2. Azure Developer CLI credential (azd installed with Homebrew, signed in as the service principal by certificate, then signed out): Rust and Python log in, both flows
- [x] F3. Owner decision: do not enable OpenSSL; recorded as exception E-CRED-1 (use client assertion)
- [x] F4. Credential inventory updated

### G. Regression re-runs of GCP-proven paths
- [x] G1. Rust native signed-in SSPI on the SQL VM (`regressions.sh`, as SYSTEM = `TDS\TDSSQL$`): Kerberos 7.4/8.0 pass, no native workers left; Negotiate to its own machine chooses NTLM (loopback), which Rust refuses unless `allow_ntlm_fallback` is set, and then logs in by NTLM
- [x] G2. Rust portable explicit-credential Kerberos and Negotiate from the runner (`kdc_url` = the domain controller): `TDS\tdsuser`, scheme KERBEROS, TDS 7.4/8.0

### H. Explicit provider completion (GCP open item 1)
- [x] H1. Owner decision: optional `complete` on the provider exchange; incomplete at LOGINACK is refused; providers without it keep legacy behavior
- [x] H2. Implemented; NTLM (local, domain, wrong password) and Kerberos pass live

### I. Finish
- [x] I1. Full Rust matrix: 251 default / 103 core / 327 all-features, 0 failed, strict Clippy, rustdoc, 62/62 Docker live; Azure paired check 117 Rust tests in 16 steps, source unchanged; Python 926 passed
- [x] I2. Evidence record, handover, credential inventory, review backlog, roadmap and Python changelog updated
- [x] I3. PR #4 `azure-auth-followups` → `main`, merged (`13ce471`)
- [x] I4. **Replaced at the owner's request:** instead of waiting for the Logic App (due 2026-10-21 18:59 UTC), the deployment was torn down with `terraform destroy` on 2026-10-20 at 22:36 UTC: 39 resources destroyed, state empty. Checked afterwards: `rg-tds-rust-azure` not found, no soft-deleted vault, no SQL server, no app registration; the deleted registration was purged from Entra's recycle bin. Local `azure.json`, `secrets/`, state and plan were deleted. **The self-delete Logic App therefore remains untested:** the automatic-expiry rehearsal is still open for a future deployment.
