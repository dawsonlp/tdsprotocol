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
- [ ] C1. Rotate `tdsuser`'s password in AD during a run (run-command on the DC)
- [ ] C2. Rust: a pool with a changeable configuration re-reads once after 18452 and reopens with the new password; unchanged credentials are not retried
- [ ] C3. Python: same scenario. Python's comparable configuration covers SQL credentials only (GCP open item 2); extending it to Windows values may need a design choice. **Decision gate if so.**
- [ ] C4. Restore the password; record the results

### D. Python Kerberos opening deadline (roadmap backlog)
- [ ] D1. Isolate the built-in Spnego adapter's native calls in bounded, serialized workers, with a reaper owning late results ([design](python-windows-authentication-contract.md#3-built-in-provider-worker-ownership))
- [ ] D2. Deterministic tests: timeout within tolerance, event loop stays responsive, cancellation, late success and error cleanup, worker-capacity bounds
- [ ] D3. Live on the runner: an unreachable KDC (temporary `KRB5_CONFIG`) returns at the deadline; real Kerberos login still works
- [ ] D4. Move the roadmap backlog entry to done

### E. Python Azure review backlog (PY-AZ-01 to 06)
Each item names the real-service evidence it needs; collect it, then decide
and fix.
- [ ] E1. PY-AZ-06: implement the owner-approved unsupported-feature policy in Python (warn on request; fail on an enabled ACK before SQL or pool admission; no retry without the flag). Live: ACKs 1/1/0/1 refused as in Rust
- [ ] E2. PY-AZ-01: capture Azure's real FEDAUTHINFO layouts (deferred flow) with both clients; tighten Python's parsing (offsets, lengths, duplicates, UTF-16) only as far as real layouts and shared malformed fixtures support
- [ ] E3. PY-AZ-02: collect real SDK refusals (wrong service principal secret, managed identity off-VM, Key Vault denial); keep provider text out of ordinary Python errors, with an explicit protected cause, as Rust does
- [ ] E4. PY-AZ-03: measure a synchronous Azure credential blocking Python's event loop; run synchronous credential work in a worker, sharing D's worker design where it fits
- [ ] E5. PY-AZ-04: paired evidence on enclave session reuse across connections, identities and pool return; scope Python's sessions per lease if the evidence supports it
- [ ] E6. PY-AZ-05: add the structural checks Rust has (such as the 32-byte root) where valid vault, enclave and SqlClient responses still pass; raise a typed error for a bad key path
- [ ] E7. Update the review backlog with each result

### F. Credential-mode gaps
- [ ] F1. Client assertion: a certificate credential on the campaign's app registration; Rust's `ClientAssertionCredential` and Python's equivalent log in
- [ ] F2. Azure Developer CLI credential on this machine (both clients)
- [ ] F3. Certificate service principal in Rust needs the SDK's OpenSSL-based feature. **Decision gate:** owner decides the dependency
- [ ] F4. Update the credential inventory

### G. Regression re-runs of GCP-proven paths
- [ ] G1. Rust native signed-in Windows SSPI on the domain-joined SQL VM
- [ ] G2. Rust portable explicit-credential Kerberos from the runner (`kdc_url` to the domain controller)

### H. Explicit provider completion (GCP open item 1)
- [ ] H1. Propose the design: require explicit provider completion, or an explicit legacy wrapper. **Decision gate**
- [ ] H2. Implement and test after agreement; confirm live against the domain

### I. Finish
- [ ] I1. Full Rust matrix (with Docker live tests) and the Python suite
- [ ] I2. Evidence record, handover, support matrix, Python changelog
- [ ] I3. PR `azure-auth-followups` → `main`, merged
- [ ] I4. Expiry rehearsal: let the Logic App delete the resource group at the deadline, check the inventory, then `terraform destroy` for the app registration and state, and purge the soft-deleted vault
