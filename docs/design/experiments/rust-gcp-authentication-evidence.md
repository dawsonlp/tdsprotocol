# Rust Windows authentication: GCP evidence checkpoint

2026-10-19 UTC. Implementation is uncommitted on `rust-client`, based on
`452d458`. This is a bounded interoperability checkpoint, **not Rust completion**.
The lab remains available for review and retesting.
The later [follow-up evidence](gcp-authentication-follow-up-evidence.md) supersedes
the remaining-gate list below where it records new corrections and tests; it
also records the unresolved Python API/worker choices and failed deadline case.

## Observed fixture and versions

Terraform created the dedicated project `tds-rust-auth-77681f69a4`, an isolated
network, a Windows domain controller, Windows SQL host, Linux runner and separate
domain-joined Windows runner in `us-central1-a`. No AD/KDC/RDP service is public.
Developer SQL/Browser and Linux SSH ingress are limited to the recorded /32.
All VMs have absolute DELETE expiry and auto-deleting standard boot disks.

- Windows Server 2022 Datacenter, build family 20348; Ubuntu 24.04 x86-64;
  development host macOS ARM64.
- Initial SQL Server 2022 RTM **16.0.1000.6**, **Developer Edition (64-bit)**,
  independently queried from the server. The same VM was then updated in place to
  **CU27, 16.0.4295.3**, independently queried after setup completed.
- Rust **1.99.1**; portable `sspi` **0.23.0**; Windows API crate **0.62.2**;
  rustls **0.23.46**; Terraform **1.5.7**, Google provider **7.18.0**.
- Verified private CA, matching `tdssql.tds.test` leaf certificate; encryption
  required. Successful matrix runs used `ExtendedProtection=0`.

Python/pyspnego independently established SQL, local/domain NTLM and remote
Kerberos/Negotiate. Microsoft's System.Data.SqlClient, running under a real
`TDS\tdsuser` password logon on the separate Windows runner, established remote
`KERBEROS`. Public-key SSH identity was not substituted for that logon.

## Successful Rust login matrix

Each row below passed TDS **7.4 and 8.0**, each with **MARS off and on**.
Every connection asserted `SUSER_SNAME()`, `ORIGINAL_LOGIN()`, `master`, physical
TCP transport, expected `auth_scheme`, `encrypt_option=TRUE`, and awaited close.
The DMV query selects the physical connection to avoid counting MARS parent and
logical rows twice.

| Client / provider | Credential source and methods | Combinations |
|---|---|---:|
| macOS / portable | SQL; local Windows NTLM; domain NTLM | 12 |
| Linux / portable | SQL; local/domain NTLM; domain Kerberos; Negotiate selecting Kerberos | 20 |
| Windows / native SSPI | Signed-in domain NTLM, Kerberos, Negotiate selecting Kerberos | 12 |
| Windows / portable | SQL; explicit local/domain NTLM, Kerberos, Negotiate selecting Kerberos | 20 |
| **Total unique combinations** | Provider, method, identity and transport counted separately | **64** |

The complete matrix first passed against RTM and was repeated successfully
against CU27. The accepted aggregate identifies server version 16.0.4295.3;
the initial RTM aggregate is retained separately.

Native Rust received no application username/password. The controller supplied
the separate OS task-logon credential through SSH stdin. Every Windows probe
reported **zero pending native workers after close**. This is retirement evidence
for these successful calls, not proof that an OS call is forcibly cancellable.

Protected per-case results and source manifests remain under ignored
`infra/gcp/artifacts/`; `accepted-login-smoke.json` contains the validated unique
64-case set. Runner source manifests record dirty-file SHA-256 hashes. Raw
credential-bearing inputs, Terraform state, tickets and keys are not published.

## Additional observed scenarios

- Wrong NTLM password: SQL Server refused login with **18452**, application SQL
  `NotSent`. Wrong Kerberos SPN and forbidden Negotiate fallback also failed.
- A separate valid domain account without a SQL login was refused with **18456**.
  Disabling that account caused provider authentication to fail before a SQL
  session was installed; the account was re-enabled in `finally`.
- Deliberately permitted Negotiate fallback with a missing service SPN succeeded
  as **NTLM**, under the expected domain principal. It was not labeled Kerberos.
- Wrong TLS hostname and untrusted CA were refused with TLS errors.
- Unreachable private KDC with a 1500 ms opening deadline failed as `Timeout`;
  the controller measured **2.119 s including SSH/process overhead**. Controlled
  tests separately establish socket closure under the shared opening deadline.
- Domain NTLM from macOS and Kerberos from Linux each passed all four transports
  for structured transaction rollback, Attention acknowledgement/drain followed
  by reuse, explicit pool return/reset, physical-connection reuse, old-lease
  revocation, preserved identity and actual UDP Browser discovery.
  Native signed-in NTLM and Kerberos also passed all eight corresponding
  Windows lifecycle combinations, with zero pending native workers after close.
- A local-key Always Encrypted integer round trip passed under NTLM and Kerberos
  against Windows SQL Server. Within the transaction the key was unwrapped once
  and reused; after commit both live column-key and master-key counts were zero.
  Each smoke database was dropped; a fresh catalog query found zero leftovers.
  This isolated smoke uses the repository's public RSA test fixture and value 42.

The final native TDS 8.0 AE check exposed SQL error **8009**, unknown parameter
type 0x00. Linux reproduced it with and without MARS; the established Python
client reproduced it even without encryption negotiation or RPC parameters.
Microsoft documents this exact RTM defect as
[bug 2042238, fixed in CU1](https://support.microsoft.com/en-us/servicing/sql/sql-server-2022/cumulative-update/kb5022375-cu1#2042238).
The same SQL VM was updated to pinned **CU27, 16.0.4295.3** using the official
download, published SHA-256 and a valid Microsoft signature. The fixture script
now performs that update before SQL acceptance. Independent Python strict-mode
RPC now passes; Rust Kerberos AE passes all four transports from Linux, and the
previously failing native TDS 8.0/MARS AE check passes. macOS NTLM AE also passes
all four transports against CU27. A final verified-TLS catalog check found zero
remaining smoke databases. No client RPC encoding
change was needed for this server defect.

The live 18452 result exposed a pool refresh gap: Rust recognized only SQL 18456.
It now rereads credentials for both 18452 and 18456, retries an opening once only
if configuration changed, and never retries application SQL. Controlled TLS
tests exercise both changed and unchanged credential-source cases.

Portable Kerberos initially failed because the adapter queried the direct
Kerberos context using a Negotiate-only operation. The query now applies only to
mandatory-Kerberos Negotiate; the full Linux and Windows portable matrices passed
after that correction.

## Documented dependency limitations — owner disposition recorded

**Required Extended Protection fails.** With `ForceEncryption=1` and
`ExtendedProtection=2`, Microsoft SqlClient succeeded while both Rust provider
paths were rejected. SQL logged **0x80090346**, incorrect/missing channel binding.
Independent witnesses with missing and deliberately incorrect bindings also
failed. Rust's certificate-based endpoint buffer matched Schannel's endpoint
buffer byte for byte; SQL expects a `tls-unique` binding instead.
An additional Allowed-policy (`ExtendedProtection=1`) NTLM probe also failed;
its fixture setting was then restored in `finally`.

The pinned rustls API does not expose the needed Finished-message data. Microsoft's
[Go driver](https://github.com/microsoft/go-mssqldb/blob/main/integratedauth/channel_binding.go)
uses `tls-unique` for TLS 1.2 and explicitly leaves TLS 1.3 binding unsupported in
that implementation. The rustls [upstream request](https://github.com/rustls/rustls/issues/995)
was closed as not planned by its original requester after their use case was
resolved using `tls-exporter`; it was not an explicit maintainer refusal and
does not promise an implementation. The owner chose to document and defer support,
without dependency forks/patch sets or TLS backend changes. An unsubmitted
[upstream discussion draft](upstream-rustls-channel-binding.md) records the use
case. No TLS secret logging or custom Finished reconstruction was added. The experimental server setting was
restored to the recorded baseline; certificate validation and encryption remain on.
The CU27 retest again accepted Microsoft SqlClient and rejected Linux portable
NTLM and native Windows Kerberos; upgrading the server did not close this gap.

**Portable NTLM retained-key erasure remains limited.** The pinned provider retains
an unguarded session-key array and RC4 state. Our zeroizing wrappers cannot erase
those private fields. The owner accepted documenting the limitation and
preparing an unsubmitted [upstream report draft](upstream-sspi-ntlm-zeroization.md),
without maintaining a dependency patch. This does not establish complete erasure.
See the [provider review](rust-authentication-provider-review.md) and the
[cross-client findings](rust-python-authentication-limitations.md).

## Remaining acceptance and campaign closure

Local all-feature regression: **252 passed, 61 live checks ignored**. The changed
18452/18456 configuration cases pass; strict all-feature Clippy passes. Thirteen
local infrastructure/configuration tests pass. The native MSVC Windows full regression also passed **252 tests, 61 ignored,
zero failures**. Strict native workspace/all-target Clippy also passes, including
the isolated SSPI crate. Native lifecycle and encryption results above were
executed against the Windows server; they are separate from these local suites.

Still distinguish unexecuted gates: duplicate-SPN isolation, live credential rotation/recovery, native late-call
cancellation stress, full privacy/capture corpus and expiry/teardown rehearsal.
Existing controlled tests cover portions of these contracts but are not fresh
Microsoft/platform acceptance for every scenario.

No teardown has occurred. Expiry is **2026-10-19 04:43:47.946868 UTC** (23:43 CDT
October 18). Paid start **00:47:35.142494 UTC** remains in the original cost ledger,
including the early VM replacement incident. The planning guard reserves
**$6.9369** for the full allocation window plus transfer/cleanup margins, below
the $10 campaign ceiling; this is not actual billing or a cloud hard spending cap.
The $1 target is not promised while retaining the lab for review.
At the final 02:45 UTC checkpoint all four VMs were running with the recorded
expiry and auto-deleting boot disks. Approximately two hours of runtime had
elapsed; the list-price compute/disk estimate is about $1.15 before transfer,
with actual billing still unverified.

Normal teardown follows review/fix/retest. Hard expiry/budget remain safety limits.
After closure, reconcile expiry-deleted VMs if necessary, destroy lab resources,
verify scoped inventory and state, then shut down the project and verify billing
detachment. Preserve local state and secrets until those checks pass.
