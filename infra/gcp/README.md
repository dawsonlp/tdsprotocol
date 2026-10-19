# Transient GCP Windows authentication lab — development and test plan

Status: deployed and configured; interoperability checkpoint recorded. This is the GCP sibling of
[`infra/azure`](../azure/README.md). Terraform owns provisioning and teardown;
guest configuration and test execution have separate, resumable commands.
The [live checkpoint](../../docs/design/experiments/rust-gcp-authentication-evidence.md)
records 64 passing login/transport combinations on SQL Server 2022 CU27 and remaining security/lifecycle
gates. Full acceptance and verified teardown remain open. See the
active checkpoint in [HANDOVER](../../HANDOVER.md).

Owner clarification: use a **new dedicated GCP project**, not one of the existing
projects. The authentication providers are subjects of the campaign: implement
and evaluate the portable explicit-credential and native Windows paths, then
base supported-provider claims on the results. No provider is accepted merely
because its documentation lists NTLM or Kerberos.

Billing instruction: reuse the billing account from the owner's last project.
The account ID and previous project association were verified through the new
project's Billing API; the ID stays in ignored project inputs. Initial CLI reads
used a disabled SDK consumer, resolved without enabling APIs on existing projects.

Cost instruction: **USD 10 maximum for the entire campaign, including retries;
USD 1 or less is the target, not a promise.** Keep the owner updated on the
preflight estimate, paid start, review/fix/retest progress, expected overruns/
retries and teardown evidence. The owner explicitly prefers retaining one lab
through full acceptance and necessary fixes over premature teardown/reprovision.
The owner delegated routine naming, location, sizing and runtime choices within
these constraints; do not ask for the same budget decision again.

Vision: finish the agreed Rust Windows-login scope with evidence from real
Windows/domain SQL Server sessions, then remove the entire paid test environment.
This is a disposable development lab, with no availability or production role.
The protocol/provider contracts are in
[design P](../../docs/design/P-windows-authentication-campaign.md).

## Scope and acceptance

| Login capability | Required evidence | Client locations |
|---|---|---|
| SQL username/password | Existing behavior still works on Windows SQL Server | macOS, Linux, Windows |
| Explicit local Windows NTLM | Local SQL-host account, actual `NTLM` session | macOS and Linux; Windows portable adapter if selected |
| Explicit domain NTLM | Domain account, actual `NTLM` session | macOS, Linux, Windows |
| Explicit domain Kerberos | Correct SQL SPN, actual `KERBEROS` session; wrong SPN fails | Linux and Windows; macOS only with approved private KDC connectivity |
| Negotiate | Correct SPN selects Kerberos; deliberately permitted fallback selects NTLM | Linux and remote Windows; portable adapter where supported |
| Native Windows signed-in identity | No application password; remote TCP session under the intended domain user | Separate domain-joined Windows runner |

Each required row must pass or be explicitly returned to the owner as an unmet
gate. Installation or a successful generic connection is insufficient. Capture
`SUSER_SNAME()`, `ORIGINAL_LOGIN()`, `DB_NAME()` and the actual session's
`net_transport`, `auth_scheme`, `encrypt_option` and `@@SPID`. Save SQL Server,
OS, provider and client versions alongside results. Assert expected values.

Keep three separate dimensions in each result: authentication method
(NTLM/Kerberos/Negotiate), provider implementation (portable `sspi` or native
Windows SSPI), and credential source (explicit account or signed-in identity).
Run portable explicit credentials on macOS/Linux and Windows where supported;
run native SSPI on the remote Windows runner. Python and SqlClient are independent
fixture witnesses, not substitutes for accepting the Rust provider adapters.

Ticket-cache/keytab APIs are a separate credential-source question: the existing
Python ticket-cache test is useful as a fixture witness, but does not establish
Rust support. Do not silently add these APIs or silently substitute passwords.
Entra, Azure SQL features, Key Vault, Windows certificate-store Always Encrypted,
enclaves, attestation and multi-domain delegation are outside this campaign.
Existing local-key Always Encrypted remains a regression check, not a new provider.

## Parallel layout and ownership

Implemented files and planned acceptance additions:

```text
infra/
  azure/                     existing Azure definitions and historical campaign
  gcp/
    README.md                this plan and eventual runbook
    .gitignore               local state, plans, credentials and raw artifacts
    project/                 separate Terraform root/state: dedicated project,
                             billing association and required API enablement
    versions.tf              Terraform/provider constraints; commit provider lockfile
    main.tf                  lab resources in the project created by project/
    variables.tf             required deployment inputs and validation
    network.tf               isolated VPC/subnet and scoped firewall rules
    vms.tf                   DC, SQL, Linux and optional Windows runner
    outputs.tf               public inventory/endpoints only
    terraform.tfvars.example non-secret placeholders only
    lab.py                   prepare, cost, plan/apply, status, destroy/verify
    configure.py             verified SSH, protected guest setup/certificates
    runner.py                current source snapshots, hashes and native builds
    campaign.py              asserted login matrix and protected evidence
    scripts/                 GCP bootstrap, AD/DNS/SPNs/TLS/SQL and runners
    tests/                   local plan/configuration/cleanup contract tests
```

Terraform owns cloud resource creation/deletion, including the dedicated project.
Use separate project and lab states so lab deletion/inventory can be verified
while the project is still accessible, before shutting down the project. Keep
both states protected locally, outside that project's lifecycle.
Scripts own guest setup and
readiness. Rust owns login protocol and provider lifetime; the application owns
credential choice and refresh. Test code owns assertions and redacted evidence.
Do not put guest setup into opaque Terraform provisioners. Do not use `gcloud`
to create extra lab resources outside the Terraform inventory.

Azure's domain/user/SPN and SQL intent can guide equivalent scripts. Its Azure
resolver, VM/image assumptions, credential-containing Terraform outputs,
command-line passwords and certificate-verification bypasses are not the GCP
contract. Keep the existing Azure campaign usable; avoid a cross-cloud framework
until real duplication justifies one.

## Deployed resource shape

| Role | Starting allocation | Lifetime / purpose |
|---|---|---|
| DC | Windows Server 2022, 2 vCPU / 8 GiB, 64 GiB boot | Disposable `tds.test` AD, DNS, users and SQL SPNs |
| SQL | Windows Server 2022, 2 vCPU / 8 GiB, 64 GiB boot | Pinned SQL Server 2022 Developer installation, mixed auth, Browser, verified TLS |
| Linux runner/jump host | Ubuntu LTS, 2 vCPU / 8 GiB, 30 GiB boot | Private KDC access, Rust/Python witness tests, administration |
| Windows runner | Windows Server 2022, 2 vCPU / 8 GiB, 64 GiB boot | Remote native SSPI and native Rust build/runtime acceptance |

The fourth VM was added through Terraform for the native Windows phase. Testing from the SQL VM
itself cannot establish remote Kerberos: Microsoft's
[SPN guidance](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections?view=sql-server-ver17)
distinguishes local NTLM from remote Kerberos. Do not run development builds on
the domain controller. Keep the Linux VM while it is needed as the jump host;
do not assume it can be destroyed before Windows testing finishes.

This single-DC shape is deliberate for a disposable lab. Pin resolved image IDs,
SQL media/build, toolchains and provider versions before apply. Use bare Windows
images plus Developer media; do not accidentally choose a paid SQL Server image.
Verify media/download/license acceptance and disk headroom before the paid window.
The selected deployment uses `us-central1-a`, all VMs at `e2-standard-2`,
`pd-standard` boot disks and pinned bare Windows/Ubuntu images. The cost
illustration below is preliminary; billing reports may lag and are not yet
verified actual charges.

Network/configuration requirements:

- Isolated custom VPC/subnet with explicit internal addresses and campaign ID;
  no production peering. Scope private AD/DNS/KDC/RPC traffic to lab members.
- Public administration is SSH to the Linux runner from one approved client CIDR.
  Windows SSH stays private. Expose SQL TCP and Browser UDP only to that CIDR
  when needed for macOS tests. Do not expose AD, Kerberos or RDP publicly.
- macOS can test portable NTLM and Browser against restricted SQL endpoints.
  Run Kerberos on the private Linux/Windows runners; a DNS/hosts entry on the Mac
  alone does not supply KDC reachability. A VPN/KDC proxy would be a separate choice.
- Use an explicit SQL FQDN/SPN and test CA. Keep socket destination, certificate
  hostname and service identity distinct, including when using an SSH TCP tunnel.
  UDP Browser checks require a real UDP path, not an SSH TCP forward.
- Configure AD DNS, GCP internal-name resolution, clock sync, SQL service identity
  and unique SPNs explicitly. Validate DNS forward/reverse/SRV records and time
  before driver tests. Follow Google's
  [AD DNS guidance](https://docs.cloud.google.com/compute/docs/instances/windows/best-practices);
  select and record one direct-client or private-forwarding-zone arrangement.
- Bootstrap public SSH authorization without passwords in metadata. Verify host
  keys using authenticated cloud evidence before delivering secrets over stdin.
  Use protected local/guest secret files, no secret argv/environment dumps or
  startup-script contents. Application Windows accounts are distinct from the
  bootstrap administrator. No guest needs broad cloud API credentials.

## Iterations and exit gates

1. **Define the authentication contract and test corpus locally.** Prepare the
   optional portable `sspi` adapter and native Windows SSPI as the provider paths
   under test. Review a pinned dependency, license, supported targets and secret
   destruction. Define SQL/NTLM/Kerberos/Negotiate selection, explicit versus
   signed-in credentials, separate SPN/TLS identity, fallback policy and coherent
   pool configuration comparison. Compare Python first; retain SQL API behavior.
   Exit: reviewed contract and named unit/controlled-peer scenarios, no cloud spend.
   Dependency review establishes suitability to test; actual provider support
   remains contingent on interoperability and lifecycle evidence.
2. **Implement Rust integrated login against controlled peers.** Add LOGIN7
   integrated-security flags/token fields, SSPI response decoding and continuation
   packets; preserve SQL login bytes. Connect opaque provider actions to the async
   shell. Bound rounds/bytes and the entire DNS/KDC/provider/login deadline. Fresh
   context per physical opening/routing/recovery; zeroize owned secrets and discard
   late results on cancel. Mask token bodies in all observation/inspection/replay
   paths. Implement success, refusal and malformed/stalled/canceled paths before
   opening a paid lab. Exit: local feature-matrix tests, strict Clippy and rustdoc.
3. **Implement and validate the sibling Terraform lab.** Add the files above,
   protected guest configuration, explicit deployment inputs and a cost preflight.
   Validate create/destroy inventories, expiry fields, firewall scope and secret
   exclusion locally. Distinguish `gcloud` login from Terraform ADC/impersonation;
   verify project-creation/billing permissions and installers without creating
   resources. After approved project creation, verify its APIs and Windows CPU/IP
   quotas before VM provisioning. Exit: reviewed project/lab plans and a rehearsed
   failure/cleanup path.
4. **Provision and prove the fixture independently.** Start one finite campaign;
   configure DC, accounts, SQL, SPNs, TLS and Linux runner with retryable readiness
   checks across reboots. Verify SQL/NTLM with Python and Kerberos with Python's
   established provider; use remote native SqlClient on the Windows runner.
   Finish a login/identity witness before Rust attribution. Exit: healthy fixture
   with principal/scheme/TLS evidence, or a diagnosed setup failure. Retain a
   recoverable fixture for correction within the budget and expiry; clean up an
   abandoned or unrecoverable campaign.
5. **Run Rust Windows-login and lifecycle acceptance.** Execute the matrix below;
   diagnose and fix Rust with the independent witnesses available. Stage the
   Windows runner only when needed. Run native Windows build/runtime/Browser
   checks and a small local-key AE regression under authenticated sessions.
   Exit: redacted per-scenario evidence and explicit remaining failures/skips.
6. **Review, fix/retest, export evidence and close the campaign.** Review the full
   acceptance matrix and report failures, skips and uncertainties while the lab
   is still available. Resolve changes and repeat affected tests/regressions in
   that same deployment. Normal teardown follows reviewed acceptance, resolved
   follow-ups and evidence export, not simply a test process exit. Clean up an
   abandoned campaign or when expiry/budget requires it; reconcile expiry-deleted
   VMs through Terraform first. Verify
   scoped cloud inventory and empty Terraform state before deleting local secrets
   or state. Update support/acceptance/handover with observed results. Rust reaches
   this agreed completion gate only after required tests and teardown both pass.

Iterations 2 and 3 can proceed independently after their contracts are settled;
paid testing begins only once both are ready. Keep campaign execution sequential
where it mutates users/SPNs/credentials/SQL services. Do not run the established
Python and Rust mutation suites concurrently against the same fixtures.

## Test scenarios and retained evidence

| ID | Scenario | Required assertion |
|---|---|---|
| A01 | SQL login regression | Same API/wire behavior; correct SQL principal |
| A02 | Local and domain explicit NTLM | Separate accounts, remote TCP, `NTLM`, intended principal |
| A03 | Explicit Kerberos, correct FQDN/SPN | Remote TCP, `KERBEROS`, intended principal; no NTLM fallback |
| A04 | Negotiate and fallback | Kerberos with healthy SPN; isolated deliberate NTLM fallback only when policy permits; mandatory Kerberos refuses it |
| A05 | Native Windows signed-in credentials | Separate runner/process under test domain identity; remote SqlClient witness and Rust agree; no application password |
| A06 | Invalid/disabled credentials and denied SQL access | Authentication versus authorization errors distinguished; no authenticated pool connection installed; no app SQL sent |
| A07 | Missing/wrong/duplicate SPN; KDC unavailable | Deterministic policy outcome and deadline; never label NTLM as Kerberos; restore fixture before next test |
| A08 | Login continuation faults | Fragmentation, >1 continuation, truncation, oversized/empty/unexpected tokens, provider errors, early/missing LOGINACK/DONE; fail closed |
| A09 | Cancel/drop/timeout/shutdown during login/KDC work | Opening deadline includes provider work; no late session installation, leaked reusable connection or unowned worker |
| A10 | Credential refresh and pool reuse | Coherent snapshot per new physical open; reread on auth failure; stale/incompatible identities not handed to new borrowers |
| A11 | Connection loss, routing, recovery | Fresh provider context and target-bound SPN; refused reacquisition reported; no application SQL replay; synthetic routing if no real target |
| A12 | TLS 7.4/8.0 × plain/MARS | Required successful methods across four transport modes; identity/TLS assertions on each; bad CA/hostname fails before secret transmission |
| A13 | TLS channel binding / Extended Protection | Provider receives verified binding; accept correct and reject mismatched/missing binding when server policy requires it; report unsupported combinations explicitly |
| A14 | Authenticated session lifecycle | Transactions, Attention cancel/drain/reuse, explicit pool return/reset, credential change, local-key AE smoke; identities remain correct |
| A15 | Browser and native Windows runtime | Actual UDP discovery, reachable resolved port; default/core/auth/encryption builds and applicable Windows tests pass |
| A16 | Credential/token privacy | Canary scan of Debug/errors, CLI, observations, captures, inspection, replay and retained logs finds no passwords or raw SSPI tokens |
| I01 | Terraform contract | Newly created dedicated project and explicit CIDR/expiry; all disks auto-delete; no secret outputs/metadata/state inputs; no inherited production default |
| I02 | Failed test versus abandoned campaign | A failed test or completed suite retains the managed lab for review/fix/retest; campaign abandonment/unrecoverable interruption attempts cleanup; forced termination relies on absolute expiry; cleanup can resume |
| I03 | Teardown and expiry | Deliberate short expiry rehearsal; Terraform reconciliation; exact campaign inventory finds no remaining billable resources |
| I04 | Acceptance hold and retest | Results reviewed with lab available; fixes and affected regressions run in the same deployment; warnings before expiry/budget-driven cleanup; normal teardown after campaign closure |

Run the full method smoke matrix; run common post-login lifecycle regressions
with one NTLM and one Kerberos representative across all four transport modes,
plus native Windows SSPI. A controlled-peer provider proves protocol handling,
not Microsoft interoperability. A configured policy proves intent, not the
observed scheme. Skips do not count as acceptance. Record unsupported server/
provider combinations instead of weakening TLS or silently changing methods.

Evidence manifest: Git commit plus dirty-source hashes if applicable, Terraform
provider lockfile, image/media/build IDs, client/provider versions, UTC times,
campaign/host identifiers, expected/actual scheme/principal, command, exit code,
scenario outcome and redacted logs. Review raw artifacts before copying a finite
report under `docs/design/experiments/`; keep credentials, tickets and raw tokens
local and ignored. Rust publication is a separate task.

## Cost and teardown contract

The earlier one-hour expiry proposal is superseded: choose a **budget-checked
absolute safety deadline that includes setup, testing, review and fix/retest**,
shared across the deployment and fixed before the first VM is created. Price
that full window, not just expected test execution time. Do source, dependency,
installer and test preparation locally first. The $1 figure is an efficiency
target; it must not force premature teardown or reduced acceptance coverage.

Keep the managed lab available while reviewing evidence and resolving likely
follow-ups. A first green run or a recoverable failed test does not trigger
teardown. Report results and give the owner an opportunity to review before
normal campaign closure. Warn before the safety deadline or budget guard forces
cleanup; report any unfinished acceptance explicitly. Extend only after a revised
cumulative estimate passes the $10 ceiling/cleanup reserve. Do not silently
renew the deadline or keep an unattended lab indefinitely.

Preliminary list-price illustration, checked 2026-10-18, `us-central1`, USD:

| Item | Calculation | Per hour |
|---|---|---|
| Four `e2-standard-2` VMs | 4 × $0.06701142 | $0.26804568 |
| Three Windows licenses | 3 × 2 vCPU × $0.046 | $0.276 |
| Four ephemeral external IPv4 addresses | 4 × $0.005 | $0.020 |
| Subtotal before disks, data transfer and any taxes | Sum | **$0.56404568** |

This conservatively gives the DC 8 GiB instead of the proposed 4 GiB and keeps
the Windows runner alive for the full hour. Delaying its creation reduces use.
Rates: [VM/Windows pricing](https://cloud.google.com/products/compute/pricing/general-purpose?hl=en),
[external IP pricing](https://cloud.google.com/vpc/network-pricing).
The illustration does not include disk charges, egress, bootstrap delays or
retries and does not assume free credits or free-tier eligibility. Before apply,
price the exact final images/disks/network use and include a cleanup margin.
Sub-$1 is plausible for a short successful campaign; repeated setup attempts
cannot be assumed to fit that target.

Before each paid apply or lifetime extension, account for all prior attempts
conservatively from allocated resource runtimes plus unconfirmed charges; do not
treat delayed billing reports as zero spend. Refuse additional work if the
projected cumulative cost plus cleanup margin would exceed $10. Prefer stopping
new test work at an estimated $8 to reserve $2 for teardown/uncertainty; this is
a software planning guard, not a guaranteed cloud billing cap. Reduce the runtime
or resource shape if the estimate cannot meet the remaining allowance. If a
sound estimate cannot stay below the ceiling, stop before provisioning.

Required inputs: new globally unique `project_id`, billing account and parent
organization/folder if applicable, region/zone, unique campaign ID, approved
client CIDR, owner, UTC expiry, maximum spend, machine/image selections and the
Windows-runner phase. No existing/default project is permitted. Preflight must
verify project creation, billing attachment and API-enablement permissions. Link
only the new project to the selected billing account; never alter the billing
account itself or APIs/IAM/resources in existing projects. An organization or
billing account is an external input, not a resource to destroy with the lab.

Estimate the campaign as the sum of each role's hourly VM/Windows charges times
its runtime, plus disk-hours, external IPv4-hours and expected egress, including
bootstrap/compilation/SQL installation and retry margin. A budget is a review
limit, not a hard billing cap. Prepare downloads/build inputs locally first.

Every VM must use an explicit absolute `termination_time` and
`instance_termination_action = "DELETE"`, with auto-deleting boot disks. An
absolute timestamp does not renew the window on restart. See
[Compute Engine runtime limits](https://docs.cloud.google.com/compute/docs/instances/limit-vm-runtime)
and the [Terraform resource contract](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance).
Use ephemeral external IPs; avoid NAT gateways, snapshots, managed AD, paid SQL
licenses and persistent storage services for this campaign.

The campaign controller owns the lab across individual test invocations and
review/fix/retest; their exit codes must not enter a per-test destroy `finally`.
On campaign closure/abandonment or an unrecoverable controller interruption,
attempt teardown in a campaign-level `finally`/signal path. A managed review hold
must retain its explicit deadline and budget guard. Laptop loss or a forced kill
can bypass cleanup. Expiry bounds VM runtime; it does not delete every
other resource. `lab.py destroy` must work without healthy guests or test success.
It must preserve state on failure and support rerun. `verify-destroy` checks both
Terraform state and the exact project/campaign resource inventory: VMs, disks,
IPs, snapshots, forwarding rules, DNS zones, routers/NAT, firewall rules, subnet,
VPC and any campaign-created IAM/storage resources. An empty `terraform state
list` alone is not proof. After resource inventory passes, destroy the project
root and verify billing detachment/project shutdown. Report `DELETE_REQUESTED`
as shutdown, not immediate permanent deletion: Google documents a
[30-day project recovery period](https://docs.cloud.google.com/resource-manager/docs/delete-restore-projects).
Delete local state/secrets only after these checks pass; preserve redacted
inventory and shutdown evidence.

## Resumable execution

Run commands from the repository root. Keep the two Terraform states, protected
inputs and the original cost ledger until cleanup has been independently verified.
The campaign was closed at the owner's request on **2026-10-19 04:29 UTC**.
Cloud inventory verified removal of its compute/network/storage resources;
the dedicated project is `DELETE_REQUESTED`, with billing disabled/detached and
both Terraform states empty. Protected teardown evidence is retained in
`artifacts/teardown-final-verification.json`. Actual billed total is unverified.
Do not reuse its inputs, saved plans or expiry. The commands below document the
previous campaign's resumable workflow; a new campaign needs fresh inputs and
the staged bootstrap described here. Read the handover before any deployment.

Initial project creation was staged: create the unbilled project first, enable
its Billing/Resource Manager/Service Usage/IAM APIs through the bootstrap provider,
then set the protected billing input and `bootstrap_complete=true` before the
full project apply. Never change the running project's `auto_create_network`
input to imitate a new bootstrap. The defaults root was used only to import and
destroy this new project's automatically created network/rules; its state is now
empty. A fresh end-to-end bootstrap/expiry/teardown rehearsal remains a separate
acceptance gate, rather than a claimed one-command workflow.

```sh
clients/python/.venv/bin/python infra/gcp/lab.py cost
clients/python/.venv/bin/python infra/gcp/lab.py status
clients/python/.venv/bin/python infra/gcp/configure.py trust
clients/python/.venv/bin/python infra/gcp/configure.py all
```

`configure.py` verifies SSH keys via authenticated guest attributes and delivers
credentials over SSH stdin. Its full sequence is resumable, but completed SQL
certificate setup requires uploading a fresh protected PFX before rerunning the
`sql` step. Domain creation and joins include reboot/readiness checks.
`configure.py` requires the established Python environment's `cryptography`.
The Windows bootstrap runs during both specialization and later boots.

The original SQL 2022 SSEI downloader is below Microsoft's manifest minimum and
fails before downloading media. The script now downloads the Developer ISO from
Microsoft and validates its mounted setup executable's Authenticode signature.
The pinned CU27 update (16.0.4295.3, Microsoft signature and published SHA-256)
is applied after RTM installation: RTM has Microsoft bug 2042238, which breaks
strict-mode RPC and therefore encrypted parameter discovery. SQL setup runs as a bounded SYSTEM task because the public-key SSH logon failed
its user DPAPI serialization. The password-bearing INI is ACL-restricted and
deleted in `finally`. No passwords enter the task action or installer argv.

Install runner tooling with `scripts/linux-tools.sh` and
`scripts/windows-tools.ps1`; upload current client sources and use
`scripts/windows-build.cmd` for the native MSVC build. Runner provisioning/build
is distinct from successful authentication. The controller's protected source
archive is a snapshot: refresh it after source changes.

```sh
clients/python/.venv/bin/python infra/gcp/campaign.py macos --client python
clients/python/.venv/bin/python infra/gcp/campaign.py linux --client python
clients/python/.venv/bin/python infra/gcp/campaign.py windows --client sqlclient
clients/python/.venv/bin/python infra/gcp/campaign.py macos --full
clients/python/.venv/bin/python infra/gcp/campaign.py linux --full
clients/python/.venv/bin/python infra/gcp/campaign.py windows --full
clients/python/.venv/bin/python infra/gcp/campaign.py windows --portable --full
```

These smoke probes assert principal, original login, scheme, database, encryption
and transport; they do not accept the wider lifecycle matrix. Linux requires
private DNS/hosts and `/etc/krb5.conf` for `TDS.TEST` at `10.43.1.4`.
The Windows controller creates a short-lived domain-user scheduled task using
the protected OS logon password. `windows-task-rights.ps1` grants that test user
batch-logon rights on the runner while preserving existing rights; it does not
add the user to the Windows administrators group. Native Rust receives no application username or
password. Task registration is removed after each probe. Protected artifacts
retain redacted outputs; never copy them wholesale into Git.

## Deployment decisions and remaining gate

- Authentication providers: portable explicit credentials and native SSPI are
  paths to implement and test; audit the selected release, then establish support
  from observed results. [Library capability documentation](https://docs.rs/sspi/latest/sspi/)
  is a starting point, not interoperability evidence.
- Lab: separate Windows runner and all four fixed-size VMs were deployed and
  tested, then destroyed on 2026-10-19 at the owner's request.
- Deployment: name the new dedicated project, resolve the existing billing
  account/parent and choose the final zone after pricing/availability checks.
  The owner supplied the $10 campaign ceiling/$1 target and required a retained
  review/fix/retest window before teardown. Select a priced safety deadline
  accordingly. Naming, location and sizing are routine implementation choices.
  GCP login, token-backed Terraform, project creation/billing attachment and
  regional CPU/disk/IP quotas were verified. No service-account key was created.

Retain available infrastructure through review/fix/retest within the fixed budget
and expiry, checking live inventory before resuming. The owner chose documented
limitations and potential upstream reports for portable NTLM retained-key erasure
and SQL Extended Protection, without dependency forks or TLS backend changes.
See the [provider review](../../docs/design/experiments/rust-authentication-provider-review.md)
and [follow-up development plan](../../docs/design/experiments/gcp-authentication-development-plan.md).

## Follow-up corrections and repeatable checks

The [follow-up evidence](../../docs/design/experiments/gcp-authentication-follow-up-evidence.md)
records implemented changes, retained failures and pending API/worker choices.

```sh
clients/python/.venv/bin/python infra/gcp/followup.py sql-refresh
clients/python/.venv/bin/python infra/gcp/followup.py sql-lifecycle
clients/python/.venv/bin/python infra/gcp/followup.py rust-lifecycle
clients/python/.venv/bin/python infra/gcp/campaign.py macos --client python --full
clients/python/.venv/bin/python infra/gcp/campaign.py linux --client python --full
clients/python/.venv/bin/python infra/gcp/campaign.py windows --client python --full
clients/python/.venv/bin/python infra/gcp/campaign.py windows --client python --portable --full
```

The Windows Python branch requires the existing runner to be prepared with
`scripts/windows-python.ps1`, which pins the official Python 3.14.8 installer,
checks its published hash and Authenticode signature, installs the test extras
and grants the domain test user read/execute access to runtime/source files.
The installer reference is the [official release page](https://www.python.org/downloads/release/python-3148/).
It adds no VM or external service. `runner.py --source-only` refreshes a source
snapshot without compiling Rust. Keep all Windows scheduled probes sequential;
run latency/cancellation checks separately from native compilation. Timeout
diagnostics retain Scheduler result and non-secret phase markers.
