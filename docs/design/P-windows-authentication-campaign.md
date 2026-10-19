# P · Windows Authentication and the Transient GCP Campaign

**Where this sits:** The remaining required Windows stage of [D-65](4-decisions.md) after local Rust encryption acceptance.

**After reading this you can** review the provider/credential boundary and the proposed lab, supply the missing deployment constraints and understand the final acceptance/teardown gates.

Status: the owner has selected Terraform setup/teardown in `infra/gcp/`, parallel
to `infra/azure/`. The [development and test plan](../../infra/gcp/README.md)
specifies six iterations, a login/lifecycle test matrix and teardown evidence.
The owner clarified that the lab belongs in a new dedicated GCP project and that
authentication providers are subjects of the testing. Portable explicit-credential
and native Windows paths will be evaluated; support claims depend on evidence.
The owner supplied a $10 total campaign ceiling, with $1 or less expected as the
target, and requested progress updates. Keep the lab through reviewed acceptance,
fixes and retests; do not destroy on the first completed test run. The earlier
one-hour expiry proposal is superseded by a priced safety deadline covering that
cycle, within the $10 ceiling. Reuse the previous project's billing account;
resolve its ID, project permissions and final resource prices before deployment.
The separate Windows runner was deployed for the native acceptance phase;
the owner subsequently authorized teardown, verified on 2026-10-19 at 04:29 UTC.
Implementation is in progress on `rust-client`: optional pinned portable
providers, an isolated native Windows adapter, protocol/shell continuations and
local scenarios are implemented. See the [provider source review](experiments/rust-authentication-provider-review.md)
for the documented NTLM erasure limitation. The dedicated Terraform project and lab VMs have
been provisioned and configured. The [live checkpoint](experiments/rust-gcp-authentication-evidence.md)
records 64 passing Microsoft login/transport combinations, independent witnesses,
and post-login regression evidence. Required Extended Protection fails because
the current TLS API cannot supply SQL Server's `tls-unique` binding; the TLS
dependency changes and NTLM erasure correction are deferred by owner decision.
Document the limitations and prepare potential upstream reports; no dependency
forks/patch sets or TLS backend changes are planned. See the
[cross-client findings](experiments/rust-python-authentication-limitations.md).
Upstream tracking: [rustls #995](https://github.com/rustls/rustls/issues/995)
is closed as not planned by its original requester; our SQL Server follow-up is
an unsubmitted draft. The [sspi erasure report](experiments/upstream-sspi-ntlm-zeroization.md)
is also a draft, with no verified upstream ticket recorded for that finding.
Wider acceptance remains open; positive logins do not close those gates.
Lab/resource removal and project shutdown are verified in the follow-up report.
The [follow-up development plan](experiments/gcp-authentication-development-plan.md)
separates confirmed Python corrections, public API checkpoints, remaining Rust
platform tests and final cross-client acceptance/cleanup into six iterations.
The [implementation checkpoint](experiments/gcp-authentication-follow-up-evidence.md)
records completed privacy/bounds/SQL-refresh corrections, fresh platform tests
and two pending provider/configuration decisions. Built-in Python provider worker
isolation is deferred to the roadmap backlog.

Intent: finish the agreed Rust Windows-authentication scope against an actual
Windows/domain SQL Server, retain independent evidence and remove the lab. Keep
Entra, Azure-specific providers, enclaves and the certificate-store AE provider
outside this campaign (D-65).

## Providers under test

Planned test paths: an optional authentication-provider interface with a pinned,
reviewed `sspi` adapter for portable explicit-credential NTLM/Kerberos, plus native
Windows SSPI for signed-in credentials. The protocol core exchanges opaque
SSPI tokens; it does not implement another password/hash/Kerberos algorithm.
The crate documents both portable providers and native Windows use:
[sspi documentation](https://docs.rs/sspi/latest/sspi/),
[maintainer repository](https://github.com/Devolutions/sspi-rs).

An operating-system-only alternative would reduce responsibility for
portable authentication crypto, but requires compatible system GSSAPI/NTLM
providers and installed credentials on each client platform. It can make NTLM
from this macOS development location harder to reproduce.

Keep provider implementation, authentication method and credential source
separate in the acceptance matrix. Test both portable and native paths rather
than choosing a supported provider from documentation alone. Verify the selected
release, credential/key destruction paths and actual Windows interoperability.
Do not promise existing-ticket-cache/keytab support until the selected adapter
has demonstrated it.

## Concepts and contracts

| Concept | Meaning / ownership |
|---|---|
| Authentication selection | Explicit SQL, NTLM, Kerberos or Negotiate policy. SQL remains independent. A Kerberos requirement must fail rather than silently succeed through NTLM. |
| Credential source | Application-owned comparable configuration; explicit credentials or native signed-in identity. Preserve coherent snapshots, credential reread on authentication failure, and password-free Debug/capture. |
| Security context | Unique provider context for one physical opening. New context for redirect/recovery; never clone a live token exchange into a pool borrower. |
| Service identity | Explicit SQL SPN (`MSSQLSvc/host:port`) associated with the authenticated target, separate from TCP destination and TLS hostname. |
| TLS binding | Verified peer identity and channel-binding input supplied to providers that support it. No certificate-verification bypass to make authentication pass. |
| Token continuation | Bounded opaque challenge/reply messages during login; normal SQL is unavailable until provider and server completion agree. Mask SSPI bytes in capture, replay and inspection. |
| Worker lifetime | Provider/KDC operations respect the opening deadline and cancellation. Late work cannot install a session; provider handles and owned secrets are destroyed on every exit. |
| Authentication evidence | Server-reported principal plus `auth_scheme` on the actual test session. Provider selection alone is not proof. |

Implement controlled success, refusal, truncated/oversized challenge, additional
round trip, provider error, stalled KDC, cancellation and late-result tests before
starting the paid window. Keep protocol/provider failures distinct from SQL
execution uncertainty; never retry application SQL to repair a failed login.

## Concrete lab proposal

| Resource | Proposed starting shape | Purpose |
|---|---|---|
| Dedicated new GCP project and isolated VPC/subnet | Explicit billing/parent and region/zone; no production peering | Campaign resource ownership; private domain/DNS/SQL traffic |
| Windows Server 2022 DC | 2 vCPU, 8 GiB, 64 GiB auto-deleted boot disk | Disposable `tds.test` AD/DNS; users, SQL service SPNs |
| Windows Server 2022 SQL VM | 2 vCPU, 8 GiB, 64 GiB auto-deleted boot disk | Install SQL Server Developer; domain membership, TCP, Browser, verified TLS; native Windows runner |
| Linux runner | 2 vCPU, 8 GiB, 30 GiB auto-deleted boot disk | Python baseline, Kerberos tools, Rust build/tests, SSH administration |
| Separate Windows runner (native phase only) | 2 vCPU, 8 GiB, 64 GiB auto-deleted boot disk | Domain identity, remote native SSPI/SqlClient and native Rust acceptance |

The Windows runner is a separate domain-joined host: a connection originating on the SQL
VM cannot establish remote Kerberos acceptance. Microsoft's
[SPN guidance](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections?view=sql-server-ver17)
distinguishes local NTLM from remote Kerberos. Keep development builds off the DC.
Enable the extra runner only for its test phase and include it in the cost review.

Use bare Windows images with Developer installation to avoid accidentally
selecting a paid SQL Server edition. Verify current image/installer availability
and region-specific Windows/CPU/disk/IP/egress prices before apply. A dollar budget
is a review limit, not a hard cloud billing cap.

Administration: SSH public keys, Linux jump host, private Windows OpenSSH. Only
the approved client CIDR can reach the jump host and the external SQL/Browser
ports needed for development-location checks. Other Windows/DC ingress stays
private. Ephemeral external IPs can supply bootstrap egress without creating a
NAT gateway. Host identity must be verified through the authenticated cloud API
before trusting first SSH connections.

Keep passwords out of Terraform/startup metadata and command-line arguments.
Create credentials in protected local files; deliver them over the authenticated
SSH connection's stdin into protected guest configuration. Use a protected local
SQL setup configuration file, then remove it. Export only the test CA's public
certificate and redacted evidence. Review guest logs before retaining them.

Every VM has an explicit absolute expiry and automatic DELETE action, with
attached boot disks set to auto-delete. Absolute expiry avoids extending the
window through guest restarts. Google documents the supported
[VM runtime limits](https://docs.cloud.google.com/compute/docs/instances/limit-vm-runtime)
and Terraform exposes `termination_time` / `instance_termination_action` in
[google_compute_instance](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance).
Expiry is a fallback: still run Terraform destroy and verify inventory.

## Campaign and closure

1. Prepare/validate project and lab Terraform roots in `infra/gcp/` and configuration locally. Require a new project,
   zone, expiry, client CIDR and cost review; never inherit the production default.
2. Provision, configure domain/DNS/time/SPNs/TLS and prove readiness. Check Python
   and native Windows SqlClient first to separate fixture failures from Rust bugs.
3. Accept local and domain NTLM, explicit Kerberos, native signed-in Windows
   authentication and any approved negotiation fallback. Assert actual schemes,
   including refused credentials and wrong SPNs.
4. Exercise native Windows builds/runtime and real Browser queries. Repeat the
   applicable TLS 7.4/8.0, plain/MARS, pool credential-refresh, recovery and
   cancellation paths with authenticated sessions.
5. Review results while the lab is available; resolve follow-up changes and
   repeat affected tests in the same deployment. Export commands, versions,
   redacted captures, scheme/principal assertions and results. Normal destroy
   follows reviewed acceptance and evidence export, not a suite's exit code.
   Warn before budget/expiry forces cleanup of unfinished work; abandoned or
   unrecoverably interrupted campaigns still require teardown. Keep state until scoped
   inventory confirms no VMs, disks, reserved addresses, snapshots, NAT gateways,
   buckets or other billable lab leftovers. Then destroy the dedicated project
   root, verify shutdown/billing detachment, and mark the Rust scope complete.
