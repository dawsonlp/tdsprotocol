# P · Windows Authentication and the Transient GCP Campaign

**Where this sits:** The remaining required Windows stage of [D-65](4-decisions.md) after local Rust encryption acceptance.

**After reading this you can** review the provider/credential boundary and the proposed lab, supply the missing deployment constraints and understand the final acceptance/teardown gates.

Status: proposal awaiting the owner's authentication-provider decision and explicit
GCP project, location, maximum spend and test-window duration. No cloud resource
has been created and no authentication dependency has been added.

Intent: finish the agreed Rust Windows-authentication scope against an actual
Windows/domain SQL Server, retain independent evidence and remove the lab. Keep
Entra, Azure-specific providers, enclaves and the certificate-store AE provider
outside this campaign (D-65).

## Provider decision

Recommended: an optional authentication-provider interface with a pinned,
reviewed `sspi` adapter for portable explicit-credential NTLM/Kerberos, plus native
Windows SSPI for signed-in credentials. The protocol core exchanges opaque
SSPI tokens; it does not implement another password/hash/Kerberos algorithm.
The crate documents both portable providers and native Windows use:
[sspi documentation](https://docs.rs/sspi/latest/sspi/),
[maintainer repository](https://github.com/Devolutions/sspi-rs).

Alternative: operating-system providers only. This reduces responsibility for
portable authentication crypto, but requires compatible system GSSAPI/NTLM
providers and installed credentials on each client platform. It can make NTLM
from this macOS development location harder to reproduce.

This is an architectural choice because it changes credential ownership,
dependencies, supported credential sources and platform requirements. Acceptance
of this proposal does not establish provider correctness; verify the selected
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
| Isolated VPC/subnet | One explicitly chosen project/region/zone; no production peering | Private domain/DNS/SQL traffic |
| Windows Server 2022 DC | 2 vCPU, 4 GiB, 64 GiB auto-deleted boot disk | Disposable `tds.test` AD/DNS; users, SQL service SPNs |
| Windows Server 2022 SQL VM | 2 vCPU, 8 GiB, 64 GiB auto-deleted boot disk | Install SQL Server Developer; domain membership, TCP, Browser, verified TLS; native Windows runner |
| Linux runner | 2 vCPU, 8 GiB, 30 GiB auto-deleted boot disk | Python baseline, Kerberos tools, Rust build/tests, SSH administration |

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

1. Prepare/validate Terraform and configuration locally. Require explicit project,
   zone, expiry, client CIDR and cost review; never inherit the production default.
2. Provision, configure domain/DNS/time/SPNs/TLS and prove readiness. Check Python
   and native Windows SqlClient first to separate fixture failures from Rust bugs.
3. Accept local and domain NTLM, explicit Kerberos, native signed-in Windows
   authentication and any approved negotiation fallback. Assert actual schemes,
   including refused credentials and wrong SPNs.
4. Exercise native Windows builds/runtime and real Browser queries. Repeat the
   applicable TLS 7.4/8.0, plain/MARS, pool credential-refresh, recovery and
   cancellation paths with authenticated sessions.
5. Export commands, versions, redacted captures, scheme/principal assertions and
   results. Destroy on success, failure or interruption. Keep state until scoped
   inventory confirms no VMs, disks, reserved addresses, snapshots, NAT gateways,
   buckets or other billable lab leftovers. Then mark the Rust scope complete.
