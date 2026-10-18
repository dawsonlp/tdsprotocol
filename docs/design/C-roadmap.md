# C · Roadmap

**Where this sits:** after [Building the Client](B-building-the-client.md), whose milestones M1–M15, M17 and M18 are built. It sets out what comes next.
**After reading this you can** say what each phase delivers, what it builds on, and which decisions it needs before it starts.

> **Status:** Rust first, then Python conveniences, then application drivers (D-63). On 2026-10-18 the user agreed the Rust completion sequence and scope (D-65): finish local work including local-key Always Encrypted, create a transient GCP Windows lab, implement and validate Windows authentication, then destroy the lab. Entra and Azure-specific providers are deferred. These are completion requirements, not claims of implementation or deployment. Each affected API/provider design is agreed before its code is written.

---

## The phases

| # | Phase | Delivers | Builds on |
|---|---|---|---|
| 1 | **A Rust client** | The same driver in Rust, with explicit ownership/permissions and the same learning intent | The design pages, and the Python code and tests |
| 2 | **Conveniences** (M16) | The standard patterns of use in one call each, in Python, asynchronous and synchronous | The driver's public surface (D-39) |
| 3 | **Application drivers** | DB-API 2.0 for Python, and possibly other standard interfaces | The conveniences |

Phase 3 depends on phase 2. Rust does not depend on completing Python M16.

## 1 · A Rust client

**Goal:** a second client that follows the same design in Rust. Its code teaches the protocol as the Python code does, with the same names, and links to the same reference pages.

**Development path:** establish the local Python baseline, analyze its code, agree ownership/permissions and exact representations, then implement Rust in small tested slices. The detailed [Rust development plan](D-rust-development.md) starts with those rules and keeps runtime/API choices explicit. [Python baseline evidence](E-python-baseline.md) separates offline, local-live and remote validation.

**How the Python client helps:**
- **The design pages are the specification for both clients.** Each Rust module names the page it implements, as each Python module does.
- **The sans-I/O core can be ported part by part:** the definitions and the codec first, then the procedures, then a shell (D-24, D-27).
- **The tests' data can be shared:** MS-TDS's own samples, the responses captured from SQL Server, and the generated collation table. A capture (D-12) recorded by either client can be replayed through the other.
- **The Python client is a reference to compare against.** For fixed deterministic inputs and options, both clients must encode the same protocol bodies and read the same semantic response record. Variable session fields, timestamps, nonces and TLS ciphertext require explicitly scoped comparisons.
- **The live tests run against the same SQL Server container**, with the same scenarios.

**Implemented baseline:** verified TDS 7.4/8.0 TLS, SQL authentication, movable
channels, cancellation/cleanup, MARS, whole-connection pooling/configuration,
routing and eligible recovery; exact scalar/large/special values, typed calls,
streaming, TVPs, bulk and transaction requests; native offline replay and shared
connection/scalar-query field inspection. The [support matrix](../../clients/rust/SUPPORT.md)
and [acceptance record](../../clients/rust/ACCEPTANCE.md) distinguish implementation,
local evidence and remaining gaps. The Rust crate is unpublished.

### Rust completion sequence · agreed 2026-10-18 (D-65)

**Outcome:** a dependable, literate Rust client with an explicit supported scope,
local-key Always Encrypted, tested Windows authentication and reproducible test
evidence. Completing this scope does not mean complete Python feature parity.

| Stage | Work | Exit evidence |
|---|---|---|
| 1 · Finish locally | Complete agreed observation/replay gaps, supported-scope correctness, readability/API/package review and repeatable checks. Implement local-key Always Encrypted, including wire metadata, normalization, authenticated encryption and parameter orchestration. Settle the supported Rust/platform floor. | Local regressions, targeted malformed/fragmented-input testing, live Docker matrices and independent .NET mutual encrypted read/write and deterministic-lookup checks. Record intentional exclusions. No cloud VMs are needed for development in this stage. |
| 2 · Create the transient Windows lab | Add Terraform and configuration/test/teardown tooling under `infra/gcp/`, alongside the historical Azure setup. Provision only when the Windows test campaign is ready. | Domain, DNS/time, SPNs, verified TLS, SQL Server and runners are ready. Existing Python Windows tests and an independent Windows client establish that the environment works before diagnosing Rust failures. |
| 3 · Implement and validate Windows authentication | Agree and implement the Rust token-provider contract and selected adapters. Test NTLM local/domain logins, Kerberos and negotiated authentication. Run native Windows client checks and actual SQL Server Browser acceptance. | Positive and negative cases, actual authentication scheme assertions (no silent Kerberos-to-NTLM success), credential redaction, cancellation/failure handling and relevant pool/recovery behavior. Exercise both TDS versions and plain/MARS where supported. |
| 4 · Retain evidence and destroy | Export redacted results/captures, destroy the Terraform-owned lab and check for residual resources. Reconcile support, acceptance and release documentation. | Required tests passed without unavailable-environment skips; Terraform state and cloud inventory confirm owned resources are gone. Mark this scoped Rust phase complete; M16 follows. Publication remains a separate action. |

**Infrastructure proposal:** two small Windows Compute Engine VMs (a disposable
AD domain controller and a domain-joined SQL Server), plus a small Linux runner
for Kerberos. Native Windows tests can run on the SQL VM. Install SQL Server
Developer on a Windows base image to avoid choosing a paid SQL Server edition
unnecessarily. Keep the lab in its own VPC, restrict administration and database
access, and keep DNS/Kerberos/Browser tests inside the lab where appropriate.
Retain the Azure implementation; adapt its test scenarios and configuration
intent rather than copying Azure-specific DNS, image or remote-command settings.

**Cost/lifecycle requirements:** explicit target project, region, resource sizes,
current cost estimate and maximum test window before apply; no reliance on the
developer's default project. Use a fixed expiry that survives guest reboots, with
automatic VM deletion and auto-deleted test disks as a fallback. Normal completion
and failure paths must run full teardown and inventory checks for VMs, disks,
addresses and any other lab-owned billable resources. VM deletion alone is not a
claim that the whole lab is destroyed. Preserve state until cleanup is verified;
do not print or commit secrets. Do not keep the lab running between development
sessions. Detailed networking, secret delivery and provider designs remain to be
reviewed before implementation.

**Explicitly deferred from this Rust completion:** Entra/federated authentication,
Azure Key Vault and Azure-specific login features/providers; Windows certificate-store
key-provider support and enclave/attestation work. The local-key choice does not
require the Windows certificate store. These capabilities remain visible in the
support matrix rather than being described as implemented. A GCP Windows lab does
not validate Azure SQL service behavior or genuine remote failover.

**Feasibility checked 2026-10-18:** Google documents [Windows/SQL Server Compute Engine VMs](https://docs.cloud.google.com/compute/docs/instances/sql-server/creating-sql-server-instances),
[Active Directory on Compute Engine](https://docs.cloud.google.com/compute/docs/instances/windows/best-practices)
and [automatic VM termination with Terraform](https://docs.cloud.google.com/compute/docs/instances/limit-vm-runtime).
Microsoft documents [Entra configuration without Azure Arc](https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/microsoft-entra-authentication-sql-server-enable-without-arc?view=sql-server-ver17),
but it still requires a tenant and application permissions, which are unavailable
for this campaign. No GCP deployment, quota or IAM acceptance is established by
this documentation review.

## 2 · Conveniences

**Goal:** each common pattern of use takes one call, and still shows what the server did (D-35).

**What it contains** (already agreed):
- **The serial channel's conveniences** (D-37): `query`, `fetch`, `fetch_value`, `call`, `prepare`, `describe` and `transaction`. Each one is an exchange and a way of reading its response, and each checks the response's shape.
- **A synchronous entry point** with the same shape as the asynchronous one (D-38).
- **A bulk-load helper** that writes the `INSERT BULK` statement from the columns (D-50).
- **An error translator** ([Done When › M16](5-done-when.md#m16--the-convenience-layer-and-the-synchronous-shell)).
- **Parameterized statements** whose SQL types are inferred from Python values. D-39 places type inference here, outside the driver.

It uses only the driver's public surface. If it needs something more, the driver is missing it (D-39).

**To decide before building:**
- Where it lives: a module of the `tds` package, or a package of its own.
- How each SQL type is inferred from a Python value, for example the length of a `str` parameter, a `Decimal`'s precision and scale, and a `datetime`'s type.
- How the synchronous shell runs. It could be a second shell around the same sans-I/O core, using blocking sockets (D-24), or it could run the asynchronous shell on an event loop of its own.

## 3 · Application drivers

**Goal:** standard interfaces that existing applications and libraries already use, built around the driver.

- **DB-API 2.0** (PEP 249), for Python: a package that depends on `tds` (D-39), built on the conveniences. Two of its questions are recorded in Decisions › Deferred: how long a serial channel lives (D-25), and what happens when a cursor runs while another has unread rows (D-26).
- **Other standard interfaces, possibly:** each one a layer around the driver, such as an SQLAlchemy dialect for Python, built on DB-API. Which ones, and in what order, is decided when phase 3 starts.

**To decide before building:**
- Whether each driver lives in this repository or in a repository of its own.
- DB-API's parameter style, and how its type objects map to the driver's types.
- How DB-API's synchronous interface uses phase 2's synchronous entry point.
- D-25 and D-26.

---

**Next:** [Decisions](4-decisions.md) · **Decisions:** D-24, D-27, D-35, D-37–D-39, D-45, D-50, D-63, D-65
