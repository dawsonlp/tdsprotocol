# Rust Azure live campaign: evidence (2026-10-20)

**Where this sits:** the live acceptance campaign that follows the
[code-complete checkpoint](rust-azure-code-complete.md), run on the transient
[`infra/azure`](../../../infra/azure/README.md) deployment. It also holds the live
results of Part B (exceptions B-1 to B-11).

**After reading this you can** see which Azure behaviors Rust has now shown
against real services, how each compares with Python and Microsoft's SqlClient,
what the campaign found, and what remains unproven.

## The deployment

- **Where:** subscription SW-Dev, resource group `rg-tds-rust-azure`, applied
  2026-10-20 18:59 UTC. 39 resources: Azure SQL (serverless, VBS enclave, Redirect),
  Key Vault, a domain controller, SQL Server 2022 on Windows, an Ubuntu runner
  with a managed identity, a service principal, a budget and the self-delete
  Logic App.
- **Limits:** the group deletes itself at 2026-10-21 18:59 UTC; budget USD 25.
- **Clients:** Rust at branch `rust-azure-integration`; Python `tds` at the same
  commit; Microsoft.Data.SqlClient 7.1.1 in Microsoft's .NET 10 SDK image.

## Results

✅ means the check passed against the real service. Rust's test names are in
[`azure_live.rs`](../../../clients/rust/tests/azure_live.rs) and
[`certstore_live.rs`](../../../clients/rust/tests/certstore_live.rs); Python's are
`test_azure_live.py`, `test_kerberos_azure.py`, `test_certstore_windows.py` and
[`paired.py`](../../../infra/azure/paired.py).

| Scenario | Rust | Python | SqlClient |
|---|---|---|---|
| Entra token up front: TDS 7.4/8.0 × MARS on/off, routed through the gateway | ✅ 2 token requests (gateway, destination) | ✅ | — |
| Entra token fetched mid-login: same matrix | ✅ 1 token request | ✅ 1 callback | — |
| SQL login baseline, 7.4/8.0 | ✅ | ✅ | — |
| Service principal, both flows | ✅ | ✅ same login and user | ✅ |
| Managed identity (runner), both flows; vault sign and verify | ✅ | ✅ (logins) | — |
| Azure-only features: ACKs `1/1/0/1` | ✅ refuses the 3 enabled, allows the absent one | ✅ continues (PY-AZ-06) | — |
| Entra pools, MARS on/off: tokens per physical login, none per reuse | ✅ | — | — |
| Unusable token | ✅ 18456 before SQL; token not in the error | — | — |
| NTLM local and domain, wrong password (18452), 7.4/8.0, verified TLS | ✅ | ✅ (unverified TLS) | — |
| SQL Server Browser | ✅ | ✅ | — |
| Kerberos and Negotiate from the ticket cache, 7.4/8.0, scheme `KERBEROS` | ✅ | ✅ | — |
| Key Vault values, enclave `LIKE 'A%'` → Ada, Alan; `salary > 50000` → Alan, Grace | ✅ own and Python's tables | ✅ own and Rust's tables | ✅ both clients' tables |
| Windows certificate store (non-exportable CNG key): mutual wrap/unwrap/sign with Python; read Python's value (41000); own round trip (52000) | ✅ | ✅ | — |

### Part B, live

| Item | Result |
|---|---|
| B-2 empty token | ✅ Azure closes the connection during login without an error token, in both flows; Python observes the same |
| B-4 Key Vault | ✅ missing key → provider failure; tampered envelope → authentication failure; after rotating a dedicated key, a **pinned** key path still unwraps and a **versionless** path no longer verifies |
| B-5 certificate store | ✅ a missing thumbprint and the wrong store fail to open; a key wrapped by another certificate is an authentication failure |
| B-6 enclave after pool return | ✅ a new lease re-authorizes keys under a new session; queries return the same rows |
| B-7 tickets | ✅ no ticket → `GSS_S_NO_CRED` (Kerberos and Negotiate); expired → `GSS_S_FAILURE` with `KRB5KRB_AP_ERR_TKT_EXPIRED` (Kerberos) or SPNEGO's own minor (Negotiate) |
| B-8 wrong Windows password | ✅ 18452 (also above) |
| B-9 CLI | ✅ `tds --auth entra-upfront` and `entra-deferred` log in as the CLI user |
| B-10 Entra × MARS × pool | ✅ (pool test with MARS on) |

## What the campaign found

One driver defect was found and fixed; every other failure was in the test
harness or scripts, or a wrong expectation that Python and the service corrected.

- **Rust described parameterless calls; Azure answered with nothing.** Rust's
  encrypted `execute` asked `sp_describe_parameter_encryption` about every call.
  For a call without parameters, sent with enclave attestation parameters, Azure
  SQL returned no result sets, and Rust's parser refused the valid statement with
  `InvalidMetadata`. Python never describes a call without parameters. Rust now
  matches Python (`enclave_connection::a_call_without_parameters_is_sent_without_a_description`),
  and the paired run passes. An earlier run had passed because an enclave session
  already existed, so no attestation parameters were sent.

- **Deferred Entra makes one token request, not two.** Azure's gateway routes
  before sending FEDAUTHINFO; only the destination asks. Python makes the same
  single callback. The harness expectation was corrected.
- **An empty token closes the connection.** The controlled test (server answers
  18456) stays valid as driver behavior; Azure's actual answer is a close.
- **Harness and script fixes:** `nvarchar` values arrive as `Value::Unicode`;
  SqlClient 7 needs `Microsoft.Data.SqlClient.Extensions.Azure` for Entra;
  `rsync -a` and archive extraction kept old timestamps, so Cargo reused stale
  libraries on the VMs; the Windows test needed `column_encryption` and separate
  batches for its key and table DDL (SQL Server compiles a batch whole); an
  environment variable was set on `cd` instead of `cargo`.

Observations for later decisions, not defects:

- **Versionless Key Vault paths break on rotation.** A column key wrapped through
  a versionless path cannot be verified after the key rotates. This is the
  vault's semantics (it verifies with the current version), and it applies to
  any client. Guidance for users: pin the key version in `KEY_PATH`.
- **Default key retention calls the vault per exchange.** With `Policies::default()`
  Rust made 10 vault unwraps across about 9 statements. This is the agreed
  retention policy; cost-sensitive users choose a longer-lived policy.
- **GSSAPI via SPNEGO hides the Kerberos minor.** Absent and expired tickets stay
  distinguishable for Negotiate (different major status), but "expired" is
  specifically identified only for Kerberos.

## Not shown live

- **Recovery:** the Redirect policy sends clients straight to the database node,
  so a local relay cannot break the connection. Recovery stays covered by
  controlled tests.
- **Credential modes** without an environment here: workload identity, client
  assertion, azd, Azure Pipelines, certificate service principal (see the
  [inventory](rust-azure-credential-inventory.md)).
- **Attested enclaves:** only Python's explicit `none` mode is in scope.
