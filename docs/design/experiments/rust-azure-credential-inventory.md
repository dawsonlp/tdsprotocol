# Rust Azure credential inventory (scenario A03)

**Where this sits:** iteration 1's required credential-mode inventory for the
[integration plan](rust-azure-integration-plan.md), recorded at the
[code-complete checkpoint](rust-azure-code-complete.md) on 2026-10-20.

**After reading this you can** say which Entra credential sources each client
can use, which have development evidence, which the live campaign will exercise,
and which are owner-agreed gaps rather than silent omissions.

## How each client takes a credential

Python's [adapter](../../../clients/python/tds/adapters/entra.py) accepts **any**
`azure-identity` credential, sync or async: it calls `get_token(scope)` with
`resource + "/.default"`, and for the deferred flow uses the server's SPN as the
resource. It does not use the server's STS URL to choose an authority. The
installed baseline is `azure-identity` 1.26.0. The previous live campaign used
only `AzureCliCredential`.

Rust has an SDK-independent async `TokenProvider` contract. The optional
`azure-identity` feature adds `AzureTokenProvider::new(Arc<dyn TokenCredential>)`,
which wraps any official Azure Identity credential with the same scope rule, plus
an `azure_cli` convenience constructor with an owned, cancellable process
executor. The pinned crate is `azure_identity` 1.0.0. The `tds` CLI's
`--auth entra-upfront|entra-deferred` uses the Azure CLI credential only. Other
credentials need application code, as in the campaign harness.

An application can supply any other token source in both clients: a Python
callable, or a Rust `TokenProvider` implementation.

## Inventory

| Credential mode | Python 1.26.0 | Rust `azure_identity` 1.0.0 | Rust development evidence | Live campaign |
|---|---|---|---|---|
| Azure CLI | `AzureCliCredential` | `AzureCliCredential`, `AzureTokenProvider::azure_cli` | `official_cli_credential_uses_selected_tenant_and_scope_without_driver_cache`, `owned_executor_cancellation_terminates_and_reaps_its_child` | **Passed live**, both clients, both flows; also the `tds` CLI |
| Service principal, secret | `ClientSecretCredential` | `ClientSecretCredential` | `service_principal_uses_configured_tenant_form_and_sdk_cache` | **Passed live**, both clients, plus .NET SqlClient |
| Managed identity | `ManagedIdentityCredential` | `ManagedIdentityCredential` | Generic adapter only: `official_credential_adapter_preserves_scope_and_expiry_without_authority_override` | **Passed live** (runner VM), both clients, both flows; vault sign/verify |
| Service principal, certificate | `CertificateCredential` | `ClientCertificateCredential` only behind the SDK's `client_certificate` feature (OpenSSL); not enabled | None | No: exception E-CRED-1 |
| Workload identity | `WorkloadIdentityCredential` | `WorkloadIdentityCredential` | None | No: needs a federated Kubernetes/CI environment |
| Client assertion | `ClientAssertionCredential` | `ClientAssertionCredential` | None | **Passed live** 2026-10-20, both clients, both flows (application-signed assertion with a disposable certificate) |
| Azure Developer CLI | `AzureDeveloperCliCredential` | `AzureDeveloperCliCredential` | None | **Passed live** 2026-10-20, both clients, both flows (azd signed in as the service principal) |
| Azure Pipelines | `AzurePipelinesCredential` | `AzurePipelinesCredential` | None | No |
| Developer-tool chain | Part of `DefaultAzureCredential` | `DeveloperToolsCredential` (Azure CLI, then azd) | None | No |
| Default chain | `DefaultAzureCredential` | **None** | — | No: gap E-CRED-2 |
| Environment variables | `EnvironmentCredential` | **None** (an application can build `ClientSecretCredential` from them) | — | No: gap E-CRED-2 |
| Custom chain | `ChainedTokenCredential` | **None** in the SDK; an application can implement `TokenCredential` or `TokenProvider` | — | No: gap E-CRED-2 |
| Interactive user flows | `InteractiveBrowserCredential`, `DeviceCodeCredential`, `AuthorizationCodeCredential`, `UsernamePasswordCredential` | **None** | — | No: gap E-CRED-2 |
| Delegated / tool caches | `OnBehalfOfCredential`, `AzurePowerShellCredential`, `VisualStudioCodeCredential`, `SharedTokenCacheCredential` | **None** | — | No: gap E-CRED-2 |

## Exceptions recorded at code completion

- **E-CRED-1, certificate service principal.** Enabling the SDK's
  `client_certificate` feature adds an OpenSSL dependency; the owner decided on
  2026-10-20 not to enable it. Certificate-based service principals use
  `ClientAssertionCredential` with an application-signed assertion, shown live.
- **E-CRED-2, credentials the Rust SDK does not provide.** Rust cannot match
  Python's "any azure-identity credential" because the official Rust SDK has no
  default chain, environment, interactive or delegated credentials. These are SDK
  gaps, not driver gaps: the driver accepts any `TokenCredential` or
  `TokenProvider`. They stay listed here rather than being silently deferred.

Workload identity and Azure Pipelines compile through the same generic adapter
but have no environment evidence; they are not claimed as working.
