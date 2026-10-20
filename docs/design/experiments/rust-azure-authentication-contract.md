# Rust Azure authentication: concrete contract for review

**Where this sits:** the authentication boundary for the Rust Azure parity phase.

**After reading this you can** distinguish the approved public/provider contract from later key/enclave decisions.

Status: authentication recommendation approved by the owner on 2026-10-19.
The unified selection, SDK-independent async provider, separate identity/runtime
bindings and Python audience/authority behavior are being implemented. Scope is
agreed in the [development plan](rust-azure-integration-plan.md). The later
key-provider and enclave decisions remain separate. Code sketches below explain
the agreed meaning; consult Rust sources for the implemented signatures.

## Intent and observed starting point

Let Rust open, route, pool and recover SQL sessions using either Python Entra
login path, with a fresh credential-source request for each physical attempt.
Keep OAuth acquisition outside TDS and preserve explicit identity, deadlines,
secret ownership and evidence boundaries. Do not replay application SQL.

At `f45aa43`, `ConnectOptions` and `ConnectionConfig` have SQL user/password
fields plus optional `WindowsAuth`; validation refuses conflicting credentials.
`ConnectionServices` carries runtime trust/observation services. The core has a
bounded SSPI request/supply boundary after verified TLS. Neither Rust opening
path implements federated authentication. Python's `EntraToken` sends a UTF-16LE
token in LOGIN7; `EntraLogin` advertises a workflow and responds to FEDAUTHINFO.
Python's adapter converts resource to `resource.rstrip('/') + '/.default'` and
does not select an OAuth authority from the server's STS URL.

## Proposed public representation

Use one comparable `Authentication` value in direct options and configuration:

```rust,ignore
enum Authentication {
    Sql(SqlCredentials),
    Windows(WindowsAuth),
    Entra(EntraLogin),
}
struct SqlCredentials { user: String, password: SecretString }
struct EntraLogin {
    source: CredentialSourceId,
    identity: CredentialIdentity,
    mode: EntraMode,
}
enum EntraMode {
    Upfront { resource: String },
    Deferred { workflow: Workflow },
}
enum Workflow { Password = 1, Integrated = 2, Interactive = 3 }
```

These are sketches, not declarations already implemented. `CredentialSourceId`
names an application binding; `CredentialIdentity` is an application-supplied
comparable identity/version label. They are not claims that the driver can infer
the actual principal from an opaque access token. Changing tenant, principal,
authority or provider binding requires a changed identity/configuration value.
Secret rotation for the same identity may remain compatible, matching existing
SQL/Windows credential-refresh semantics. Do not compare OAuth bearer bytes as
configuration. The driver cannot detect an application mislabeling a changed
identity; document that responsibility.

Preserve `ConnectOptions::new(host, port, user, password, roots)` and
`ConnectOptions::integrated(...)` as constructors of that selection. Add an Entra
constructor. Migrate existing public credential field access and all in-repo
callers; Rust is unpublished, but document the source-level API change. The
one-time SQL password-change option remains separately validated as SQL-only;
its completed-login promotion behavior remains unchanged.

Alternative: add an optional Entra setting beside today's SQL and Windows
fields. That reduces source churn, but admits three competing selections and
requires repeated conflict validation. This is viable if preserving public field
access is preferred; it is not the recommendation.

## Runtime provider and secret contract

Keep the provider independent of the Azure SDK. Direct options and
`ConnectionServices` carry an immutable mapping from source ID to
`Arc<dyn TokenProvider>`; configuration only names the binding/identity. A pool's
service map is fixed. Rebinding requires a new services owner/pool; credential
renewal may occur inside the same bound source. Missing bindings fail before TCP.

```rust,ignore
struct TokenRequest<'a> {
    resource: &'a str,
    sts_url: Option<&'a str>,
    // Physical target and workflow are context, not replacement audiences.
    host: &'a str,
    port: u16,
    workflow: Option<Workflow>,
}
struct AccessToken { secret: SecretString, expires_at: Option<SystemTime> }
trait TokenProvider: Send + Sync {
    fn acquire<'a>(&'a self, request: TokenRequest<'a>) -> TokenFuture<'a>;
}
```

`TokenFuture` is a boxed Send future borrowing the provider/request. Its result
owns the token. Driver-owned token strings and encoded authentication buffers
are zeroized on release and omitted from Debug, Display, capture and inspection.
The provider/SDK/OS may keep other copies; their erasure is not guaranteed.
The token is not parsed as a JWT. The wire vectors preserve empty strings. The shell applies a 48 KiB UTF-16LE
resource limit and refuses provider-declared expired tokens; absent expiry stays
unknown. These driver/metadata boundaries are distinct from a claim about what
Azure accepts. Named controlled cases cover bounds and explicit expiry.

Provider failures expose a stable category; a protected source accessor may
retain the original error without ordinary formatting. This is a proposed Rust
error contract, not a claim that Python's diagnostic policy is defective.

The shell polls acquisition inside the original absolute opening deadline.
Cancellation drops the future and the candidate connection. Spawned/native work
must own eventual cleanup and cannot install a late result. The core performs no
provider I/O. Route/recovery candidates ask again; a source may return a valid
cached token. Expiry after completed SQL login alone does not revoke a session.

## Audience, authority and SDK integration

Upfront mode defaults its configured resource to
`https://database.windows.net/`. Deferred mode passes the resource and STS URL
received in FEDAUTHINFO to the generic provider, matching Python. The optional
Azure adapter uses the resource-to-scope conversion above and the authority and
tenant selected when its credential was constructed. It does not create a new
credential from server-supplied authority text. Do not add a new audience/domain
allowlist as an assumed compatibility correction.

The pinned optional SDK is `azure_identity` 1.0.0 with `azure_core` 1.0.0; its credentials implement
the official `TokenCredential` abstraction. Review and pin exact dependency
features, transitive runtime/process behavior and SDK secret conversions when
changing the optional adapter. The dependency/lockfile change is in this branch. Candidate
credential surfaces and platform behavior need source review plus controlled
tests; SDK compilation is not acceptance against Entra.

Primary references checked 2026-10-19:
[Azure Identity](https://docs.rs/azure_identity/1.0.0/azure_identity/),
[Azure CLI credential](https://docs.rs/azure_identity/1.0.0/azure_identity/struct.AzureCliCredential.html).

## Wire work independent of the public API choice

Add a small federated-authentication definition module. Match Python feature
library/workflow bytes, UTF-16LE token lengths, PRELOGIN echo and nonce, and the
packet-type-8 body. Shared artificial fixtures are generated with Python's actual
definitions. A Rust integration test consumes them without Python/network at
test time; a separate paired command regenerates into a temporary directory and
checks drift. Unknown/malformed inputs are classified separately from valid
wire parity. Do not silently turn a Python review hypothesis into Rust policy.

A controlled Python comparison also accepts deferred LOGINACK without preceding
FEDAUTHINFO and makes no provider call; Rust preserves that outcome, without SQL
fallback or a claim that Azure uses that sequence. Valid known requests and driver
resource bounds are tested separately from service validity.

These definitions alone do not enable Entra login. Subsequent controlled peers
must establish both versions, legal message ordering, feature ACKs, verified TLS,
routing/recovery, cancellation, privacy and connection reuse/discard outcomes.

## Later decisions remain separate

Before key-service work, propose asynchronous local/remote/native operations that
retain today's key policies without converting a vault key into a local private
`Master`. Before enclave integration, agree session/counter ownership and compare
Python's server-keyed session reuse with Rust physical-epoch/lease authority.
No proposed narrower scope is called a Python correction. Neither decision is
settled by agreeing the authentication contract. The unrelated enclave completion
backlog remains outside this phase's Python-parity scope.
