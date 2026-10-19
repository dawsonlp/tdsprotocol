# Python authentication contract: API choices awaiting the owner

This proposal makes the two design checkpoints in the
[GCP correction plan](gcp-authentication-development-plan.md) concrete. It is not
an implemented API. Capture/privacy, authentication resource bounds, SQL opening
refresh and independent Rust acceptance can proceed without these choices.

## 1. Explicit provider completion

Recommended contract: every Windows `SecurityExchange` exposes a boolean
`complete` property in addition to its existing `step(challenge)` method.
pyspnego already provides this property. The initial exchange is validated before
LOGIN7 is sent; missing/non-boolean completion is a clear adapter-contract error.

The proposed contract requires provider completion before accepting a session. Final SSPI routing has already been corrected through the existing step
interface: a token is passed to the provider even alongside LOGINACK. An invalid final
token or an incomplete context refuses opening; no SQL authority is installed.
An output token must not be sent as application traffic after server completion.
Token/round limits and the original opening deadline still apply.

This changes the contract for application-written adapters lacking completion.
Preferred migration: expose the library's actual completion state, with an early
error and migration example. The alternative offered to the owner is an explicit
compatibility wrapper accepting an application-supplied completion predicate.
Neither option silently infers completion from token presence or LOGINACK.
Final-token dispatch/refusal is implemented through the existing interface;
the explicit completion-property requirement remains the pending choice.

## 2. Comparable Windows configuration values

Recommended representation: extend `ConnectionConfig` with an optional immutable
`windows_auth` value, while retaining positional SQL construction. Default empty
SQL user/password values permit Windows-only construction; validation rejects
mixed SQL credentials and Windows authentication. SQL still requires a nonempty
user when `windows_auth` is absent.

Proposed `WindowsAuth` value:

| Field | Meaning |
|---|---|
| method | NTLM, Kerberos or Negotiate |
| username/password | Explicit credentials, or both absent for the signed-in identity; password excluded from representation |
| service / service_principal | Target service policy, separate from TCP destination and TLS hostname |
| allow_ntlm_fallback | Explicit Negotiate policy; new comparable configuration defaults to requiring Kerberos |

Named constructors distinguish explicit credentials from signed-in identity.
The value does not contain a live provider context or callback. A stable
`ConnectionServices` provider factory creates adapters from each accepted value;
the built-in implementation uses pyspnego, imported only when selected.
Existing direct `login=WindowsLogin(provider)` construction remains available.

Snapshot equality includes credentials. Recovery compatibility permits only a
password refresh for the same identity, authentication method and service/fallback
policy. Other changes require a new session. Every retry/recovery creates a new
security context; no active borrower's identity changes. Authentication refusal
permits one source reread and, only on change, one opening retry under the shared
deadline. Application SQL is never replayed.

Native signed-in identity is external process/OS state. As with Rust, external
identity changes require pool retirement; they are not automatically detected by
comparing an unchanged signed-in value. Machine Kerberos configuration remains
external to Python's adapter; this proposal does not invent per-opening KDC URL
support equivalent to Rust's portable provider.

Alternatives offered to the owner: a separate Windows configuration type, or
deferring this configuration extension while completing SQL refresh. No Entra
configuration, TLS backend or dependency-erasure changes are included.

Synchronous provider scheduling remains a separate lifecycle concern. Current
Python providers can block the event loop; an asyncio timeout cannot preempt a
blocking native call. Any worker isolation must serialize each context's calls,
own late results and distinguish caller cancellation from eventual native cleanup.

## 3. Built-in provider worker ownership

The live unreachable-KDC test confirmed blocking inside pyspnego startup: a
1500 ms opening remained blocked when its process was stopped at 4010 ms.
Recommended correction: keep `Spnego.begin` returning a security exchange, but
defer native context creation and perform its serialized steps in bounded
workers. Its `step` may return an awaitable, already allowed by the interface.

The async shell keeps the opening deadline. Each submitted call owns its context
until it finishes. A reaper owns late results after caller cancellation and
releases them rather than installing a context/session. Retain worker capacity
until actual completion so canceled openings cannot create unlimited native
work. Generic application adapters remain subject to the cooperative async
contract rather than being silently moved between threads.

Signed-in process identity must remain distinct from thread impersonation.
Test caller timeout, event-loop responsiveness, late success/error cleanup and
runtime shutdown separately. A native call cannot be forcibly interrupted;
runtime/process shutdown may still wait for it. No promise of immediate
OS-managed key erasure follows from dropping caller authority.

The owner deferred this fix to the
[roadmap backlog](../C-roadmap.md#backlog--python-kerberos-opening-deadline).
The blocking-deadline limitation remains documented until the fix is implemented;
no worker implementation is claimed in this checkpoint.
