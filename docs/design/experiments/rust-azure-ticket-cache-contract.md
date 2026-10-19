# Rust ticket-cache authentication: provider decision

**Where this sits:** the remaining ticket-cache path in the approved full Rust Azure parity scope.

**After reading this you can** configure the approved system-cache provider and distinguish development evidence from live Kerberos acceptance.

Status: approved by the owner on 2026-10-19; optional provider implemented.
The existing portable `sspi` 0.23.0 adapter acquires outbound
credentials from an explicit username/password and runs its TCP KDC exchanges.
That path does not consume the system cache used by Python's `Spnego` adapter.
Python's Azure campaign explicitly tests both Kerberos and Negotiate after
`kinit`; neither test supplies a password to the driver.

## Intent and recommendation

Authenticate with the current system ticket cache without implementing cache
formats, ticket renewal or KDC discovery in the TDS client. The optional
`system-gssapi` provider uses the operating system's GSSAPI on Linux/macOS. Keep native
Windows SSPI and portable explicit credentials as their existing alternatives.
Use the same bounded login token/round protocol and absolute opening deadline.

The comparable authentication selection names the system provider, Kerberos or
Negotiate, the intended principal when supplied, and the SQL service principal.
The default system cache is selected by the native library (including its normal
`KRB5CCNAME` environment behavior); the driver never changes process environment
or runs `kinit`. A selected principal is acquired through GSSAPI, not inferred
from token contents. Cache renewal for that identity may supply a fresh ticket
on each physical attempt. A configured principal change remains a pool identity
change. Applications that change an implicit system identity must retire their
existing sessions explicitly, as with the existing signed-in Windows provider.

Default Negotiate requires Kerberos, matching the current Rust policy. Do not
silently permit an NTLM fallback through an installed GSS mechanism. Keep channel
binding and the selected mechanism visible as safe typed evidence. The provider
owns native credential, target-name and context handles and releases every output
buffer. Private tickets never enter an application configuration snapshot.

Native calls may block on the system's KDC implementation. Run them on counted
workers with owned context/token results. Cancellation drops authority under the
original opening deadline; a worker that finishes later owns cleanup and cannot
install its context. Native-library ticket/cache allocations remain outside the
driver's erasure guarantee. Isolate FFI in a companion crate; retain
`forbid(unsafe_code)` in the main client.

## Implemented selection and platform boundary

Enable Cargo feature `system-gssapi`, which also enables `integrated-auth`:

```rust
use tds_client::auth::{Credentials, Method, WindowsAuth};
let mut auth = WindowsAuth::system_cache(Method::Negotiate);
auth.credentials = Credentials::SystemCache {
    principal: Some("tdsuser@TDS.TEST".into()),
};
auth.service_principal = Some("MSSQLSvc/tdssql.tds.test:1433".into());
// Pass auth to ConnectOptions::integrated with explicit verified TLS roots.
```

Omit the principal to let the system select an identity. A supplied principal is
imported as a Kerberos principal and acquired through GSSAPI. Neither `kdc_url`
nor explicit-password credentials are accepted by this provider. Direct NTLM is
unsupported here; the portable/native Windows providers retain their behavior.

The companion `clients/rust/native-gssapi` links macOS's GSS framework or Linux's
MIT-compatible `libgssapi_krb5`. Linux builds need the library and linker files
(for example, Debian's `libkrb5-dev`). Other targets report unsupported; selecting
this provider without its Cargo feature also reports unsupported. There is no
automatic switch to another provider.

MIT and Apple expose different pre-token restriction paths. Linux acquires the
SPNEGO wrapper credential and uses `gss_set_neg_mechs`; Apple acquires a credential
containing only the permitted mechanisms, which its SPNEGO implementation uses
to construct the offer. The default permits only Kerberos. Explicit
`allow_ntlm_fallback` permits Kerberos and NTLM, never arbitrary installed
mechanisms. Completion checks the actual context mechanism, and Kerberos-only
contexts must report mutual authentication. Native names/credentials/contexts
and every output buffer have owned cleanup, including partial failure results.

The existing TLS endpoint binding is translated from the SSPI header layout to
GSSAPI application data. It cannot change between rounds. Full observation adds
`Inspection::Gssapi(GssapiEvidence)` with the selected mechanism and whether the
client supplied channel binding; this does not claim server-side enforcement or
support for SQL Server's required `tls-unique` Extended Protection.

The CLI adds `--system-gssapi` and optional `--principal`; `login_probe` accepts
`provider: "system-gssapi"` and optional `principal`. Both use the same integrated
login abstraction and preserve verified TLS. They do not require a password.

Alternative: extend the portable provider to parse cache files and implement
renewal/service-ticket behavior. This introduces a second ticket manager and
different platform/cache support from Python's native provider. Recommend the
system provider instead. Do not replace the portable explicit-password path.

Development acceptance uses controlled native-call outcomes for cancellation,
mechanism enforcement, ownership and sanitized errors, plus compilation/linking
on supported hosts and explicit unavailable-platform behavior. Successful native
Kerberos login against the Azure domain controller remains a later live gate.

Implementation references: [adapter](../../../clients/rust/src/auth/gssapi.rs),
[native boundary](../../../clients/rust/native-gssapi/src/system.rs), and
[controlled native tests](../../../clients/rust/native-gssapi/src/system/tests.rs).
MIT documents [credential acquisition and cache selection](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/gssapi.html).
Mechanism restriction follows [RFC 4178 Appendix B](https://www.rfc-editor.org/rfc/rfc4178.html#appendix-B)
on MIT; Apple's [credential-based SPNEGO offer](https://github.com/apple-oss-distributions/Heimdal/blob/main/lib/gssapi/spnego/compat.c)
supplies the macOS equivalent. The implementation does not constrain native
keytab/cache policy beyond the requested identity and permitted mechanisms;
automatic acquisition/refresh configured in the system library remains native.

## Development evidence — 2026-10-19

The [retained check report](rust-azure-ticket-cache-checks.json) records the
source hashes and command results. The updated finite paired runner checks 175
source files and confirmed they did not change during the comparisons:

- Six companion tests pass on macOS and separately on Linux ARM64 with Rust
  1.99.1/MIT GSSAPI. Controlled calls cover named/default credentials, SQL SPN,
  pre-token mechanism restriction, completion evidence, binding conversion and
  stability, bounded tokens/rounds, mutual authentication and partial-result
  cleanup. A native name-import/release test exercises real ABI/linkage without
  accessing credentials. Linux tests use a disposable network-disabled container,
  verified official toolchain archive, and read-only source/dependency mounts.
- Three adapter tests pass for caller cancellation, original-deadline expiry,
  late-result cleanup/counting and conflicting configuration inputs. A separate
  build without `system-gssapi` passes its explicit unavailable-feature test.
- Sixteen integrated-authentication/configuration regressions pass, including
  controlled verified-TLS continuation, opening deadline and principal/service
  changes as pool-identity changes. The paired Entra/SDK/key/enclave comparisons
  also pass; Python production code is unchanged.
- The macOS all-feature workspace run passes 299 tests with 62 environmental
  tests ignored; the protocol-only run passes 102 with none ignored.
  Strict workspace Clippy, strict rustdoc, formatting and diff
  checks pass. The Windows GNU companion stub compiles. A full Windows client
  cross-check was not completed: its offline attempt needed an uncached existing
  dependency (`curve25519-dalek-derive`); native Windows runtime was not exercised.

These are implementation, controlled-provider and local regression results.
No cached-credential SQL login, Azure domain-controller login or server-side
Extended Protection acceptance is claimed. The Azure campaign remains deferred.
