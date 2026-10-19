# Rust authentication provider review — 2026-10-19

This is source-review evidence, not Microsoft interoperability acceptance.

Owner decision after review: **document the limitations and prepare potential
upstream reports; do not maintain dependency forks/patch sets or change TLS
backends for this work.** Portable NTLM remains available with the retained-key
erasure limitation. SQL Extended Protection support is deferred. This accepts
the documented scope, not a claim that either limitation is fixed. Other campaign
acceptance and teardown gates remain separate.

Drafts, not submitted: [sspi retained-state cleanup](upstream-sspi-ntlm-zeroization.md)
and [rustls channel-binding discussion](upstream-rustls-channel-binding.md).
The [cross-client findings](rust-python-authentication-limitations.md) record
Python gaps separately; Python is not an already-correct reference for these
security properties.

## Upstream issue references

| Finding | Existing upstream ticket | Downstream report status |
|---|---|---|
| SQL Extended Protection / missing tls-unique API | [rustls #995](https://github.com/rustls/rustls/issues/995), closed as not planned by the original requester; no implementation committed | [SQL Server follow-up draft](upstream-rustls-channel-binding.md), not submitted |
| Portable NTLM retained-key/RC4-state erasure | No verified upstream ticket recorded for this finding | [sspi cleanup draft](upstream-sspi-ntlm-zeroization.md), not submitted |

Draft documents are not upstream tickets. Add the actual ticket URL here and in
the client documentation if a report is later submitted. Other NTLM issues about
negotiation/interoperability are not evidence that this erasure finding is tracked.

The implementation pins portable `sspi` 0.23.0, without its default synchronous
network client. The async shell supplies bounded TCP KDC exchanges under the
original opening deadline. Provider messages are opaque to the protocol core;
the client does not implement another NTLM or Kerberos algorithm.

## Portable provider findings

Observed in the downloaded 0.23.0 source:

- `Secret<T>` derives zeroization and zeroization on drop. Credential passwords,
  NTLM signing keys and Kerberos retained session/sub-session keys use that
  wrapper.
- `Ntlm::session_key` is `Option<[u8; SESSION_KEY_SIZE]>`, rather than `Secret`.
  `Ntlm` has no zeroizing destructor for this field.
- NTLM's RC4 sealing state is an ordinary 256-byte array behind `State`; neither
  that state nor `Rc4` implements zeroization on drop.
- The crate overview mentions native Windows libraries, but the current crate
  source does not expose the `winapi` module referenced by older comments. A
  separate native adapter is required.

Sources: [NTLM context](https://docs.rs/crate/sspi/0.23.0/source/src/ntlm/mod.rs),
[RC4 state](https://docs.rs/crate/sspi/0.23.0/source/src/crypto/rc4.rs),
[secret wrapper](https://docs.rs/crate/sspi/0.23.0/source/src/secret.rs),
[Kerberos key storage](https://docs.rs/crate/sspi/0.23.0/source/src/kerberos/encryption_params.rs).

Our owned credentials, opaque tokens, provider input/output buffers and generated
outgoing login packet buffers use `zeroize`. This does not erase a dependency's
private unguarded state. Successful authentication cannot prove its erasure.
Do not claim that portable NTLM currently satisfies retained-key erasure.

Disposition: retain portable NTLM with an explicit limitation and prepare an
upstream cleanup request. No local dependency patch is planned. Temporary/local
copies and compiler/runtime effects would still need a separate audit even if
upstream protects these retained fields. No universal memory-erasure guarantee
or complete retained-key erasure acceptance follows from interoperability.

## Native provider boundary

`clients/rust/native-sspi` isolates the Windows API FFI and owns credential/context
handles with destructors calling `DeleteSecurityContext` and
`FreeCredentialsHandle`. The protocol crate retains `forbid(unsafe_code)`.
Token buffers are bounded and zeroized. Native signed-in credentials are acquired
inside a blocking worker; the wrapper counts pending calls and a reaper owns
late results so an abandoned opening cannot install them.

Windows SSPI calls are not forcibly preemptible. They can outlive the caller's
opening deadline; the worker must finish and release its handles. Test eventual
worker retirement separately from caller timeout. Windows/kernel-managed key
storage is outside our ability to inspect or directly overwrite.

## Required Extended Protection: TLS decision

Live SQL Server 2022 Developer tests established a second architecture gate.
With `ForceEncryption=1` and `ExtendedProtection=2`, Microsoft SqlClient succeeds,
but both Rust provider paths are rejected with SQL's SSPI status `0x80090346`
(incorrect/missing channel binding). Independent pyspnego witnesses with absent
and deliberately wrong bindings are also rejected. Rust's generated
`tls-server-end-point` buffer exactly matches Windows Schannel's endpoint buffer
and the configured leaf certificate; it is the wrong binding type for this SQL
Server policy. Schannel separately exposes a `tls-unique:` binding.

The pinned rustls 0.23.46 source exposes peer certificates and exporters, but not
the Finished bytes needed for this binding. The upstream
[request](https://github.com/rustls/rustls/issues/995) is closed as not planned.
The original requester closed it after implementing `tls-exporter` for their
own use case; a maintainer had raised security constraints and asked for context,
rather than categorically refusing the feature. No implementation is committed.
The [discussion draft](upstream-rustls-channel-binding.md) records that history
and our different constraint of interoperating with an existing SQL Server.
Do not substitute an endpoint hash or silently call this gate passed. No TLS
secret logging, custom Finished reconstruction or TLS dependency patch is added.

Disposition: defer Extended Protection support and prepare an upstream
compatibility discussion. No rustls fork, Finished-data reconstruction or
alternative TLS backend is planned. Any future upstream solution must address
TLS 1.2 extended-master-secret/resumption semantics, TLS 1.3 Schannel
compatibility, validated-handshake timing and retained state.
The lab's policy was restored to the recorded `ExtendedProtection=0` baseline for
unaffected lifecycle/encryption tests. TLS encryption and certificate validation
remain required. Required Extended Protection remains unaccepted.
An additional `ExtendedProtection=1` (Allowed) experiment also rejected portable
NTLM; that setting likewise cannot be advertised as supported. The baseline was
again restored in `finally`.

An upstream discussion should ask for a supported approach rather than presume
that exposing raw Finished data is the accepted design. Review full/resumed TLS
1.2 separately and require appropriate extended-master-secret protection.
Windows Schannel returns a `tls-unique:` buffer for TLS 1.3 too, but RFC 5929 does
not define that TLS 1.3 behavior: interoperability and security review are
separate gates. Do not assume a generic exporter equals what SQL Server accepts.
Invalid/unavailable bindings must remain failures.

The isolated FFI crate first passed an `x86_64-pc-windows-gnu` compile check from
macOS. Subsequent native MSVC builds and successful remote native/portable login
matrices are recorded in the [live checkpoint](rust-gcp-authentication-evidence.md).
Required Extended Protection and wider lifecycle acceptance remain separate gates.
