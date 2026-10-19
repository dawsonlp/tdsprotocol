# Draft upstream discussion: SQL Server authentication channel binding

Status: **draft only; not submitted**. Intended repository:
[rustls/rustls](https://github.com/rustls/rustls).
The existing [issue #995](https://github.com/rustls/rustls/issues/995), checked
during this review, already requests `tls-unique` information. It is closed as
not planned, with no committed implementation. The original requester closed
it; this was not an explicit maintainer refusal. Prefer a follow-up to that
discussion if maintainers allow it;
do not submit a duplicate without checking current guidance and related work.

Suggested title: **SQL Server Extended Protection: supported channel-binding approach?**

## What the earlier discussion established

In January 2022, a rustls maintainer explained that `tls-unique` is undefined for
TLS 1.3 and its replacement could use existing APIs. For TLS 1.2, they raised
the triple-handshake concern, suggested restricting any implementation to
connections negotiating extended master secret, and asked for the use case.
That was a request for context with security constraints, not a categorical
rejection. See the [maintainer response](https://github.com/rustls/rustls/issues/995#issuecomment-1026041350).

The original requester controlled both ends of their application and could use
TLS 1.3. After implementing `tls-exporter`, they closed the issue on July 31,
2022, explaining that the replacement had been published as RFC 9266. When
another participant asked for reopening, the requester declined. The refusal
to reopen was the requester's, not the maintainer's. See the
[closure explanation](https://github.com/rustls/rustls/issues/995#issuecomment-1200484417)
and [follow-up](https://github.com/rustls/rustls/issues/995#issuecomment-1206672244).

Our SQL Server integration differs: we implement the client and cannot choose
or replace the deployed server's accepted binding mechanism. Existing exporter
APIs resolved the original requester's use case; we have not established that
they solve this SQL Server compatibility requirement. This distinction supports
asking for guidance, without assuming the maintainers will accept a new API or
that implementation is planned.

## Environment and observed behavior

We use rustls 0.23.46 for a Rust TDS client, with portable `sspi` 0.23.0 and a
separate native Windows SSPI adapter. The SQL fixture was Windows Server 2022
with SQL Server 2022 Developer, repeated after an in-place update to CU27
16.0.4295.3. All successful baseline cases verified the CA and server hostname.

| Controlled server policy | Client | Observed result |
|---|---|---|
| ForceEncryption=1, ExtendedProtection=0 | Rust portable/native | Login matrices passed |
| ForceEncryption=1, ExtendedProtection=2 | Microsoft System.Data.SqlClient | Connected |
| Same required policy | Rust portable NTLM and native Windows Kerberos | Refused; SQL logged SSPI `0x80090346` |
| Required policy | Independent witnesses with missing or deliberately wrong binding | Refused |
| ExtendedProtection=1 | Rust portable NTLM | Refused |

Our certificate-based `tls-server-end-point` binding matched Schannel's endpoint
buffer byte for byte. Schannel also exposed a separate `tls-unique:` buffer.
The results indicate a binding-type compatibility gap in this SQL configuration;
they do not establish a general failure of certificate-based bindings elsewhere.
Our pinned rustls API exposes peer certificates and exporters, but we found no
supported API supplying the needed handshake-derived binding.

## Request for guidance

Is there a supported approach for interoperating with SQL Server Extended
Protection while retaining rustls, or is this intentionally outside its scope?
We recognize the security concerns and requester-led closure in #995. Does this
SQL Server constraint change the available options, particularly for TLS 1.2
with extended master secret? This draft does not presume that a raw Finished-data
accessor is the right API or that an implementation has been accepted.

Any proposed solution needs separate treatment of full/resumed TLS 1.2 sessions,
extended-master-secret requirements, handshake-completion timing and TLS 1.3
compatibility/security. Schannel returning a similarly named buffer under TLS
1.3 does not establish that RFC 5929 defines it or that substituting a generic
TLS exporter will interoperate safely.

We can provide a sanitized reproduction using SQL Server with encryption and
Extended Protection required, a verified certificate, a remote domain identity
and the same SPN, comparing SqlClient with the rustls-based client. Current
evidence is in our downstream campaign report; no standalone upstream minimal
reproduction or exhaustive resumed-session/TLS-version matrix is attached yet.

## Downstream disposition

We document Extended Protection as unsupported and retain verified TLS. We are
not maintaining a rustls fork, reconstructing Finished data, logging TLS secrets
or introducing another TLS backend. This is an integration/API question, not a
claim of a rustls vulnerability. No private fixture addresses or credentials
are needed for submission.
