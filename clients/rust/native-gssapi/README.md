# System GSSAPI boundary

This unpublished MIT-licensed companion owns native names, credentials, security
contexts and output buffers. The TDS crate retains `forbid(unsafe_code)` and runs
native credential/context work on counted blocking workers. No passwords, cache
parsers, ticket bytes, environment mutation, `kinit` subprocess or ticket-renewal
policy is implemented here.

Linux links MIT-compatible `libgssapi_krb5`; install the development linker files
(Debian: `libkrb5-dev`). macOS links the system GSS framework. Other targets
return `Error::Unavailable` without linking a GSS library.

The API accepts Kerberos or Negotiate, a SQL service principal and optional client
principal. Default Negotiate permits only Kerberos. MIT's SPNEGO credential uses
`gss_set_neg_mechs`; Apple's SPNEGO consumes the mechanisms present in the acquired
credential. Explicit NTLM fallback permits only Kerberos/NTLM. Completion checks
the actual mechanism and required mutual-authentication flag.

Driver-owned token copies use `Zeroizing`; native allocations/cache erasure
remain the library's responsibility. A returned channel-binding flag means the
client supplied binding data, not that a server enforced Extended Protection.

Run controlled ownership/mechanism tests plus native name import/linkage:

```sh
cargo test --manifest-path clients/rust/Cargo.toml -p tds-native-gssapi
```

These tests do not require or read a ticket cache. Actual cached-credential SQL
login is a separate live acceptance gate. See the
[approved contract](../../../docs/design/experiments/rust-azure-ticket-cache-contract.md).
