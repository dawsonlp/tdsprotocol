# Draft upstream report: NTLM retained secret-state cleanup

Status: **draft only; not submitted**. Intended repository:
[Devolutions/sspi-rs](https://github.com/Devolutions/sspi-rs).
Review current upstream source and existing reports before submission; these
observations concern the pinned version, not an assertion about every release.

Suggested title: **Zeroize retained NTLM session key and RC4 state on drop**

## Context and observed source

We use `sspi` 0.23.0 for a portable SQL Server Windows-authentication adapter.
The crate's packaged VCS revision is
`b21f4581a880cfb5eb096d95c64d0dcea5229158`.

At that revision:

- [`Ntlm::session_key`](https://github.com/Devolutions/sspi-rs/blob/b21f4581a880cfb5eb096d95c64d0dcea5229158/src/ntlm/mod.rs)
  is `Option<[u8; SESSION_KEY_SIZE]>`. We found no zeroizing destructor for it.
- [`Rc4` and `State`](https://github.com/Devolutions/sspi-rs/blob/b21f4581a880cfb5eb096d95c64d0dcea5229158/src/crypto/rc4.rs)
  retain ordinary state, including `State([u8; 256])`, with no zeroizing drop.
- Other secrets use the crate's `Secret<T>` zeroization wrapper.

Consumer-side zeroizing input/output buffers cannot clear these private fields.
Our requirement is to overwrite owned retained authentication secrets when their
context is released. Successful authentication does not establish that cleanup.

## Request

Would the maintainers consider zeroizing these retained fields on drop, using
the existing secret wrapper or an equivalent approach? Please also clarify any
intended limits to the crate's secret-memory cleanup guarantees, including
cloned contexts, replacement paths and error paths.

Suggested validation would observe cleared state before deallocation rather
than read freed memory, and retain normal NTLM interoperability coverage.
Protecting retained fields would not establish erasure of all temporary copies,
compiler-generated copies or operating-system memory.

## Evidence boundary

This is a source-level cleanup finding. We have not demonstrated exploitation,
memory recovery after free or a remotely accessible disclosure. No severity or
CVE claim is made. SQL Server NTLM interoperability passed independently; that
does not measure erasure. No credentials, tokens or memory dumps accompany this
draft. No downstream fork or patch set has been created.
