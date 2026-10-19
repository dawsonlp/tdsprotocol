# Rust Azure authentication: development evidence

**Where this sits:** the first authentication slice on `rust-azure-integration`, based on `f45aa43`.

**After reading this you can** reproduce the paired checks and distinguish implemented authentication from full Azure parity and real-service acceptance.

The owner approved the [authentication contract](rust-azure-authentication-contract.md)
on 2026-10-19. This work is uncommitted and unpublished. The
[key-provider/enclave contract](rust-azure-key-provider-contract.md) is a separate
pending design decision. Actual Azure infrastructure/testing remains deferred
until code completion for the entire phase.

## Implemented and observed

| Scenario | Evidence and limit |
|---|---|
| A01, upfront/deferred wire | 24 Python-production-encoder vectors; UTF-16 lengths, all workflows, echo and nonce; an independent supplementary-Unicode assertion |
| A04, FEDAUTHINFO | Five Python-helper vectors, each split at every byte boundary: normal, missing, duplicate, odd/surrogate and clipped fields; bounded impossible directory refusal |
| A01, actual local opening | Both paths × TDS 7.4/8.0 × plain/MARS, fixed PRELOGIN nonce and echo, fragmented deferred metadata, successful SQL completion |
| A02/A06, routing | Both paths request the provider for both physical targets; repeated redirect refuses after the second target and does not create a third attempt |
| A02/A06, recovery | Both paths obtain another token for replacement transport, preserve the logical channel and submit one subsequent application batch; no replayed batch |
| A05, cancellation/deadline | A pending provider future retires on timeout/caller cancellation and the local candidate socket closes; token-size/declared-expiry refusal sends no LOGIN7 |
| A03, SDK adapter | Official TokenCredential fake receives Python-equivalent scopes and preserves expiry; STS text does not select authority; no actual Entra request |
| A07, privacy | Guarded token buffers and redacted Debug/errors; Full observer packet bodies/field trees and decoded capture packets contain no artificial token marker, including keep-password capture configuration |
| Replay | Redacted login replies are missing evidence, with an explicit incomplete diagnostic; packet-type-8 bodies are not interpreted as SQL or restored tokens |
| Configuration | Comparable Entra identity changes are incompatible; provider objects and bearer-token bytes remain outside snapshots; unbound sources refuse before TCP |

The controlled suite contains eight named tests in `tests/azure_login.rs` and
three in `tests/azure_wire.rs`. Matrix combinations inside a test are not counted
as separate test functions. The SDK adapter adds one unit test. PRELOGIN also has
a unit regression for a directory whose entry order differs from data order.

## Findings and policy boundaries

The malformed-input comparison found and corrected a Rust replacement-decoding
mismatch: Python emits one replacement character for a final high surrogate plus
a partial next unit. Rust now matches it. No Python production behavior changed.

A separate controlled Python run (`test_logins.FakeServer`) accepts deferred
LOGINACK without FEDAUTHINFO and invokes no token callback. Rust preserves that
outcome; the regression does not establish that Azure uses or accepts that
sequence. No SQL/Windows credential fallback is introduced.

Final review corrected a Rust PRELOGIN directory-order assumption and kept the
existing SQL/Windows live checker on its original path. The final affected checks
and PRELOGIN unit tests were run after these last review changes. The broad
regression matrix started earlier, so its counts exclude the last added PRELOGIN
unit and its default-feature count excludes the last added ordering scenario.

The shell's UTF-16LE token resource limit is 48 KiB. FEDAUTHINFO metadata is
bounded at 64 KiB, and token continuations at eight rounds. Provider-declared
expired tokens are refused; absent expiry remains unknown and no JWT is parsed.
Empty strings remain representable in the wire vectors. These bounds/metadata
rules are not claims about Azure's accepted credential sizes or empty-token use.

SDK Identity/Core 1.0.0 are pinned with optional Tokio/rustls transport features.
Source review found non-erasing SDK secret storage and a default Tokio CLI
executor without explicit kill-on-drop. Driver-owned copies erase; SDK copies
remain outside that guarantee. The supplied CLI constructor uses an owned
executor requesting kill-on-drop. Immediate OS termination/runtime-shutdown
reaping is not claimed or independently accepted here. Generic externally
constructed credentials retain their own worker/cache responsibilities.
Primary API reference: [Azure Identity 1.0.0](https://docs.rs/azure_identity/1.0.0/azure_identity/).

## Reproduce and retained provenance

From the repository root:

```sh
python3 tools/check_rust_azure.py
python3 tools/check_rust.py
```

Both use locked offline dependencies; controlled peers need localhost sockets.
The first runner records source hashes and paired outcomes. Its final portable
summary is retained in [authentication-checks.json](rust-azure-authentication-checks.json).
It compares current Python output with saved fixtures before invoking Rust.
It does not provision resources or run real credential acquisition.

The broad development matrix passed: 228 default tests (57 live ignored),
100 core-only tests, 265 all-feature tests (61 live ignored), formatting, strict
Clippy in all three configurations and all-feature rustdoc. Final affected and
PRELOGIN reruns cover the subsequent small review corrections described above.
Live ignored functions were not run in this activity.

Local regression logs: `/private/tmp/tds-rust-azure-development-checks-20261019`.
Final affected checks: `/private/tmp/tds-azure-final-targeted.log` (40 passed).
Final PRELOGIN checks: `/private/tmp/tds-azure-prelogin-final.log` (two passed).
Final paired logs: `/private/tmp/tds-azure-paired-final-20261019` (three core wire
tests, eleven wire/opening tests, one SDK unit test; these runs overlap).

## Still required

The full [parity plan](rust-azure-parity-scenarios.md) remains open. Current tests
are a finite initial authentication slice, not completion of A01–A07 or every
adversarial/provider/pool schedule. Remaining work includes Azure feature
negotiation, wider SDK credential-shape/process/platform tests, mixed-provider
key service, Key Vault, Windows certificate-store, transparent enclave and
ticket-cache integration. Native Windows runtime, actual Azure, Microsoft-client
interop and cloud teardown acceptance follow the full code-complete checkpoint.
The unrelated enclave-completion backlog is unchanged and outside this activity.
