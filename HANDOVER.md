# Rust client handover

## Current development — Rust Azure integration, 2026-10-19

PR #1 merged the Rust client and GCP campaign work into `main` at `f45aa43`.
The old `rust-client` branch was deleted locally and remotely. New branch
`rust-azure-integration` starts at that merge. The owner requested a development
plan guided by Python, with cloud test infrastructure set up after code completion.
The owner clarified that the goal is the full Python Azure integration surface:
Entra/Azure SQL, Key Vault, Python's explicit no-attestation enclave mode,
certificate-store and ticket-cache paths used in the Azure campaign, plus existing
Windows/Browser regressions. The [plan](docs/design/experiments/rust-azure-integration-plan.md)
uses [paired Python/Rust scenarios](docs/design/experiments/rust-azure-parity-scenarios.md)
as the primary development evidence; actual Azure testing is deferred until full
code completion. Key Vault and enclave work are required, not follow-ons. Public
API/token-provider and audience/authority boundaries have now been approved for
authentication; its first development slice is implemented. Key-provider and
enclave-session boundaries have also been approved and implemented. No Azure resource provisioning has started. Earlier branch/running-lab
descriptions below are historical. Rust remains unpublished.

The owner additionally directed that Python weaknesses suspected during this
phase go to the [review backlog](docs/design/experiments/python-azure-review-backlog.md).
Python's real-service-tested behavior is the baseline. Do not change Python
production behavior or assume a proposed Rust correction is correct from static
inspection/local comparisons; retain hypotheses and the real-service tests needed
to decide them. This phase-specific direction supersedes the earlier general
instruction to apply shared corrections immediately to both clients.

## Rust Azure authentication development checkpoint — 2026-10-19

The owner approved the [authentication contract](docs/design/experiments/rust-azure-authentication-contract.md).
`ConnectOptions`/`ConnectionConfig` use `Authentication::{Sql, Windows, Entra}`;
existing constructors remain, but public credential field access has migrated.
Runtime token providers stay in services, while source/identity labels compare
as configuration. Both upfront and deferred Entra paths, PRELOGIN echo/nonce,
FEDAUTHINFO, routing/recovery, redaction and replay missing-evidence handling are
implemented with controlled tests. Optional `azure-identity` pins official
Identity/Core 1.0.0; the CLI adds two Entra modes using an owned Azure CLI executor.
No real credential acquisition/Azure interoperability is claimed.

The [authentication evidence](docs/design/experiments/rust-azure-authentication-evidence.md)
records the passing development matrix, final affected reruns, source hashes and
remaining limits. Use `python3 tools/check_rust_azure.py` for the current finite paired slice and
`python3 tools/check_rust.py` for regressions. The owner subsequently approved the
[key-provider/enclave contract](docs/design/experiments/rust-azure-key-provider-contract.md).
The common async key service, optional official Key Vault adapter, Windows CNG
companion and transparent version-two explicit-none enclave path are implemented
with [paired development evidence](docs/design/experiments/rust-azure-key-enclave-evidence.md); native/Azure runtime acceptance remains separate.
The final all-feature check passed 289 tests, with 62 environment-dependent cases
ignored. Strict lint/docs and the Windows companion cross-check passed.
The owner approved the [ticket-cache provider](docs/design/experiments/rust-azure-ticket-cache-contract.md):
optional `system-gssapi` now implements system-cache Kerberos/Negotiate on
Linux/macOS behind the existing security-context abstraction. It uses a separate
native companion, explicit principal/service identity, pre-token mechanism
restriction, typed safe evidence and counted cancellation cleanup. CLI and
`login_probe` support the new selection. Actual Azure ticket login remains a
later gate. Its [development check report](docs/design/experiments/rust-azure-ticket-cache-checks.json)
retains the source-hashed paired comparisons; the newer all-feature workspace
regression passes 299 tests, 62 ignored, with strict lint/docs. The
[unsupported-feature policy](docs/design/experiments/rust-azure-feature-probe-contract.md)
is also now owner-approved and implemented: warn on an explicit unsupported
request, permit absent/disabled ACK, but fail/close on enabled ACK before SQL
or pool admission, with no flag-removal retry. Python correction is backlogged
as PY-AZ-06. Actual Azure acceptance and broader cross-feature work remain;
full-scope completion is not claimed.
The [latest feature-policy report](docs/design/experiments/rust-azure-feature-policy-checks.json)
retains 15 passing paired checks against 179 stable source files and the final
workspace regression (304 passed, 62 ignored), plus strict lint/docs and core
compilation. Earlier source-hash reports describe earlier checkpoints.
Python production behavior and the unrelated enclave-completion backlog remain
unchanged. This branch records the Azure development checkpoint; consult Git
history/status for subsequent work. Rust remains unpublished.

## GCP lab closed — 2026-10-19 04:29 UTC

The owner authorized teardown after reviewing the campaign. Terraform destroyed
the lab resources and dedicated project `tds-rust-auth-77681f69a4`. Independent
cloud inventory found zero VMs, disks, reserved IPs, snapshots, forwarding rules,
routers, firewalls, subnets, VPCs and storage buckets. The campaign guest service
account was removed; only Google's default Compute service account remained
before project shutdown. Cloud DNS's API was disabled, so its zone inventory was
unavailable rather than reported as a successful empty query.

At **04:29:52 UTC**, the project was `DELETE_REQUESTED`, billing was disabled and
the billing account was detached. Both lab and project Terraform states were
empty; the earlier default-network cleanup state was also empty. This is verified
shutdown, not immediate permanent deletion. Actual billed total remains unverified.
Protected test evidence, cleanup logs, final inventory and local states are
retained under `infra/gcp/`; do not reuse the closed campaign's inputs/expiry.
Earlier descriptions of a running lab below are historical. Recreating a lab
requires a new campaign; a clean end-to-end deployment rehearsal remains open.

Prepared 2026-10-18. Branch: `rust-client`. Commit `452d458` contains the local
Rust completion checkpoint, field inspection, encryption, tests and retained
acceptance evidence, and has been pushed to `origin/rust-client`. The earlier
`6e2da04` implementation/interrupted-I/O checkpoint is historical.
Inspect `git status` before editing to distinguish any further changes.
Python key-retention changes are committed and released as **v0.3.0** on `main`
and annotated tag `v0.3.0` at `1e974dc`. The Rust implementation remains unpublished.
The active checkout stays on `rust-client`, with Python metadata aligned to the
release and its unfinished Rust source preserved. See the v0.3.0 checkpoint below;
earlier v0.2.0 and implementation checkpoints are historical.

The aim is a clear, literate Rust TDS client with Python's assessed correct
behavior, explicit ownership, exact values and visible wire conversations.
Check Python before choosing different behavior. Substantive corrections should
apply to both clients. Record architectural questions instead of inventing policy.

## Python release checkpoint — 2026-10-18

All Python corrections discovered during Rust development are committed, including
self-contained Python TVP replay fixtures and [release notes](clients/python/CHANGELOG.md).
`main` and annotated tag `v0.2.0` point to `74959f1`. The release contains no Rust
implementation. Both remote pointers and the published GitHub assets were verified:
https://github.com/dawsonlp/tdsprotocol/releases/tag/v0.2.0

Main commits are `e58b929` (Python fixes), `39b5ef7` (documentation repository link)
and `74959f1` (version/release metadata and completed TVP documentation). The
current branch has the equivalent Python/site commits plus `4695b76`, aligning
its Python version/lockfile/release notes to 0.2.0. `git diff main -- clients/python`
is empty. Existing Rust and draft-design working files were preserved by hash.

The isolated main checkout passed **782 tests, 13 skipped**, in 117.39 seconds.
Wheel/source builds, installed-wheel version/import/CLI checks and downloaded
GitHub asset checksums passed. GitHub Pages deployment for `74959f1` succeeded;
the live site's repository link was fetched and verified. The temporary release
worktree was removed after publication. Python and Rust mutation suites remained
sequential. Rust release/publication is a separate future task.

## Read these first

- [Support matrix](clients/rust/SUPPORT.md): current implemented features and
  remaining gaps. It supersedes older historical gap lists.
- [Acceptance evidence](clients/rust/ACCEPTANCE.md): the top check table and final
  **Transparent Always Encrypted** section are the latest checkpoint. Earlier sections
  retain historical results, including the preceding table/bulk slice.
- [Interruption matrix](clients/rust/INTERRUPTIONS.md): named submission, partial
  socket write, cleanup, pool/recovery and runtime-shutdown boundaries and limits.
- [Field inspection](docs/design/L-rust-field-inspection.md): shared definitions,
  packet/message/token coordinates, bounded evidence, masking and current scope.
- [Rust README](clients/rust/README.md): public API, lifetime rules and CLI.
- [Offline replay design](docs/design/K-offline-replay.md): approved representation,
  capture compatibility, failure boundaries and evidence limits.
- [Completion design](docs/design/J-rust-completion.md): approved and implemented
  input-only TVPs (A1), borrowed BulkWriter (A2), transactions and special types.
- [Design index](docs/design/README.md) and [checklist](RUST_CHECKLIST.md).
  Markdown is authoritative; `site/` is its offline presentation.

## Latest checkpoint: transparent local-key Always Encrypted

### Active Windows authentication continuation — 2026-10-19 UTC

The owner authorized implementation and bringing up the GCP lab, with a **$10
total campaign ceiling including retries**, a $1 efficiency target and retention
through review/fix/retest. Work remains uncommitted on `rust-client`.

`integrated-auth` adds opaque bounded SSPI continuations, zeroizing owned tokens/
credentials, portable `sspi` 0.23.0 NTLM/Kerberos/Negotiate, explicit TCP KDC I/O,
TLS endpoint binding, fresh recovery contexts and credential-source reread on
authentication refusal. Native Windows SSPI is isolated in `native-sspi`, keeping
the protocol crate's unsafe-code prohibition. CLI options and the stdin-only
`login_probe` example are included. Native blocking calls can outlive cancellation;
counted workers/reapers own eventual cleanup and cannot install late results.

The latest full local all-feature run recorded **252 passed, 61 live tests
ignored**; the subsequent 18452/18456 configuration cases and strict Clippy pass.
Focused tests cover verified-TLS NTLM, early LOGINACK refusal, login/KDC deadlines,
SSPI fragmentation/round limits, per-message completion and replay privacy.
Native MSVC builds and **64 distinct real Windows SQL Server login/transport
combinations pass** across macOS portable, Linux portable, Windows portable and
Windows signed-in native SSPI. See the [live evidence checkpoint](docs/design/experiments/rust-gcp-authentication-evidence.md)
for the exact conditions, lifecycle/Browser/encryption results and unmet gates.
Native MSVC full regression also passed 252 tests, 61 ignored, zero failures.
Native NTLM/Kerberos passed eight authenticated lifecycle combinations. Local-key
AE passed all four transports from macOS NTLM and Linux Kerberos, plus native
Windows Kerberos with TDS 8.0/MARS. SQL was updated in place to CU27 (16.0.4295.3)
to correct Microsoft's documented RTM strict-mode RPC defect; all 64 login
combinations were repeated successfully afterward. Strict native workspace
Clippy passes. This does not close the remaining acceptance gates below.

**Owner decision: document and defer dependency changes.** Portable NTLM remains
available with its documented retained-key erasure limitation. SQL Extended
Protection is unsupported; neither Required policy nor the tested Allowed/NTLM
combination passed. No dependency forks/patch sets or TLS backend changes are
planned. This is an accepted scope limitation, not a security-correctness claim.
See the [provider review](docs/design/experiments/rust-authentication-provider-review.md),
which links two unsubmitted upstream drafts, and the
[cross-client findings](docs/design/experiments/rust-python-authentication-limitations.md)
for documented Python follow-up work. Those Python findings are not fixed.
The SQL experiment was restored to `ExtendedProtection=0`; verified TLS encryption
remains required. Other campaign acceptance and teardown gates remain open.
The [follow-up development plan](docs/design/experiments/gcp-authentication-development-plan.md)
is approved and in progress: Python capture privacy, provider completion/bounds,
SQL credential refresh, a gated Windows configuration design, remaining Rust
platform acceptance, and cross-client testing/cleanup. The
[follow-up evidence](docs/design/experiments/gcp-authentication-follow-up-evidence.md)
records implemented Python privacy, sanitized replay metadata, token/round/message
bounds and SQL source reread/retry. Local Python: 532 passed, 379 live/Azure cases
deselected. macOS Rust: 253 passed/61 ignored; native Windows: 254 passed/61 ignored.
Native Windows strict workspace Clippy passes. Five existing Rust live recovery/
rotation functions and eight Python live configuration functions passed on GCP.
Real native cancellation observed outstanding workers and eventual retirement
in four opening profiles. The previously listed native cancellation/SQL rotation
gates must be read with this newer evidence.

Two decisions remain pending in the owner input panel: custom-provider completion
compatibility and Python Windows credential-source representation. The owner
deferred built-in synchronous provider isolation to the
[roadmap backlog](docs/design/C-roadmap.md#backlog--python-kerberos-opening-deadline).
A Linux test configured for 1500 ms remained
blocked in pyspnego startup when its process was stopped at 4010 ms. This is an
unfixed deadline defect, not a successful timeout check. See the
[concrete API proposal](docs/design/experiments/python-windows-authentication-contract.md).
Final SSPI routing is corrected, including coalesced LOGINACK and refusal of
invalid final tokens/extra output. Requiring explicit provider completion and
Python Windows configuration still need the owner decisions.
Windows lifecycle reruns passed after two task timeouts; the cause remains
unconfirmed and the diagnostics/repeat results are retained. No teardown occurred.

Terraform project: `tds-rust-auth-77681f69a4`, region `us-central1`, zone
`us-central1-a`, isolated network and DC/SQL/Linux/separate Windows VMs. Billing
is linked to the same verified existing account; its ID and credentials stay in
ignored inputs. Absolute VM DELETE expiry: **2026-10-19 04:43:47.946868 UTC**.
The paid clock began **00:47:35.142494 UTC** and is retained in the protected cost
ledger. Thirteen local cost/plan/configuration/certificate tests pass. The modeled full window plus
contingency/cleanup reserve stays below $10; actual billing is not yet verified.

An initial metadata update unexpectedly replaced fresh VMs because the provider
treated equivalent `Z` and `+00:00` expiry strings as different ForceNew values.
This happened before domain setup or credentials were delivered. Canonical `Z`
inputs plus a tested guard now refuse *all* delete/replacement actions in apply.
The subsequent plan preserved existing VMs and added only the Windows runner.
Do not blindly extend expiry through Terraform: this provider marks that field
ForceNew. Review an in-place scheduling operation and reconcile state instead.

Use `infra/gcp/lab.py` and `configure.py`, protected `gcp.json`, `secrets/`, cost
ledger and Terraform states. Do not print their credentials or delete state.
DC/domain, SQL Developer, SPNs, verified CA and both runners are configured.
`campaign.py` runs asserted smoke probes; `runner.py` refreshes dirty-source
snapshots and builds current probes. Protected artifacts include the accepted
64-case set, source hashes, failure cases and the Extended Protection experiment.
Verify live state before resuming. Normal
teardown follows reviewed acceptance/evidence export, not a test process exit.
Expiry and budget remain safety limits; warn before they force cleanup.

### Previously completed local encryption checkpoint

The local SQL integration is implemented in [design O](docs/design/O-rust-transparent-encryption.md):
version-one negotiation and wire metadata, exact normalization, fresh parameter
descriptions, named parameter encryption, authenticated rows/outputs and owned
bulk, including bulk returned result sets. Raw/default/core reading and replay
preserve explicit ciphertext; crypto failures use `NotDecrypted` cells. Decrypted
values never enter the core observation/capture pipeline. Ordinary plaintext SQL
and parameters keep their existing capture policy.

`Connection::encrypted` attaches one key owner for the current physical epoch/
lease and flushes deferred reset before key use. Transaction retention remains
the default; exchange and fixed-age overrides are explicit. `finish` skips crypto
for discarded rows. A discovery error means application SQL `NotSent`; application
SQL is not replayed. Close/drop and reattach after physical recovery. Applications
can explicitly retire keys with `invalidate_keys()`.

Current checks are **209 default, 90 core-only, 240 encryption-enabled**,
**61 all-feature live and 57 default live**; strict Clippy in all three modes,
formatting, rustdoc and all-feature local package verification pass.

The [retained report](docs/design/experiments/rust-transparent-encryption.md)
contains independent .NET read/write/lookup/bulk evidence across all 28 type cases,
a four-mode live lifecycle matrix and synthetic fault/capture checks. The tested
minimum is Rust 1.99.1 on macOS ARM64; examples, license/packaging and repeatable
`tools/check_rust.py --live` checks are included. Encrypted source producers and
borrowed plaintext chunk readers are not provided; crypto values are bounded at
16 MiB. This is the finite local AE scope, not full Python parity.

Next is the [Windows/provider campaign](docs/design/P-windows-authentication-campaign.md).
The owner selected Terraform setup/teardown in `infra/gcp/`, beside `infra/azure/`.
The [GCP plan](infra/gcp/README.md) defines six iterations, the additional-login
test matrix, a proposed separate Windows runner for remote native SSPI, cost
inputs and independently verified teardown. This is planning, not deployed IaC.
The owner clarified that Terraform must create a new dedicated GCP project and
that portable/native authentication providers are to be tested, with support
determined by evidence. The owner supplied a **$10 total campaign ceiling**,
including retries, with **$1 or less as the target**, and requested updates.
Routine naming/location/sizing choices are delegated. Retain the lab through
reviewed acceptance and fix/retest; do not tear down after the first suite or
recoverable failure. The earlier one-hour expiry is superseded: price a safety
deadline covering setup/test/review/retest within the $10 ceiling and warn before
budget/expiry forces cleanup. The previous project's billing
account is to be reused, but its ID/parent, permissions and final prices remain
unverified. No paid apply until those checks and cumulative cost preflight pass.
GCP CLI login is available; Terraform credentials and
deployment permissions remain unverified. No authentication dependency,
Windows-authentication implementation, cloud resource or Rust release is claimed.
The local checklist remains excluded from Git. Scoped Rust is not done until
Windows acceptance and verified lab teardown are complete.

## Previous checkpoint: local completion continuation

The local-only `RUST_COMPLETION.local.md` checklist is excluded through
`.git/info/exclude`. Its first five finite slices are checked: baseline, timing,
supported request/streamed-response inspection, replay evidence diagnostics and
targeted robustness. Read its scope notes; it does not assert every metadata
extension or reconstruct columns absent from a recording.

Rust exposes `Timing` on live/owned response snapshots at all levels. The shell
supplies physical-epoch-relative monotonic time to the core; the first packet is
stamped on reader consumption as Python does. Completion waits for terminal
message proof; cancellation measures cleanup. Recorded `took` descriptions are
preserved by replay. RPC/TVP/transaction/bulk input inspection and incremental
row/RETURNVALUE fragments share the existing checked readers. Large request
inspection retains its 1 MiB diagnostic omission bound.

Current checks: **206 default**, **87 core-only**, **57 serial Docker**; both
strict Clippy configurations, fmt, rustdoc and CLI build. Eight actual full-level
bulk/stream CLI captures across both versions × plain/MARS replay through both
clients with masking and timing checked. Logs: `/private/tmp/tds-completion-*`;
captures: `/private/tmp/tds-completion-cli-xxt77an8`.

**Encryption policy/local-crypto foundation implemented (D-66):** the optional
`encryption` feature provides local PKCS#8 RSA loading, signed unwrap, derived
AES/HMAC handles and authenticated byte encryption/decryption. Independent master
and column policies default to transaction; exchange and fixed-age time options
are implemented. Time can span transactions within one connection/lease. Idle
expiry, capacity eviction, cancellation/late-result checks, guarded memory and
runtime-shutdown cleanup are covered by named scenarios.

Read [scenarios](docs/design/experiments/encryption-policy-scenarios.md), then
[implementation N](docs/design/N-encryption-policy-implementation.md), then
[evidence](docs/design/experiments/encryption-policy-evidence.md). The source is
`clients/rust/src/encryption/`; `Connection::key_session` binds to actual decoded
transaction/context, pool return, recovery and close. At that foundation checkpoint applications owned a manual byte-crypto exchange
guard; the transparent SQL adapter above now supplies it.
The deferred-reset correction clears pre-ACK keys without retiring a newly
borrowed service. Opaque security-context changes require explicit invalidation.

Twenty exchanges prove 1/1 loads/unwraps for transaction defaults, 20/20 for
exchange, 1/20 for a retained master and 1/1 for retained columns only. The
30-scenario campaign has 28 unit/controller tests, one controlled recovery matrix
and two live SQL functions across 7.4/8.0 × plain/MARS. Source review traces native
RSA consistency and default destruction paths; test instrumentation separately
checks five owned buffer stages before deallocation. Stronger stack/register,
abort, custom-allocator, swap/dump guarantees are not claimed.

Python's reproduced cache collision is corrected using complete wrapped evidence
and provider/backend identity retirement. The probe now yields false/2/true;
96 focused Python encryption tests passed at that Rust-foundation checkpoint.
The subsequent Python retention checkpoint below replaces context-wide key
retention; erasure limits for Python/library temporary copies remain explicit.

New checks: 235 encryption-enabled default checks, 206 normal checks, 87 core-only,
59 serial Docker; strict Clippy in all three configurations, formatting and
all-feature rustdoc. The release `key_policy_cost` example measures the actual
service with guarded PEM loading, worker scheduling and value round trips.
Retained counters, raw logs, source hashes and cost JSON are linked from evidence.

Those local SQL integration requirements are now completed by the latest
checkpoint above. Scoped Rust remains unfinished until Windows acceptance.

That local source checkpoint is now committed in `452d458`. No GCP resources
have been created.

## Previous slice: connection/scalar-query field inspection

`inspection::Node` and optional recording in the checked reader implement named
fields/groups, explicit packet/message/token byte ranges, bounded raw/display
prefixes, protocol-reference paths and located issues. Definitions provide the
field names/ranges. Packet headers, PRELOGIN, selected LOGIN7 identity/options,
SQL batches, LOGINACK, INFO/ERROR, column/scalar row metadata/cells, NBCROW and
completion tokens form the agreed vertical slice.

Live `observe::Event.fields` is populated only at Full, alongside the existing
packet/record inspection. Healthy Outline/Full lines remain identical. The native
`replay_with_inspection(input, true, callback)` adds `Content::Inspection`; the
existing `replay` API builds no trees. Both CLI modes render the shared trees.
Capture JSONL remains unchanged. LOGIN7 inspection retains no aggregate login
payload and keeps credential spans masked even for keep-password recordings.
The whole-message diagnostic assembly bound is 1 MiB and does not limit SQL;
nodes retain at most 8,192 raw bytes and 1,024 display bytes plus a marker.

Independent Python fixtures exposed a Rust offline LOGIN7-version byte-order
defect. That field now reads little-endian, matching Python and the correct
sender; LOGINACK remains big-endian. Python code is unchanged. The prior MARS
interruption peer gained a missing first-request read checkpoint so its measured
five-byte raw tail cannot be swallowed by an earlier buffered TLS read.

Five pure inspection tests and one controlled TLS test supplement the existing
suite. Nine artificial Python cases check field ranges/bytes. Controlled tests
compare live/replayed trees with one-byte TDS payload packets in all four modes.
A new live SQL Server test compares actual login, INFO, scalar/NULL/Unicode row
and completion trees under 7.4/8.0 × non-MARS/MARS. It accepts the valid ROW or
NBCROW framing actually returned. Detailed timings and broader RPC/TVP/bulk/
streamed-value trees remain separate work. See the current acceptance check table.

## Preceding slice: interrupted I/O acceptance

The approved next iteration adds fifteen deterministic private driver tests in
`clients/rust/src/connection/shell/interruptions.rs`. A `cfg(test)`-only endpoint
field gates the real driver write boundary and forces short writes, WouldBlock,
zero writes and I/O failures. Real controlled TCP/TLS peers observe delivery.
The field and harness are absent from ordinary builds; public APIs and protocol
policies are unchanged. No production defect was established by this matrix.

Named cases cover pre-submission versus submitted abandonment; selected encrypted
TCP offsets (0, 1, 5, 17); ordinary and streamed input; partial IGNORE and Attention
writes; delegated close; owner/driver abort; MARS shared failure while writes are
blocked; prepared bulk discard; pool capacity/replacement; explicit recovery
without SQL replay; and current-endpoint revocation on runtime destruction after
pool rotation. Most cases exercise 7.4/8.0 × plain/MARS. Runtime destruction checks
plain connections under both versions. The exact matrix and exclusions are in
`INTERRUPTIONS.md`, rather than a claim of every offset or schedule.

Peer checkpoints make gates apply to request bytes after login/MARS SYN. One
test captures the successful short-write conversation and replays exactly two
batches with zero diagnostics; exact byte delivery is established independently
by its peer. Python send/undo and close/discard paths were inspected and remain
unchanged. This iteration is local branch work, separate from publication.

## Preceding completed slice: native offline replay

Native offline replay is implemented in `clients/rust/src/replay.rs` and
`replay/json.rs`, with input-reading definitions in `requests/decode.rs` and the
shared type codec. The public `replay::replay(BufRead, callback)` emits owned
recorded events, packet descriptions, decoded requests/records and diagnostics.
The actual CLI offers `--replay PATH [--observe off|outline|full]`; it opens no
connection and reads no credential or CA configuration.

One existing unversioned JSONL file represents one physical connection. Packet
channel IDs are logical lifetimes, not SMP wire IDs. Decode routing/recovery
files separately. Negotiated result encoding is shared; response readers are
per channel. Recorded times/durations remain recorded evidence. Exact Python
event text uses `SqlText`, including lone UTF-16 surrogates. Credential-bearing
packet bodies are withheld, even if a supplied recording retained credentials.

Requests materialize whole inputs; response reading is incremental. Format/wire
issues produce located diagnostics and preserve the valid emitted prefix. The
CLI exits nonzero on issues; reader/callback I/O errors are separate failures.
Zero decode issues does not prove session closure or every obligation created
by arbitrary SQL. Missing saved NO_METADATA context and unsupported extensions
are explicit limits. Broader field trees and timing analysis remain separate work.

Python's `types.TableInput` now retains saved TVP declarations and rows, separate
from result cells. It reads default columns, sort/unique/placement hints and exact
rows, including subsequent parameters/calls. Tests are in `test_tvp_replay.py`.
Rust tests are in `replay.rs`, `cli.rs`, `live_replay.rs` and `live_recovery.rs`.

The preceding slice remains important: input-only `ParamValue`/`TableType`, unique
row sources and borrowed `BulkWriter` finish/source/abort are implemented. Awaited
abort/close cancel and drain; unfinished Drop or unresolved pool return discard;
recovery refuses pending bulk. Python has the corresponding close/pool/recovery
fix. No implicit commit/rollback or request execution/retry is introduced.

## Fresh evidence and limits

The field-inspection checkpoint passes **196 default**, **78 core-only**, and
**57 serial Docker** checks. Both strict Clippy modes, fmt/docs/build and all
**37 JavaScript syntax checks** pass. The actual Full CLI shows field ranges,
reference paths and masked credentials with the expected scalar result.
Logs use `/private/tmp/tds-inspect-*`. Design L has an offline generated page.
No Python implementation or full Python regression was changed/run in this slice.

The preceding replay checkpoint had **175 default**, **73 core-only**, **56 serial
Docker tests**, with final affected replay tests rerun. The interrupted-I/O
checkpoint passes **190 default**, **73 core-only**, and **56 serial Docker**
checks. Both strict Clippy modes, formatting, documentation and executable build
pass. Python's preceding full run was **782 passed, 13 skipped**, 120.60 seconds;
it was not rerun for those Rust-only tests. Generated design pages were unchanged
at that interrupted-I/O checkpoint.

Both offline readers accept **48 fresh saved physical recordings** (32 two-client
scenario captures plus 16 Rust recovery epochs) with credential masking. Native
Rust also checks four in-memory owned/produced TVP recordings and logical recovery
row attribution. This establishes local Docker/controlled acceptance, not complete
Python parity, cross-platform/failover acceptance or measured performance.

A newly tried three-column table with defaulted identity and reversed placement
was refused with 8037/8061 through both clients on the local server. The established
four-column variant with a defaulted computed final column succeeds. Its cause
is unresolved; the acceptance log records it without changing server-validation
policy or claiming every placement combination succeeds.

## Continuing work

Use the support matrix: remaining metadata-extension fields, binary XML, alternate compute
tokens, authentication/encryption providers, broader platform/failover evidence,
additional interruption offsets/schedules and readability/release review remain open.
Native replay and Python TVP replay are completed; older pending notes are stale.
The approved finite interrupted-I/O and connection/query inspection slices are
implemented; they do not promise exhaustive scheduling or field coverage.
The user agreed a broader completion sequence on 2026-10-18 (D-65): finish local
Rust work including local-key Always Encrypted and independent .NET checks; add
Terraform GCP Windows/domain infrastructure; implement/test Windows NTLM/Kerberos
authentication; retain evidence and verify full teardown, then finish the scoped
Rust phase and move to M16. Entra and Azure-specific providers/features, Windows
certificate-store key-provider support and enclaves/attestation are deferred.
Timing is part of local completion rather than the overall roadmap objective.
See [the roadmap](docs/design/C-roadmap.md) for gates and cost/lifecycle requirements.
No GCP resources have been provisioned. `gcloud` and Terraform are installed;
the current gcloud default project belongs to another production workload and
must not be used. The owner selected a new dedicated project, the previous
project's billing account and a $10 total ceiling/$1 target. Keep one lab through
review/fix/retest, with a budget-checked safety expiry; verify project/billing
permissions and final prices before apply.
Cloud permissions/quotas are unverified.

The existing server is `mssql-2025`, `127.0.0.1:14325`, database `tds_test`.
Recheck availability. Use existing Compose and ignored credentials/test CA; do not
print secrets or recreate data volumes. Run full Python and Rust Docker mutation
suites sequentially. Exact commands are in the acceptance document.

```sh
cargo build --offline --manifest-path clients/rust/Cargo.toml --bin tds
clients/rust/target/debug/tds --help
clients/rust/target/debug/tds --replay conversation.jsonl --observe full
clients/python/.venv/bin/python tools/probe_offline_replay.py
```

The probe uses temporary recordings and disposable SQL objects with cleanup.
An optional recording-directory argument checks existing files without a server.
Rust recovery tests can save masked files with `TDS_RECOVERY_CAPTURE_DIR`; the
current sixteen are in `/private/tmp/tds-replay-recovery-iteration`. Test logs use
`/private/tmp/tds-replay-*`. Temporary evidence is not a committed fixture corpus.
After design edits run `uv run --offline tools/render_planning_pages.py`.


## Python key-retention implementation checkpoint — 2026-10-18 (before release)

Python now implements D-66 in its transparent Always Encrypted facade: transaction
(default with exchange fallback), exchange and fixed-age retention; independent
local master/column policies; bounded caches; idle expiry and exchange overrides.
One bank and statement/enclave context belongs to each physical connection/lease.
Decoded server events, pool return/reset, transport failure/recovery and close
clear/revoke authority. Deferred reset completes before parameter describing.
Owned mutable root/AES/MAC/IV buffers are overwritten; Python/library and native
provider copies remain outside that guarantee. Provider overrides and custom
backends' existing bytes contract are preserved. See the [API reference](docs/design/3-reference/always-encrypted.md#key-retention)
and [design/scenarios/evidence](docs/design/experiments/python-encryption-retention.md).

Full Python checks: **866 passed, 13 Windows/Azure infrastructure skips** in
153.30 seconds, including the existing Python/.NET encryption interoperability
check. Focused core/encryption/controller checks: **77 passed**. Forty new live
policy cases cover TDS 7.4/8.0 × plain/MARS. An unsent BulkRows source failure
exposed a prior continuation bug: preparation is now retained until awaited
channel close cancels/drains it; unresolved return/recovery remains refused.

No commit, release or cloud infrastructure was created. Rust source was preserved;
its transparent encrypted SQL integration and independent Rust/.NET acceptance
remain next. Do not confuse Python's completed SQL integration with Rust's service
foundation or equate the two memory-erasure guarantees.


## Python v0.3.0 release checkpoint — 2026-10-18

Python retention work is committed on the active branch as `98d25fd`, and copied
without Rust commits to main as `ce9566c`. Release commit `1e974dc` updates version,
lockfile, compatibility notes, policy decision and documentation. Main and the
annotated `v0.3.0` tag were pushed and remotely verified at that release commit.
GitHub Release: https://github.com/dawsonlp/tdsprotocol/releases/tag/v0.3.0
Its notes explicitly say Rust implementation exposed the need for these policies.

The isolated main-based checkout passed **866 tests, 13 Windows/Azure infrastructure
skips** in 148.29 seconds, including Python/.NET encryption interoperability.
An initial run lacked ignored mock-server TLS fixtures; linking the existing
local test CA, server certificate and server key fixed setup without source changes.
When repeating isolated tests, supply all three TLS fixtures and the test password
through the environment; never commit/copy key material into release assets.

Wheel and source builds passed offline. All 34 packaged Python modules match the
release checkout. An isolated installed wheel verified version 0.3.0, API imports,
CLI help, all policy choices, value crypto and cleanup. The three GitHub assets
(wheel, source archive, SHA256SUMS) were downloaded and verified against the local
artifacts and published checksums. GitHub Pages run `39171122479` succeeded; its
live index, Python retention page and Always Encrypted reference match the release.

The active branch has metadata/evidence alignment commit `82998a9`;
`git diff main -- clients/python` is empty. Other snapshotted source/draft files
were preserved by hash; this handover was updated intentionally. The temporary
release worktree is removed after verification. Existing Rust work remains
uncommitted and unpublished; Rust SQL encryption/.NET acceptance is still next.
