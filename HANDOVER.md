# Rust client handover

Prepared 2026-10-18. Branch: `rust-client`. This development checkpoint commits the
Rust implementation, tests, fixtures, design records, probes and offline site.
Inspect `git status` before editing to distinguish subsequent working changes.
Python corrections are committed and released as **v0.2.0** on `main`; the Rust
implementation remains unpublished. The active checkout stays on `rust-client`.

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
  **Native offline replay** section are the latest checkpoint. Earlier sections
  retain historical results, including the preceding table/bulk slice.
- [Rust README](clients/rust/README.md): public API, lifetime rules and CLI.
- [Offline replay design](docs/design/K-offline-replay.md): approved representation,
  capture compatibility, failure boundaries and evidence limits.
- [Completion design](docs/design/J-rust-completion.md): approved and implemented
  input-only TVPs (A1), borrowed BulkWriter (A2), transactions and special types.
- [Design index](docs/design/README.md) and [checklist](RUST_CHECKLIST.md).
  Markdown is authoritative; `site/` is its offline presentation.

## Latest completed slice

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
are explicit limits. Full field trees/reference links and timing analysis remain
separate work.

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

Rust: **175 default**, **73 core-only**, **56 serial Docker tests**. After the
final diagnostic-only refinements, **11 affected default** and **9 core-only**
tests pass again. Strict Clippy in both modes, formatting, rustdoc and executable
build pass. Python: **782 passed, 13 skipped**, 120.60 seconds. Python's full run
followed all Rust/live probe mutation work. Generated pages and all page JavaScript
syntax checks pass; `git diff --check` is clean.

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

Use the support matrix: field inspection/timings, binary XML, alternate compute
tokens, authentication/encryption providers, broader platform/failover evidence,
forced partial-write/abort coverage and readability/release review remain open.
Native replay and Python TVP replay are completed; older pending notes are stale.

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
