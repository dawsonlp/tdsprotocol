# Recovery channel identity experiment

**Where this sits:** Evidence for the shared connection recovery contract.
**After reading this you can** distinguish a successful recovery login from usable recovered channels, and explain the identities and permissions that survive.

Observed 2026-10-17 on the `rust-client` development branch. The intent is to
preserve usable connection/channel objects across an eligible session recovery,
without giving any interrupted exchange authority over the replacement.

## Question and original observations

Does a successful recovery login actually leave the original channel usable?
The original Python implementation reused an application channel's number as its
physical SMP session id. Against the existing Docker SQL Server (LOGINACK
17.0.5015), the saved probe observed:

| Case | Original result |
|---|---|
| Fresh connection, first wire id 0 | SELECT returned 11 |
| Fresh connection, first wire id 1 | ConnectionError |
| Channel 0 survives an idle relay cut and recovery | Same object returned 22 |
| Close channel 0, retain channel 1, cut and recover | Login succeeded; query on the same channel 1 timed out |

The latter reader stayed alive without a core failure until the probe deadline.
This distinguishes a successful recovery login from successful channel recovery.
These observations do not establish a universal MC-SMP first-id requirement.

## Intervention and resulting behavior

Separate the application lifetime id from the physical SMP wire id. Preserve the
application id and owner; allocate fresh wire ids from zero for each replacement
transport. Route incoming SMP frames through the inverse mapping. New channels
continue the application counter and the replacement transport's wire counter.
Never reuse either identity within its own lifetime/namespace.

The same probe now observes channel 1 returning 22 after recovery, mapped to wire
id 0. The fresh-first-wire-id-1 control still fails. The intervention fixes both
outgoing addressing and incoming delivery, rather than merely changing SYN.

| Application lifetime | Before the break | Replacement transport |
|---|---|---|
| Channel 0, closed by application | Wire 0, retired | Remains closed; no new mapping |
| Channel 1, retained owner | Wire 1 | Wire 0 |
| Channel 2, retained owner | Wire 2 | Wire 1 |
| New channel 3 | Does not exist | Wire 2 |

Thus stale application id 0 cannot target retained channel 1 merely because its
new wire id happens to be 0. Likewise, an old response's authority belongs to the
failed physical epoch, even when its application channel continues.

Run from the repository root, using the existing ignored Docker credentials/CA:

```sh
clients/python/.venv/bin/python -u tools/probe_mars_recovery_identity.py
clients/python/.venv/bin/python -m pytest clients/python/tests/test_recovery_channel_identity.py clients/python/tests/test_recovery_channel_identity_live.py -q
```

Two core cases and eight Docker cases pass. The live matrix covers TDS 7.4/8.0 ×
plain/MARS, three recoveries through the same objects (automatic and explicit),
session settings, retained fetched rows, multiple MARS survivors and reverse
response consumption, later channel allocation, retired channel controls,
pre-recovery delegated channel/connection close permissions, and a separate
independently replayable recording per physical connection. Old unfinished
response read/cancel/close operations leave the replacement request undisturbed
and emit no Attention. NOWAIT flushes output before the cut, and the response is
asserted unfinished; merely receiving a SELECT row would not establish this.

Full Python regression after the correction: **695 passed, 13 skipped**, 112.17 s.
The skips were 10 Azure, 2 Kerberos and 1 Windows certificate-store case. A
subsequent focused run with the stronger close/Attention assertions passed all
10 new cases in 2.87 s. These are recorded run results, not fresh evidence from a
future checkout. No in-flight SQL replay or transaction rollback is inferred.

## Agreed implementation contract

The user approved implementation after this feasibility check. A logical
connection and each unrevoked channel retain their authority across eligible
recovery. A physical connection owns TCP/TLS/login, wire ids and one recording.
Each exchange belongs to exactly one physical epoch. Recovery retires all old
exchange controls, pending read/abandonment guards included; root/channel close
permissions still apply to their logical lifetimes. Application-closed channels
stay closed. Pool return retires borrower authority independently of recovery.

Recover only from observed transport failure with server-approved reconstructible
session state. An idle break may be recovered before sending a newly submitted
request. An interrupted request fails with its partial response and uncertain
execution; explicit recovery must precede subsequent SQL. Never replay it.
Protocol/fatal/recording/cleanup failures and explicit revocation do not qualify
for automatic recovery. Failure writing a requested new recording is terminal.

Python implements this with a fresh core/link, retained application ids/owners,
fresh SMP ids and old response sources pinned to the failed core. Rust uses one
persistent driver, fresh protocol state and physical epoch checks; its
implementation and acceptance results are recorded in `clients/rust/ACCEPTANCE.md`.
The Python proof alone is not Rust acceptance or evidence for every deployment.

## Rust implementation results

The same behavior is now implemented and tested in Rust. Run from `clients/rust`:

```sh
cargo test --all-features --offline
cargo test --no-default-features --offline
TDS_RECOVERY_CAPTURE_DIR=/private/tmp/tds-rust-recovery-captures cargo test --offline --test live_connection --test live_recovery -- --ignored --test-threads=1 --nocapture
```

From the repository root, check saved recordings through Python:

```sh
clients/python/.venv/bin/python tools/replay_rust_recovery_captures.py /private/tmp/tds-rust-recovery-captures
```

| Evidence | Result |
|---|---|
| Rust all-feature regression | 31 unit, 61 controlled-network, 4 rustdoc checks pass |
| Rust core-only regression | 28 tests pass |
| Existing Rust Docker scenarios | 22 pass, zero skips, 7.57 s |
| New Rust Docker recovery matrices | 3 tests pass, zero skips, 4.96 s |
| Saved Rust physical conversations | 16 replay through Python; logical row attribution and credential redaction pass |
| Formatting, strict Clippy in both feature configurations, rustdoc generation | Pass |
| Final full Python regression after transport pinning and failed-socket closure | 696 passed, 13 skipped, zero failures; 123.24 s |

The new live matrices contain 4 continuity scenarios with three replacements
each, 8 interrupted-request/control scenarios and 10 refusal/opt-out scenarios.
They retain original channel values and pre-recovery close handles. An armed old
read future and unfinished response survive recovery and are then dropped; the
same channel successfully runs new SQL. A separate path observes uncertainty,
proves subsequent SQL does not automatically reconnect, then explicitly recovers.
Already buffered old tokens can still precede the original failure; they never
come from the replacement exchange. Retained metadata/fetched rows stay usable.

Eight controlled TLS cases check missing/malformed/duplicate/unrequested feature
acknowledgement, a silent candidate's single deadline, explicit retry, root close,
recovery-future Drop, optional observer failure across a failed attempt, direct
capture refusal and new saved-recording factory/write failure. Artificial
Python-generated login/recovery fixtures are byte-for-byte comparators; the normal
Rust test suite does not require Python or Docker to consume them.

The open-transaction refusal is checked on plain connections. SQL Server returns
3997 and rolls back a transaction left open at the end of a MARS batch, so that
batch cannot establish the intended idle refusal. Temporary-table refusal and
feature opt-out cover both modes. These tests do not infer rollback of an
interrupted application request, nor prove remote availability-group failover,
other platforms, full SQL type support or performance.

## Reading the implementation

Python's `Link` allocates wire identities and maps incoming frames back to public
ids. `ConnectionCore.adopt` carries owners/public ids forward. Response sources
keep the failed core, and `Connection._run` pins its socket/inboxes and rejects
late I/O after core replacement, including a delayed application callback.

In Rust, `tokens` describes FEATUREEXTACK/SESSIONSTATE and `session::Recovery`
keeps opaque values, per-state ordering, refusals and the original baseline.
`ConnectionCore` encodes recovery logins and maps each logical channel to its new
wire session. `connection::shell::recovery` owns candidate sockets, deadline and
commit. `Endpoint`/`Abandon` distinguish continuing logical close authority from
epoch-scoped request abandonment; comparison and revocation share a short lock.
No core callback, socket, task identity or clock policy is needed to express the
protocol transitions.
