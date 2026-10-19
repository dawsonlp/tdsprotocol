# Bulk continuation and abandonment experiment

**Where this sits:** Evidence for completion decision A2, after successful `INSERT BULK` and before any row data.
**After reading this you can** distinguish the Rust ownership choice from SQL Server cleanup and transaction effects.

## Question and scope

This document preserves the investigation before the correction. The user has
since approved the borrowed writer and the six cleanup rules below. Both clients
now enforce the continuation during close/pool return/recovery. Rerunning the
probe on the corrected source should show safe channel close and replacement of
the pool's unresolved connection; the original failure rows are historical
observations, not expectations for the corrected clients. See
[completion design](../J-rust-completion.md) and the new lifecycle tests.

The public API could expose a borrowed writer or Python's two-request sequence.
Both would send the same successful wire conversation: SQL batch containing
`INSERT BULK`, server completion, bulk metadata/rows/DONE, server completion.
The server cannot distinguish the Rust representations. Their difference is
whether Rust borrowing or runtime checks protect the continuation. Abandonment
policy is a separate choice; a borrowed writer need not discard on an explicitly
awaited abort.

The initial A2 wording combined the ownership choice with conservative Drop
behavior. This experiment separates them. No production client code is changed
by this investigation. A1's input-only table parameter representation was approved
by the user independently.

## Reproduction

Run from the repository root:

```sh
clients/python/.venv/bin/python tools/probe_bulk_continuation.py
```

Observed on 2026-10-17 against the existing Docker SQL Server 17.0.5015,
`tds_test`, verified project CA, TDS 7.4/8.0 × plain/MARS. The tool obtains existing
ignored credentials without printing them. Raw experimental requests bypass
Python's `OutOfTurn` guard deliberately; they are not an application API.
Cases use connection-local temporary tables. One uniquely named permanent table
allows another connection to observe transaction rollback on physical close;
it is dropped in `finally`. No data volume or container is recreated.

The first attempted MARS rollback probe used T-SQL BEGIN and subsequent work in
one batch; the server refused the unfinished batch transaction with error 3997.
The corrected experiment uses the client's explicit transaction-manager BEGIN,
matching the existing transaction contract. This was a probe correction, not a
bulk-upload finding. The corrected four-mode probe completed twice; the final
run asserts the server-state results. Output: `/private/tmp/tds-bulk-continuation.log`.

## Observations

| Action after preparation | Observed result |
|---|---|
| Send the expected bulk message with zero rows | A successful count-zero completion; next query succeeds; no open transaction in the autocommit case |
| Send Attention and consume the full acknowledgement | DONE status `0x22` (ERROR + ATTENTION); next query succeeds; zero rows and no open transaction in the autocommit case |
| Attention with an earlier explicit transaction, `XACT_ABORT OFF`, and one preceding insert | Next query reports one retained row, `@@TRANCOUNT=1`, `XACT_STATE()=1`; the transaction remains open and committable; explicit rollback then succeeds |
| Close the whole physical connection after an earlier committed insert and another insert in an explicit transaction | A separate observer sees only the committed insert; the preceding uncommitted insert is rolled back |
| Send an unrelated INSERT/SELECT instead of bulk data | Error 4022; that INSERT does not execute; a subsequent ordinary query succeeds |
| Close/reopen Python's plain channel without completing the continuation | The replacement's first query gets error 4022; another query then succeeds |
| Close/reopen Python's MARS channel without completing the continuation | Replacement query fails with `ConnectionError` or server errors 3980/596, then `ChannelClosed`; no safe reusable connection is established by this path |
| Return the pending continuation through Python's pool | The pool reuses the original protocol core. The next borrower fails with error 4022 in plain framing, or `ConnectionError` in MARS framing |

The MARS observation describes the present client/server interaction. The first
query's error varies between runs. Exception types alone do not establish which
server FIN/connection handling detail caused it; this experiment does not
attribute every MARS failure to server policy.
The plain pool failure and recorded core identity already demonstrate an unsafe
handover, independently of the MARS cause.

Three existing live tests were also rerun and passed:

- `test_bulk_data_out_of_turn_closes_the_connection`: standalone bulk data receives
  an error completion and is followed by connection closure. An intervening
  request gets error 4022 and ends the bulk expectation; bulk data after that is
  out of turn.
- `test_a_failing_source_is_abandoned_and_nothing_loads`: after more than one
  packet of rows, a source failure uses IGNORE/EOM, no rows load and reuse works.
- `test_identity_one_statement_and_transactions`: constraint failure loads no
  rows; a successful bulk insert inside an explicit transaction is removed by
  an explicit rollback.

These existing tests use their configured default transport. The new gap probe
provides the explicit four-mode matrix. The zero-row case is a completed empty
statement, not a cancellation; triggers/options are not assessed by that case.

## Consequences for both clients

An unfinished bulk continuation is a real server obligation even after its first
response has ended. It must remain visible to channel close, pool release and
recovery eligibility. Python currently tracks it for ordinary request ordering,
but close and pool release overlook it. This is a shared correctness requirement,
not a reason to preserve Python's present failure in Rust.

Policy investigated here and subsequently approved and implemented:

1. A borrowed `BulkWriter` protects same-channel sending/reading authority.
   Runtime continuation state remains necessary for delegated controls and lease
   return, since channels do not exclusively borrow their connection.
2. Successful completion sends the bulk terminator and consumes the response.
   It does not commit an application's enclosing transaction.
3. An explicit awaited abort in the preparation gap sends Attention, consumes its
   acknowledgement under the existing cleanup budget and permits reuse only
   after proof. The surrounding transaction follows actual session announcements;
   abort does not silently roll back or commit it.
4. Partial transmission retains the established IGNORE/EOM cleanup procedure;
   cancellation after complete transmission must observe acknowledgement and the
   received completion. No operation is replayed.
5. Dropping unfinished authority without awaited cleanup discards the physical
   connection, consistent with the existing Rust Drop contract. This loses its
   session, affects MARS siblings and rolls back open transactions. Already
   committed work is not undone; a lost final reply can leave bulk execution
   uncertain.
6. A pool must not hand the pending continuation to another borrower. Awaited
   proven cleanup may preserve the connection; unresolved state must discard.
   Apply the corresponding close/release correction to Python after agreement.

The two-request public API can implement the same server policy using runtime
checks. The remaining A2 choice is primarily how explicitly the public API
expresses this ownership, rather than which server behavior is available.

Sources: the local experiment above and the existing Python tests;
[MS-TDS Bulk Load](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/88176081-df75-4b24-bcfb-4c16ff03cbfa),
[Bulk Load BCP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/ab4a7d62-cd1f-4db1-b67d-ecae58f493e3).

## Correction verified

The same probe now asserts the corrected outcomes. A fresh four-mode run passes:
channel close is followed by a successful zero-row count; unresolved pool return
uses a different protocol core and has no old temporary table. Session IDs were
reused by the server during this run, so they are not used as physical-connection
identity evidence. The earlier transaction/Attention/physical-close observations
remain unchanged. Log: `/private/tmp/tds-bulk-continuation-corrected.log`.

The full Python regression passes **766 tests, 13 skips**. The Rust controlled
and live cases and the runnable bulk demo are listed in
[acceptance](../../../clients/rust/ACCEPTANCE.md).
