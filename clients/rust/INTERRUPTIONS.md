# Interrupted I/O: acceptance boundaries

Approved iteration, 2026-10-18. The outcome is a connection that is either proved
clean before reuse or explicitly discarded, with execution uncertainty preserved.
This is a finite acceptance matrix, not an assertion about every scheduler or
kernel-buffer arrangement.

## Representation and obligations

An exchange belongs to a channel lifetime and a physical epoch. A pool return
retires its borrower endpoint. Recovery retires the failed physical epoch while
preserving eligible logical channels. Neither operation retries interrupted SQL.

The relevant boundaries are distinct:

| Boundary | Required consequence |
|---|---|
| Exchange future created but unpolled | No submission or connection revocation |
| Waiting for mailbox capacity | Dropping the future submits nothing and preserves the connection |
| Command submitted, including before its first socket byte | Abandonment revokes the connection; the caller cannot assume the driver has not started |
| A request packet is partly written | Resume at the retained offset, or discard; never restart that packet or SQL |
| Streamed input has started, then fails or is explicitly closed | Finish the current packet, send IGNORE + EOM, and drain before reuse; failed/abandoned cleanup discards |
| Complete request awaiting a response | Awaited cancellation requires Attention acknowledgement and its message boundary |
| Prepared bulk continuation | Completion or explicit abort must resolve it; abandonment discards |
| Physical epoch or pool borrower replaced | Old advancing guards cannot revoke the replacement; old borrower controls have no authority |
| Driver/runtime destroyed | Revoke the current endpoint and close the owned socket, even after a pool endpoint rotation |

`PossiblyExecuted` is conservative. A scripted zero-byte write after command
submission does not add a public `NotSent` guarantee. A cancellation, IGNORE,
completed drain, or physical close is not evidence of transaction rollback.

## Deterministic driver tests

The private `connection::shell::interruptions` module drives the ordinary
connection, channel, pool, producer, recovery and teardown paths. A test-only
endpoint field controls the existing `flush_output` write boundary. It can limit
real TCP writes, return `WouldBlock`, pause readiness, return zero, or inject an
I/O error. It does not replace the driver loop, protocol core, TCP peer or TLS.
The module and field are absent from ordinary library builds. No public transport
interface or background cleanup policy is introduced.

Each request-write script starts after the peer has acknowledged login and
observed the MARS SYN where applicable. This prevents a test from accidentally
interrupting channel creation instead of the intended request. Gates use
one-shot notifications, rather than sleeps or assumptions about buffer sizes.
Each network scenario has a five-second failure bound. The cleanup-timeout case
uses an explicit 100 ms protocol cleanup budget.

Unless stated otherwise, each row runs TDS 7.4 and 8.0 with plain and MARS channels.
Here, plain means non-MARS; every network scenario uses verified TLS.
Offsets count encrypted TCP bytes from the selected output, not SQL characters
or decrypted TDS fields. Offset 5 is the TLS record header boundary; offset 17
is an interior point in these controlled records.

| Test function in `src/connection/shell/interruptions.rs` | Selected boundary and evidence |
|---|---|
| `exchange_abandonment_distinguishes_unpolled_reserved_and_submitted_work` | Three mailbox/submission states; only submitted abandonment revokes; no socket needed |
| `short_writes_and_would_block_resume_at_the_exact_offset_without_replaying_sql` | Writes of 1, 2 and 7 bytes with an intervening `WouldBlock`, pause after 10 bytes, then a 3-byte write; peer receives each exact SQL body once; native replay sees exactly two batches with zero issues |
| `zero_and_failed_partial_writes_discard_and_report_uncertain_execution` | Zero write or `BrokenPipe` at offsets 0, 1, 5 and 17; exact peer byte count, uncertain execution, no reuse or pending reconnect |
| `aborting_the_owner_during_a_blocked_write_discards_every_selected_prefix` | Owner task aborted at offsets 0, 1, 5 and 17; exact peer byte count and socket destruction without opening the write gate |
| `aborting_the_driver_during_a_partial_write_keeps_execution_uncertainty` | Driver task aborted at offset 5; waiter retains exchange step and uncertain execution; endpoint revoked and socket closed |
| `partial_stream_writes_preserve_ignore_eom_cleanup_and_reuse` | Streamed RPC paused at offset 5, then producer failure; peer sees IGNORE + EOM; original error and ended response retained; next batch succeeds |
| `a_partial_ignore_eom_write_failure_preserves_both_causes_and_discards` | Producer failure followed by `BrokenPipe` after three cleanup bytes; both causes survive and transport is discarded |
| `delegated_close_finishes_the_partial_packet_then_ignores_and_drains_before_reuse` | Close established while the first streamed packet is paused at offset 5; IGNORE/drain and MARS FIN precede a new channel lifetime; closed lifetime cannot send |
| `a_cleanup_deadline_interrupts_a_partly_written_attention_without_reuse` | Attention paused at offset 3; repeated cancellation preserves the first deadline; timeout retains cancellation and cleanup causes and discards |
| `abandoning_cleanup_during_a_partial_attention_discards_without_finishing_its_write` | At Attention offset 3, drop the close future or only the advancing read future; immediate revocation and exact three-byte peer tail |
| `aborting_bulk_data_send_discards_the_prepared_continuation` | After successful preparation, abort the data-sending owner at offsets 0 and 5; no recovery/adoption of unfinished bulk |
| `mars_reads_a_peer_failure_while_writes_are_blocked_and_fails_both_channels` | MARS only, both versions; invalid incoming SMP while a sibling send is paused at offset 5; both exchanges receive the same cause with incomplete response records |
| `a_pool_replaces_an_aborted_partial_send_without_losing_capacity_or_authority` | Abort at offset 5; return discards and restores capacity; a fresh verified login receives only the replacement SQL; old close controls cannot affect it |
| `explicit_recovery_after_a_partial_write_never_replays_the_interrupted_request` | `BrokenPipe` after five bytes; explicit server-acknowledged recovery; old epoch guard is harmless; replacement receives only newly submitted SQL |
| `runtime_shutdown_revokes_the_current_rotated_pool_endpoint_and_closes_its_socket` | Plain channels, both versions; destroy a runtime with a retained idle lease after endpoint rotation; peer observes EOF; stale channel fails; another runtime obtains capacity and a fresh login |

Existing controlled tests complement this matrix: `cancellation.rs` checks final
DONE before ACK, malformed/missing ACK, and abandoned acknowledgement waits;
`streaming_shell.rs` checks partial streamed-value reads and waiting producers;
`bulk_shell.rs` checks the preparation gap; `pool.rs` checks FIN-return cancellation;
`recovery.rs` checks failed and abandoned replacement logins. The live suite checks
actual SQL Server cancellation, response abandonment and owner-task abortion.

## Commands and limits

```sh
cargo test --offline --lib connection::shell::interruptions
cargo test --offline
cargo test --offline --no-default-features
cargo test --offline --tests -- --ignored --test-threads=1
```

Run from `clients/rust/`. Live cases use the existing isolated SQL Server and
ignored credentials. Python and Rust server mutation suites must remain serial.
Current run results are in [ACCEPTANCE.md](ACCEPTANCE.md).

The selected cases have not established a production defect or a reason to change
the agreed Python/Rust policies. Python's send/undo, close/drain and canceled-close
discard behavior were inspected; Python is unchanged in this iteration.

Remaining limits include other offsets/packet sizes, successful MARS credit
updates under every blocked-write schedule, task abort at every TLS handshake or
recovery write, all TVP/type combinations, real kernel saturation, other native
platforms, remote failover, and memory/latency/throughput measurements. Saved
capture packets describe protocol output, not proof of individual socket writes;
the controlled peer supplies the byte-delivery evidence here.
