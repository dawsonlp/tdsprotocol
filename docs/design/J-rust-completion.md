# Rust completion work and architectural decisions

**Where this sits:** The autonomous continuation after typed RPC and large-value streaming.
**After reading this you can** see completed slices, evidence limits and decisions reserved for the user.

**Vision:** complete the Rust protocol client as clear, literate code with Python's
correct behavior, explicit ownership and permissions, exact values and visible
wire conversations. Reuse the agreed unique channel/source and borrowed reader
contracts. Keep optional diagnostics separate from saved recording failures.

The user authorized proceeding through independent work while away, recording
architectural questions here rather than blocking the whole task. Existing Python
code and protocol documentation establish the baseline; an implementation detail
within those contracts is not a new policy decision.

## Work queue

1. Implemented: explicit transaction-manager requests and announced session state.
2. Implemented: unique sources in batched RPC calls, using the existing producer contract.
3. Implemented: browse/classification metadata; CLR serializations, `sql_variant`,
   native JSON, vectors and explicit SQL collation views.
4. Implemented: input-only TVP values and unique row producers (A1); borrowed
   bulk continuation ownership and explicit finish/abort (A2 below).
   Field inspection, authentication providers and encrypted
   conversations remain separate work in the support matrix.
5. Verify the whole regression, actual CLI, Python cross-replay and shared fixes;
   record commands and evidence in the acceptance document.

## Architectural decisions

### A1. Table-valued input representation

A table parameter has a SQL table-type identity, column/default/order metadata,
and owned or produced rows. It never arrives as a scalar result cell. Python's
dynamic parameter values can directly contain either rows or a row source;
Rust's approved `Option<Value>` currently describes scalar/large cell payloads.

Scenario: one RPC mixes an integer, a produced table of rows, and an output value.
The producer must remain unique and obey existing partial-send cleanup. Each
row's cells are whole values, matching Python, with server-default columns omitted.

Approved by the user on 2026-10-17: add an input-only parameter value type for
table-valued inputs. Returned scalar cells do not acquire input-only table/source
meaning. This permits the necessary change to the unpublished parameter
construction API. `ParamValue::Scalar` and `ParamValue::Table` now distinguish
these inputs. Existing scalar `Param::new` calls remain valid; direct users of
the unpublished `Param.value` field must match the enum. `Param::table` accepts
owned rows, while `StreamedCall::table_source` binds a unique `RowSource` to a
None placeholder. `TableType` keeps type identity, default columns and hints;
row cells omit server-default columns. `send_order` must place every column once
so values can be encoded; semantic applicability remains the server's decision.

### A2. Bulk continuation authority between exchanges

Python models `BulkInsert` followed by `BulkRows` as two ordinary requests, with
an explicit channel continuation state. A successful first response leaves the
server waiting for bulk data; it must not make the connection pool-reusable.

Scenario: preparation succeeds, then the application drops its next step, submits
a different request, or returns the lease. The client must protect the unfinished
protocol obligation across this gap.

Approved by the user on 2026-10-17: expose a dedicated borrowed `BulkWriter`.
Bulk sequencing is an explicit exception to server-only semantic validation,
as already decided for Python in D-50. Both representations send the same wire
conversation. Borrowing protects ordinary same-channel use statically; runtime
state remains necessary for delegated controls and pool return in either case.

The [bulk continuation experiment](experiments/bulk-continuation.md) separates
this ownership question from abandonment policy. Explicit Attention in the gap
is acknowledged and permits reuse under both versions × plain/MARS. Under
`XACT_ABORT OFF`, an earlier explicit transaction stays open and committable.
Physical close instead rolls back earlier uncommitted work. The experiment
exposed Python channel close/pool return overlooking the continuation. The shared
correction is now implemented: awaited close drains Attention; unresolved pool
return discards instead of exposing that obligation to another borrower.

Approved cleanup contract: a borrowed writer offers awaited finish
and awaited abort. Abort uses the appropriate protocol cleanup and permits reuse
only after proof, under the existing budget. Drop without awaited cleanup
discards, following the established Rust contract; it is not the only way to
stop an upload. No automatic commit/transaction rollback or replay is introduced.
The existing Python request pair follows the same server policy. Implementation
includes closing a prepared continuation through Attention/drain and refusing
pool reuse/recovery while that obligation remains unresolved. No automatic
transaction commit/rollback is added.

`SerialChannel::bulk(sql, columns)` borrows the channel after successful
preparation. The application supplies SQL and matching result metadata; no SQL
is generated. `finish(rows)` validates owned rows before data transmission;
`finish_source(source)` polls whole rows incrementally. Local failure before the
first data packet explicitly aborts the prepared operation. Partial input uses
the existing IGNORE/EOM and bounded drain path, without retrying rows or claiming
rollback. `abort()` waits for Attention acknowledgement, including its message
boundary. An ordinary DONE is not that proof. Drop performs no protocol I/O.

Runtime continuation state supplements borrowing: forgotten writers cannot send
unrelated requests, delegated controls still work, and pool/recovery checks see
the obligation. After delegated close has drained successfully, dropping the old
writer cannot revoke a replacement channel. Python retains its explicit request
pair and task ownership, with the same close/reuse/recovery consequences.

TVP owned request bytes match twelve Python-generated cases. Controlled peers
check produced-table offsets across trailing parameters and batched calls, plus
bulk ACK ordering, timeout and forgotten-writer cleanup. Docker tests exercise
7.4/8.0 × plain/MARS, real TVP procedures/defaults/hints/outputs, bulk exact values,
large cells, source failures before/after transmission, transaction preservation,
delegated close and pool discard. Exact current totals are in
[Rust acceptance](../../clients/rust/ACCEPTANCE.md).

## Implementation and evidence

### Explicit transactions and batched producers

`transactions::Transaction` is one ordinary exchange describing begin, save,
commit, rollback, promote, propagation or coordinator-address lookup. `Begin`
names the isolation/name; `End.begin` requests another begin in the same message.
Only received ENVCHANGE changes the shared transaction descriptor. Rust adds no
implicit transaction guard, rollback-on-drop, retry or authority beyond the
authenticated SQL principal. Deferred pool reset also applies to these requests.
Nested/savepoint/commit-and-begin and reset scenarios pass against Docker;
distributed request encodings match Python, but successful external coordinator
enlistment is not established by a local refusal/reuse test.

`StreamedCalls` consumes a sequence of `StreamedCall` values. All declarations
and bindings validate before any producer is polled or bytes are committed.
Producer offsets refer to the complete RPC body, including batch separators.
A later producer failure uses existing partial-input cleanup and preserves
execution uncertainty. A batch is not atomic; earlier calls may have executed.
No source or call is replayed, and successful drain does not prove rollback.

### Metadata, special values and negotiated encodings

`ResultSet` retains TABNAME/COLINFO browse provenance and DATACLASSIFICATION
independently of row retention. Classification resolves checked references to
named labels and information types; version two also carries ranks. Public
accepted feature bytes remain in `Session.features`. A requested version may
be downgraded; malformed, duplicate and unrequested acknowledgements are refused.
The runtime defaults request only implemented Python defaults: recovery, UTF-8,
JSON, vector version two and classification version two. Bare LOGIN7 codec
defaults remain opt-in so constructed wire definitions stay explicit.

- `SqlType::Clr` identifies database/schema/type. `Value::Binary` and binary
  chunks retain its serialization; assembly and size remain result wire metadata.
  Input declarations contain names alone. No CLR assembly is loaded or interpreted.
- `Value::Variant(SqlVariant)` carries its own supported bounded base declaration
  and non-NULL payload. Outer `None` is SQL NULL. Nested variants, large bases,
  contradictory properties and truncated bounded bodies are refused.
- `Value::Vector(SqlVector)` preserves float32/float16 IEEE bits. `SqlHalf`
  provides an exact, checked float32 conversion. Every binary16 bit pattern is
  covered; nonfinite inputs and rounding are refused. The Docker server's actual
  acknowledged version decides the live float16 expectation. Constructed float16
  codec evidence is kept separate from server acceptance. A non-native vector
  fallback is character JSON text; UTF-8 negotiation can select varchar.
- `SqlType::Json` uses `Value::Unicode(SqlText)` and Unicode chunks. The SQL
  declaration stays distinct from `TypeInfo.json_utf8`, the negotiated result
  encoding. Results decode incrementally as accepted UTF-8 or UTF-16, preserving
  Python's exact surrogate semantics. Inputs always use strict UTF-8 and refuse
  unpaired surrogates. No JSON parser or normalization rewrites the document.
  Saved JSON columns use the current session encoding in both clients, even if
  their metadata came from a connection with a different accepted UTF-8 setting.

### Collated text and command-line learning

Exact varchar bytes remain `SqlTextBytes`. Explicit `decode`, `from_text`,
`Collation.encode` and `Collation.decoder` provide SQL-corrected character views.
The generated mapping is derived from Python's reviewed SQL Server 17.0.5015
tables and codec behavior: sixteen legacy pages plus UTF-8. Unknown collations,
Unicode-only varchar conversion views and unrepresentable characters are refused;
there is no guessed page or replacement character. Invalid stored bytes use
Python's low-surrogate escapes. Encoding selects SQL's canonical byte mapping,
which need not reproduce every alias of the original bytes. The original bytes
remain untouched. A streaming view retains only an incomplete character suffix.

`tools/generate_rust_collations.py` regenerates the binary tables and independent
Python digests without database credentials. Pure checks cover every byte pair
and fragmented decoding; Docker checks bounded/max values on all seventeen pages
under TDS 7.4/8.0 × plain/MARS. These data are shared SQL mappings, not the separate
strict host-codec policy used by Browser discovery.

The actual `tds` executable demonstrates explicit transactions with
`--demo-transactions`, accepts JSON/vector/CLR/varchar literals, and displays
decoded varchar values when the collation is known. CLR identities preserve
case. Vector literals refuse rounding. Existing query/RPC/fetch/chunk/file-source
operations remain available. Eight new CLI recordings cross-replay with Python
and retain LOGIN7 masking; earlier scalar/streaming probes remain regression checks.

### Shared Python corrections and evidence boundaries

The new cross-replay experiment exposed missing negotiated result context in
Python replay and result-only layouts being used for input inspection. The live
login and replay now share feature interpretation. RPC input definitions name
their direction: JSON input is UTF-8, CLR input omits result assembly/size, and
legacy input omits result provenance/pointer framing. Fifteen NULL/empty/value
cases check actual full recording and replay under both result-encoding settings.
Both clients also reject vector payload/header contradictions. Python's live
float16 test now follows negotiated capability instead of one server's refusal.

See [the acceptance record](../../clients/rust/ACCEPTANCE.md) for final commands,
counts and limits. Native platform/provider/distributed-server claims require
their own infrastructure; local Docker and controlled peers establish narrower
evidence. Full Python parity, field inspection trees and native Rust replay are
not implied by this slice.


Native offline replay and shared Python table-input reading are implemented in
[design K](K-offline-replay.md); its acceptance supersedes the earlier replay gap.
