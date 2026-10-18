# Offline Rust replay

**Where this sits:** the observation and capture contract, implemented in Rust.
**After reading this you can** replay a recording and distinguish decoded evidence from missing context.

**Vision:** inspect a Python or Rust recording with the Rust client, without a
server, and distinguish recorded facts, decoded content and missing evidence.
Approved iteration, 2026-10-18. The existing unversioned JSONL format remains
readable. This iteration does not change capture writers or introduce a new
schema. A future incompatible format requires an explicit version decision.

## Representation

One recording represents one physical connection. Its application channel IDs
are logical lifetimes, not SMP wire IDs. Recovery/routing produce separate files;
replay does not invent links between them. A line contains a recorded event, a
plaintext TDS packet, or the starting wall-clock reference. Line order and
recorded time are retained, including any nonmonotonic times. Events are retained
as recorded text; protocol decoding uses packet bytes rather than parsing that
text. Recorded durations are evidence, not replay execution timings.

Packets assemble into messages independently per direction/channel. Requests
have input declarations, parameters and table rows. Responses have ordered
records and shared negotiated encoding context, with separate channel readers.
Decoded table inputs remain distinct from result cells. An offline reader owns
data only; it has no transport, SQL execution or producer authority.
Python event text can contain lone UTF-16 surrogates. Replay retains it as
`SqlText`; the JSON parser never substitutes characters in the emitted text.

## Reading and failures

Replay reads JSON lines in order and emits recorded events, packet descriptions,
decoded messages/records and diagnostics. Response values advance through the
existing incremental decoder. Request bodies and their whole input values are
materialized for inspection; replay is not a constant-memory promise. No new
live-client retention policy is introduced.

Malformed JSON or a damaged packet ends trusted decoding at that point. A message
decode failure retires that channel reader: replay must not guess offsets or
claim later context is known. The valid emitted prefix remains available.
Diagnostics name the line, direction, logical channel and body offset where
known. Unsupported vocabulary and unfinished evidence are distinguished from
malformed content. EOF does not prove server completion or physical closure.
Known outstanding responses and unfinished packet messages are reported.
When a NO_METADATA response omits columns supplied only by its original caller,
the wire alone cannot reconstruct them. Rust reports incomplete evidence and
preserves the valid prefix, rather than labeling those bytes malformed or
guessing columns. No new metadata sidecar/capture schema is introduced.
Zero replay issues means the available evidence decoded. It does not prove a
complete SQL conversation: arbitrary SQL can create transaction or bulk
obligations that cannot be inferred from packet framing alone.

Credential-bearing packet bodies are withheld from packet inspection. LOGIN7
inspection lists identity and options, not credential payloads. Replay never
echoes invalid JSON or arbitrary error buffers. Query/data inspection remains
intentional, following the existing capture contract.

## Acceptance

Use Python-generated request/type corpora, controlled malformed/fragmented
recordings, and fresh captures from both implementations. Compare exact values,
parameter/default/output flags, table metadata/rows, result ordering and accepted
feature context. Exercise 7.4/8.0, plain/MARS, cancellation, bulk abort and
recovery recordings. Run live mutation suites sequentially. Actual commands and
limits belong in `clients/rust/ACCEPTANCE.md` after execution.
