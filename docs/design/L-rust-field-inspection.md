# L · Rust Field Inspection

**Where this sits:** the diagnostic layer of [The Client](A-the-client.md), after [offline replay](K-offline-replay.md) and the [interrupted I/O acceptance matrix](../../clients/rust/INTERRUPTIONS.md).
**After reading this you can** locate inspected fields in their wire bytes, follow their protocol references, and distinguish whole-message trees from incremental token fragments.

> **Status: implemented and extended 2026-10-18.** Live observation and native replay share field readers for connections, supported requests and selected response fields/fragments. The [acceptance record](../../clients/rust/ACCEPTANCE.md) identifies current verification. This is selected inspection coverage, not Python feature parity.

## 1 · Intent and representation

A conversation should explain its own bytes. A field tree records names, byte
ranges, decoded displays and references from the definitions that read them.
It carries evidence; it grants no send, read, cancellation or recovery authority.

Rust's `inspection::Node` follows Python's existing inspection concept:

| Field | Meaning |
|---|---|
| `name` | Definition-owned field or group name |
| `basis` | `Packet`, `Message` payload, or `Token` |
| `range` | Start included, end excluded, measured within that basis |
| `raw` | At most the first 8,192 bytes of the range; sensitive data are masked or omitted |
| `shown` | Decoded display, limited to 1,024 UTF-8 bytes plus a truncation marker |
| `children` | Nested groups or fields sharing the root's coordinate basis |
| `source` | Repository-relative protocol reference page, optionally with an anchor |
| `sensitive` | The node contains credential evidence that must remain hidden |
| `issue` | A located decoding failure, when the supported input is malformed |

Packet header ranges start at the eight-byte header. Message ranges exclude all
packet headers. Token ranges start at that token's tag, independently of the
number of packets carrying it. These are not TCP offsets, TLS record offsets,
file offsets, response-wide offsets or timestamps. Descendants use the same
basis as their root. A pointer group encloses its directory entry and referenced
value; such enclosing ranges can overlap. An NBCROW NULL has no cell bytes: its
zero-width cell range is accompanied by the actual null-bitmap field.

`Node::find(&["column 1", "name"])` returns an exact named path. `render()` shows
names, basis/ranges, decoded meaning and reference paths. A leaf's hex display is
limited to 32 bytes. The node still retains its bounded raw prefix for inspection.

## 2 · Definitions and delivery

The checked `wire::Reader` records fields only when explicitly enabled. The
existing packet, LOGIN7, PRELOGIN, request, token and scalar definitions supply
names at their actual read boundaries. The semantic decoding rules are shared;
the CLI does not maintain another set of offsets or protocol field labels.

The selected slice includes:

- All eight packet-header bytes and their named fields.
- PRELOGIN directory entries and option data.
- LOGIN7 fixed options and selected identity pointers/text, with credential
  entries masked. Unknown extensions remain opaque.
- SQL batch headers and exact UTF-16 text.
- LOGINACK, INFO, ERROR, DONE/DONEPROC/DONEINPROC.
- COLMETADATA column flags, scalar TYPE_INFO and names; ROW/NBCROW scalar cells.
- RPC call/parameter groups, input type/value fields, TVP declarations/hints/cells,
  transaction operations, Attention and bulk input metadata/cells/completion.
- Streamed ROW/NBCROW headers and cell/value fragments; scalar and large
  RETURNVALUE headers/fragments; RETURNSTATUS.

Streamed fragments use offsets relative to their enclosing ROW/NBCROW or
RETURNVALUE token, including framing consumed on a decode step that yields no
semantic item. They retain only that step's bytes, not a second whole streamed
value. Fragment boundaries can depend on packet/input consumption. A NULL cell
may have an empty range. Bulk known-length payloads retain their actual raw
layout; the ordinary decoder's synthetic PLP conversion does not create invented
inspection bytes.

At `Full`, live `observe::Event.fields` carries trees alongside the existing
packet/record inspection. Healthy outline/full event lines remain identical.
Malformed tokens may produce a full-level field diagnostic before any semantic
record exists. Terminal completion trees are held until the enclosing message
boundary proves completion, like the existing semantic completion record.

At `Outline` and `Off`, no field trees are built. Existing optional-observer
failure isolation and required-recording failure behavior are retained.

Offline `replay::replay` preserves its existing event interface and builds no
trees. `replay::replay_with_inspection(input, true, callback)` additionally emits
`Content::Inspection(Node)`; false behaves like `replay`. Locations, diagnostics
and summary counts retain their existing meaning. The executable selects trees
for `--replay PATH --observe full`. Live `--observe full` prints the same trees.

Capture packet JSONL is unchanged. Response events additionally use the existing
optional `took` field for timing descriptions. A capture stores events and plaintext
packets; trees are reconstructed from those packets. Trees do not prove that a
queued packet reached the socket or that SQL executed.

## 3 · Bounds and failure evidence

Live whole-message inspection assembles only the selected request/PRELOGIN
families. Above 1 MiB, live and replay inspection emit the same explicit
omitted-inspection summary and keep protocol processing unchanged. This is a diagnostic bound, not a new request or
response limit. Response token inspection uses the existing incremental decoder;
large-value streaming is not materialized into a new whole inspection value.
Neither these bounds nor individual-node limits establish a total memory bound
for a complete observed conversation or application-retained trees.

LOGIN7 inspection always applies the existing whole-message credential mask,
even to recordings made with `keep_password=True`. It retains no aggregate login
payload. Password, new-password and SSPI nodes contain masked bytes and a hidden
display; unknown authentication payloads are not decoded. Packet-header trees
retain only the eight header bytes. Incomplete credential messages never acquire
an invented complete LOGIN7 tree.

A semantic token is not published while its required bytes remain incomplete.
Committed stream-framing fragments can be inspected while waiting for more data.
On a malformed
bounded token, the tree retains the successfully read prefix and a located issue;
the semantic decoder still reports its original error. An unsupported field
family is not described as complete inspection. Missing saved NO_METADATA context
and existing replay evidence limits remain explicit.

## 4 · Acceptance and remaining work

The committed Python inspection definitions generate nine artificial fixtures
with independent field ranges and bytes. Rust checks those ranges, credential
masking, bounded rendering, malformed-token prefixes, no trees when disabled,
and zero-width NBCROW NULL cells. Controlled verified-TLS tests split reply token
payloads into one-byte packets and compare live and replayed trees under both
protocol versions with and without MARS. A separate SQL Server case compares
actual login, messages, scalar/NULL/Unicode rows and completion trees in all four
modes. It accepts the valid ROW or NBCROW framing actually returned by the server.

This work exposed a Rust offline-reader defect: LOGIN7's TDS-version field was
read as big-endian. LOGIN7 uses little-endian; LOGINACK uses big-endian. The shared
LOGIN7 identity reader now matches Python and the sender. No Python change was
needed.

Independent Python RPC/TVP/transaction fixtures now exercise inspection and every
truncated prefix. Streamed row/output tests check exact raw ranges across every
small input stride. Controlled TLS compares live and saved RPC/TVP and transaction
trees in the four transport modes. A finite 2,048-case seeded malformed-input
corpus checks parser failure and inspection bounds; it is not exhaustive fuzzing.

Exchange timing is implemented through `response::Timing`, live `Response::timing()`
and owned `FetchedResponse::timing`. See The Client's timing contract. Detailed
fields for every metadata extension and unsupported token vocabulary remain
separate. No memory, latency or throughput benchmark is claimed.
