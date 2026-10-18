# Rust client support and remaining work

Working state on `rust-client`, 2026-10-18. This is an unpublished implementation,
not Python feature parity. The design pages define intended behavior for both
languages; this matrix says what Rust currently implements and what still needs
code, agreement or independent runtime evidence.

| Area | Implemented in Rust | Remaining |
|---|---|---|
| Ownership and cleanup | Unique movable channels, borrowed responses, delegated close/cancel, epoch/lease retirement, discard on current work abandonment, awaited Attention/drain; deterministic partial-write/task-abort acceptance matrix | Additional offsets/scheduling and platform combinations; broader response vocabulary |
| Connection | Verified TLS, TDS 7.4/8.0, SQL login, app/host/process identity, language, ODBC, read-only intent, one-hop routing | Additional login vocabulary/features and provider contracts |
| Recovery | Server-reported snapshots/refusals/reset, stable logical handles, fresh wire ids, old exchange retirement, explicit/idle recovery | Real remote failover/platform coverage; extend tests as types/requests arrive |
| MARS/pool | Per-frame credit, independent readers, shared state/errors, whole-connection explicit leases, reset/discard, unresolved bulk discard | Extend to encryption; measured performance |
| Browser | Instance/machine/DAC, IPv4 broadcast, strict ASCII/UTF-8/Windows-1252, pure codec and controlled UDP | Other shared code pages; actual Windows Browser acceptance (Linux SQL Server has none) |
| Requests | Literal batches; typed named/built-in RPC, batched owned/unique-source calls, defaults, input/output parameters, input-only TVPs/row sources; borrowed bulk finish/abort; explicit transaction-manager messages | Successful distributed-coordinator acceptance; broader server/type combinations |
| Scalar data | Approved heterogeneous rows; integer/bit/float bits, decimal/money, temporal/GUID, bounded text/binary; exact checked structs, explicit SQL collation views and input writers | Broader server/version collation evidence; Browser codecs have a separate strict policy |
| Large/special data | PLP max/XML/CLR/native JSON; legacy text/ntext/image reads and whole inputs; borrowed typed chunks, owned values, unique async sources; sql_variant; float32/float16 vector codecs; whole-cell TVP/bulk row sources | Binary XML and encrypted metadata; live float16 acceptance when the server offers it |
| Responses | Ordered records, retained call groups/outputs, browse and sensitivity metadata/ranks, fetch/finish, forward result-set/row/value views, explicit read-ahead, once-only SQL errors, partial failure snapshots | Alternate compute tokens and provider extensions |
| Observation/capture | Steps/messages/packets/tokens, optional-observer failure isolation, credential masking, one saved recording per physical connection, native Rust/Python offline replay, located failure diagnostics and a runnable CLI | Field inspection trees/links and detailed timings; saved NO_METADATA context and unsupported wire extensions |
| Authentication | SQL authentication and separately authenticated restricted-principal acceptance | Windows/Entra/provider exchanges |
| Direct password change | LOGIN7 encoding/redaction, final-success credential promotion, recovery, uncertain lost completion; pools reject one-time change requests | Broader server/platform acceptance |
| Pool configuration | Comparable SQL snapshots, application source/static adapter, bounded opening/recovery reads, stale retirement and explicit failures | Built-in file providers, dynamic TLS/provider bindings and capacity; native platform acceptance |
| Always Encrypted | Explicit unsupported errors | Wire extension, optional crypto/provider orchestration, normalization and independent .NET interoperability |
| Packaging/platforms | One safe Rust crate, optional Tokio shell, fmt/strict lint/rustdoc, local Docker suite | Supported Rust/platform floor, broader platforms, fuzzing/readability/release review; publication is a separate authorized task |

The approved [public type/value API](../../docs/design/F-rust-value-api.md) is implemented for scalar and large reads.
The [credential lifetime record](../../docs/design/G-login-credential-lifetime.md)
separates server password changes from the pool's configuration responsibility.
The [shared configuration design](../../docs/design/H-pool-configuration.md) maps
the implemented read/snapshot contract and lifecycle rules in both clients.
No built-in file reader or watcher is selected.

See [ACCEPTANCE.md](ACCEPTANCE.md) for exact commands, counts and evidence limits.
The [interrupted I/O matrix](INTERRUPTIONS.md) records the tested send/read/cleanup,
pool/recovery and runtime-shutdown boundaries; it does not claim every schedule.
The [completion work and decision list](../../docs/design/J-rust-completion.md)
records implemented A1 (input-only table-valued parameters) and A2 (borrowed bulk
continuation authority). Its linked experiment demonstrates explicit gap abort
and the original Python close/pool-release defect; the shared correction is now
implemented and tested. Native replay and shared Python TVP input inspection are implemented in
[design K](../../docs/design/K-offline-replay.md). Both readers inspect saved table
metadata/rows. Full field inspection and detailed timings remain separate work.
