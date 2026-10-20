# Rust client support and remaining work

Working state on `rust-azure-integration`, 2026-10-19. This is an unpublished implementation,
not Python feature parity. The design pages define intended behavior for both
languages; this matrix says what Rust currently implements and what still needs
code, agreement or independent runtime evidence.

**Active Azure phase:** the new [full-parity plan](../../docs/design/experiments/rust-azure-integration-plan.md)
supersedes the following phase's deferrals as a work list. Both Entra paths,
SDK-independent async providers, optional official Azure Identity adapter,
routing/recovery token requests and masking are implemented with local paired
and controlled-peer evidence. The approved async key-provider/enclave contract
now has a common service, optional official Key Vault adapter, Windows CNG
companion, and transparent version-two explicit-none enclave execution. Actual
Azure/CNG acceptance and remaining cross-feature coverage remain open.
The approved unsupported-feature policy warns on explicit diagnostic requests
and stops opening on enabled ACKs; absent/disabled ACKs may complete login. The approved optional
[system ticket-cache provider](../../docs/design/experiments/rust-azure-ticket-cache-contract.md)
implements Kerberos/Negotiate on Linux/macOS; ticket login passed against the
Azure campaign's domain on 2026-10-20 ([live evidence](../../docs/design/experiments/rust-azure-live-evidence.md)). See the [current key/enclave evidence](../../docs/design/experiments/rust-azure-key-enclave-evidence.md).
The historical scoped completion below describes the preceding phase.

**Completion scope agreed 2026-10-18:** finish local work including local-key Always
Encrypted; create a transient Terraform GCP Windows/domain lab; implement and
validate NTLM/Kerberos authentication; retain evidence and verify full teardown.
Entra, Azure-specific features/providers, Windows certificate-store key-provider
support and enclaves/attestation are deferred from this scoped completion. The
remaining column below includes both required work and these explicit deferrals;
it is not an instruction to finish every item before M16. See the
[roadmap](../../docs/design/C-roadmap.md) for the sequence and acceptance gates.

| Area | Implemented in Rust | Remaining |
|---|---|---|
| Ownership and cleanup | Unique movable channels, borrowed responses, delegated close/cancel, epoch/lease retirement, discard on current work abandonment, awaited Attention/drain; deterministic partial-write/task-abort acceptance matrix | Additional offsets/scheduling and platform combinations; broader response vocabulary |
| Connection | Verified TLS, TDS 7.4/8.0, SQL login, app/host/process identity, language, ODBC, read-only intent, one-hop routing | Additional login vocabulary/features and provider contracts |
| Recovery | Server-reported snapshots/refusals/reset, stable logical handles, fresh wire ids, old exchange retirement, explicit/idle recovery | Real remote failover/platform coverage; extend tests as types/requests arrive |
| MARS/pool | Per-frame credit, independent readers, shared state/errors, whole-connection explicit leases, reset/discard, unresolved bulk discard | Broader authenticated/platform combinations; measured end-to-end performance |
| Browser | Instance/machine/DAC, IPv4 broadcast, strict ASCII/UTF-8/Windows-1252, pure codec and controlled UDP; live Windows SQL Browser UDP discovery | Other shared code pages; broader live instance/DAC/broadcast acceptance |
| Requests | Literal batches; typed named/built-in RPC, batched owned/unique-source calls, defaults, input/output parameters, input-only TVPs/row sources; borrowed bulk finish/abort; explicit transaction-manager messages | Successful distributed-coordinator acceptance; broader server/type combinations |
| Scalar data | Approved heterogeneous rows; integer/bit/float bits, decimal/money, temporal/GUID, bounded text/binary; exact checked structs, explicit SQL collation views and input writers | Broader server/version collation evidence; Browser codecs have a separate strict policy |
| Large/special data | PLP max/XML/CLR/native JSON; legacy text/ntext/image reads and whole inputs; borrowed typed chunks, owned values, unique async sources; sql_variant; float32/float16 vector codecs; whole-cell TVP/bulk row sources | Binary XML; live float16 acceptance when the server offers it |
| Responses | Ordered records, retained call groups/outputs, browse and sensitivity metadata/ranks, fetch/finish, forward result-set/row/value views, explicit read-ahead, once-only SQL errors, partial failure snapshots | Alternate compute tokens and provider extensions |
| Observation/capture | Steps/messages/packets/tokens, optional-observer failure isolation, credential masking, physical-connection capture, native replay; exchange timing at every level; connection/RPC/TVP/bulk/transaction trees and incremental row/output fragments with ranges/raw/reference links | Complete metadata-extension fields; reconstruction of unrecorded NO_METADATA context; unsupported wire extensions |
| Authentication | SQL; optional portable NTLM/Kerberos/Negotiate, native signed-in Windows SSPI, and system-cache Kerberos/Negotiate via Linux/macOS GSSAPI; 64 earlier real SQL Server login/transport combinations passed with verified TLS, plus controlled-peer scenarios | System-cache Kerberos/Negotiate passed live (2026-10-20); refusals keep GSSAPI status numbers. Required Extended Protection is unsupported: SQL expects tls-unique, unavailable through the pinned rustls API. Owner chose documented limitations and upstream drafts, without dependency forks/patch sets or TLS backend changes. Portable NTLM retained-key erasure is not guaranteed; wider lifecycle acceptance remains; Entra passed live against Azure SQL with the Azure CLI, a service principal and a managed identity, both flows, TDS 7.4/8.0 × MARS; other credential modes have no environment evidence (see the credential inventory) |
| Direct password change | LOGIN7 encoding/redaction, final-success credential promotion, recovery, uncertain lost completion; pools reject one-time change requests | Broader server/platform acceptance |
| Pool configuration | Comparable SQL snapshots, application source/static adapter, bounded opening/recovery reads, stale retirement and explicit failures | Built-in file providers, dynamic TLS/provider bindings and capacity; native platform acceptance |
| Always Encrypted | Local PKCS#8 RSA/AES/HMAC; transaction/exchange/fixed-age policies; wire versions one/two, explicit-none P-384 enclave sessions/packages and signed key release, async opaque providers with optional Key Vault/CNG adapters, exact normalization, fresh named-parameter preparation, results/outputs, owned bulk and independent .NET interoperability; explicit failure values and ciphertext-only core capture/replay | Owned AE values (16 MiB bound); encrypted source producers/borrowed plaintext chunks are not provided. Key Vault, the VBS enclave (explicit no-attestation mode) and the Windows CNG certificate store passed live with Python and SqlClient cross-reads (2026-10-20); other attestation modes are not implemented |
| Packaging/platforms | Safe protocol crate plus isolated native Windows SSPI, CNG certificate and system GSSAPI FFI crates; Rust 1.99.1 on macOS ARM64 and earlier native MSVC Windows, optional Tokio/crypto, examples and MIT notices; four earlier live Windows cancellation profiles retired their workers | Broader cancellation/security/platform evidence; companion-crate dependency requires a package/release strategy before publication; historical single-crate package evidence does not cover this workspace |

Authentication upstream tracking: [rustls #995](https://github.com/rustls/rustls/issues/995)
is closed as not planned by its original requester; no implementation is
committed. The [sspi retained-state cleanup report](../../docs/design/experiments/upstream-sspi-ntlm-zeroization.md)
and [rustls SQL Server follow-up](../../docs/design/experiments/upstream-rustls-channel-binding.md)
remain unsubmitted drafts. No verified upstream ticket is recorded for the sspi
erasure finding. See the [provider review](../../docs/design/experiments/rust-authentication-provider-review.md)
for source evidence and the limitations we retain.

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
metadata/rows. [Design L](../../docs/design/L-rust-field-inspection.md) defines the
implemented connection/scalar-query inspection slice. Broader field coverage and
detailed timings remain separate work.

The [transparent encryption design](../../docs/design/O-rust-transparent-encryption.md)
and [acceptance report](../../docs/design/experiments/rust-transparent-encryption.md)
close the local AE integration requirements. The [Windows/provider proposal](../../docs/design/P-windows-authentication-campaign.md)
records the deployed campaign and accepted dependency limitations. The
[live checkpoint](../../docs/design/experiments/rust-gcp-authentication-evidence.md)
separates Windows interoperability evidence from earlier local acceptance. The
[follow-up report](../../docs/design/experiments/gcp-authentication-follow-up-evidence.md)
records later tests and verified project/resource teardown on 2026-10-19;
Windows credential rotation, broader acceptance and a clean deployment/expiry
rehearsal remain open.
