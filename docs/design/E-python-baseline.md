# E · Python Baseline for the Rust Client

**Where this sits:** evidence for [Building the Rust Client](D-rust-development.md), before Rust implementation.
**After reading this you can** distinguish what the Python implementation demonstrates, what passed in this run, and what needs further evidence.

> **Observed 2026-10-17.** Starting checkout: `0f56444` (`Initial commit`), with a clean worktree. This is a source review and local test report. It does not reconfirm the repository's earlier Azure or Windows acceptance claims.

## 1 · Environment and setup

The repository already provides an isolated SQL Server 2025 Developer service in `docker/macos/compose.sqlserver-2025.yaml`. It binds only loopback: port 14325 for SQL and 14345 for DAC. The tests use this service, not the older Azure SQL Edge service.

| Item | Observed value |
|---|---|
| Host / Docker engine | Apple Silicon; Docker engine `aarch64`, 10 CPUs, 8,319,504,384 bytes configured memory |
| Docker client / Compose | 29.8.2 / v5.6.0 |
| Python / uv / pytest | CPython 3.14.8 / uv 0.12.23 / pytest 9.1.1 |
| SQL Server image | `mcr.microsoft.com/mssql/server:2025-CU9-GDR1-ubuntu-24.04`, `linux/amd64` |
| Pulled image digest | `sha256:742481d1b1186cccc81220a1eaacef244ca8d0f7d19c8e5c70df8ae541ffbab2` |
| Credentials | Generated in ignored `docker/macos/.env`, mode 0600; value not recorded |
| TLS | Generated local test CA and server certificate with the repository's script; `openssl verify` returned `server.pem: OK` |
| Data volume | Compose-created named volume; retained |
| SQL container after authorized restart | Running and healthy with Rosetta enabled |
| Observed SQL Server | 2025 RTM-CU9-GDR, 17.0.5015.4, Enterprise Developer Edition, Ubuntu 24.04.5 LTS |

Commands performed, from the repository root unless noted:

```sh
sh docker/macos/tls/make-test-certificates.sh
docker compose -f docker/macos/compose.sqlserver-2025.yaml up -d
```

The credential file was created before Compose ran. No existing credential or data volume was replaced. From `clients/python/`:

```sh
uv sync --group dev
uv run pytest -m 'not live and not azure' -q -ra --junitxml=/tmp/tdsprotocol-python-unit-20261017.xml
uv run pytest -q -ra --junitxml=/tmp/tdsprotocol-python-all-20261017.xml
```

Test output is also in `/tmp/tdsprotocol-python-unit-20261017.log` and `/tmp/tdsprotocol-python-all-20261017.log`. These are local temporary artifacts, not durable repository records.

## 2 · Test results and limits

### Before Rosetta: offline evidence

| Run | Passed | Skipped | Deselected | Duration |
|---|---:|---:|---:|---:|
| Explicit offline selection | 323 | 0 | 263 | 2.37 s |
| Complete suite | 326 | 260 | 0 | 1.56 s |

No tests failed. Three tests in modules marked `live` run without the SQL fixture, so the complete run has three more passes than the explicit offline selection. Their passes are not live SQL Server evidence.

The complete run's 260 skips comprise:

| Reason | Count |
|---|---:|
| Local SQL Server not listening on `127.0.0.1:14325` | 247 |
| Azure infrastructure not deployed | 10 |
| Kerberos runner unavailable | 2 |
| Windows certificate-store environment unavailable | 1 |

The offline suite covers specification samples, captured response fragmentation, exact value codecs, serial-channel permissions, MARS credit rules, transaction request encoding, session recovery state, token parsing, encryption primitives and literate errors. These passes do not establish fresh TLS interoperability, SQL execution, pool cleanup against SQL Server, .NET encryption interoperability, or remote provider behavior.

### SQL Server startup issue, resolved

The initial Compose start exited before normal SQL startup. Logs reported:

```text
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
```

Container inspection showed exit 139, no OOM kill, and repeated restarts. A disposable invocation of `/opt/mssql/bin/sqlservr --version` also crashed under QEMU. Docker Desktop's `UseVirtualizationFrameworkRosetta` setting was `false`; the Compose file explicitly calls for Rosetta on Apple Silicon. The crashing test container was stopped with its data retained.

The user then explicitly authorized enabling Rosetta and restarting Docker Desktop despite interruption to running services. The previous running-container inventory was saved, Docker Desktop was stopped, and only `UseVirtualizationFrameworkRosetta` was changed to `true`. A private settings backup was retained at `/tmp/tdsprotocol-docker-settings-before-rosetta.json`. Docker Desktop was started, and all 19 previously running containers were restored to running state, including four evaluation containers that did not restart automatically. No containers or volumes were deleted.

The same pinned SQL Server service then became healthy. The Rosetta setting was re-read as `true`. Trusted-certificate CLI checks succeeded:

```sh
# From clients/python/
uv run tds --ca-file ../../docker/macos/tls/test-ca.pem --query 'SELECT @@VERSION'
uv run tds --ca-file ../../docker/macos/tls/test-ca.pem --tds-version 8.0
```

The first query reported SQL Server 17.0.5015.4 and used TDS 7.4 with TLS 1.2. The second returned `SELECT 1` over TLS 1.3 with ALPN `tds/8.0`. This supplies fresh local setup, login, certificate-verification and query evidence; earlier QEMU failure is no longer a live-test blocker.

### Fresh-volume test prerequisites

The first local-live run was interrupted after **9 failures and 52 passes** in 31.06 seconds. Several tests connected to `tds_test` before the type tests that create it ran. Their errors were database 4060 / 911, followed in login cases by the general login error 18456. A separate RPC-fixture assertion compared the captured container's hostname `6a376fcf9e7e` with the current container's hostname `e3ee3eff7b30`.

The isolated test database was then prepared explicitly:

```sh
uv run tds --ca-file ../../docker/macos/tls/test-ca.pem --query "IF DB_ID('tds_test') IS NULL CREATE DATABASE tds_test"
```

No Python implementation or test assertion was changed. A fresh live suite and complete suite use this prepared test database. Captured host identity remains subject to the existing assertions and must be reported if it fails; it is not silently removed from comparisons.

### After Rosetta: local-live evidence

The prepared local-live command is:

```sh
uv run pytest -m 'live and not azure' -q -ra --junitxml=/tmp/tdsprotocol-python-live-prepared-20261017.xml
```

Its output is `/tmp/tdsprotocol-python-live-prepared-20261017.log`. It includes the Docker-based .NET Always Encrypted comparison, whose first run downloads the SDK image and NuGet packages. Result: **248 passed, 2 failed, 336 deselected, zero skipped**, in 118.86 seconds. The independent `test_sqlclient_and_the_driver_read_each_others_values` check passed (25.364 seconds), including the driver's insert and bulk-load paths and Microsoft's SqlClient in the opposite direction.

The two failing assertions are:

| Test | First reported difference |
|---|---|
| `test_calls_live.py::test_every_rpc_fact_on_request_response_still_holds` | `REFUSED_THEN_RUNS`: error 8162 has current server `e3ee3eff7b30`; the capture has `6a376fcf9e7e` |
| `test_responses_live.py::test_every_batch_fact_on_request_response_still_holds` | `STATEMENT_FAILS`: error 8134 has the same current-versus-captured server-name difference |

The assertion output alone identifies the first mismatch; it does not prove every remaining item matches. A separate diagnostic comparison checks every sample against the current `@@SERVERNAME`, replacing only that specific known captured server identity in expected error/message items. It does not change tests, fixtures or client code. The diagnostic passed all **15 scenarios** (three RPC, twelve batch): every remaining item and field matched, and the actual server-name field was compared with independently queried `@@SERVERNAME`. The script and log are `/tmp/tdsprotocol-compare-live-records.py` and `/tmp/tdsprotocol-compare-live-records-20261017.log`. This is additional diagnostic evidence; it does not turn the two original assertions into passes.

### Complete suite with the live server

```sh
uv run pytest -q -ra --junitxml=/tmp/tdsprotocol-python-all-rosetta-20261017.xml
```

Result: **571 passed, 2 failed, 13 skipped**, in 101.67 seconds. Output is `/tmp/tdsprotocol-python-all-rosetta-20261017.log`. The failures are the same two captured-hostname assertions listed above. All local server-dependent tests ran; none skipped because SQL Server was unavailable. The 13 remaining skips are ten Azure tests, two Kerberos runner tests, and one Windows certificate-store test.

| Evidence before portability fixes | Outcome |
|---|---|
| Server readiness and both trusted TLS protocol versions | Confirmed locally |
| Local-live suite | 248 passed, 2 failed, no skips |
| Complete suite | 571 passed, 2 failed, 13 remote-environment skips |
| Independent .NET Always Encrypted interoperability | Passed |
| All captured RPC/batch scenarios with explicit current server identity | All 15 matched; original failing assertions unchanged |
| Docker recovery | All 19 previously running containers restored; SQL Server healthy with zero restarts after Rosetta startup |

### Portability fixes

The two captured-response tests have a useful regression purpose: replay the documented RPC and batch scenarios against a live server and compare their asserted record structure, rows, errors, messages, completions and outputs with the captured records. The server's reported identity depends on its environment. Treating the capture container's name as a required live identity was a fixture defect.

The fixes preserve that purpose:

- `response_samples.py` records the capture's `SERVER_NAME` as provenance; no sample bytes change.
- `test_response.at_server` copies only the expected record's named `Error.server` and `Message.server` fields to the current server identity. It checks the capture origin, preserves empty server fields, and never rewrites rows or message text. The actual live record remains unchanged, so an incorrect reported identity still fails equality.
- Each live scenario queries `@@SERVERNAME` on its own connection, retains `odbc=False`, and selects `language="us_english"` rather than inheriting a login's message language. All other asserted fields and item positions remain exact. This is a server-context-aware regression comparison, not a claim of identical behavior across every SQL Server version or configuration.
- The two aggregate tests are parameterized into 15 individual scenarios. A failure in one no longer prevents assertions on the remaining scenarios. Three focused offline checks protect the adaptation's limited scope and capture provenance.
- Database creation moves from the type-test helper to the SQL Server Compose service. Its post-start hook waits for the TCP listener and a successful master query, then applies `docker/macos/init/tds_test.sql`. SQL creates `tds_test` only if missing. The health check opens `tds_test`; the documented `up -d --wait` command includes database readiness. Existing tables and data are retained. Docker Compose 2.30+ is required.

Runtime checks used a separate Compose project and an empty data volume while the normal test container was temporarily stopped. The first startup attempt, which launched `sqlcmd` immediately, encountered a SQLPAL security-subsystem crash under Rosetta. A clean control without the hook started successfully. Adding the TCP-listener gate before launching `sqlcmd` allowed another fresh instance to start healthy with zero restarts. This supports the gate on the observed local environment; it is not a general diagnosis of every SQLPAL crash.

Validation after that change:

| Check | Outcome |
|---|---|
| Response-reader tests plus all captured live scenarios on the normal instance | 78 passed |
| Empty-volume Compose startup | Healthy; `tds_test` created automatically; zero restarts |
| Different fresh instance: all 15 captured scenarios plus one bulk scenario | 16 passed; no preceding type-test setup |
| Recreate the disposable instance and rerun initialization | Healthy; marker table and row 42 preserved |
| Restore original test service | Healthy with its original retained data volume |

The disposable probe containers, networks and volumes were removed. Other project services were not stopped by these checks. Python driver implementation was unchanged. ### Post-fix complete-suite result

```sh
uv run pytest -q -ra --junitxml=/tmp/tdsprotocol-python-portable-20261017.xml
```

**589 passed, 13 skipped, zero failures**, in 102.52 seconds. Output is `/tmp/tdsprotocol-python-portable-20261017.log`. The same 13 remote-environment tests remain skipped; all local tests, including .NET Always Encrypted interoperability, passed.

The suite now contains 602 cases. Splitting two aggregate tests into 15 scenarios adds 13 cases, and the comparison helper has three new checks. Those 16 new cases account for the inventory change; the two previous failing assertions are now passing scenarios. A final Compose recreation also verifies the TCP-gated health probe with the retained normal volume.

Tests use disposable, named test databases and alter test-server settings. They run only against the isolated test service and serially. The existing `sa` fixture is intentionally privileged for these scenarios. Azure, Windows and Kerberos infrastructure remains outside this local run; it was not provisioned by this task.

## 3 · Python code analysis

The implementation contains 10,869 lines across the top-level `tds` modules, `connection` and `encryption` modules counted for this review, including the generated collation table. This is an inventory, not a complexity or quality measurement. The structure follows the learning design in D-27: named protocol definitions and procedures, with generic machinery underneath.

| Read in this order | Source evidence | Consequence for Rust |
|---|---|---|
| Byte machinery and packets | `tds/wire.py`: `Reader.take`, `seek`, `limit`, `Incomplete`, `MalformedMessage`, bounded inspection bytes. `packet.py`: explicit 8-byte header, split/join and incremental writer | Centralize bounds checks, keep field order visible, and distinguish incomplete from malformed input. Port concepts rather than Python reflection/dynamic records. |
| Hello and login | `prelogin.py`, `login7.py`, `logins.py`: field definitions, offset tables, features, SQL/SSPI/federated login descriptions | Keep security decisions and credential-bearing fields inspectable. Token-provider integrations remain outside generic byte machinery. |
| Types | `types.py`: type metadata, exact validation and codecs, custom ticks, collation-specific text; generated `collations.py` | Representation choices precede API/process choices. Standard Rust application types do not cover every stored SQL value. |
| Requests | `requests.py`: `Context`, request protocol, `Encoded` and chunk sources; `transactions.py`: request vocabulary | A request owns its packet type and encoding. Core exchange should not branch on operation semantics. Validate whole values before transmission and streamed values as produced. |
| Responses | `response.py`: `ResponseReader`, `RowDecoder`, forward-only `Response`, `Unread`, `FetchedResponse`, typed record items | Preserve token order, missing counts, errors-at-end, explicit unread behavior and exact partial records. Rust may express ownership differently without inventing a call/statement tree. |
| Connection rules | `connection/core.py`: channels store owners, `_check_owner`, `exchange`, `_undo`, `cancel`, `release`, `adopt` | Task ownership, busy exchange, bulk continuation, recovery and pool reset are separate invariants. Check them in addition to memory ownership. |
| Async shell and pool | `connection/shell.py`: bounded plain inbox, generator action runner, `_ChannelSource`, `SerialChannel`, exclusive `Pool` leases | Runtime is machinery. Python cancellation injects errors into procedures and can await cleanup; Rust future drop needs a deliberately different mechanism. |
| Observation and capture | `observe.py`, `capture.py`: off/outline/full, field trees, credential redaction, JSONL packet/event recording and offline decode | Retain learning behavior and capture compatibility; default redaction includes all credential paths. Credential-bearing messages are buffered for redaction across packets, so Rust needs an explicit size bound. |
| Encryption extension | `encryption/context.py` and related modules: provider/key state and describe/encrypt/decrypt around ordinary exchanges | Preserve composition. Keep encrypted wire representation distinct from key access and cryptography. Independent .NET comparisons are necessary. |

### Porting findings

**Python checks task identity as well as serialization.** The Python core compares caller identity on send/read. `test_serial_channels.py` checks wrong-owner use, explicit transfer, immediate busy/extra-channel refusal and cancel from another caller. A Rust mutex plus `&mut self` would not automatically retain the same task restriction. The user selected a movable-ownership proposal for Rust (D-64), so the plan explicitly documents that semantic difference instead of claiming unchanged task permissions.

**Scope exit is protocol work.** `Response.__aexit__` awaits close, Attention and drain. `Response.__del__` only warns and leaves the channel busy. The pool tests distinguish successful awaited cleanup from abandonment: an unresolved exchange causes the whole connection to be discarded. A Rust destructor must not mark a channel idle just because the response value no longer exists.

**Exact text is not always a Unicode string.** Python uses `surrogatepass` for SQL's unpaired UTF-16 code units and escapes to retain noncanonical code-page bytes and invalid stored UTF-8. The Rust plan must establish lossless values and explicit conversions before claiming Python parity.

**Numeric and time exactness is intentional.** Python constructs decimal values from digits without precision-limited decimal arithmetic; custom time values retain 100 ns and 1/300-second ticks. Errors refuse rounding and name the call, parameter, row or column. Preserve those semantics and the distinction between a type's metadata and its value.

**Response parity is semantic, not just matching rows.** `test_response.py` compares captured records under whole, one-byte and randomized fragmentation, and with observation disabled. It checks messages, errors, completions, output ordinals and unknown/missing counts as well as row data. These are useful shared fixtures and Rust acceptance criteria.

**Backpressure depends on consumption.** Plain connections bound their inbox to eight packets. MARS returns credit as packets are consumed. Carry the policy into both the Rust core and shell; otherwise one can appear bounded while the other's queue grows. This review did not measure maximum retained memory or performance.

**Source and design are not identical in every detail.** The core's module description says it never uses a clock, but `connection/core.py` imports and calls `time.perf_counter()` for event and exchange timing. The Rust plan should supply time at the shell boundary. Also, `response.py` contains the asynchronous reading facade as well as the pure reader; the older building-plan layout table locates that facade in `shell.py`. Use actual source when mapping responsibilities. These observations do not invalidate the passing tests, and no Python refactor was performed.

**Round trips can preserve a shared mistake.** The existing Always Encrypted tests explicitly compare both write/read directions with .NET because the server cannot inspect encrypted plaintext. Retain independent evidence; do not count Rust/Python agreement or self round trips as sufficient cryptographic interoperability.

**Existing gaps remain gaps.** The design documents TVP replay limitations, constructed-only float16 vectors, unobserved enhanced routing, unconfirmed mirroring behavior, and no implemented enclave attestation. A Rust milestone must either establish new evidence or report the same limitation. Earlier documentation's historical test totals do not replace the fresh results recorded above.

## 4 · What this precursor establishes

The Python source and regression suites provide a concrete starting point for Rust. The isolated SQL Server now runs under Rosetta, trusted TLS works for both protocol versions, and the test database is prepared. After the portability fixes, the complete run supplies 589 passes, no failures and 13 explicit remote-environment gaps. The live assertions validate all 15 scenarios against their current server identity. Compose initialization has been checked with both an empty volume and retained data. Rust implementation has not begun, and Rust runtime parity is not established by Python results.
