# C · Roadmap

**Where this sits:** after [Building the Client](B-building-the-client.md), whose milestones M1–M15, M17 and M18 are built. It sets out what comes next.
**After reading this you can** say what each phase delivers, what it builds on, and which decisions it needs before it starts.

> **Status:** order revised by the user, 2026-10-17 (D-63): Rust first, then Python conveniences, then application drivers. The [Rust development plan](D-rust-development.md) is a proposal; its [Python baseline](E-python-baseline.md) records the precursor evidence and server setup. Each phase's design is agreed before its code is written. Accepted milestones are then added to [Done When](5-done-when.md).

---

## The phases

| # | Phase | Delivers | Builds on |
|---|---|---|---|
| 1 | **A Rust client** | The same driver in Rust, with explicit ownership/permissions and the same learning intent | The design pages, and the Python code and tests |
| 2 | **Conveniences** (M16) | The standard patterns of use in one call each, in Python, asynchronous and synchronous | The driver's public surface (D-39) |
| 3 | **Application drivers** | DB-API 2.0 for Python, and possibly other standard interfaces | The conveniences |

Phase 3 depends on phase 2. Rust does not depend on completing Python M16.

## 1 · A Rust client

**Goal:** a second client that follows the same design in Rust. Its code teaches the protocol as the Python code does, with the same names, and links to the same reference pages.

**Development path:** establish the local Python baseline, analyze its code, agree ownership/permissions and exact representations, then implement Rust in small tested slices. The detailed [Rust development plan](D-rust-development.md) starts with those rules and keeps runtime/API choices explicit. [Python baseline evidence](E-python-baseline.md) separates offline, local-live and remote validation.

**How the Python client helps:**
- **The design pages are the specification for both clients.** Each Rust module names the page it implements, as each Python module does.
- **The sans-I/O core can be ported part by part:** the definitions and the codec first, then the procedures, then a shell (D-24, D-27).
- **The tests' data can be shared:** MS-TDS's own samples, the responses captured from SQL Server, and the generated collation table. A capture (D-12) recorded by either client can be replayed through the other.
- **The Python client is a reference to compare against.** For fixed deterministic inputs and options, both clients must encode the same protocol bodies and read the same semantic response record. Variable session fields, timestamps, nonces and TLS ciphertext require explicitly scoped comparisons.
- **The live tests run against the same SQL Server container**, with the same scenarios.

**Current first slice:** `clients/rust/` contains a runtime-independent core and the approved Tokio shell/in-memory rustls pairing. One persistent connection task, movable channel authority, borrowed responses and conservative abandonment are agreed. Both TDS versions now support verified TLS, independent MARS channels and explicit-return pooling for the current integer/token subset; see the [Rust reading path and evidence](../../clients/rust/README.md).

**Cancellation slice:** explicit awaited Attention/drain, exchange-scoped cancel handles and a separate configurable 5-second cleanup budget are agreed and implemented. Cleanup failure preserves the original cause and discards the connection. Delegated channel close and stale-lifetime isolation are now corrected in both clients; Python additionally has MARS/partial-send evidence.

**Observation slice:** the approved failure policy and one recording per physical
connection are implemented in both clients. Rust provides initial step/message/
packet/token observation and credential-redacted JSON-lines recording; four fresh
Rust recordings replay through Python. Field inspection trees, detailed timings
and Rust-native replay remain open. Python pools/routing/recovery use recording
factories; reusing one transport across loans keeps its recording.

**Routing slice:** one-hop routing, a single deadline, destination certificate
identity and separate recordings are implemented/tested through a local router
to Docker under both TDS versions × plain/MARS.

**Recovery slice:** the [identity experiment](experiments/recovery-channel-identity.md)
and shared correction now underpin both clients. Eligible recovery preserves
logical channels and close permissions, allocates fresh wire ids and retires old
exchange authority. Rust epoch guards protect replacements from old read/Drop
controls. Both versions × plain/MARS run against Docker; interrupted requests are
never replayed. Sixteen Rust physical recordings replay through Python with
logical row attribution and redaction checked. Broader types/platforms and real
failover infrastructure remain separate acceptance work.

**Still to decide before affected implementation:** response interfaces beyond the implemented Python-compatible retention subset, exact value representations beyond the first integer/text subset, neutral shared-fixture format, supported Rust/platform floor and later milestone details. The broader connection features remain tracked in the Rust plan.

## 2 · Conveniences

**Goal:** each common pattern of use takes one call, and still shows what the server did (D-35).

**What it contains** (already agreed):
- **The serial channel's conveniences** (D-37): `query`, `fetch`, `fetch_value`, `call`, `prepare`, `describe` and `transaction`. Each one is an exchange and a way of reading its response, and each checks the response's shape.
- **A synchronous entry point** with the same shape as the asynchronous one (D-38).
- **A bulk-load helper** that writes the `INSERT BULK` statement from the columns (D-50).
- **An error translator** ([Done When › M16](5-done-when.md#m16--the-convenience-layer-and-the-synchronous-shell)).
- **Parameterized statements** whose SQL types are inferred from Python values. D-39 places type inference here, outside the driver.

It uses only the driver's public surface. If it needs something more, the driver is missing it (D-39).

**To decide before building:**
- Where it lives: a module of the `tds` package, or a package of its own.
- How each SQL type is inferred from a Python value, for example the length of a `str` parameter, a `Decimal`'s precision and scale, and a `datetime`'s type.
- How the synchronous shell runs. It could be a second shell around the same sans-I/O core, using blocking sockets (D-24), or it could run the asynchronous shell on an event loop of its own.

## 3 · Application drivers

**Goal:** standard interfaces that existing applications and libraries already use, built around the driver.

- **DB-API 2.0** (PEP 249), for Python: a package that depends on `tds` (D-39), built on the conveniences. Two of its questions are recorded in Decisions › Deferred: how long a serial channel lives (D-25), and what happens when a cursor runs while another has unread rows (D-26).
- **Other standard interfaces, possibly:** each one a layer around the driver, such as an SQLAlchemy dialect for Python, built on DB-API. Which ones, and in what order, is decided when phase 3 starts.

**To decide before building:**
- Whether each driver lives in this repository or in a repository of its own.
- DB-API's parameter style, and how its type objects map to the driver's types.
- How DB-API's synchronous interface uses phase 2's synchronous entry point.
- D-25 and D-26.

---

**Next:** [Decisions](4-decisions.md) · **Decisions:** D-24, D-27, D-35, D-37–D-39, D-45, D-50, D-63
