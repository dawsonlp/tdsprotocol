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

**To decide before building:**
- Where it lives. D-45's layout suggests `clients/rust/`.
- Its asynchronous runtime, or whether its core stays independent of any runtime, with a shell for each.
- Its TLS library, which must support ALPN: TDS 8.0 offers `tds/8.0` in the TLS handshake.
- Whether the shared test data moves to a format that does not depend on a language, such as JSON, read by both test suites.
- The order of its milestones.

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
