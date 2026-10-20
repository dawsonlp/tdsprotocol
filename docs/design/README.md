# TDS Client — Design

> **Status:** the protocol pages cover **connecting and logging in**, **the requests**, **what a response holds**, and **every data type**. *The Client* covers the client's structure; *Building the Client* is the agreed plan for the code, and its milestones M1–M15, M17 and M18 are built. Anything not marked agreed in [Decisions](4-decisions.md) is a proposal.
>
> **This folder is the system of record.** [`site/`](../../site/index.html) is a separate deliverable that presents it interactively (D-29). When the two disagree, this folder is right.

## Reading path

Read in order. Each part builds on the one before it.

| # | Part | What it gives you | Time |
|---|------|-------------------|------|
| 1 | [The Model](1-model.md) | The whole protocol on one page, plus the vocabulary | 5 min |
| 2 | [Worked Example: a Login](2-example-login.md) | One real login, byte by byte | 15 min |
| 3 | Reference: [Packet](3-reference/packet.md) · [Token Stream](3-reference/token-stream.md) · [PRELOGIN](3-reference/prelogin.md) · [LOGIN7](3-reference/login7.md) · [Login Response](3-reference/login-response.md) · [Requests](3-reference/requests.md) · [Request Response](3-reference/response.md) · [Data Types](3-reference/types.md) · [Conversations](3-reference/conversations.md) · [Connect](3-reference/connect.md) · [Browser](3-reference/browser.md) · [Always Encrypted](3-reference/always-encrypted.md) | Exact shapes and rules, for looking things up | as needed |
| 4 | [Decisions](4-decisions.md) | What is agreed, what is proposed, and why | 5 min |
| 5 | [Done When](5-done-when.md) | How to tell that each slice and milestone is finished | 5 min |
| A | [The Client](A-the-client.md) | How the code is built and what the running client shows | 10 min |
| B | [Building the Client](B-building-the-client.md) | Where the code lives, the milestones, and how each is tested | 10 min |
| C | [Roadmap](C-roadmap.md) | What comes after the milestones: Rust, Python conveniences, application drivers | 5 min |
| D | [Building the Rust Client](D-rust-development.md) | Proposed ownership/permissions, exact representations, coding practices and milestones | as needed |
| E | [Python Baseline](E-python-baseline.md) | Source analysis, current test results and server setup | 10 min |
| F | [Rust Type and Value API](F-rust-value-api.md) | Approved heterogeneous rows, exact values and declared SQL types; scalar reads implemented | as needed |
| G | [Credential Lifetime](G-login-credential-lifetime.md) | Server password changes, observed recovery/reset failures and the distinct pool configuration responsibility | as needed |
| H | [Pool Configuration Snapshots](H-pool-configuration.md) | Implemented Python/Rust snapshot APIs, lifetime rules, failure boundaries and acceptance evidence | as needed |
| I | [Typed Calls and Streaming](I-rust-rpc-and-streaming.md) | Typed RPC, forward results, runnable Rust CLI and the proposed large-value ownership surface | as needed |
| J | [Rust Completion and Decisions](J-rust-completion.md) | Implemented transactions, batched sources, special types and metadata; table-valued/bulk input decisions | as needed |
| K | [Offline Rust Replay](K-offline-replay.md) | Existing capture compatibility, exact input reading and located incomplete-evidence diagnostics | as needed |
| L | [Rust Field Inspection](L-rust-field-inspection.md) | Shared live/replay field trees, byte ranges, bounded raw evidence and protocol references | as needed |
| M | [Rust Encryption Lifetimes and Cost](M-rust-encryption-lifetimes.md) | Implemented transaction/exchange/time foundation and measured cost/security tradeoffs; transparent SQL encryption remains separate | as needed |
| N | [Encryption Policy Implementation](N-encryption-policy-implementation.md) | Implemented key service, ownership, deadlines, worker cancellation and driver lifecycle link | as needed |
| O | [Rust Transparent Always Encrypted](O-rust-transparent-encryption.md) | Implemented wire/value/parameter/result adapter and finite local SQL acceptance | as needed |
| P | [Windows Authentication Campaign](P-windows-authentication-campaign.md) | Provider proposal, missing deployment constraints and transient GCP acceptance/teardown gates | as needed |
| Plan | [GCP Authentication Corrections](experiments/gcp-authentication-development-plan.md) | Six iterations for Python fixes, shared authentication parity, remaining Rust acceptance and verified cleanup; dependency changes remain deferred | as needed |
| Contract | [Rust Azure Authentication](experiments/rust-azure-authentication-contract.md) | Approved unified login selection and SDK-independent async provider boundary; initial implementation | as needed |
| Check | [Rust Azure Authentication Evidence](experiments/rust-azure-authentication-evidence.md) | Finite paired wire/decoding, controlled login/routing/recovery and SDK-adapter evidence; live acceptance pending | as needed |
| Contract | [Rust Azure Key Providers and Enclaves](experiments/rust-azure-key-provider-contract.md) | Opaque local/remote/native capabilities and facade/epoch session ownership; approved and in implementation | as needed |
| Check | [Rust Azure Key and Enclave Evidence](experiments/rust-azure-key-enclave-evidence.md) | Async policies, official SDK requests, Python cryptographic comparison, controlled enclave SQL and native compilation | as needed |
| Contract | [Rust Ticket Cache](experiments/rust-azure-ticket-cache-contract.md) | Approved optional system GSSAPI for the kinit cache; implemented, live acceptance pending | as needed |
| Contract | [Rust Azure Feature Policy](experiments/rust-azure-feature-probe-contract.md) | Approved: warn on unsupported request; enabled acknowledgement fails opening | as needed |
| Plan | [Rust Azure Integration](experiments/rust-azure-integration-plan.md) | Full Python Azure parity: Entra, Key Vault, enclave and campaign provider paths; code completion before cloud testing | as needed |
| Plan | [Rust/Python Azure Parity Scenarios](experiments/rust-azure-parity-scenarios.md) | Paired behavioral, wire, crypto and lifecycle comparisons; source-test traceability and deferred live acceptance | as needed |
| Check | [Rust Azure Code-Complete Checkpoint](experiments/rust-azure-code-complete.md) | Scenario-to-test traceability, cross-feature tests and owner-agreed exceptions B-1 to B-11 before the live campaign | as needed |
| Check | [Rust Azure Credential Inventory](experiments/rust-azure-credential-inventory.md) | Entra credential modes in Python and Rust, their evidence, live coverage and recorded SDK gaps | as needed |
| Backlog | [Python Azure Review](experiments/python-azure-review-backlog.md) | Suspected weaknesses and proposed remedies awaiting real-service evidence; no Python production fixes in this phase | as needed |
| Check | [GCP Follow-up Evidence](experiments/gcp-authentication-follow-up-evidence.md) | Implemented corrections, Windows runtime results, retained failures and remaining API/worker choices | as needed |
| Check | [Rust SQL Encryption Evidence](experiments/rust-transparent-encryption.md) | Independent .NET, lifecycle, fault and capture boundaries; repeatable regression results | as needed |
| Check | [Encryption Policy Scenarios](experiments/encryption-policy-scenarios.md) | Named synthetic, controlled-peer and live SQL lifecycle acceptance scenarios and their evidence limits | as needed |
| Check | [Encryption Policy Evidence](experiments/encryption-policy-evidence.md) | Retained counters, regression results, native cleanup review, driver observations and actual service cost | as needed |
| Check | [Python Key Retention](experiments/python-encryption-retention.md) | Python policy API, transparent SQL lifecycle integration, scenarios and evidence limits | as needed |
| Experiment | [Recovery Channel Identity](experiments/recovery-channel-identity.md) | Failure reproduction, intervention, shared lifetime contract and Python/Rust results | as needed |
| Experiment | [Bulk Continuation](experiments/bulk-continuation.md) | Server behavior after preparation, explicit abort versus physical close, and the Python pool-release defect | as needed |

## How every page is built

- It opens with **where it sits** and **what you'll be able to do** after reading it.
- Every page is one kind of content: concept, example, reference, procedure, decision or check. Pages of the same kind share a template.
- Diagrams and byte layouts appear next to the text that explains them.
- Each fact is stated in one place. Other pages link to it.
- MS-TDS section numbers appear only in a closing **Source** line, for anyone checking against the official document.
- A reference page's **Edge cases** keep two lists apart: **where SQL Server differs from MS-TDS**, and **what MS-TDS doesn't state**. Both name the SQL Server version they were observed on.

## How every page is written

The readers are developers everywhere, many of whom read English as a second language.

- **Plain, literal English.** No idioms, slang, metaphors, jokes or cultural references. Prefer a plain verb to a phrasal verb when it is clearer: "delete", not "take down".
- **Short, complete sentences:** one idea each, with a subject and a verb. A list item or table cell may be a short phrase. Avoid chains of clauses joined by colons.
- **Succinct:** each fact is said once, without filler or repetition.
- **One word for one thing:** use the vocabulary of [The Model](1-model.md). Don't switch between synonyms.
- **US spelling:** behavior, canceled, labeled, normalize. Names from code, MS-TDS and SQL Server keep their own spelling (asyncio's `CancelledError`).
- **Absolute dates** (2026-10-17), not "now", "recently" or "today".
- **Impersonal voice:** "the driver", "the client", "the application", not "we" or "you", except in instructions to the reader.

## Where SQL Server differs from MS-TDS

Observed on SQL Server 2025 (17.0.5015), SQL Server 2022 on Windows and Azure SQL Database. Each is described where it applies.

| What | Where |
|---|---|
| Several token tags don't follow MS-TDS's length-rule bits | [Token Stream › Rules](3-reference/token-stream.md#rules) |
| A *promote transaction* ENVCHANGE has more bytes than its length says | [Token Stream › Edge cases](3-reference/token-stream.md#edge-cases) |
| `json` arrives as UTF-16LE, not UTF-8, unless the login asked for UTF-8 support | [Data Types › Edge cases](3-reference/types.md#edge-cases) |
| A table parameter's default needs the default status bit | [Data Types › Edge cases](3-reference/types.md#edge-cases) |
| The response to an abandoned request (*ignore* + *last*) has a message before its DONE | [Requests › Edge cases](3-reference/requests.md#edge-cases) |
| An enclave package's length is a u16, not MS-TDS's u32 | [Always Encrypted › Edge cases](3-reference/always-encrypted.md#edge-cases) |
| MS-TDS numbers Always Encrypted's algorithm two ways | [Always Encrypted › Edge cases](3-reference/always-encrypted.md#edge-cases) |
| A large value in bulk data with a known length is the bytes alone, not chunks | [Requests › Edge cases](3-reference/requests.md#edge-cases) |
| Promoting a transaction begun in T-SQL works | [Requests › Edge cases](3-reference/requests.md#edge-cases) |
| MS-TDS contradicts itself on how the coordinator's address comes back | [Requests › Edge cases](3-reference/requests.md#edge-cases) |
| MS-TDS's sample transaction-manager request has the wrong request type | [Requests › Edge cases](3-reference/requests.md#edge-cases) |

## Known gaps

What the client cannot do yet, or what has not been confirmed. Each is described where it applies.

| Gap | Where | Until |
|---|---|---|
| Database mirroring's partner is tested only with constructed bytes, because SQL Server on Linux has no mirroring and the Windows test server was not mirrored | [Login Response](3-reference/login-response.md) | not scheduled |
| Enhanced routing (ENVCHANGE 21, routing to a database) is not followed. The test server acknowledged the feature with 0, so enhanced routing was never observed | [Connect › Options](3-reference/connect.md#options) | a server that sends it |
| Always Encrypted's enclaves run only without attestation. Microsoft Azure Attestation and Host Guardian Service are not built | [Always Encrypted › Enclaves](3-reference/always-encrypted.md#enclaves) | not scheduled |
| `float16` vectors are tested only with constructed bytes, because the test server refuses them | [Data Types › Edge cases](3-reference/types.md#edge-cases) | a server that offers them |

## Next

The milestones M1–M15, M17 and M18 in [Building the Client](B-building-the-client.md#4--milestones--agreed-d-46) are built. As D-62 decided, the logins and Azure's features were built before M16. The Rust client is next, before M16, following the user's revised priority (D-63). Its [development proposal](D-rust-development.md) begins with ownership and permissions. The [Python baseline](E-python-baseline.md) records 589 passes, no failures and 13 remote-environment skips after fixing captured-server portability and automatic test database initialization. SQL Server runs under Rosetta, and local TLS and .NET interoperability checks passed. Python conveniences and application drivers follow in the [Roadmap](C-roadmap.md).
