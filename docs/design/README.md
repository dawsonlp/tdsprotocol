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
| C | [Roadmap](C-roadmap.md) | What comes after the milestones: conveniences, a Rust client, application drivers | 5 min |
| Check | [Python Key Retention](experiments/python-encryption-retention.md) | Policy API, lifecycle boundaries, test scenarios and evidence | as needed |

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

The milestones M1–M15, M17 and M18 in [Building the Client](B-building-the-client.md#4--milestones--agreed-d-46) are built. As D-62 decided, the logins and Azure's features were built before M16. M16, the convenience layer and the synchronous shell, is next. It is the first phase of the [Roadmap](C-roadmap.md), followed by a Rust client and application drivers such as DB-API (D-63).
