# tdsprotocol

[![Design site](https://github.com/dawsonlp/tdsprotocol/actions/workflows/pages.yml/badge.svg)](https://dawsonlp.github.io/tdsprotocol/)

A client for Microsoft's **Tabular Data Stream (TDS)** protocol, versions 7.4 and 8.0: the wire protocol of SQL Server and Azure SQL. It is designed so that reading the code teaches the protocol, and so that the running client can display what it does at any level of detail.

**Read the design online: [dawsonlp.github.io/tdsprotocol](https://dawsonlp.github.io/tdsprotocol/)**. It is an interactive guide to TDS and to this client, with byte-by-byte packet diagrams that show details when you hover over them. Begin with *The Model*, a five-minute read.

**Status:** the Python client's milestones M1–M15, M17 and M18 are built. They cover TDS 7.4 and 8.0, every request and token, MARS, bulk load, transactions, session recovery, routing, Always Encrypted, and SQL Server, Windows and Entra ID logins. The next priority is the Rust client. Its [development plan](docs/design/D-rust-development.md) begins with ownership and permissions; the [Python baseline](docs/design/E-python-baseline.md) records the test evidence and server setup. Python M16 remains pending ([Done When](docs/design/5-done-when.md)).

**[Roadmap](docs/design/C-roadmap.md):** a Rust client built with the Python code and tests as its reference, then Python conveniences, then application drivers such as DB-API.

**The design's system of record** is [docs/design/](docs/design/README.md); the site presents the same content. To read the site offline, open [site/index.html](site/index.html) in a browser.

| Path | What |
|------|------|
| `docs/design/` | **The design: the system of record**, organized as a reading path: model → worked example → reference → decisions → done-when |
| `clients/python/` | The Python client and its command-line tool ([how to run it](clients/python/README.md)) |
| `site/` | A separate deliverable: an interactive web view of the design, with packet grids and hover details ([how it's built](site/README.md)) |
| `docker/macos/` | Local SQL Server containers for testing (Azure SQL Edge; SQL Server 2025) |
| `docs/specification/` | Microsoft's specifications (PDF), the authority that the design and the code are checked against. They are not in git; `python3 tools/fetch_specifications.py` downloads the latest published versions |
| `tools/` | Utilities for the whole repository |

## License

MIT: see [LICENSE](LICENSE).

Microsoft's SqlClient (MIT) was a reference for Always Encrypted's cryptography and key formats, which MS-TDS doesn't define, and is run in the tests as an independent check. No SqlClient code is copied. [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) gives the exact scope and SqlClient's license.

## Microsoft's specifications

The protocols are Microsoft's, published under its [Open Specifications](https://learn.microsoft.com/en-us/openspecs/) terms, so this repository does not hold copies. Each canonical page lists every revision, newest first:

- [MS-TDS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/): the Tabular Data Stream protocol
- [MC-SQLR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/): the SQL Server Resolution Protocol, spoken by the SQL Server Browser
- [MC-SMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-smp/): the Session Multiplex Protocol, under MARS

`python3 tools/fetch_specifications.py` downloads the latest published MS-TDS and MC-SQLR into `docs/specification/` as `<name>_v<date>.pdf`, the date the code cites (“Checked against MS-TDS v20260617”).
