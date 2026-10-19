# Shared Python capture subset

These bodies are byte-for-byte copies of named constants in
`clients/python/tests/response_samples.py`, captured from SQL Server 17.0.5015
with `odbc=False`. That source records the SQL requests and original server name
`6a376fcf9e7e`. These files preserve that provenance; they are not expectations
about a live server name. Only the currently supported integer/token subset is
included. Rust tests use them without a Python executable or SQL Server.

When a source capture changes, review and update both languages together. The
Rust tests also check fragmentation and semantic outcomes, rather than treating
a capture alone as proof of protocol correctness.
