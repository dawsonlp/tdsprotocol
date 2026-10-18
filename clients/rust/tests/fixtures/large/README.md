# Python large-value codec corpus

`python.json` contains 21 deterministic cases produced by Python's actual type
writers: NULL, empty and nonempty values for nvarchar(max), varchar(max),
varbinary(max), XML, ntext, text and image. Unicode includes an unpaired surrogate;
raw text carries the fixture's explicit Windows collation. No server or secret is
used. Legacy RPC input framing differs from legacy row framing, so both are kept.

Regenerate from the repository root:

```sh
PYTHONPATH=clients/python:clients/python/tests clients/python/.venv/bin/python \
  clients/rust/tests/fixtures/large/generate.py
```

`tests/large_values.rs` decodes result bytes in single-byte fragments, compares the
exact payload, then checks Rust parameter bytes against the Python writer.
