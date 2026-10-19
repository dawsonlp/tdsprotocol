# Encryption policy fixtures

`master.pem` is an intentionally public disposable RSA private key, like the TLS
peer keys in the adjacent fixtures. Never deploy it or use it to protect data.
`python.json` contains Python-generated wrapped CEKs, deterministic/randomized
encrypted values and a correctly authenticated value with invalid padding.

Generate with `clients/python/.venv/bin/python clients/rust/tests/fixtures/encryption/generate.py`.
The fixture values are synthetic, deterministic byte patterns, not application data.

`generate_sql.py` reads the established Python exact-type corpus and emits
`sql.json` (28 SQL types / 56 edge values / NULLs), `wire.json` (independent raw
metadata/output bytes), and `authenticated.json` (public canary plus a corrupted
ciphertext). It uses the existing public key; it does not regenerate it.

```sh
PYTHONPATH=clients/python:clients/python/tests clients/python/.venv/bin/python clients/rust/tests/fixtures/encryption/generate_sql.py
```

The live Rust test sends these application values through Rust's own adapter,
then runs Microsoft's SqlClient directly in its SDK container. Python supplies
fixture values, not encryption or SQL orchestration during Rust acceptance.
