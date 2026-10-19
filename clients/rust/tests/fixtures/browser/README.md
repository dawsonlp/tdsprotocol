# Browser fixture provenance

`machine.bin`, `instance.bin` and `dac.bin` are the unchanged MC-SQLR §4 examples
retained by `clients/python/tests/test_browser.py`. `cp1252.bin` records Python's
strict codec for every byte: a little-endian Unicode scalar, or FFFFFFFF for an
undefined byte. No endpoint discovery or credentials were captured.

Generate from the repository root:

```sh
PYTHONPATH=clients/python:clients/python/tests clients/python/.venv/bin/python clients/rust/tests/fixtures/browser/generate.py
```

Rust tests consume these fixed bytes without requiring Python or a real Browser.
Controlled UDP tests use ephemeral loopback ports and never broadcast off-machine.
