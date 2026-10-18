# Python inspection evidence

Regenerate from the repository root:

```sh
PYTHONPATH=clients/python clients/python/.venv/bin/python tools/generate_rust_inspection.py
```

The nine artificial cases use Python's actual packet, LOGIN7, PRELOGIN and token
inspection definitions. Each selected field retains its raw bytes and Python's
range, normalized to its packet/message/token root. Rust paths are explicitly
mapped where naming differs; semantic displays need not use identical wording.
The LOGIN7 version value independently checks little-endian decoding.

The login input is the existing artificial `../login7/default.bin`; its fake
password is already part of that committed fixture. No network, environment
credentials or application recordings are read. SQL Server and controlled-TLS
acceptance compare fresh live/saved trees separately.
