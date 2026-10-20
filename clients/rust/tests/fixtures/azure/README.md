# Artificial Azure comparison fixtures

`generate.py` runs Python's production `tds.logins` encoders with artificial
tokens, fixed nonces and each workflow/echo value. `wire.json` retains 24 cases
and the Python source SHA-256. Empty credentials test only the wire format.
Neither these fixtures nor the Rust encoders establish successful Entra login.

From the repository root:

```sh
clients/python/.venv/bin/python clients/rust/tests/fixtures/azure/generate.py
cargo test --offline --locked --manifest-path clients/rust/Cargo.toml --test azure_wire --no-default-features
```

The first command checks current Python output against the retained fixture;
`--write` explicitly regenerates after review. Rust consumes the file without
requiring Python, an SDK, credentials or sockets. Source hashes detect drift,
not service compatibility. Extend the paired cases for PRELOGIN, LOGIN7,
FEDAUTHINFO and controlled lifecycle behavior as their implementations arrive.

`key_providers.py --verify` checks the saved envelope and local/vault metadata
signatures with production Python providers and the intentionally public RSA
key in `../encryption/master.pem`. Its fake vault performs real RSA operations.
Rust uses the official Keys SDK through a fake HTTP transport, and Python's
`--check` mode reads Rust's exported envelope/signature results in the paired
runner. No real vault is contacted; SDK authentication/request formatting and
provider order are development evidence only.

`enclave.py --verify` checks a saved package made by Python's real enclave code
with fixed public P-384 scalars 1/2. Rust compares public blobs and derives the
same secret, authenticates Python packages, then emits random packages that
Python decrypts and checks. The corpus also supplies version-two framing and
controlled SQL description responses. These are explicit no-attestation tests,
not evidence of a real protected enclave. Test private keys must never be used
for deployment. Running either script without an argument explicitly regenerates
its random fixture outputs; the runner uses verification mode.
