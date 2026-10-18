# LOGIN7 definition parity

`generate.py` runs the actual Python `login7.login` definition with deterministic,
artificial values, no feature extension and Rust's library identity. The generated
bodies are compared byte for byte by Rust's encoder tests. There are no live
credentials, process ids or host identities in these files. Regeneration is an
explicit review step; tests need neither Python nor a live server.

`default.bin`: ODBC defaults on; empty language asks for the login's default.
`custom.bin`: ODBC defaults off; Deutsch; read-only intent; a Unicode app name.
Both include a fixed process id, LCID and fixed names. Tests also assert flags and
offset/count fields directly so matching definitions alone do not prove correctness.

`password-change.bin` is an artificial Python-encoded login containing distinct
old/new passwords and the SESSIONRECOVERY extension. Rust compares all bytes,
including offsets/counts and both flags, then verifies that both credential ranges
are masked. The codec alone does not claim completed password-change support in
the shell/pool; that shared credential-lifetime choice is documented separately.
