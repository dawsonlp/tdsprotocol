# Shared scalar values

`python.json` is deterministic output of Python's actual TYPE_INFO/value codecs,
using the existing short-type boundary cases in `tests/test_types.py`, plus
negative decimal zero and fixed-size wire layouts. `generate.py` records the
command and provenance. All data are artificial; there are no credentials.

The Rust tests compare explicit payload views, exercise fragmentation and both
ROW/NBCROW NULL forms, and keep declared type identity separate from wire codes.
Text fixtures compare exact bytes and collation; SQL code-page decoding is a
later slice. The old invalid datetimeoffset success fixture is replaced by a
valid minimum-local-date boundary. Both clients now reject UTC/local overflow,
invalid ticks and offsets before parameter encoding. The corpus has 96 cases;
the Rust parameter writers also compare the nullable parameter encodings.

These are codec comparisons. `live_scalars.rs` separately checks real values
against Docker SQL Server with both TDS versions and plain/MARS transports.
