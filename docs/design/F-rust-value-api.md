# Rust type and value API

**Where this sits:** The approved scalar representation and its remaining implementation slices.
**After reading this you can** distinguish declared SQL types, exact values, NULL, heterogeneous rows and work still pending.

**Intent:** extend the client from integer rows to Python's full SQL vocabulary
while preserving exact values, explicit declared types and readable code.
The user approved the explicit enum and exact structs on 2026-10-17. Scalar
read/write, typed RPC and the subsequently approved borrowed large-value/source
surfaces are implemented; the remaining special-type vocabulary is pending.
[Design I](I-rust-rpc-and-streaming.md) records the streaming ownership and cleanup contract. The sketch below records the agreed direction, including the
implemented `Param` surface; it is not a claim that every item is implemented.

Python separates a declared `SqlType`, a parameter's value (`None` means NULL),
and column metadata. This is reasonable: NULL has no scalar payload, a decimal
value is not its column's precision declaration, and an integer's wire code is
not a different declared SQL type. Python's SQL-specific temporal values retain
100 ns ticks and legacy 1/300-second ticks without rounding. Decimal sign is kept
even for zero. Rust should preserve these decisions.

## Agreed public concepts

```rust,ignore
// Non-NULL scalar payload. Add variants only with the corresponding codec/tests.
pub enum Value {
    Integer(i64),
    Bit(bool),
    Real(SqlReal),       // exact f32 bits; explicit conversion to f32
    Float(SqlFloat),     // exact f64 bits; explicit conversion to f64
    Decimal(SqlDecimal), // sign, u128 magnitude and scale, precision up to 38
    Money(SqlMoney),     // signed ten-thousandths, no float intermediate
    Unicode(SqlText),    // existing exact UTF-16; conversion to String is fallible
    Text(SqlTextBytes),  // exact bytes, collation and a fallible decoded view
    Binary(Vec<u8>),
    Guid(SqlGuid),
    Date(SqlDate),
    Time(SqlTime),
    DateTime2(SqlDateTime2),
    DateTimeOffset(SqlDateTimeOffset),
    DateTime(SqlDateTime),
    SmallDateTime(SqlSmallDateTime),
    // Variant, CLR, vector and large-value representations follow their slice.
}

pub type Row = Vec<Option<Value>>; // None is SQL NULL; metadata supplies its type

pub enum SqlType {
    Integer { size: IntegerSize },
    Bit,
    Decimal { precision: u8, scale: u8, numeric: bool },
    // Other explicitly declared SQL types, with checked lengths/scales/collations.
}

pub struct Param {
    pub name: SqlText,
    pub sql_type: SqlType,
    pub value: Option<Value>,
    pub output: bool,
    pub use_default: bool, // DEFAULT sends NULL with its distinct status bit
}
```

Declared SQL type and wire encoding remain distinct: fixed INT4 and nullable
INTN(4) both represent SQL `int`, but decoding retains which wire layout arrived.
Column flags, user type and name remain separate metadata. A parameter's declared
type decides how its value is encoded; an incompatible payload is rejected before
any bytes are sent. No implicit inference of SQL types from Rust values.

Exact structs expose checked constructors and explicit conversions. A value too
precise for the destination must fail unless the caller explicitly requests a
rounding conversion. Decimal precision 38 fits an unsigned 128-bit magnitude;
keeping sign separately preserves negative zero. Time uses 100 ns ticks, legacy
datetime keeps days since 1900 and 1/300-second ticks, and datetimeoffset keeps UTC
date/ticks plus its original minute offset, as Python does.

This changes the unpublished integer-only row API from `Vec<Option<i64>>` to
`Vec<Option<Value>>`. Driver retention, cancellation, channel ownership, pooling
and recovery semantics stay the same. Checked scalar accessors can make common
integer/text reads concise, but cannot grant independent stream authority.

## Scope and evidence before each addition

Start with the existing integer decoder migrated to `Value::Integer`, then bit,
floats, Unicode and binary, exact numeric/temporal types, explicit RPC parameters
and returns. Preserve Python's edge-case fixtures and compare deterministic
bodies and values. Run actual Docker queries in both TDS versions and under MARS.
Code-page handling and large-value streaming require their own concrete boundary
review; do not substitute replacement decoding or buffer a stream silently.

Alternative: keep `Row` and non-NULL values private while reviewing a typed-only
accessor surface. That postpones the row representation decision but adds a new
reading layer before full type support. The approved choice is the explicit enum
because the protocol, Python baseline and heterogeneous SQL rows are all visible.

## Implemented scalar read slice

`values.rs` defines the exact payloads and checked conversions; `types.rs` defines
`SqlType`/`TypeInfo`, and `types/codec.rs` reads their layouts. A column carries
`type_info.sql_type`, the original `code` and its raw maximum byte length. Integer
aliases therefore share declared identity without erasing their wire encoding.
`Record::Row` and all fetched rows now use `Vec<Option<Value>>`. Existing
connection, retention, cancellation, pool and recovery tests use that API.

The supported scalar reads cover integers, bit, real/float, decimal/numeric,
money/smallmoney, date/time/datetime2/datetimeoffset, legacy datetime and
smalldatetime, GUID, bounded Unicode/non-Unicode characters and binary values.
Text bytes retain their column collation; non-Unicode decoding is still pending.
No PLP stream is silently buffered. Scalar parameter writers validate declarations
and exact values before any request bytes; named/built-in calls, defaults and
input/output parameters are implemented. See [Typed Calls and Streaming](I-rust-rpc-and-streaming.md).

Ninety-six deterministic Python codec cases cover its valid boundary values,
fixed and length-prefixed aliases, NULL, negative zero, unpaired surrogates and
empty values. Pure tests check fragmented tokens, NBCROW omissions, invalid
lengths/metadata and precision/calendar overflow. Docker separately checks
heterogeneous retained rows, NULL and reuse under both versions × plain/MARS.

### Shared validation correction: implemented

The earlier Python pure fixture included UTC `0001-01-01 00:00`, offset -14:00,
placing the local date before year 1. The RPC slice corrects Python's parameter
validation to enforce UTC/local date bounds, whole-day ticks and whole-minute
offsets within ±14 hours. Aware Python datetimes that overflow UTC conversion
also raise ValueRefused. Rust's checked constructors already enforce these rules.

The invalid success fixture is replaced by a valid minimum-local-date boundary;
nine explicit invalid direct/aware cases test local/UTC overflow, ticks and
offsets. The valid corpus now includes 96 cases. Rust parameter bytes match the
Python scalar corpus, including compact decimal payloads, and deterministic RPC
bodies match Python's actual Call/Calls encoder. Docker separately checks scalar
inputs, NULL, defaults, output values, grouped returns and saved metadata under
both TDS versions × plain/MARS. Exact storage and offsets remain unchanged.
