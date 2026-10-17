# Data Types

**Where this sits:** token › field › **value**. Every column (in COLMETADATA), every output value (RETURNVALUE) and every parameter describes its type, then carries values laid out as that type says.
**Use this page to** read or write any value: its type's description on the wire (TYPE_INFO), its layout, and the value the driver gives you for it.

## Purpose

On the wire, a value has no type of its own. Its column's or parameter's **type description** says how to read it. The driver has one vocabulary of SQL Server types, `tds.types`, for columns and parameters alike (D-40). Every value it reads goes back exactly (D-48). This page covers the short types (M2), the large ones (M4), `sql_variant` (M5), `json` and `vector` (M6), CLR types (M7), and tables (M8).

## Shape

A type description is a one-byte **type code**, then whatever that code needs. A value is then laid out as the code says. NOT NULL columns may use the **fixed-size codes**, which have no length per value. Nullable columns, and every parameter, use the **codes with a length**.

| Code | Type | After the code | Each value |
|---|---|---|---|
| `30` `34` `38` `7F` | `tinyint` `smallint` `int` `bigint`, fixed size | — | 1, 2, 4 or 8 bytes, little-endian; `tinyint` unsigned |
| `26` | integer with a length | size: 1, 2, 4 or 8 | length (0 = NULL), then that many bytes |
| `32` / `68` | `bit`, fixed / with a length | — / size 1 | 1 byte / length, then 1 byte |
| `6A` `6C` | `decimal`, `numeric` | size, precision, scale | length (0 = NULL; 5, 9, 13 or 17), sign (1 = not negative, 0 = negative), then the value × 10^scale as an unsigned little-endian integer |
| `3B` `3E` / `6D` | `real` `float`, fixed / with a length | — / size 4 or 8 | IEEE 754: 4 or 8 bytes |
| `3C` `7A` / `6E` | `money` `smallmoney`, fixed / with a length | — / size 8 or 4 | the value × 10⁴ as a signed integer. `money` sends its high 4 bytes first, then its low 4 |
| `3D` / `6F`·8 | `datetime` | — / size 8 | days since 1900-01-01 (i32; negative before 1900, as early as 1753), then 1/300-second ticks since midnight (u32) |
| `3A` / `6F`·4 | `smalldatetime` | — / size 4 | days since 1900-01-01 (u16), then minutes since midnight (u16) |
| `28` | `date` | — | length (0 or 3), days since 0001-01-01 (u24) |
| `29` | `time(n)` | scale n | length (0, or 3, 4 or 5 by scale), then units of 10⁻ⁿ second since midnight |
| `2A` | `datetime2(n)` | scale n | length, the time as for `time(n)`, then the date as for `date` |
| `2B` | `datetimeoffset(n)` | scale n | length, the **UTC** time, the **UTC** date, then the offset in minutes (i16, ±840) |
| `24` | `uniqueidentifier` | size 16 | length (0 or 16), 16 bytes; the first three groups little-endian |
| `AF` `A7` | `char(n)` `varchar(n)` | max length (u16, bytes), collation (5 bytes) | length (u16; `FFFF` = NULL), bytes in the collation's code page |
| `EF` `E7` | `nchar(n)` `nvarchar(n)` | max length (u16, bytes = 2n), collation | length (u16; `FFFF` = NULL), UTF-16LE |
| `AD` `A5` | `binary(n)` `varbinary(n)` | max length (u16) | length (u16; `FFFF` = NULL), bytes |

`rowversion` arrives as `binary(8)` with user type 80, and `sysname` as `nvarchar(128)` with user type 256 (the column's user type).

**Large values** (M4, D-47):

| Code | Type | After the code | Each value |
|---|---|---|---|
| `A5` `A7` `E7` | `varbinary(max)` `varchar(max)` `nvarchar(max)` | max length `FFFF`; a collation for the text types | **PLP**, below |
| `F1` | `xml` | schema present (u8); if 1, the database (u8-length text), owning schema (u8-length text) and schema collection (u16-length text) | PLP of UTF-16LE text |
| `23` `63` `22` | `text` `ntext` `image` | max length (u32); a collation for `text` and `ntext`; in a result, the table it comes from: a part count (u8), then each part (u16-length text) | in a result: a text pointer (u8 length, then that many bytes; length 0 means NULL and nothing follows), an 8-byte timestamp, then the length (u32) and the bytes. As a parameter: the length (u32; `FFFFFFFF` = NULL), then the bytes |

**PLP** (partially length-prefixed), MS-TDS §2.2.5.2.3:

| Field | Size | Meaning |
|---|---|---|
| total length | u64 | the value's length; `FFFFFFFFFFFFFFFF` = NULL; `FFFFFFFFFFFFFFFE` = not known yet |
| *then each chunk:* | | |
| length | u32 | this chunk's length; 0 ends the value |
| data | as long as that | the value's next bytes |

In bulk data, a value whose length is known is that length, then the bytes alone ([Requests › Edge cases](requests.md#edge-cases)).

**`sql_variant`** (code `62`, M5): its type description is a max length (u32, 8,016). Each value carries its own base type:

| Field | Size | Meaning |
|---|---|---|
| length | u32 | the rest of the value; 0 = NULL |
| base type | u8 | the base type's code; the fixed-size code for integers, `bit`, `real`, `float`, `money`, `smallmoney`, `datetime` and `smalldatetime` |
| property count | u8 | how many bytes of properties follow |
| properties | as counted | `time`, `datetime2`, `datetimeoffset`: the scale · `decimal`, `numeric`: precision, scale · `binary`, `varbinary`: max length (u16) · `char` … `nvarchar`: collation (5), max length in bytes (u16) · the rest: none |
| value | the rest | the base value, laid out as usual but **without its own length**: the sql_variant's length covers it |

A `sql_variant` can't contain NULL or a large type. The driver gives each value as a `SqlVariant(type, value)`, and sends it back with the same base type (D-48).

**`json` and `vector`** (M6) arrive as their real types only when the login asked for JSON support and vector support (D-8); otherwise the server sends `nvarchar` text.

| Code | Type | After the code | Each value |
|---|---|---|---|
| `F4` | `json` | — | PLP. **The server sends UTF-8 with the UTF-8 login feature, UTF-16LE without; it reads parameters as UTF-8** (Edge cases) |
| `F5` | `vector(n)`, `vector(n, float16)` | max length (u16: 8 + n × element size), element type (u8: `00` float32, `01` float16) | length (u16; `FFFF` = NULL), then an 8-byte header: layout `A9`, version `01`, the count (u16), the element type, 3 reserved bytes; then the values, little-endian |

The driver gives a `json` value as `str`, and a vector as `SqlVector(element, values)`, each value exactly a float32 or float16. A `vector` column has user type 255.

**CLR types** (code `F0`, M7): `hierarchyid`, `geometry`, `geography`, and types users define in .NET assemblies. A value is the type's own serialization; the type description names the type.

| Where | After the code | Each value |
|---|---|---|
| a result | max size (u16; `FFFF` = no limit), then the database, schema and type name (each u8-length text), then the assembly-qualified name (u16-length text) | PLP |
| a parameter | the database, schema and type name (each u8-length text; the database may be empty) | PLP |

The driver gives a value as `bytes`, and a column's type as `Clr`, named `database.schema.type` (`str(column.type)`). Parameters name it with `types.hierarchyid`, `types.geometry`, `types.geography`, or `types.clr("schema.type")`, or reuse the column's type. An outer layer converts the bytes into shapes or paths (D-39).

**Table-valued parameters** (code `F3`, M8, D-49): a table sent to a procedure, as a parameter only. It never comes back.

| Field | Size | Meaning |
|---|---|---|
| database, schema, type name | u8-length text, each | the table type. The database must be empty. The names may be empty for a procedure's parameter, whose type the server knows |
| column count | u16 | 1 to 1,024; `FFFF` means *no table* |
| *then each column:* | | |
| user type | u32 | 0 |
| flags | u16 | `0001` nullable · `0200` **default**: the server fills the column, and rows leave out its values |
| type | TYPE_INFO | the column's type, as for a parameter |
| name | u8-length text | always empty |
| *then, optionally:* | | |
| sort and unique hint | `10`, a count (u16), then each column number (u16) and its flags (u8: `01` ascending · `02` descending · `04` unique) | the rows are sorted by these columns, in this order; the unique ones have no duplicates |
| send order | `11`, a count (u16), then every column number (u16) | the order each row's values travel in |
| end | `00` | |
| *then each row:* | | |
| row | `01`, then each value but the default columns', as for a parameter | |
| end | `00` | no more rows |

Columns are numbered from 1. The driver writes a table type as its name and its columns' types, in order: `types.table("shop.price_change", types.int, types.decimal(10, 2))`. A column the server fills is `types.default(type)`. `order=`, `unique=` and `send_order=` give the optional tokens. The value is an iterable of tuples, or a source of tuples. Each tuple holds the values of every column except those marked `types.default`, in the type's order. The driver sends them in the send order. `DEFAULT` sends *no table*. The driver checks only what its encoding needs; the server checks the rest (Edge cases).

**Collation**, 5 bytes:

| Bits | Field | Meaning |
|---|---|---|
| 0–19 | locale id | for example `0x0409`, English (United States) |
| 20–27 | flags | `01` ignore case · `02` ignore accent · `04` ignore width · `08` ignore kana · `10` binary · `20` binary2 · `40` **UTF-8** |
| 28–31 | version | the collation's version |
| 32–39 | sort id | non-zero for SQL collations (`SQL_…`) |

**Its code page:** UTF-8 if the UTF-8 flag is set; otherwise the sort id's, for SQL collations; otherwise the locale's. The table is `tds/collations.py`, generated from the server (D-44). Code page 0 means Unicode only, so `varchar` can't use the collation.

## Rules

- **The same type, whichever code it arrives in.** A NOT NULL `int` column arrives as `38`, a nullable one as `26`·4. Both are `types.int`; the code stays visible in observability.
- **Parameters always use the codes with a length,** so they can be NULL.
- **A `varchar` value is in its own column's collation,** not the session's.
- **A max length of `FFFF` means `(max)`:** those values come as PLP. The driver spells it `types.MAX`: `types.varbinary(types.MAX)` (D-47).
- **A large value is read whole, or value by value** (`result_set.streamed()`), and sent whole or from a source (The Client §4, D-41, D-47).
- **`text`, `ntext` and `image` can't be sent from a source:** their length goes first.
- **A session without the ODBC flag cuts every large value to 4,096 bytes** (TEXTSIZE), before the server sends it (D-9).
- **A table's values are sent whole,** never from a source: rows can come from a source, but not a single value inside one.
- **A decimal value's integer may be shorter than its precision's maximum:** each value's length says how long it is. The driver writes the smallest of 4, 8, 12 or 16 bytes that holds the value, as the server does. Inside a `sql_variant` the size is visible (`SQL_VARIANT_PROPERTY(v, 'TotalBytes')`).
- **The value the driver gives** (D-48):

  | Type | Value |
  |---|---|
  | `tinyint` … `bigint` · `bit` | `int` · `bool` |
  | `decimal`, `numeric`, `money`, `smallmoney` | `Decimal`, with the column's scale |
  | `float`, `real` | `float` |
  | `date` · `smalldatetime` | `datetime.date` · `datetime.datetime` |
  | `time` · `datetime2` · `datetimeoffset` | `SqlTime` · `SqlDateTime2` · `SqlDateTimeOffset`: 100 ns ticks, exactly |
  | `datetime` | `SqlDateTime`: 1/300-second ticks, exactly |
  | `char` … `nvarchar` | `str` |
  | `binary`, `varbinary` | `bytes` |
  | `uniqueidentifier` | `uuid.UUID` |
  | CLR types | `bytes`: the type's serialization |
  | a table (parameters only) | an iterable or source of tuples |
  | NULL | `None` |

  The `Sql…` values convert to Python's types exactly, or refuse unless rounding is asked for.
- **Text decodes as SQL Server reads it, and encodes back to the same bytes.**
  - A byte sequence reads as the server's character when the server writes that character back as the same bytes.
  - Any other sequence the server holds is carried as escapes (U+DC80–U+DCFF), so it goes back unchanged.
  - `nvarchar` keeps unpaired surrogates.
- **A value that doesn't fit its declared type exactly is refused before sending:** out of range, too long, too much scale, finer time precision, or a character the code page can't hold.

## Example

The second result set of [Request Response](response.md)'s first example, an empty `nvarchar(1)` column named `b`:

| Bytes | Field | Value |
|---|---|---|
| `00 00 00 00` | user type | 0 |
| `20 00` | flags | computed: an expression, not a table column; not nullable |
| `E7` | type code | `nvarchar` |
| `02 00` | max length | 2 bytes: `nvarchar(1)` |
| `09 04 D0 00 34` | collation | locale `0x0409` · ignore case, width, kana · sort id 52: `SQL_Latin1_General_CP1_CI_AS`, code page 1252 |
| `01 62 00` | name | `b` |

`1.50` as a `decimal(10, 2)` parameter: `6A 09 0A 02` (decimal · size 9 · precision 10 · scale 2), then `09 01 96 00 00 00 00 00 00 00` (length 9 · not negative · 150).

## Edge cases

**Where SQL Server differs from MS-TDS.** Observed from SQL Server 2025 (17.0.5015).
- **`json` arrives as UTF-16LE unless the login asked for UTF-8 support.** MS-TDS says `json` values follow RFC 8259, which requires UTF-8 between systems. SQL Server reads parameters as UTF-8, as RFC 8259 requires. It sends values as UTF-8 only when the login's UTF-8 support feature was accepted (D-8, on by default), and as UTF-16LE otherwise. Nothing in the value says which encoding it uses, so the driver reads each value by what the login agreed.
- **A table can't be NULL, and *no table* needs the default status bit.** MS-TDS says the bit must be zero for a table, but SQL Server refuses *no table* without it (error 8060: "a null table-valued parameter is required to be sent as a default parameter"). The driver sends *no table* for `DEFAULT` with the bit set, and the procedure sees an empty table. It sends `None` as *no table* without the bit, and the server refuses it.
- **A large value in bulk data with a known length is the length, then the bytes alone,** not chunks ([Requests › Edge cases](requests.md#edge-cases)).

**What MS-TDS doesn't state.** Observed from SQL Server 2025 (17.0.5015).

- **What the server refuses in a table parameter,** each with its own error: more or fewer columns than the type has (500); more than 1,024 columns (8050); a table inside a table (8032); a hint naming a column twice, or a column the table doesn't have (8054); a hint on a column the server fills (8057); an output table (8162).

- **SQL Server's code pages are not Python's.**
  - In the single-byte code pages, SQL Server gives a character to every byte, where Python's codec refuses 1 to 31 per code page: C1 controls (0x81 → U+0081 in cp1252) and private-use characters (cp874, cp1253, cp1255, cp1257).
  - In the double-byte code pages it maps whole user-defined areas to private-use characters: 2,151 sequences in cp936 and 6,219 in cp950.
  - It also reads 249 cp950 sequences as different characters than Python does.
  - It encodes some cp932 characters two ways (NEC and IBM extensions, such as U+7E8A as ED40 or FA5C) and writes the IBM form, so ED40 is carried as escapes.

  `tds/collations.py` records every difference.
- **UTF-8 `varchar`:**
  - SQL Server refuses some invalid UTF-8, such as a lone 0x80 or an overlong 0xC0 0xAF (error 9833).
  - It stores some as given: 0xFF, an encoded surrogate, a code point past U+10FFFF.
  - It drops a trailing incomplete sequence.
  - **It sends stored invalid bytes with U+FFFD in their place,** without the UTF-8 login feature (D-8). Those values can't be sent back exactly. The driver shows what the server sent. With the feature (the driver's default), they arrive as stored, and go back exactly.
- **Converting `char` or `varchar` to `varbinary` drops trailing zero bytes.** `DATALENGTH` and `binary(n)` don't, and the value on the wire doesn't.
- **Binary values compare as if padded with zero bytes:** `0x00 = 0x0000` is true.
- **SQL Server 2025 (17.0.5015) has no float16 vectors:** it accepts vector support version 1 only, and refuses `vector(n, float16)` ("'float16' is not a recognized vector base type"). The driver reads and writes them as MS-TDS defines, tested with constructed bytes.
- **A declared `varchar` parameter is in the database's default collation,** so a value in another collation is converted when the server receives it. A value in a declared `nvarchar` parameter goes back exactly, except the sequences the server itself writes back differently ([Requests › Edge cases](requests.md#edge-cases)).
- **A CLR column's type names the database the column belongs to:** `tempdb.sys.geometry` for a temporary table's column, the current database for an expression. The system types report `hierarchyid` with a max size of 892, and `geometry` and `geography` with no limit.
- **A fixed-size user CLR type** (.NET's Native format) reports its size, 9 for a point of two `int`s, and its column carries the fixed-length CLR flag (`0x100`, `ColumnFlags.FIXED_LENGTH_CLR_TYPE`). Its values still come as PLP.
- **The sort and unique hint is checked:** rows out of the order it gives are refused (error 4819), and so are duplicates where the type has a key.
- **A column the server fills must be flagged default:** an `IDENTITY` column sent with values is refused (error 1077).
- **`sp_executesql` needs the table type's name:** when no procedure gives the type, empty names are refused (error 8059). A procedure's parameter accepts them.
- **A session logged in without the ODBC flag** (`odbc=False`; the driver's default is on, D-9) starts with every ANSI option off, and TEXTSIZE at 4,096 bytes. So:
  - arithmetic overflow gives NULL, not an error;
  - `NULL + N'x'` is `N'x'`;
  - a `char(n) NULL` column created in such a session holds its values unpadded.

---

**Source:** MS-TDS §2.2.4.2.1.3, §2.2.5.1.2, §2.2.5.2.3, §2.2.5.4–§2.2.5.6, §2.2.5.5.2, §2.2.5.5.4, §2.2.5.5.5, §2.2.5.5.6, §2.2.5.5.7, §2.2.6.1, §2.2.6.4
