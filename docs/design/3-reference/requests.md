# Requests

**Where this sits:** message › **body**, a structure › field. It is the client's half of an exchange: what the client asks the server.
**Use this page to** read or build any request the driver sends: the headers every request carries, then the request itself.

## Purpose

Every request is one message on a serial channel, and the server answers it with one [response](response.md). The driver's requests are the protocol's own (D-39):

| Request | Packet type | Here |
|---|---|---|
| **SQL batch**: T-SQL text | `01` | below |
| **RPC**: procedure calls with typed parameters | `03` | below |
| **Bulk load**: rows into a table, as a stream | `01`, then `07` | below; not built yet |
| **Transaction manager**: begin, commit, roll back, savepoints, distributed transactions | `0E` | below; not built yet |

Cancel isn't a request. It is a header-only packet of type `06` that ends the exchange in progress ([Conversations](conversations.md) #9).

## Shape

**Headers.** SQL batches, RPCs and transaction-manager requests begin with them.

| Field | Size | Meaning |
|---|---|---|
| total length | u32 | the length of all the headers, this field included |
| *then each header:* | | |
| length | u32 | this header's length, this field included |
| type | u16 | `0001` query notifications · `0002` transaction descriptor · `0003` trace activity |
| data | as the type says | |

**The transaction descriptor header** (type `0002`) is required, and is the only one the driver sends:

| Field | Size | Meaning |
|---|---|---|
| transaction | u64 | the descriptor from the latest *begin transaction* announcement; 0 when none is open |
| outstanding requests | u32 | requests active on the connection, this one included; more than 1 only under MARS |

**SQL batch** (packet type `01`):

| Field | Size | Meaning |
|---|---|---|
| headers | as above | |
| enclave package | u16 length, then bytes | always present once Always Encrypted's enclaves are agreed; empty when there's nothing to send ([Always Encrypted](always-encrypted.md)) |
| text | to the end of the message | the T-SQL, as UTF-16LE. It has no length field. It runs to the end of the message, across as many packets as it needs. |

**RPC** (packet type `03`): the headers, then one or more calls separated by a BATCH marker, `FF`.

| Field | Size | Meaning |
|---|---|---|
| procedure | name: u16 length, then UTF-16LE · or `FF FF` and a u16 built-in number | which procedure to call |
| options | u16 | `01` recompile · `02` no metadata · `04` reuse metadata |
| enclave package | u16 length, then bytes | always present once Always Encrypted's enclaves are agreed; empty when there's nothing to send ([Always Encrypted](always-encrypted.md)) |
| *then each parameter:* | | |
| name | u8 length, then UTF-16LE | `@name`, or empty for positional |
| status | u8 | `01` by reference: an output parameter · `02` default value · `08` encrypted ([Always Encrypted](always-encrypted.md)) |
| type | TYPE_INFO ([Data Types](types.md)) | the parameter's declared type |
| value | as the type says | NULL when the status asks for the default. A large value is PLP. A whole value is sent with its total length. A value from a source is sent with its length *not known yet*, in chunks as the source produces them ([Data Types](types.md), D-41). A table is sent as its columns, then its rows, whole or as a source produces them ([Data Types](types.md), D-49) |
| cipher info | when encrypted | what the ciphertext holds, and with which column key ([Always Encrypted](always-encrypted.md)) |

**Bulk load** is two messages, each its own exchange:

1. **A SQL batch:** `INSERT BULK table (column type, …) [WITH (options)]`. It names the columns the rows will fill, and the server answers with a DONE. The options are `CHECK_CONSTRAINTS`, `FIRE_TRIGGERS`, `KEEP_NULLS`, `TABLOCK`, `ORDER (column, …)`, `ROWS_PER_BATCH = n` and `KILOBYTES_PER_BATCH = n`.
2. **The bulk data** (packet type `07`). It has **no headers**:

   | Field | Meaning |
   |---|---|
   | COLMETADATA | the columns, laid out as in a response ([Request Response](response.md)), with a key table once column encryption is agreed, and an encrypted column's crypto metadata ([Always Encrypted](always-encrypted.md)). The statement names an encrypted column by its ciphertext's type. The columns must match the statement's columns exactly (Edge cases). |
   | ROW, repeated | one row each, laid out as in a response |
   | DONE | the end; its count is ignored |

   The server answers with one DONE carrying the number of rows loaded. Some column types are sent as other types: `xml`, `json`, `text`, `ntext`, `image` and CLR types (Edge cases).

**Transaction-manager request** (packet type `0E`): the headers, a request type (u16), then the payload.

| Type | Request | Payload | The server answers with |
|---|---|---|---|
| 0 | the coordinator's address | empty bytes with a u16 length: `00 00` | one row with one binary column |
| 1 | propagate: join a distributed transaction | the coordinator's cookie, as bytes with a u16 length | per MS-TDS, a result set holding the new descriptor. Not observed, because it needs a cookie from a coordinator |
| 5 | begin | isolation (u8), then a name | a *begin* announcement, for the outermost transaction only |
| 6 | promote to a distributed transaction | none | a *promote* announcement carrying the coordinator's token |
| 7 | commit | a name, flags (u8: `01` begin another), then, when beginning another, its isolation and name | a *commit* announcement for the outermost transaction; then *begin*, if asked |
| 8 | roll back | as commit. A savepoint's name rolls back to the savepoint. | a *rollback* announcement, unless only to a savepoint; then *begin*, if asked |
| 9 | savepoint | a name, which must not be empty | nothing |

**A name** is a u8 byte count, then the name as UTF-16LE. **Isolation:** `00` unchanged · `01` read uncommitted · `02` read committed · `03` repeatable read · `04` serializable · `05` snapshot. An isolation level given with *begin another* stays for the session after that transaction ends. The announcements are on [Request Response](response.md#transaction-announcements).

**Built-in procedures**, called by number:

| Number | Procedure | Number | Procedure |
|---|---|---|---|
| 1–9 | `sp_cursor`, `sp_cursoropen`, `sp_cursorprepare`, `sp_cursorexecute`, `sp_cursorprepexec`, `sp_cursorunprepare`, `sp_cursorfetch`, `sp_cursoroption`, `sp_cursorclose` | 12 | `sp_execute` |
| 10 | `sp_executesql` | 13 | `sp_prepexec` |
| 11 | `sp_prepare` | 14 | `sp_prepexecrpc` |
| | | 15 | `sp_unprepare` |

## Rules

- **Headers come once, at the start of the message,** not in every packet.
- **The transaction descriptor follows the session.** The client takes it from the server's announcements (ENVCHANGE begin, commit and roll back), never from its own guess at what the SQL did.
- **A request's packets carry the reset flag** on the first packet when the connection was returned to a pool since its last request ([Packet](packet.md), D-36).
- **The text runs to the end of the message.** A batch larger than one packet is split across packets. The last packet is marked *last*.
- **An output parameter is sent by reference with a value.** The procedure sees the value sent, NULL included. TDS has no output-only parameter (D-40).
- **Several calls in one RPC are separated by BATCH (`FF`).** MS-TDS also defines NO-EXEC (`FE`), which skips the call before it; the driver never sends it (D-40).
- **The driver checks each value against its declared type before sending** (D-48). A value that doesn't fit is refused, and nothing is sent.
- **A request from a source is sent while the source produces it.** Each chunk, or each row of a table, is checked when it is encoded.
- **A request that fails or is canceled partway is undone** (D-41):
  - **nothing sent yet:** nothing to undo;
  - **part of it sent:** the next packet carries *ignore* + *last*, and the server runs nothing and answers with a DONE marked *error* (after a message of its own; see Edge cases);
  - **all of it sent:** Attention cancels it.

  In each case the driver reads the server's answer, so that the channel is free. Then it raises the original error.

## Example

`SELECT 1` as a SQL batch, outside a transaction, with one request outstanding:

| At | Bytes | Field | Value |
|---|---|---|---|
| 00 | `01 01 00 2E 00 00 01 00` | packet header | SQL batch · last · 46 bytes |
| 08 | `16 00 00 00` | total length | 22 |
| 0C | `12 00 00 00` | length | 18 |
| 10 | `02 00` | type | transaction descriptor |
| 12 | `00 00 00 00 00 00 00 00` | transaction | 0: none |
| 1A | `01 00 00 00` | outstanding requests | 1 |
| 1E | `53 00 45 00 4C 00 45 00 43 00 54 00 20 00 31 00` | text | `SELECT 1` |

**A call:** `#bump` with one output parameter, `@a = 41`:

| Bytes | Field | Value |
|---|---|---|
| `03 01 00 39 00 00 01 00` | packet header | RPC · last · 57 bytes |
| `16 00 00 00` … `01 00 00 00` | headers | as above |
| `05 00 23 00 62 00 75 00 6D 00 70 00` | procedure | 5 code units: `#bump` |
| `00 00` | options | none |
| `02 40 00 61 00` | name | `@a` |
| `01` | status | by reference: an output parameter |
| `26 04` | type | `int`, 4 bytes |
| `04 29 00 00 00` | value | 41 |

## Edge cases

- **Query notifications and trace activity headers** are optional, and the driver doesn't send them. Query notifications ask the server to report when a query's results change. Trace activity carries a correlation id.

**Where SQL Server differs from MS-TDS.** Observed from SQL Server 2025 (17.0.5015).
- **The answer to *ignore* + *last* has a message before its DONE.** MS-TDS says the server answers with a DONE marked *error*. SQL Server sends that DONE after a message: for a call abandoned partway, error 4002 (severity 16, “The incoming tabular data stream (TDS) protocol stream is incorrect. The stream ended unexpectedly.”); for bulk rows, message 3621 (“The statement has been terminated.”). The driver reads this as the answer to the undo. The application gets the error that caused the undo. *Corrected 2026-10-16:* this page said a lone DONE, based on a test that matched a different response.
- **A table's default needs the default status bit,** which MS-TDS says must be zero for a table ([Data Types › Edge cases](types.md#edge-cases)).
- **A large value in bulk data with a known length is the length, then the bytes:** no chunks, and no chunk of length 0 at the end. MS-TDS defines a known-length PLP value with chunks, and says the bulk data is laid out as the server would send the same rows. The server does send chunks, and refuses them in bulk data (error 4804). The unknown-length form, with chunks, is accepted as MS-TDS defines it.
- **Promoting a transaction begun in T-SQL works.** MS-TDS says promote is supported only for transactions begun by a transaction-manager request, and that the server returns an error otherwise. SQL Server promotes it and returns a token, as for any other transaction.
- **The coordinator's address comes as one row,** as MS-TDS's description of the request says. Its description of the announcements says a *transaction manager address* announcement answers this request, and its table of announcements says that kind isn't used. None is sent.
- **MS-TDS's sample transaction-manager request** is labeled *promote*, but its request type is `16 00`, which is 22. Promote is 6.

**What MS-TDS doesn't state.** Observed from SQL Server 2025 (17.0.5015).
- **An empty batch** (or one holding only spaces or a comment) is still a request. The server answers with one final DONE, no count, statement code 253.
- **A declared `varchar` parameter is in the database's default collation,** whatever collation the value arrives in. This applies to `sp_executesql`'s declarations and to procedure parameters alike. The server converts the value when it arrives, and chooses a similar-looking character where it can: Greek α arrived as `a`, with no error. Therefore a value from a `varchar` column in another collation is sent back unchanged only through a parameter declared `nvarchar`. Even then, sequences the server itself writes back differently, such as duplicate encodings or default characters, can't pass through any text parameter ([Data Types](types.md#edge-cases)).
- **`sp_execute` called by number refuses a named handle** with error 4002, "the TDS stream is incorrect". It accepts the handle positional, or a name when called by name. `sp_prepare`, `sp_prepexec` and `sp_executesql` accept named parameters by number.
- **The *no metadata* option is ignored:** for `sp_executesql` and `sp_execute` alike, the server still sends the columns. The driver reads either.
- **Bulk load's two messages must be adjacent, on the same channel:**
  - bulk data without a successful `INSERT BULK` just before it gets a DONE marked *error*, and then **the server closes the connection**;
  - another request between them fails with error 4022, "bulk load data was expected but not sent", and ends the bulk load. Bulk data after that closes the connection as above.
- **The bulk data's columns must match the statement's exactly, by position:**
  - a different type is refused (error 4815, *invalid column length*), for example `bigint` data for an `int` column;
  - so is the wrong code for the column's nullability (error 4816, *invalid column type*): a `NOT NULL` column needs the fixed-size code, as the server would send it;
  - every column the statement names must be sent (error 4804);
  - names are ignored, but an empty name is refused (error 4804).
- **Some columns load as another type:**

  | Column | The data's type | The statement declares |
  |---|---|---|
  | `xml` | `nvarchar(max)`, as MS-TDS says | either |
  | CLR types | `varbinary(max)`, as MS-TDS says | either |
  | `text`, `ntext`, `image` | `varchar(max)`, `nvarchar(max)`, `varbinary(max)` | the `(max)` type: declaring the column's own type is refused (error 4816) |
  | `json` | `nvarchar(max)` | `nvarchar(max)`: declaring `json` is refused (error 4816) |

  Data in the column's own type is refused (error 4816; error 4804 for `text` with a text pointer). `sql_variant` and `vector` load as themselves.
- **Identity values in bulk data are kept,** and the identity continues from them, without `IDENTITY_INSERT`.
- **The options, as observed:**
  - without `CHECK_CONSTRAINTS`, constraints aren't checked, and the server marks them *not trusted*; with it, a violation fails the load (error 547);
  - without `KEEP_NULLS`, a NULL takes the column's default;
  - triggers fire only with `FIRE_TRIGGERS`, once per load;
  - `ORDER` is checked: rows out of order fail the load (error 4819).
- **A bulk load runs as one statement:** a failed `CHECK` constraint loads no rows, and a bulk load inside a transaction rolls back with it.
- **Transaction names are UTF-16LE.** An odd byte count is refused (error 3976).
- **Only the outermost transaction is announced.** A nested begin, an inner commit, a savepoint and a rollback to a savepoint announce nothing.
- **A refused savepoint name aborts the transaction:** an empty name (error 3977) or an odd byte count (error 3976) rolls back everything, and the server announces the rollback.

---

**Source:** MS-TDS §2.2.1.4, §2.2.1.6, §2.2.1.7, §2.2.5.2.3, §2.2.5.3, §2.2.6.1, §2.2.6.6, §2.2.6.7, §2.2.6.9, §2.2.7.9, §4.13
