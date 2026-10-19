# tds: the Python client

A TDS 7.4 and 8.0 client whose code teaches the protocol, and which can display what it does while it runs. The design is in [`docs/design/`](../../docs/design/README.md).

See [the release notes](CHANGELOG.md) for the corrections found during Rust development.

## Windows authentication limitations

The GCP campaign exposed shared limitations and Python follow-up work; basic
successful logins do not establish complete security acceptance. The current
Spnego adapter supplies no TLS channel binding, so SQL Extended Protection is
not an accepted capability. Provider-owned authentication-key erasure has not
been audited to the same standard as the Rust source review.

The GCP follow-up implements default incoming-token redaction, safe login
metadata for replay, provider-error diagnostic masking, 48 KiB token/eight-step
limits and a 64 KiB Windows-login message bound. Configured SQL pools reread once
on SQL 18452/18456 and retry opening only for changed settings under the original
deadline; application SQL is never replayed.

Final SSPI tokens are processed even alongside LOGINACK; invalid final tokens,
extra provider output after server acceptance and duplicate challenges are
refused. Requiring explicit provider completion still awaits the custom-adapter
compatibility decision. Windows configuration snapshots
await their API decision. Synchronous pyspnego startup can block the event loop
past the opening deadline; worker isolation is also awaiting an owner decision.
See the
[cross-client findings](../../docs/design/experiments/rust-python-authentication-limitations.md)
and [follow-up evidence](../../docs/design/experiments/gcp-authentication-follow-up-evidence.md)
for scope and remaining acceptance cases. The owner chose documentation
and potential upstream reports; no dependency forks or TLS backend changes are
being introduced for this work.

## Always Encrypted key retention

```python
from tds.encryption import Encryption, LocalKeyStore, Policies, Policy

encryption = Encryption([LocalKeyStore("keys")])  # transaction retention by default
# Or reuse keys for at most five minutes within one physical connection/pool lease:
encryption = Encryption([LocalKeyStore("keys")], policies=Policies(
    master=Policy.time(300), column=Policy.time(300),
))

# Override only this exchange, including parameter preparation and result reading:
async with await channel.exchange(request, policies=Policies(
    master=Policy.exchange(), column=Policy.exchange(),
)) as response:
    result = await response.fetch()
```

Transaction retention falls back to exchange retention in autocommit. Fixed-age
retention can span transactions, expires while idle, and never renews on use.
Expiry reloads keys on demand; it does not limit transaction duration. Choose an
age longer than acquisition itself: an acquisition exceeding its age is refused.
Keys never cross connection/borrower boundaries. Each lease has one encryption
wrapper. An override does not erase keys
retained by earlier exchanges; changing lease defaults clears them.
`connection.key_statistics`
reports successful local master loads, unwraps and live cache sizes without
revealing keys. Set defaults for an existing lease between exchanges with
`connection.keys.set_policies(Policies(...))`; doing so clears retained keys.

Local RSA masters and column keys have separate policies. Custom/vault/certificate
providers retain ownership of private-key operations; only their returned column
keys are cached here. Owned mutable CellKey buffers are overwritten on release,
but Python and native libraries may create temporary copies that this cannot
reliably erase. Custom backends keep their existing `bytes` input contract; those
call-boundary copies are also outside the erasure guarantee. Direct `encryption.cell_key(key)` is now uncached and caller-owned;
close it after use, or use `encryption.key_session()` with explicit exchange guards.
See the [reference](../../docs/design/3-reference/always-encrypted.md#key-retention)
and [scenarios/evidence](../../docs/design/experiments/python-encryption-retention.md).

## Run it

First, from the repository root, start the local SQL Server 2025 with its test certificate. The steps are in [`docker/macos/tls`](../../docker/macos/tls/README.md):

```sh
docker/macos/tls/make-test-certificates.sh
docker compose -f docker/macos/compose.sqlserver-2025.yaml up -d --wait
```

Compose 2.30 or later is required. Its post-start hook waits for SQL Server and creates `tds_test` if missing. The health check opens that database, so `--wait` returns only after the test environment is ready. Existing data is retained.

The captured-response live tests query the current server identity and select `us_english`; they do not require the machine or container that produced the captures. The original capture bytes remain unchanged for offline decoding checks.

Then run the client from this folder. `CA` is the test certificate authority that signed the container's certificate. The tests trust it and nothing else (D-10):

```sh
CA=../../docker/macos/tls/test-ca.pem
uv run tds --ca-file $CA                          # log in, SELECT 1, close: one line per step and message
uv run tds --ca-file $CA --tds-version 8.0        # TLS first: TDS 8.0
uv run tds --ca-file $CA --observe full           # every message expanded to its fields and bytes
uv run tds --ca-file $CA --mars --channels 2      # two serial channels, as MARS sessions on one connection
uv run tds --ca-file $CA --query "SELECT @@VERSION"
uv run pytest                                     # captured messages, channel and response rules, live tests
```

The password comes from `MSSQL_SA_PASSWORD`, or else from `docker/macos/.env`. It is never shown: observability masks it, and a test checks that it can't appear in any form.

## Use it as a library

```python
import tds

async with tds.Pool("127.0.0.1", 14325, user="sa", password=..., ssl_context=ssl.create_default_context(cafile="test-ca.pem"), size=5) as pool:
    async with pool.connection() as connection:            # borrowed whole: this session is yours alone
        async with connection.serial_channel() as channel:  # one request at a time, owned by this task
            async with await channel.exchange(tds.Batch("SELECT name FROM sys.databases")) as response:
                async for result_set in response:          # the response streams: result sets as they arrive…
                    async for row in result_set:           # …and their rows, as plain tuples
                        print(row)
                response.completions                       # the record: every DONE, with its count if valid
```

`tds.connect(...)` returns a single `Connection`, which is used the same way. Requests are made only on a serial channel.

For settings that can change, implement `ConfigService.read()` to return an
immutable `tds.ConnectionConfig` and construct the pool once:

```python
class Settings:
    async def read(self) -> tds.ConnectionConfig:
        # Application-controlled async configuration/secret resolution.
        return await load_current_sql_settings()

pool = tds.Pool.from_config(
    Settings(), size=5,
    services=tds.ConnectionServices(ssl_context=context),
    timeout=15.0, cleanup_timeout=5.0,
)
```

Construction is lazy. Each physical opening/recovery reads once; idle reuse does
not. Values include host, port, user/password, initial database and login defaults;
TLS/callback bindings and pool limits remain fixed. Each pool compares its own
accepted snapshot, including the credential. Known obsolete idle/returned
connections are discarded; active borrowers continue. Login rejection fails
loudly without retry/fallback, and a later corrected read can succeed through the
same pool. Recovery accepts password-only changes and preserves original channel
handles, including after pool closure. There is no watcher or monitoring thread.
Readers must cooperate with async cancellation and must not reenter this pool.

An undiscovered rotation can still fail the first SQL request carrying deferred
session reset. The client reports that failure and never replays SQL. Source
failures raise `ConfigurationError` with a safe phase/reason; inspecting
`source_error` is explicit. See the [configuration API](tds/config.py).

`new_password` is a distinct server-changing direct-login request. Pools reject
it. A fully successful direct login retains the new credential for recovery and
clears the request. Lost completion sets `password_change_uncertain` on the error
and adds an exception note; cancellation likewise cannot undo a server change.

`tds_version="8.0"` (or `strict=True`) starts TLS before anything else. The default is `"7.4"`, which agrees on encryption in the hello. In both cases the whole connection is encrypted. The certificate is checked with Python's `ssl.SSLContext`, passed as `ssl_context`. If the certificate must name a host other than the one connected to, `server_hostname` gives that name (D-10). [Connect › Options](../../docs/design/3-reference/connect.md#options) describes each option.

`observe` receives what the running client does. It can be `observe.Printer(Level.OUTLINE)`, `observe.Printer(Level.FULL)` or any callable. `None` turns it off, which costs the least. `connection.observe` changes it between exchanges. `capture=tds.capture.Capture("session.jsonl")` records the conversation in a file, and `tds.capture.replay("session.jsonl", Printer(Level.FULL))` shows it again, offline, exactly as before. A capture holds query text and data. It holds the password only if it is asked to (D-12). Saved table inputs decode as `types.TableInput`, retaining their declaration and exact rows; they do not become result cells. The Rust development branch also reads these files with `tds --replay session.jsonl`.

Each Capture belongs to one physical connection, even after detachment. Pools
require `capture_factory`, a callable returning a new Capture with a distinct
output per opened connection. Reusing the same transport across loans keeps its
recording. Connect also supports the factory for separate files on routing and
recovery; a direct capture refuses those transitions. The application owns and
closes its capture resources. A failed live observer is disabled and its exception
is available as `connection.observation_error`; database work and recording
continue. A recording write/flush failure instead raises `tds.CaptureError` and
discards the connection. Its `cause` retains the writer error. Sent SQL may still
have executed; closing is not proof of rollback.

`odbc=True`, the default, sets the login's ODBC flag, so the session starts with ODBC's defaults (ANSI options on, unlimited TEXTSIZE), as ODBC, .NET and JDBC clients get them. `odbc=False` gives the server's own defaults, which truncate large values to 4,096 bytes (D-9).

- `await response.fetch()` reads to the end and returns a `FetchedResponse`, held in memory. It can be read again or indexed (`fetched.result_sets[0].rows[0]`).
- Errors are raised at the end of the response, as a `tds.ServerError` carrying the whole record (`e.response`).
- Procedures are called with explicitly typed parameters, one or several in a request:

  ```python
  from tds import Call, Calls, Param, types
  call = Call("shop.place_order", Param("@customer", types.int, 42), Param("@order", types.int, None, output=True))
  async with await channel.exchange(call) as response:
      [returned] = await response.returns(unread=tds.Unread.DISCARD)
      returned.status, returned.outputs["@order"].value
  ```
- A table-valued parameter's type lists the types of its table type's columns, in order. Its value is rows, given as tuples. A column that the server fills is `types.default(…)`:

  ```python
  changes = types.table("shop.price_change", types.int, types.decimal(10, 2))
  Call("shop.update_prices", Param("@changes", changes, [(1, Decimal("9.99")), (2, Decimal("4.50"))]))
  ```
- A bulk load is two requests on one serial channel: the application's own `INSERT BULK` statement, then the rows, described by columns taken from `SELECT TOP 0` of the same columns (D-50):

  ```python
  async with await channel.exchange(tds.Batch("SELECT TOP 0 id, total FROM shop.orders")) as response:
      columns = (await response.fetch()).result_sets[0].columns
  for request in (tds.BulkInsert("INSERT BULK shop.orders (id int NOT NULL, total money) WITH (TABLOCK)"),
                  tds.BulkRows(columns, rows)):                      # rows: a list of tuples, or an async source
      async with await channel.exchange(request) as response:
          await response.fetch()                                     # the second says how many rows loaded
  ```
- Transactions can be controlled by protocol requests in `tds.transactions`: `Begin`, `Commit`, `Rollback`, `Save`, `Promote`, `Propagate`, `CoordinatorAddress` (D-51). The session follows the server's announcements.
- Large values (`types.MAX`, `xml`, `text`, `ntext`, `image`) arrive whole in tuples, or value by value with `result_set.streamed()`, each as a `tds.ValueStream` of bytes or str. A parameter's value can also be a source: an async iterator. The driver sends each part as the iterator produces it.
- `response.cancel()` may be called from any task; the owner's next read raises `tds.Cancelled`. Leaving the `async with` block early also cancels the response.
- The record's items (`Completion`, `Message`, `Error`, `ReturnStatus`, `OutputValue`, `Announcement`, `Return`) are in `tds.response`.

## Read it

Read the modules in this order, which is also the order of the reference pages:

1. `tds/packet.py`: the 8-byte header; splitting messages into packets and joining them back.
2. `tds/prelogin.py`: the hello.
3. `tds/login7.py`: the login.
4. `tds/tokens.py`: how the server's replies are read, token by token.
5. `tds/types.py`: the type vocabulary (`tds.types`): each type's description on the wire, its values, and its checks.
   `tds/collations.py` is its generated table of how SQL Server reads each code page (`tools/generate_collations.py`).
6. `tds/requests.py`: what the client asks: the headers every request carries, the SQL batch, procedure calls, and bulk load.
   `tds/transactions.py` holds the transaction-manager requests.
7. `tds/response.py`: the record of what the server did, and how a response is read forward as it arrives.
8. `tds/connection/core.py`: the connect procedure from start to end, then TLS, MARS, serial channels, exchange and cancel.

`tds/wire.py` and `tds/connection/shell.py` are machinery. `tds/wire.py` is the engine that reads and writes the definitions, and `tds/connection/shell.py` is the asyncio code that moves bytes. Read them to learn *how* the client works. The modules above describe *what* it does.
