"""Always Encrypted over a connection: the shared context, and the connections and serial channels it wraps (D-60).

An Encryption holds provider bindings and default retention policies. Each connection lease owns its key bank,
statement descriptions and enclave sessions. Encryption opens connections (and pools) whose login asks for column
encryption, or wraps a connection already opened that way. Their serial channels do what Always Encrypted needs around each exchange:

  a call with parameters    First, a separate exchange: sp_describe_parameter_encryption says which parameters go
                            into encrypted columns, with which column key, and how. Each of those parameters is
                            normalized, encrypted, and sent as varbinary ciphertext with its cipher info. The answer
                            is kept for the same statement. If the server refuses a call encrypted by a kept answer
                            (because a column was re-encrypted with another key), the call is described again and
                            sent once more.
  bulk data                 Each encrypted column's values are encrypted with the key its column description names.
  every response            Encrypted values are decrypted as they are read, through the hook that the core gives
                            each exchange. Output parameters are decrypted with the keys that describing their call
                            found.

Everything else belongs to the connection: requests, responses, observability, recovery. The server's messages and
errors arrive as they would without encryption.
"""

import asyncio
import contextlib
import copy
import weakref
from dataclasses import dataclass
from typing import Any, Iterable

from .. import types
from ..connection.core import Event
from ..connection.shell import Connection, Pool, SerialChannel, connect
from ..login7 import DEFAULT_FEATURES, Feature
from ..requests import Builtin, BulkRows, Call, Calls, CipherInfo, Param
from ..response import Error, ServerError
from ..tokens import EnvKind, TRANSACTION_KINDS
from ..types import Character, ColumnKey, Collation, Encrypted, EncryptionType, MasterKeyValue, ValueRefused, is_source
from .backend import Backend, CryptographyBackend
from . import enclave
from .cell import ALGORITHM, CellKey, DecryptionFailed
from .keys import KeyNotDecrypted, KeyStore
from .normalize import VERSION, denormalize, normalize
from .policy import KeySession, Policies

DESCRIBE = "sp_describe_parameter_encryption"
REFUSED_AS_STALE = (206, 33514, 33195)  # errors that refuse a call encrypted with information no longer valid.
# 206: operand type clash (observed when a column was re-encrypted with another key). 33514: SqlClient retries on it.
# 33195: an enclave session that the enclave no longer has.
ALGORITHM_ID = 2  # AEAD_AES_256_CBC_HMAC_SHA256, as COLMETADATA and sp_describe_parameter_encryption number it


class EncryptionNotAgreed(ValueError):
    """Always Encrypted needs a connection whose login asked for column encryption, and a server that agreed."""


@dataclass(frozen=True)
class _Described:
    """sp_describe_parameter_encryption's answer for one statement: each parameter to encrypt, by name, and the column
    keys an enclave needs, with each master key's signature (one per encrypted value of the key)."""

    params: dict
    enclave: dict  # column key ordinal: (ColumnKey, [(MasterKeyValue, signature)])


def _asked(features) -> bool:
    return any((f[0] if isinstance(f, tuple) else f) == Feature.COLUMN_ENCRYPTION for f in features)


@dataclass(frozen=True)
class _Encrypting:
    """One parameter that goes into an encrypted column: how, and with which column key."""

    key: ColumnKey
    encryption_type: EncryptionType
    algorithm: int
    normalization: int


class Encryption:
    """Always Encrypted providers and default policies, shared by the connections it opens/wraps (D-60, D-66).

        encryption = Encryption([LocalKeyStore("keys")])
        async with await encryption.connect(host, port, user=…, password=…) as connection: …
        async with encryption.pool(host, port, user=…, password=…) as pool: …
        encrypted = encryption.wrap(connection)       # a connection opened with Feature.COLUMN_ENCRYPTION

    Keys belong to each connection lease; transaction retention is the default.
    Outside a transaction the default retains them only through the exchange."""

    def __init__(self, key_stores: Iterable[KeyStore], backend: Backend | None = None,
                 enclave_attestation: str | None = None, *, policies: Policies | None = None):
        """`enclave_attestation`: use the server's enclave, attested this way. Only "none" is built. It is for Azure
        SQL Database's VBS enclaves without attestation, and it trusts the server to run a real enclave (enclave.py)."""
        if enclave_attestation not in (None, "none"):
            raise ValueError(f"enclave_attestation={enclave_attestation!r}: only \"none\" is built; Microsoft Azure "
                             "Attestation and Host Guardian Service attestation aren't yet")
        self.key_stores = {store.name.upper(): store for store in key_stores}
        self.backend = backend or CryptographyBackend()
        self.enclave_attestation = enclave_attestation
        self.policies = Policies() if policies is None else policies
        if not isinstance(self.policies, Policies):
            raise TypeError("policies must be Policies")
        self._plans: dict[tuple, _Described] = {}  # by statement and declarations
        self._sessions: dict[str, enclave.EnclaveSession] = {}  # the enclave sessions made, by server

    # ----------------------------------------------------------------------- connections

    def _options(self, options: dict) -> dict:
        features = tuple(f for f in options.pop("features", DEFAULT_FEATURES) if not _asked([f]))
        version = b"\x02" if self.enclave_attestation is not None else b"\x01"  # 2: with enclaves, if the server has one
        return {**options, "features": (*features, (Feature.COLUMN_ENCRYPTION, version))}

    async def connect(self, host: str, port: int, **options: Any) -> EncryptedConnection:
        """tds.connect, with column encryption added to the login's features."""
        return self.wrap(await connect(host, port, **self._options(options)))

    def pool(self, host: str, port: int, **options: Any) -> EncryptedPool:
        """tds.Pool whose connections ask for column encryption. Each connection is lent wrapped."""
        return EncryptedPool(self, Pool(host, port, **self._options(options)))

    def wrap(self, connection: Connection) -> EncryptedConnection:
        if not _asked(connection._core.options.features):
            raise EncryptionNotAgreed("this connection's login didn't ask for column encryption: open it with "
                                      "Encryption.connect, or tds.connect(features=[…, Feature.COLUMN_ENCRYPTION])")
        if Feature.COLUMN_ENCRYPTION not in connection.features:
            raise EncryptionNotAgreed("the server didn't agree to column encryption at login: it may be older than "
                                      "SQL Server 2016, or not support Always Encrypted")
        return EncryptedConnection(self, connection)

    # ----------------------------------------------------------------------- keys

    def key_session(self, policies: Policies | None = None) -> KeySession:
        """Standalone explicit lifetime. Connections create their own lease-local session."""
        return KeySession(self, policies)

    def cell_key(self, key: ColumnKey, *, exchange=None) -> CellKey:
        """A column key. Without an exchange this is uncached; the caller owns/should close it."""
        if exchange is not None:
            return exchange.cell_key(key)
        failures = []
        for value in key.values:
            store = self.key_stores.get(value.key_store.upper())
            if store is None:
                failures.append(f"{value.key_store} “{value.key_path}”: no key store of that name here")
                continue
            try:
                found = CellKey(store.decrypt_column_key(value.key_path, value.algorithm, value.encrypted), self.backend)
            except (KeyNotDecrypted, ValueError) as e:
                failures.append(str(e))
                continue
            return found
        held = ", ".join(self.key_stores) or "none"
        raise KeyNotDecrypted(f"column key {key.key_id} (version {key.version}) of database {key.database_id} can't be "
                              f"decrypted: {'; '.join(failures)}. The key stores here: {held}")

    @contextlib.contextmanager
    def _using_key(self, key, exchange):
        cell = self.cell_key(key, exchange=exchange)
        try:
            yield cell
        finally:
            if exchange is None:
                cell.close()

    # ----------------------------------------------------------------------- values

    def decrypt(self, encrypted: Encrypted, ciphertext: bytes, plan: dict[str, _Encrypting] | None = None,
                *, exchange=None) -> Any:
        """The decrypted value. The core's decrypt hook calls this with the plan of the call being answered."""
        if encrypted.algorithm != ALGORITHM_ID:
            raise DecryptionFailed(f"{encrypted.algorithm_label} isn't an algorithm this driver has: only {ALGORITHM}")
        if encrypted.normalization != VERSION:
            raise DecryptionFailed(f"normalization version {encrypted.normalization}; this driver knows {VERSION}")
        key = encrypted.key
        if key is None:  # an output parameter: describing its call named the key
            name = encrypted.parameter
            planned = (plan or {}).get(f"@p{name + 1}" if isinstance(name, int) else name.lower())  # as _statement named it
            if planned is None:
                raise DecryptionFailed(f"output parameter {encrypted.parameter} is encrypted, but its call's "
                                       "describing didn't name its column key")
            key = planned.key
        with self._using_key(key, exchange) as cell:
            return denormalize(encrypted.base, cell.decrypt(ciphertext))

    def encrypt_value(self, column: Encrypted, value: Any, *, exchange=None) -> bytes | None:
        """A value for an encrypted column, as bulk data carries it: its ciphertext, with the column's key."""
        if value is None:
            return None
        if column.algorithm != ALGORITHM_ID:
            raise ValueRefused(f"the column is encrypted with {column.algorithm_label}; this driver has only {ALGORITHM}")
        collation = column.base.collation if isinstance(column.base, Character) else None
        with self._using_key(column.key, exchange) as cell:
            return cell.encrypt(normalize(column.base, value, collation),
                                column.encryption_type == EncryptionType.DETERMINISTIC)

    def encrypt(self, param: Param, how: _Encrypting, collation: Collation | None, *, exchange=None) -> Param:
        """A parameter, as its encrypted column takes it: varbinary ciphertext, with its cipher info."""
        if how.algorithm != ALGORITHM_ID:
            raise ValueRefused(f"parameter {param.name} goes into a column encrypted with algorithm {how.algorithm}; "
                               f"this driver has only {ALGORITHM}")
        cipher = CipherInfo(param.type, how.encryption_type, how.key.database_id, how.key.key_id, how.key.version,
                            how.key.metadata_version, how.algorithm, None, how.normalization)
        if param.value is None:
            return Param(param.name, types.varbinary(8000), None, param.output, cipher)
        with self._using_key(how.key, exchange) as cell:
            ciphertext = cell.encrypt(normalize(param.type, param.value, collation),
                                      how.encryption_type == EncryptionType.DETERMINISTIC)
        sent = types.varbinary(types.MAX) if param.output or len(ciphertext) > 8000 else types.varbinary(len(ciphertext))
        return Param(param.name, sent, ciphertext, param.output, cipher)

    # ----------------------------------------------------------------------- describing

    def forget(self, statement: str, declarations: str, server: str | None = None) -> None:
        """Drop a kept answer and the server's enclave session, because the server refused a call made with them."""
        self._plans.pop((statement, declarations), None)
        if server is not None:
            session = self._sessions.pop(server, None)
            if session is not None:
                session.key.close()

    async def plan(self, channel: SerialChannel, statement: str, declarations: str,
                   server: str | None = None) -> tuple[_Described, bool]:
        """Which parameters of a statement go into encrypted columns, and how, and which column keys its enclave needs:
        sp_describe_parameter_encryption's answer, kept for the next time the same statement is sent. Also returns
        whether the answer was a kept one. `server` is given when the connection agreed to enclaves. If there is no
        session with its enclave yet, the describing call also sends attestation parameters, and the answer makes the
        session."""
        cached = self._plans.get(id_ := (statement, declarations))
        if cached is not None and (not cached.enclave or server in self._sessions):
            return cached, True
        params = [Param("", types.nvarchar(types.MAX), statement),  # by position, as SqlClient passes them. The
                  Param("", types.nvarchar(types.MAX), declarations)]  # third one's name isn't documented.
        private = None
        if server is not None and server not in self._sessions:
            attestation, private = enclave.attestation_parameters(self.backend)
            params.append(Param("", types.varbinary(len(attestation)), attestation))  # varbinary(n). The server refuses
            # varbinary(max) here (error 214, “of type 'unsupported protocol type'”, observed)
        async with await channel.exchange(Call(DESCRIBE, *params)) as response:
            described = await response.fetch()
        keys: dict[int, list] = {}
        signed: dict[int, list] = {}
        for row in described.result_sets[0].rows:
            ordinal, database_id, key_id, version, metadata_version, value, store, path, algorithm = row[:9]
            master = MasterKeyValue(value, store, path, algorithm)
            keys.setdefault(ordinal, []).append((database_id, key_id, version, metadata_version, master))
            if len(row) > 10 and row[9]:  # is_requested_by_enclave, then the master key's signature
                signed.setdefault(ordinal, []).append((master, row[10]))
        column_keys = {ordinal: ColumnKey(*entries[0][:4], tuple(e[4] for e in entries)) for ordinal, entries in keys.items()}
        plan = {}
        for _, name, algorithm, encryption_type, key_ordinal, normalization in described.result_sets[1].rows:
            if encryption_type:  # 0: plaintext
                plan[name.lower()] = _Encrypting(column_keys[key_ordinal], EncryptionType(encryption_type), algorithm,
                                                 normalization)
        if private is not None and len(described.result_sets) > 2 and described.result_sets[2].rows:
            self._sessions[server] = enclave.session(described.result_sets[2].rows[0][0], private, self.backend)
        answer = _Described(plan, {o: (column_keys[o], signed[o]) for o in signed})
        self._plans[id_] = answer
        return answer, False

    def enclave_package(self, server: str, statement: str, needed: dict, *, exchange=None) -> bytes:
        """The enclave package for a call, with the column keys that the enclave asked for. A key is sent only if its
        master key's signature allows its keys to go to an enclave. SqlClient checks this too. Without the check, a
        server could ask for any key."""
        session = self._sessions.get(server)
        if session is None:
            raise DecryptionFailed("the statement needs the server's enclave, but no session with it was made: "
                                   "describing it returned no attestation info")
        with contextlib.ExitStack() as stack:
            return self._enclave_keys(session, statement, needed, exchange, stack)

    def _enclave_keys(self, session, statement, needed, exchange, stack):
        sent = []
        for key, masters in needed.values():
            allowed = any(self.key_stores.get(m.key_store.upper()) is not None and
                          self.key_stores[m.key_store.upper()].verify_master_key_metadata(m.key_path, True, signature or b"")
                          for m, signature in masters)
            if not allowed:
                raise KeyNotDecrypted(f"column key {key.key_id} of database {key.database_id} would go to the server's "
                                      "enclave, but no master key holding it signs that it allows enclave computations "
                                      "(CREATE COLUMN MASTER KEY … ENCLAVE_COMPUTATIONS (SIGNATURE = …))")
            cell = stack.enter_context(self._using_key(key, exchange))
            # Cache eviction while collecting several keys must not zero an
            # earlier package input. Own a temporary mutable copy until packaged.
            root = bytearray(cell.root)
            stack.callback(lambda root=root: root.__setitem__(slice(None), bytes(len(root))))
            sent.append((key.database_id, key.metadata_version, key.key_id, root))
        return session.package(statement, sent)


def _statement(call: Call) -> tuple[str, str, list[tuple[str, Param]]] | None:
    """What to describe for a call: its statement, its parameters' declarations, and those parameters, each with the
    name that describing uses for it. None if the call has no parameters. A procedure's positional parameters are
    described as @p1, @p2, … in place, and are still sent by position."""
    if call.target == Builtin.SP_EXECUTESQL:
        if len(call.params) < 3:
            return None
        statement, declarations = call.params[0].value, call.params[1].value
        return statement, declarations, [(p.name, p) for p in call.params[2:]]
    if not call.params:
        return None
    named = [(p.name or f"@p{i + 1}", p) for i, p in enumerate(call.params)]
    target = Builtin(call.target).name.lower() if isinstance(call.target, Builtin) else call.target
    arguments = ", ".join((f"{name} = {name}" if p.name else name) + (" OUTPUT" if p.output else "") for name, p in named)
    declarations = ", ".join(f"{name} {p.type}{' OUTPUT' if p.output else ''}" for name, p in named)
    return f"EXEC {target} {arguments}", declarations, named


class EncryptedConnection:
    """A connection whose serial channels encrypt parameters and decrypt values (D-60). Everything else belongs
    to the wrapped connection. `connection` is that connection, and its attributes can be read through this object."""

    def __init__(self, encryption: Encryption, connection: Connection):
        existing = getattr(connection, "_encrypted_wrapper", None)
        if existing is not None and existing() is not None and not existing()._returned:
            raise EncryptionNotAgreed("this connection already has an encryption wrapper for its current lease")
        self.encryption, self.connection = encryption, connection
        self._context = copy.copy(encryption)
        self._context._plans, self._context._sessions = {}, {}
        self._core = connection._core
        self._returned = False
        self.keys = encryption.key_session()
        if connection.session.transaction:
            self.keys.transaction_begin(connection.session.transaction)
        connection._encrypted_wrapper = weakref.ref(self)
        # The physical connection owns its extension until return/close. A live
        # response must still be revoked even if the application drops its facade.
        connection._lifecycle = self._lifecycle

    def _clear_metadata(self):
        self._context._plans.clear()
        for session in self._context._sessions.values():
            session.key.close()
        self._context._sessions.clear()

    def _lifecycle(self, event, change):
        if event != "session":
            self.keys.close()
            self._clear_metadata()
            if event in ("pool_return", "close"):
                self._returned = True
            return
        if change.kind in TRANSACTION_KINDS:
            if self.connection.session.transaction:
                self.keys.transaction_begin(self.connection.session.transaction)
            else:
                self.keys.transaction_end()
        elif change.kind in (EnvKind.DATABASE, EnvKind.COLLATION, EnvKind.RESET_COMPLETE):
            self.keys.invalidate()
            self._clear_metadata()

    async def _ready(self, channel):
        if self._returned:
            raise KeyNotDecrypted("the encrypted connection lease has ended")
        raw = self.connection
        if not raw.alive and raw._core.broken_while_idle:
            await raw.recover()
        if self._core is not raw._core:
            self.keys.close()
            self.keys = self.encryption.key_session()
            self._core = raw._core
            self._clear_metadata()
            if raw.session.transaction:
                self.keys.transaction_begin(raw.session.transaction)
        self.keys._check_open()
        raw._core.exchange_channel(channel.id, asyncio.current_task())
        # Deferred pool reset must restore database/collation BEFORE describing
        # or encrypting parameters. No key guard is acquired for this empty batch.
        if raw._core.reset_pending:
            from ..requests import Batch
            async with await channel.exchange(Batch("")) as response:
                await response.finish()
        self._context.key_stores = self.encryption.key_stores
        self._context.backend = self.encryption.backend

    @property
    def key_statistics(self):
        return self.keys.statistics

    def __getattr__(self, name: str) -> Any:
        return getattr(self.connection, name)

    def serial_channel(self) -> EncryptedSerialChannel:
        return EncryptedSerialChannel(self, self.connection.serial_channel())

    async def close(self) -> None:
        await self.connection.close()

    async def __aenter__(self) -> EncryptedConnection:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()


class EncryptedSerialChannel:
    """A serial channel whose exchanges encrypt a call's parameters, and decrypt every value read."""

    def __init__(self, connection: EncryptedConnection, channel: SerialChannel):
        self.connection, self.channel = connection, channel
        self.id = channel.id

    async def exchange(self, request: Any, *, policies: Policies | None = None):
        """Prepare, send and decrypt under one guard, released at terminal response completion.

        The optional policies override applies only to this exchange. Exact scope
        matching prevents a stricter override from borrowing broader cached keys.
        """
        await self.connection._ready(self.channel)
        encryption = self.connection._context
        for attempt in (1, 2):
            guard = self.connection.keys.exchange(policies)
            try:
                plan: dict[str, _Encrypting] = {}
                kept: list[tuple[str, str]] = []
                sent = await self._prepared(request, plan, kept, guard)
                response = await self.channel.exchange(sent, decrypt=lambda encrypted, ciphertext, plan=plan, guard=guard:
                                                       encryption.decrypt(encrypted, ciphertext, plan, exchange=guard),
                                                       on_complete=guard.close)
                if not kept or attempt == 2:
                    return response
                first = await response.peek()
                if not (isinstance(first, Error) and first.number in REFUSED_AS_STALE):
                    return response
                with contextlib.suppress(ServerError):
                    await response.finish()
                for statement, declarations in kept:
                    encryption.forget(statement, declarations, self._server())
                self._show(f"the server refused {request}, encrypted by an earlier describing (error {first.number}: "
                           f"{first.text[:120]}): describing it again, and sending it once more")
            except BaseException:
                guard.close()
                raise

    def _server(self) -> str | None:
        """The server whose enclave this connection uses, if its login agreed to enclaves. The enclave session is kept
        under this name."""
        core = self.connection.connection._core
        if core.negotiated.get("column_encryption", 0) < 2 or self.connection.encryption.enclave_attestation is None:
            return None
        return f"{core.options.login_server_name or core.options.host}/{core.options.database}"

    def _show(self, text: str) -> None:
        core = self.connection.connection._core
        if core.observing:
            core.observe(Event("encryption", text))

    async def _prepared(self, request: Any, plan: dict, kept: list, guard) -> Any:
        if isinstance(request, Call):
            return await self._encrypted(request, plan, kept, guard)
        if isinstance(request, Calls):
            return Calls(*[await self._encrypted(call, plan, kept, guard) for call in request.calls])
        if isinstance(request, BulkRows):
            return self._bulk(request, guard)
        return request

    def _bulk(self, request: BulkRows, guard) -> BulkRows:
        """Bulk data whose encrypted columns' values are encrypted, row by row, as the rows are sent."""
        columns = request.columns
        if not any(isinstance(c.type, Encrypted) for c in columns):
            return request
        encryption = self.connection._context

        def encrypted(n: int, row: Any) -> Any:
            if not isinstance(row, (tuple, list)) or len(row) != len(columns):
                return row  # the core refuses it, saying why
            out = []
            for i, (column, value) in enumerate(zip(columns, row), 1):
                try:
                    out.append(encryption.encrypt_value(column.type, value, exchange=guard) if isinstance(column.type, Encrypted)
                               else value)
                except ValueRefused as e:
                    e.within(f"column {column.name or i} ({column.type})")
                    e.within(f"row {n}")
                    e.within(str(request))
                    raise
            return tuple(out)

        rows = request.rows
        if is_source(rows):
            async def produced():
                n = 0
                async for row in rows:
                    n += 1
                    yield encrypted(n, row)
            return BulkRows(columns, produced())
        return BulkRows(columns, [encrypted(n, row) for n, row in enumerate(rows, 1)])

    async def _encrypted(self, call: Call, plan: dict, kept: list, guard) -> Call:
        described = _statement(call)
        if described is None:
            return call
        statement, declarations, params = described
        server = self._server()
        answer, was_kept = await self.connection._context.plan(self.channel, statement, declarations, server)
        found = answer.params
        if was_kept or answer.enclave:
            kept.append((statement, declarations))
        if not found and not answer.enclave:
            return call
        plan.update(found)
        package = call.enclave_package
        if answer.enclave:  # the statement needs the enclave: its keys go with the call
            query = call.params[0].value if call.target == Builtin.SP_EXECUTESQL else (
                Builtin(call.target).name.lower() if isinstance(call.target, Builtin) else call.target)
            package = self.connection._context.enclave_package(server, query, answer.enclave, exchange=guard)
        session = self.connection.connection.session.collation
        collation = Collation(session) if session else None
        encrypted = []
        for name, param in params:
            how = found.get(name.lower())
            try:
                encrypted.append(self.connection._context.encrypt(param, how, collation, exchange=guard) if how else param)
            except ValueRefused as e:
                e.within(f"parameter {param.name} ({param.type}, encrypted)")
                e.within(str(call))
                raise
        unencrypted = call.params[: len(call.params) - len(params)]
        return Call(call.target, *unencrypted, *encrypted, options=call.options, columns=call.columns,
                    enclave_package=package)

    def hand_over(self, task) -> None:
        self.channel.hand_over(task)

    async def close(self) -> None:
        await self.channel.close()

    async def __aenter__(self) -> EncryptedSerialChannel:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()


class EncryptedPool:
    """A pool whose connections are lent wrapped (D-60, D-36)."""

    def __init__(self, encryption: Encryption, pool: Pool):
        self.encryption, self.pool = encryption, pool

    @contextlib.asynccontextmanager
    async def connection(self):
        async with self.pool.connection() as connection:
            wrapped = self.encryption.wrap(connection)
            try:
                yield wrapped
            finally:
                wrapped._lifecycle("pool_return", None)

    async def close(self) -> None:
        await self.pool.close()

    async def __aenter__(self) -> EncryptedPool:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()
