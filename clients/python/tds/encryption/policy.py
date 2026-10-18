"""D-66 key retention. One bank per physical connection and exclusive pool lease.

All operations run synchronously on the owning event loop, including providers.
The timer holds only a weak reference; it does not keep an abandoned bank alive.
"""

import asyncio
import math
import time
import weakref
from dataclasses import dataclass, replace

from .cell import CellKey
from .keys import KeyNotDecrypted, LocalKeyStore


@dataclass(frozen=True)
class Policy:
    kind: str = "transaction"
    seconds: float | None = None

    def __post_init__(self):
        if self.kind not in ("exchange", "transaction", "time"):
            raise ValueError("key policy must be exchange, transaction or time")
        if self.kind == "time":
            if (isinstance(self.seconds, bool) or not isinstance(self.seconds, (int, float))
                    or not math.isfinite(self.seconds) or self.seconds <= 0
                    or not math.isfinite(time.monotonic() + self.seconds)):
                raise ValueError("key age must be positive and finite")
        elif self.seconds is not None:
            raise ValueError("only a time policy has an age")

    @classmethod
    def exchange(cls):
        return cls("exchange")

    @classmethod
    def transaction(cls):
        return cls("transaction")

    @classmethod
    def time(cls, seconds: float):
        """Fixed maximum age in seconds; use never extends the deadline."""
        return cls("time", seconds)


@dataclass(frozen=True)
class Policies:
    master: Policy = Policy()
    column: Policy = Policy()
    master_capacity: int = 8
    column_capacity: int = 32

    def __post_init__(self):
        if not isinstance(self.master, Policy) or not isinstance(self.column, Policy):
            raise TypeError("master and column must be Policy objects")
        for capacity in (self.master_capacity, self.column_capacity):
            if type(capacity) is not int or not 1 <= capacity <= 4096:
                raise ValueError("key capacity must be an integer from 1 to 4096")


@dataclass(frozen=True)
class Statistics:
    master_loads: int = 0
    unwraps: int = 0
    hits: int = 0
    evictions: int = 0
    expirations: int = 0
    live_masters: int = 0
    live_columns: int = 0
    closed: bool = False


@dataclass(repr=False)
class _Entry:
    value: object
    deadline: float | None


def _dispose(value):
    if isinstance(value, CellKey):
        value.close()
    # Native RSA objects are released by reference count; their internals belong
    # to the provider/backend. Python offers no portable zeroize for them.


async def _runtime_lifetime(reference):
    try:
        await asyncio.Future()
    finally:
        bank = reference()
        if bank is not None:
            bank.close()


def _expire(reference):
    bank = reference()
    if bank is not None:
        bank._timer = None
        bank._purge()
        bank._schedule()


class KeySession:
    """Explicit key lifetime for one lease. Driver wrappers supply server events.

    Standalone callers may use transaction_begin/end and `with session.exchange()`.
    A time policy requires a running asyncio loop when a key is acquired.
    """

    def __init__(self, encryption, policies: Policies | None = None):
        self.encryption = encryption
        self._policies = encryption.policies if policies is None else policies
        if not isinstance(self._policies, Policies):
            raise TypeError("policies must be Policies")
        self._masters, self._columns = {}, {}
        self._bindings = None
        self._timer = None
        self._runtime_task = None
        self._closed = False
        self._context = self._sequence = self._generation = 0
        self._transaction = 0
        self._guards = set()
        self._counts = Statistics()

    @property
    def policies(self):
        return self._policies

    def set_policies(self, policies: Policies):
        """Replace defaults between exchanges, clearing all previous key authority."""
        self._check_open()
        if not isinstance(policies, Policies):
            raise TypeError("policies must be Policies")
        if self._guards:
            raise ValueError("key policies can change only between exchanges")
        self.invalidate()
        self._policies = policies

    @property
    def statistics(self):
        """Snapshot only: reading statistics never triggers expiration."""
        return replace(self._counts, live_masters=len(self._masters), live_columns=len(self._columns),
                       closed=self._closed)

    def _count(self, name):
        self._counts = replace(self._counts, **{name: getattr(self._counts, name) + 1})

    def exchange(self, policies: Policies | None = None):
        self._check_open()
        self._watch_runtime()
        chosen = self.policies if policies is None else policies
        if not isinstance(chosen, Policies):
            raise TypeError("policies must be Policies")
        self._sequence += 1
        self._guards.add(self._sequence)
        return KeyExchange(self, self._sequence, self._context,
                           self._generation if self._transaction else None, chosen)

    def _watch_runtime(self):
        if self._runtime_task is None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                return  # standalone synchronous lifetimes require explicit close
            self._runtime_task = loop.create_task(_runtime_lifetime(weakref.ref(self)),
                                                  name="tds key lifetime", eager_start=True)

    def __enter__(self):
        self._check_open()
        return self

    def __exit__(self, *exc):
        self.close()

    def transaction_begin(self, descriptor: int):
        self._check_open()
        if not descriptor:
            raise ValueError("a transaction descriptor must be nonzero")
        if descriptor != self._transaction:
            self.transaction_end()
            self._generation += 1
            self._transaction = descriptor

    def transaction_end(self):
        self._transaction = 0
        self._remove(lambda identity, entry: identity[0][0] == "transaction")

    def invalidate(self):
        """Context changed: old guards lose authority; new exchanges may proceed."""
        self._context += 1
        self._clear()

    def close(self):
        self._closed = True
        self._guards.clear()
        self._clear()
        task = self._runtime_task
        if task is not None and not task.done():
            task.cancel()

    def _clear(self):
        for table in (self._masters, self._columns):
            for entry in table.values():
                _dispose(entry.value)
            table.clear()
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _check_open(self):
        if self._closed:
            raise KeyNotDecrypted("the key session is closed")

    def _check(self, guard):
        self._check_open()
        if guard.id not in self._guards or guard.context != self._context:
            raise KeyNotDecrypted("the key exchange is closed or its connection context changed")

    def _remove(self, predicate):
        for table in (self._masters, self._columns):
            for identity, entry in list(table.items()):
                if predicate(identity, entry):
                    del table[identity]
                    _dispose(entry.value)
        self._schedule()

    def _purge(self):
        now = time.monotonic()
        def expired(identity, entry):
            if entry.deadline is not None and now >= entry.deadline:
                self._count("expirations")
                return True
            return False
        self._remove(expired)

    def _schedule(self):
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        deadlines = [e.deadline for t in (self._masters, self._columns) for e in t.values()
                     if e.deadline is not None]
        if deadlines and not self._closed:
            loop = asyncio.get_running_loop()
            self._watch_runtime()
            self._timer = loop.call_later(max(0, min(deadlines) - time.monotonic()), _expire, weakref.ref(self))

    def _scope(self, guard, policy):
        if policy.kind == "transaction" and guard.transaction is not None and self._transaction:
            if guard.transaction == self._generation:
                return ("transaction", guard.transaction)
        if policy.kind == "time":
            asyncio.get_running_loop()  # fail before acquiring anything without an idle-expiry runtime
            return ("time", policy.seconds)
        return ("exchange", guard.id)

    def _get(self, table, identity):
        entry = table.pop(identity, None)
        if entry is not None:
            table[identity] = entry  # LRU, without renewing the deadline
            self._count("hits")
            return entry.value
        return None

    def _put(self, table, identity, value, born, capacity):
        deadline = born + identity[0][1] if identity[0][0] == "time" else None
        if deadline is not None and time.monotonic() >= deadline:
            _dispose(value)
            raise KeyNotDecrypted("key acquisition exceeded its fixed maximum age")
        while len(table) >= capacity:
            oldest = next(iter(table))
            _dispose(table.pop(oldest).value)
            self._count("evictions")
        table[identity] = _Entry(value, deadline)
        self._schedule()
        return value

    def _binding_check(self):
        enc = self.encryption
        current = (enc.backend, tuple((name, store, getattr(store, "backend", None))
                                     for name, store in enc.key_stores.items()))
        old = self._bindings
        if old is None or (old[0] is not current[0] or len(old[1]) != len(current[1]) or any(
                a[0] != b[0] or a[1] is not b[1] or a[2] is not b[2] for a, b in zip(old[1], current[1]))):
            self._clear()
            self._bindings = current  # actual references prevent object-id reuse

    def cell_key(self, guard, key):
        self._check(guard)
        self._binding_check()
        self._purge()
        column_scope = self._scope(guard, guard.policies.column)
        master_scope = self._scope(guard, guard.policies.master)
        evidence = tuple((v.key_store.upper(), v.key_path, v.algorithm.upper(), v.encrypted) for v in key.values)
        identity = (column_scope, key.database_id, key.key_id, key.version, key.metadata_version, evidence)
        found = self._get(self._columns, identity)
        if found is not None:
            return found
        failures = []
        for value in key.values:
            store = self.encryption.key_stores.get(value.key_store.upper())
            if store is None:
                failures.append(f"{value.key_store} “{value.key_path}”: no key store of that name here")
                continue
            born = time.monotonic()
            try:
                if (isinstance(store, LocalKeyStore)
                        and getattr(store.decrypt_column_key, "__func__", None) is LocalKeyStore.decrypt_column_key):
                    master_id = (master_scope, value.key_store.upper(), value.key_path)
                    master = self._get(self._masters, master_id)
                    if master is None:
                        master_born = time.monotonic()
                        master = store._master_key(value.key_path)
                        self._check(guard)
                        self._count("master_loads")
                        self._put(self._masters, master_id, master, master_born, guard.policies.master_capacity)
                    root = store._decrypt_with_master(value.key_path, value.algorithm, value.encrypted, master)
                else:
                    root = store.decrypt_column_key(value.key_path, value.algorithm, value.encrypted)
                self._count("unwraps")
                found = CellKey(root, self.encryption.backend)
                del root
            except (KeyNotDecrypted, ValueError) as error:
                failures.append(str(error))
                continue
            try:
                self._check(guard)  # a reentrant provider may have revoked the lease
                return self._put(self._columns, identity, found, born, guard.policies.column_capacity)
            except BaseException:
                found.close()
                raise
        raise KeyNotDecrypted(f"column key {key.key_id} (version {key.version}) of database {key.database_id} "
                              f"can't be decrypted: {'; '.join(failures)}. The key stores here: "
                              f"{', '.join(self.encryption.key_stores) or 'none'}")

    def __del__(self):
        if hasattr(self, "_closed"):
            self.close()


class KeyExchange:
    """Non-shareable exchange authority. Close clears its exchange-local entries."""

    def __init__(self, bank, id_, context, transaction, policies):
        self.bank, self.id, self.context = bank, id_, context
        self.transaction, self.policies = transaction, policies

    def cell_key(self, key):
        return self.bank.cell_key(self, key)

    def close(self):
        self.bank._guards.discard(self.id)
        self.bank._remove(lambda identity, entry: identity[0] == ("exchange", self.id))

    def __enter__(self):
        self.bank._check(self)
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        self.close()
