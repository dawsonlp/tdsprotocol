"""D-66 controller scenarios: observed acquisition counts and lifetime boundaries."""

import asyncio
from dataclasses import replace

import pytest

from tds import types
from tds.encryption import DecryptionFailed, Encryption, KeyNotDecrypted, LocalKeyStore, Policies, Policy
from tds.encryption.backend import CryptographyBackend


class CountingBackend(CryptographyBackend):
    def __init__(self):
        super().__init__()
        self.loads = self.unwraps = 0

    def rsa_key(self, pem):
        self.loads += 1
        return super().rsa_key(pem)

    def rsa_oaep_decrypt(self, key, data):
        self.unwraps += 1
        return super().rsa_oaep_decrypt(key, data)


@pytest.fixture
def setup(tmp_path):
    backend = CountingBackend()
    store = LocalKeyStore(tmp_path, backend)
    store.create_master_key("master.pem")
    wrapped = store.encrypt_column_key("master.pem", b"A" * 32)
    key = types.ColumnKey(7, 1, 1, b"12345678", (
        types.MasterKeyValue(wrapped, store.name, "master.pem", "RSA_OAEP"),))
    backend.loads = backend.unwraps = 0
    return Encryption([store]), key, backend


def use(bank, key, policies=None):
    with bank.exchange(policies) as exchange:
        cell = exchange.cell_key(key)
        encrypted = cell.encrypt(b"value", True)
        assert exchange.cell_key(key).decrypt(encrypted) == b"value"
        return cell


@pytest.mark.parametrize("master,column,transaction,loads,unwraps", [
    (Policy.transaction(), Policy.transaction(), True, 1, 1),
    (Policy.exchange(), Policy.exchange(), True, 20, 20),
    (Policy.transaction(), Policy.exchange(), True, 1, 20),
    (Policy.exchange(), Policy.transaction(), True, 1, 1),
    (Policy.transaction(), Policy.transaction(), False, 20, 20),
])
def test_twenty_exchanges_count_real_local_operations(setup, master, column, transaction, loads, unwraps):
    encryption, key, backend = setup
    bank = encryption.key_session(Policies(master, column))
    if transaction:
        bank.transaction_begin(123)
    for _ in range(20):
        use(bank, key)
    assert (backend.loads, backend.unwraps) == (loads, unwraps)
    assert (bank.statistics.master_loads, bank.statistics.unwraps) == (loads, unwraps)
    bank.transaction_end()
    assert bank.statistics.live_columns == bank.statistics.live_masters == 0
    bank.close()


def test_transaction_generations_and_old_reader_fallback(setup):
    encryption, key, backend = setup
    bank = encryption.key_session()
    bank.transaction_begin(123)
    old = bank.exchange()
    cell = old.cell_key(key)
    bank.transaction_begin(123)  # duplicate/unchanged announcement does not rotate
    assert use(bank, key) is cell
    bank.transaction_end()
    assert not any(cell.root)
    bank.transaction_begin(123)  # reused descriptor, different generation
    fresh = use(bank, key)
    fallback = old.cell_key(key)
    assert fallback is not fresh
    assert (backend.loads, backend.unwraps) == (3, 3)
    old.close()
    assert not any(fallback.root) and any(fresh.root)
    bank.transaction_end()
    assert not any(fresh.root)
    bank.close()


def test_strict_override_cannot_borrow_transaction_entries(setup):
    encryption, key, backend = setup
    bank = encryption.key_session()
    bank.transaction_begin(9)
    broad = use(bank, key)
    strict = use(bank, key, Policies(Policy.exchange(), Policy.exchange()))
    assert strict is not broad and not any(strict.root) and any(broad.root)
    assert use(bank, key) is broad
    assert (backend.loads, backend.unwraps) == (2, 2)
    bank.close()


def test_fixed_age_is_non_sliding_and_independent(setup, monkeypatch):
    import tds.encryption.policy as module
    now = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    async def go():
        encryption, key, backend = setup
        bank = encryption.key_session(Policies(Policy.time(20), Policy.time(10)))
        bank.transaction_begin(1)
        first = use(bank, key)
        now[0] = 109
        bank.transaction_end()
        assert use(bank, key) is first  # across autocommit without renewing
        now[0] = 110
        second = use(bank, key)
        assert second is not first and not any(first.root)
        assert (backend.loads, backend.unwraps) == (1, 2)
        # The master expires at 120 even though the new column lives until 120.
        now[0] = 120
        bank.transaction_begin(2)
        third = use(bank, key)
        assert third is not second
        assert (backend.loads, backend.unwraps) == (2, 3)
        bank.close()
    asyncio.run(go())


def test_idle_timer_zeroes_without_another_lookup(setup):
    async def go():
        encryption, key, backend = setup
        bank = encryption.key_session(Policies(Policy.time(.15), Policy.time(.15)))
        first = use(bank, key)
        assert bank.statistics.live_columns == bank.statistics.live_masters == 1
        await asyncio.sleep(.3)
        # statistics is a pure snapshot, not the mechanism of expiration
        assert not any(first.root)
        assert bank.statistics.live_columns == bank.statistics.live_masters == 0
        assert bank.statistics.expirations == 2
        bank.close()
    asyncio.run(go())


def test_long_transaction_and_open_reader_reload_after_expiry(setup):
    async def go():
        encryption, key, backend = setup
        bank = encryption.key_session(Policies(Policy.time(.15), Policy.time(.15)))
        bank.transaction_begin(7)
        with bank.exchange() as exchange:
            first = exchange.cell_key(key)
            ciphertext = first.encrypt(b"long transaction", True)
            await asyncio.sleep(.3)
            assert not any(first.root)
            second = exchange.cell_key(key)
            assert second.decrypt(ciphertext) == b"long transaction"
            assert (backend.loads, backend.unwraps) == (2, 2)
        bank.close()
    asyncio.run(go())


def test_eviction_zeroes_and_reloads(setup):
    encryption, key, backend = setup
    bank = encryption.key_session(Policies(column_capacity=1))
    bank.transaction_begin(1)
    first = use(bank, key)
    second = use(bank, replace(key, key_id=2))
    assert not any(first.root) and any(second.root)
    use(bank, key)
    assert (backend.loads, backend.unwraps, bank.statistics.evictions) == (1, 3, 2)
    bank.close()


def test_different_connections_and_borrowers_never_share_keys(setup):
    encryption, key, backend = setup
    first, second = encryption.key_session(), encryption.key_session()
    first.transaction_begin(1)
    second.transaction_begin(1)
    one, two = use(first, key), use(second, key)
    assert one is not two and (backend.loads, backend.unwraps) == (2, 2)
    first.close()
    assert not any(one.root) and any(two.root)
    second.close()


def test_context_change_and_close_revoke_old_guards(setup):
    encryption, key, backend = setup
    bank = encryption.key_session()
    guard = bank.exchange()
    first = guard.cell_key(key)
    bank.invalidate()
    assert not any(first.root)
    with pytest.raises(KeyNotDecrypted, match="context changed"):
        guard.cell_key(key)
    guard.close()
    new = bank.exchange()
    new.cell_key(key)
    bank.close()
    with pytest.raises(KeyNotDecrypted, match="closed"):
        new.cell_key(key)
    new.close()


def test_buffer_zeroization_and_released_object_refusal(setup):
    encryption, key, backend = setup
    bank = encryption.key_session()
    guard = bank.exchange()
    cell = guard.cell_key(key)
    buffers = [cell.root, cell._encryption, cell._mac, cell._iv]
    assert all(any(buffer) for buffer in buffers)
    guard.close()
    assert all(not any(buffer) for buffer in buffers)
    with pytest.raises(DecryptionFailed, match="released"):
        cell.encrypt(b"no", True)
    with pytest.raises(DecryptionFailed, match="released"):
        cell.decrypt(b"")
    bank.close()


def test_direct_calls_are_uncached_and_caller_owned(setup):
    encryption, key, backend = setup
    first, second = encryption.cell_key(key), encryption.cell_key(key)
    assert first is not second and (backend.loads, backend.unwraps) == (2, 2)
    first.close()
    second.close()


@pytest.mark.parametrize("construct", [
    lambda: Policy.time(0), lambda: Policy.time(-1), lambda: Policy.time(float("nan")),
    lambda: Policy.time(float("inf")), lambda: Policy.time(True), lambda: Policy("other"),
    lambda: Policy("transaction", 1), lambda: Policies(master_capacity=0),
    lambda: Policies(column_capacity=4097), lambda: Policies(master_capacity=True),
    lambda: Policies(master="transaction"),
])
def test_invalid_policy_refused(construct):
    with pytest.raises((ValueError, TypeError)):
        construct()


def test_time_requires_idle_expiry_runtime_before_loading(setup):
    encryption, key, backend = setup
    bank = encryption.key_session(Policies(column=Policy.time(1)))
    with bank.exchange() as exchange:
        with pytest.raises(RuntimeError, match="no running event loop"):
            exchange.cell_key(key)
    assert backend.loads == backend.unwraps == 0
    bank.close()


def test_provider_failure_is_not_cached_and_other_candidates_work(setup):
    encryption, key, backend = setup
    bad = replace(key.values[0], encrypted=b"bad")
    bank = encryption.key_session()
    bank.transaction_begin(1)
    with bank.exchange() as guard:
        with pytest.raises(KeyNotDecrypted):
            guard.cell_key(replace(key, values=(bad,)))
        assert bank.statistics.live_columns == 0
        found = guard.cell_key(replace(key, values=(bad, *key.values)))
        assert found.decrypt(found.encrypt(b"fallback", True)) == b"fallback"
    assert backend.loads == 1 and backend.unwraps == 1
    bank.close()


def test_reentrant_provider_revocation_cannot_insert():
    class Store:
        name = "TEST"
        def decrypt_column_key(self, *args):
            bank.close()
            return b"A" * 32
    encryption = Encryption([Store()])
    key = types.ColumnKey(1, 1, 1, bytes(8), (types.MasterKeyValue(b"wrapped", "TEST", "p", "a"),))
    bank = encryption.key_session()
    with bank.exchange() as guard:
        with pytest.raises(KeyNotDecrypted, match="closed"):
            guard.cell_key(key)
    assert bank.statistics.closed and bank.statistics.live_columns == 0


def test_master_backend_replacement_invalidates_both_caches(setup):
    encryption, key, backend = setup
    bank = encryption.key_session()
    bank.transaction_begin(1)
    first = use(bank, key)
    store = next(iter(encryption.key_stores.values()))
    replacement = CountingBackend()
    store.backend = replacement
    second = use(bank, key)
    assert first is not second and not any(first.root)
    assert (replacement.loads, replacement.unwraps) == (1, 1)
    bank.close()


def test_expired_acquisition_is_discarded_without_retry(setup, monkeypatch):
    import tds.encryption.policy as module
    now = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    encryption, key, backend = setup
    original = backend.rsa_key
    def slow(pem):
        master = original(pem)
        now[0] += 10
        return master
    monkeypatch.setattr(backend, "rsa_key", slow)
    async def go():
        bank = encryption.key_session(Policies(Policy.time(1), Policy.time(1)))
        with bank.exchange() as guard:
            with pytest.raises(KeyNotDecrypted, match="exceeded its fixed maximum age"):
                guard.cell_key(key)
        assert backend.loads == 1 and backend.unwraps == 0
        assert bank.statistics.live_columns == bank.statistics.live_masters == 0
        bank.close()
    asyncio.run(go())


def test_master_expiry_does_not_shorten_an_independent_column_age(setup, monkeypatch):
    import tds.encryption.policy as module
    now = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    async def go():
        encryption, key, backend = setup
        bank = encryption.key_session(Policies(Policy.time(5), Policy.time(20)))
        first = use(bank, key)
        now[0] = 106
        assert use(bank, key) is first
        assert bank.statistics.live_masters == 0 and bank.statistics.live_columns == 1
        use(bank, replace(key, key_id=2))  # new column needs another master load
        assert (backend.loads, backend.unwraps) == (2, 2)
        now[0] = 120
        assert use(bank, key) is not first and not any(first.root)
        bank.close()
    asyncio.run(go())


@pytest.mark.parametrize("policies", [Policies(), Policies(Policy.time(60), Policy.time(60))])
def test_runtime_shutdown_revokes_an_escaped_bank(setup, policies):
    encryption, key, backend = setup
    async def go():
        bank = encryption.key_session(policies)
        bank.transaction_begin(1)
        return bank, use(bank, key)
    bank, cell = asyncio.run(go())
    assert bank.statistics.closed and not any(cell.root)
    assert bank.statistics.live_columns == bank.statistics.live_masters == 0


def test_simultaneous_exchange_policies_are_isolated(setup):
    encryption, key, backend = setup
    bank = encryption.key_session(Policies(Policy.exchange(), Policy.exchange()))
    one, two = bank.exchange(), bank.exchange()
    first, second = one.cell_key(key), two.cell_key(key)
    assert first is not second
    one.close()
    assert not any(first.root) and any(second.root)
    assert two.cell_key(key) is second
    two.close()
    bank.close()


def test_policy_change_requires_idle_and_clears_prior_authority(setup):
    encryption, key, backend = setup
    bank = encryption.key_session()
    bank.transaction_begin(1)
    guard = bank.exchange()
    cell = guard.cell_key(key)
    with pytest.raises(ValueError, match="between exchanges"):
        bank.set_policies(Policies(Policy.exchange(), Policy.exchange()))
    guard.close()
    bank.set_policies(Policies(Policy.exchange(), Policy.exchange()))
    assert not any(cell.root) and bank.statistics.live_columns == 0
    assert bank.policies.column == Policy.exchange()
    use(bank, key)
    assert bank.statistics.live_columns == bank.statistics.live_masters == 0
    bank.close()


def test_local_provider_override_is_not_bypassed(setup):
    encryption, key, backend = setup
    original = next(iter(encryption.key_stores.values()))
    class RefusingStore(LocalKeyStore):
        def decrypt_column_key(self, *args):
            raise KeyNotDecrypted("application refused this key")
    encryption.key_stores[original.name] = RefusingStore(original.directory, backend)
    with encryption.key_session() as bank, bank.exchange() as guard:
        with pytest.raises(KeyNotDecrypted, match="application refused"):
            guard.cell_key(key)
    assert backend.loads == backend.unwraps == 0


def test_completion_callback_waits_for_message_boundary_and_runs_once():
    from tds.response import ResponseReader
    calls = []
    reader = ResponseReader(False, lambda change: None, on_complete=lambda: calls.append("done"))
    reader.feed(b"\xfd" + bytes(12), False)
    assert not reader.ended and calls == []
    reader.feed(b"", True)
    assert reader.ended and calls == ["done"]
    reader.resume()
    assert calls == ["done"]


def test_false_policy_is_refused_rather_than_silently_using_defaults(setup):
    encryption, key, backend = setup
    with pytest.raises(TypeError, match="Policies"):
        Encryption([], policies=False)
    with pytest.raises(TypeError, match="Policies"):
        encryption.key_session(False)
    with encryption.key_session() as bank:
        with pytest.raises(TypeError, match="Policies"):
            bank.exchange(False)
        assert not bank._guards


def test_instance_provider_override_is_not_bypassed(setup):
    encryption, key, backend = setup
    store = next(iter(encryption.key_stores.values()))
    def refuse(*args):
        raise KeyNotDecrypted("instance refused this key")
    store.decrypt_column_key = refuse
    with encryption.key_session() as bank, bank.exchange() as guard:
        with pytest.raises(KeyNotDecrypted, match="instance refused"):
            guard.cell_key(key)
    assert backend.loads == backend.unwraps == 0


def test_custom_backend_keeps_its_existing_bytes_contract():
    from tds.encryption.cell import CellKey
    native = CryptographyBackend()
    class BytesBackend:
        def aes_cbc_encrypt(self, key, iv, data):
            assert type(key) is bytes
            return native.aes_cbc_encrypt(key, iv, data)
        def aes_cbc_decrypt(self, key, iv, data):
            assert type(key) is bytes
            return native.aes_cbc_decrypt(key, iv, data)
    cell = CellKey(b"A" * 32, BytesBackend())
    assert cell.decrypt(cell.encrypt(b"custom backend", True)) == b"custom backend"
    cell.close()
    assert not any(cell._encryption)
