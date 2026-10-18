"""Synthetic Always Encrypted cache-identity probe; no server or real secrets.

Run from the repository root:
    clients/python/.venv/bin/python tools/probe_encryption_cache_identity.py

The synthetic provider returns artificial key bytes directly. This isolates
cache lookup; it does not test RSA wrapping, authentication or a live deployment.
"""

import contextlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "clients/python"))

from tds.encryption.context import Encryption
from tds.types import ColumnKey, MasterKeyValue


class SyntheticStore:
    name = "SYNTHETIC"

    def __init__(self):
        self.calls = 0

    def decrypt_column_key(self, path, algorithm, encrypted):
        self.calls += 1
        return encrypted


def key(byte):
    return ColumnKey(7, 1, 1, b"12345678", (
        MasterKeyValue(byte * 32, SyntheticStore.name, "test.pem", "RSA_OAEP"),
    ))


def main():
    store = SyntheticStore()
    context = Encryption([store])
    with context.key_session() as bank, bank.exchange() as exchange:
        first = exchange.cell_key(key(b"A"))
        second = exchange.cell_key(key(b"B"))
        with contextlib.closing(Encryption([SyntheticStore()]).cell_key(key(b"B"))) as independent:
            result = {
                "different_key_table_returned_same_cached_object": first is second,
                "repeat_first_table_reused_cached_object": exchange.cell_key(key(b"A")) is first,
                "provider_lookups_for_two_tables": store.calls,
                "second_result_matches_independent_second_key": (
                    second.encrypt(b"probe", True) == independent.encrypt(b"probe", True)
                ),
            }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
