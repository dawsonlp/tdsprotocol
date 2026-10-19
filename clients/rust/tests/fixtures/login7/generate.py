"""Generate deterministic shared LOGIN7 bodies using Python's actual definition.

From the repo root:
    PYTHONPATH=clients/python clients/python/.venv/bin/python clients/rust/tests/fixtures/login7/generate.py

Every credential/name is artificial. These are protocol fixtures, never logins.
"""
from pathlib import Path
from tds import login7

CASES = (
    ("default", True, "", False, "tds (rust)", "fixture-host"),
    ("custom", False, "Deutsch", True, "service-λ", "machine-1"),
)

for name, odbc, language, intent, app, host in CASES:
    body, _ = login7.login(dict(
        tds_version=login7.TDS_7_4, packet_size=4096, client_library_version=0x00010000,
        client_process_id=1234, connection_id=0, option_flags_1=login7.OptionFlags1(0xe0),
        option_flags_2=login7.OptionFlags2(1 | (2 if odbc else 0)),
        type_flags=login7.TypeFlags(0x20 if intent else 0), option_flags_3=login7.OptionFlags3(0),
        time_zone=0, locale=0x409,
        variable_part=dict(host_name=host, user_name="fixture-user", password="not-a-real-password",
            app_name=app, server_name="fixture-server", extension=b"", library_name="tds (rust)",
            language=language, database="fixture-database", client_id=bytes(6), windows_auth=b"",
            attach_file="", new_password="", large_windows_auth_length=0)), {}, False)
    path = Path(__file__).parent / f"{name}.bin"
    path.write_bytes(body)
    print(f"{path.name}: {len(body)} bytes")

body, _ = login7.login(dict(
    tds_version=login7.TDS_7_4, packet_size=4096, client_library_version=0x10000,
    client_process_id=1234, connection_id=0, option_flags_1=login7.OptionFlags1(0xe0),
    option_flags_2=login7.OptionFlags2(3), type_flags=login7.TypeFlags(0),
    option_flags_3=login7.OptionFlags3.CHANGE_PASSWORD, time_zone=0, locale=0x409,
    variable_part=dict(host_name='fixture-host', user_name='fixture-user', password='not-a-real-password',
        app_name='tds (rust)', server_name='fixture-server', extension=b'', library_name='tds (rust)',
        language='', database='fixture-database', client_id=bytes(6), windows_auth=b'', attach_file='',
        new_password='also-artificial-λ', large_windows_auth_length=0)),
    {login7.Feature.SESSION_RECOVERY: b''}, False)
(Path(__file__).parent / 'password-change.bin').write_bytes(body)
