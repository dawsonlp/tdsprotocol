"""Artificial recovery fixtures from Python's actual definitions; no live state.
Run from repo root with PYTHONPATH=clients/python:clients/python/tests.
"""
from pathlib import Path
from tds import login7
from tds.session import RECOVERY, INITIAL_STATES, Recovery, SessionState
from tds.wire import Record
from mstds_samples import SESSION_RECOVERY_DATA

folder = Path(__file__).parent
states = {0: bytes.fromhex('00 60 81 14 FF E7 FF FF 00'), 2: b'\x07\x01', 4: b'\x00',
          5: b'\xff' * 4, 6: b'\x00', 7: b'\x02', 8: bytes(8), 9: b'\xff' * 4}
initial = SessionState(database='master', language='us_english', collation=bytes.fromhex('09 04 D0 00 34'))
(folder / 'initial.bin').write_bytes(INITIAL_STATES.encode({'states': [{'id': i, 'value': v} for i, v in states.items()]}, False)[0])
recovery = Recovery(initial, states)
recovery.follow(Record(sequence=1, status=1, states=[Record(id=9, value=bytes.fromhex('28 23 00 00'))]), 'SET TEXTSIZE 9000')
encoded = RECOVERY.encode(recovery.data(initial), False)[0]
assert encoded == SESSION_RECOVERY_DATA
(folder / 'recovery.bin').write_bytes(encoded)
values = dict(tds_version=login7.TDS_7_4, packet_size=4096, client_library_version=0x10000,
    client_process_id=1234, connection_id=0, option_flags_1=login7.OptionFlags1(0xe0),
    option_flags_2=login7.OptionFlags2(3), type_flags=login7.TypeFlags(0),
    option_flags_3=login7.OptionFlags3(0), time_zone=0, locale=0x409,
    variable_part=dict(host_name='fixture-host', user_name='fixture-user', password='not-a-real-password',
        app_name='tds (rust)', server_name='fixture-server', extension=b'', library_name='tds (rust)',
        language='', database='fixture-database', client_id=bytes(6), windows_auth=b'', attach_file='',
        new_password='', large_windows_auth_length=0))
for name, data in [('login', b''), ('recover-login', encoded)]:
    (folder / f'{name}.bin').write_bytes(login7.login(values, {login7.Feature.SESSION_RECOVERY: data}, False)[0])
