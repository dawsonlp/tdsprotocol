"""Keep the unchanged Python/MC-SQLR examples as Rust comparison inputs.
Run from repo root with PYTHONPATH=clients/python:clients/python/tests.
"""
from pathlib import Path
from tds import browser
from test_browser import MACHINE_REPLY, INSTANCE_REPLY, DAC_REPLY
folder = Path(__file__).parent
for name, value in [('machine', MACHINE_REPLY), ('instance', INSTANCE_REPLY), ('dac', DAC_REPLY)]:
    (folder / f'{name}.bin').write_bytes(value)
# Every strict CP1252 byte's decoded Unicode scalar, or FFFFFFFF if undefined.
scalars = []
for value in range(256):
    try:
        scalar = ord(bytes([value]).decode('cp1252'))
    except UnicodeDecodeError:
        scalar = 0xffffffff
    scalars.append(scalar)
(folder / 'cp1252.bin').write_bytes(b''.join(s.to_bytes(4, 'little') for s in scalars))
