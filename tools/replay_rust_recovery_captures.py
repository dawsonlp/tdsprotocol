"""Check this experiment's Rust recordings with Python's unchanged replay reader.

Generate with TDS_RECOVERY_CAPTURE_DIR=<directory> cargo test --test live_recovery
-- --ignored --test-threads=1, then pass that directory to this script. It checks
all 16 physical epochs, logical MARS row attribution and LOGIN7 redaction. Only
summary results are printed; credentials and packet/query bodies stay private.
"""
import base64
import io
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'clients/python'))
from tds.capture import replay


def check(directory):
    paths = sorted(Path(directory).glob('*.jsonl'))
    assert len(paths) == 16, f'expected 16 physical recordings, found {len(paths)}'
    for path in paths:
        events = []
        replay(io.StringIO(path.read_text()), events.append)
        rows = {}
        for event in events:
            if event.node is not None:
                assert "can't be decoded" not in event.node.shown, path.name
            if event.kind != 'receive' or event.node is None:
                continue
            match = re.search(r'channel (\d+)', event.text)
            channel = int(match[1]) if match else None
            for node in event.node.children:
                if node.name == 'ROW' and len(node.raw) == 5:
                    rows.setdefault(channel, []).append(int.from_bytes(node.raw[1:], 'little', signed=True))
        if '-mars-true-' in path.name and '-epoch-0' not in path.name:
            assert 23 in rows[1] and 24 not in rows[1], path.name
            assert 24 in rows[2] and 23 not in rows[2], path.name
        if '-epoch-0' in path.name:
            assert 11 in rows[1 if '-mars-true-' in path.name else None], path.name
        packets = [base64.b64decode(line['bytes']) for line in map(json.loads, path.read_text().splitlines())
                   if line.get('packet') == 'send' and base64.b64decode(line['bytes'])[0] == 0x10]
        body = b''.join(packet[8:] for packet in packets)
        assert body, path.name
        for field in [44, 86]:  # password and new password: UTF-16 counts
            offset = int.from_bytes(body[field:field + 2], 'little')
            size = 2 * int.from_bytes(body[field + 2:field + 4], 'little')
            assert body[offset:offset + size] == bytes(size), path.name
    print(f'{len(paths)} physical recordings: replay, logical row attribution and LOGIN7 redaction passed')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: replay_rust_recovery_captures.py <directory>')
    check(sys.argv[1])
