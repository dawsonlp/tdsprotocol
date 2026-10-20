#!/usr/bin/env python3
"""Repeat the Rust acceptance matrix. --live opts into disposable Docker SQL tests.

No cloud deployment is performed. Run Python's mutating SQL suite separately.
Logs and the JSON summary go to --output (outside Git by default).
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    output = args.output or Path(tempfile.mkdtemp(prefix='tds-rust-check-'))
    output.mkdir(parents=True, exist_ok=True)
    cargo = ['cargo']
    manifest = ['--manifest-path', str(ROOT / 'clients/rust/Cargo.toml')]
    matrix = [
        ('fmt', cargo + ['fmt', *manifest, '--check']),
        ('default', cargo + ['test', *manifest, '--locked', '--offline']),
        ('core', cargo + ['test', *manifest, '--locked', '--offline', '--no-default-features']),
        ('encryption', cargo + ['test', *manifest, '--locked', '--offline', '--all-features']),
        *[(f'clippy-{name}', cargo + ['clippy', *manifest, '--locked', '--offline', *features,
                                     '--all-targets', '--', '-D', 'warnings'])
          for name, features in [('default', []), ('core', ['--no-default-features']),
                                 ('encryption', ['--all-features'])]],
        ('rustdoc', cargo + ['doc', *manifest, '--locked', '--offline', '--all-features', '--no-deps']),
    ]
    if args.live:
        # Native certificate-store acceptance needs Windows and its own fixture; it refuses other hosts.
        native = [] if sys.platform == 'win32' else [
            '--skip', 'native_non_exportable_certificate_mutually_wraps_and_signs_with_python']
        matrix.append(('live', cargo + ['test', *manifest, '--locked', '--offline', '--all-features',
                                       '--', '--ignored', '--test-threads=1', '--nocapture', *native]))
    result = {'started': dt.datetime.now(dt.timezone.utc).isoformat(), 'checks': []}
    for name, command in matrix:
        log = output / f'{name}.log'
        print(f'{name}: {log}', flush=True)
        started = dt.datetime.now(dt.timezone.utc)
        with log.open('w') as stream:
            ran = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                                 env={**os.environ, 'RUSTDOCFLAGS': '-D warnings'})
        text = log.read_text()
        counts = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
        check = {'name': name, 'command': command, 'returncode': ran.returncode,
                 'seconds': (dt.datetime.now(dt.timezone.utc) - started).total_seconds()}
        if counts:
            check['passed'], check['failed'], check['ignored'] = map(sum, zip(*[map(int, c) for c in counts]))
        result['checks'].append(check)
        (output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
        if ran.returncode:
            print(text[-6000:])
            raise SystemExit(ran.returncode)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
