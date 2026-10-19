#!/usr/bin/env python3
"""Refresh a source snapshot and build the Rust login probe on an existing VM."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tarfile

import configure
import lab

ROOT=Path(__file__).resolve().parents[2]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role',choices=['linux','windows'])
    parser.add_argument('--source-only',action='store_true',help='Refresh sources without rebuilding Rust')
    args=parser.parse_args();configure.deadline()
    paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','clients/rust','clients/python'],cwd=ROOT,text=True).splitlines()
    archive=configure.ARTIFACTS/f'{args.role}-client-source.tar.gz'
    hashes={}
    with tarfile.open(archive,'w:gz') as out:
        for name in sorted(paths):
            path=ROOT/name
            if path.is_file():
                hashes[name]=hashlib.sha256(path.read_bytes()).hexdigest()
                out.add(path,arcname=name,recursive=False)
    lab.write_private(configure.ARTIFACTS/f'{args.role}-source.json',dict(commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),files=hashes,archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()))
    if args.role=='linux':
        configure.copy('linux',archive,'/home/tds/client-source.tar.gz')
        command='mkdir -p /home/tds/tdsprotocol && tar xzf /home/tds/client-source.tar.gz -C /home/tds/tdsprotocol'
        if not args.source_only:command+=' && . $HOME/.cargo/env && cd /home/tds/tdsprotocol/clients/rust && cargo build --all-features --example login_probe --locked'
    else:
        configure.copy('windows',archive,'C:/tds/client-source.tar.gz')
        configure.copy('windows',configure.HERE/'scripts/windows-build.cmd','C:/tds/windows-build.cmd')
        action='tar -xf C:/tds/client-source.tar.gz -C C:/tds/source'
        if not args.source_only:action+='; cmd.exe /c C:/tds/windows-build.cmd'
        command='powershell.exe -NoProfile -NonInteractive -Command "'+action+'"'
    result=configure.ssh(args.role,command,check=False)
    # Guest diagnostics are protected by configure.ssh. Avoid echoing arbitrary
    # build-script output, which is outside the campaign evidence contract.
    print(f'{args.role}: source refresh'+('' if args.source_only else '/build')+f' exit {result.returncode}',flush=True)
    if result.returncode:raise SystemExit('Build failed; inspect protected diagnostics')


if __name__=='__main__':main()
