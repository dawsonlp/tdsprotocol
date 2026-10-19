#!/usr/bin/env python3
"""Focused follow-up acceptance on the existing lab; never provisions or deletes VMs."""
import argparse
import asyncio
import secrets
import ssl
import uuid

import campaign
import configure
import lab


async def sql_refresh():
    import tds

    configure.deadline()
    c = campaign.config('macos', 'sql')
    context = ssl.create_default_context(cafile=c['ca_file'])
    results = []

    async def query(connection, sql):
        async with connection.serial_channel() as channel:
            async with await channel.exchange(tds.Batch(sql)) as response:
                return await response.fetch()

    async with await tds.connect(c['host'], 1433, user=c['username'], password=c['password'],
                                 ssl_context=context, server_hostname=c['server_name'],
                                 tds_version='8.0') as admin:
        for version in ['7.4', '8.0']:
            for mars in [False, True]:
                name = 'tds_followup_' + uuid.uuid4().hex
                old, new = ['Tds!1' + secrets.token_urlsafe(24) for _ in range(2)]
                pool = bad = None
                # This protected record makes cleanup possible after interruption.
                lab.write_private(configure.SECRET/'followup-login.json', dict(login=name, active=True))
                await query(admin, f"CREATE LOGIN [{name}] WITH PASSWORD='{old}', CHECK_POLICY=OFF")
                try:
                    await query(admin, f"ALTER LOGIN [{name}] WITH PASSWORD='{new}'")

                    class Source:
                        calls = 0
                        refresh = True
                        async def read(self):
                            self.calls += 1
                            return tds.ConnectionConfig(c['host'], 1433, name,
                                new if self.refresh and self.calls > 1 else old,
                                database='master', tds_version=version, mars=mars)

                    services = tds.ConnectionServices(ssl_context=context, server_hostname=c['server_name'])
                    source = Source()
                    pool = tds.Pool.from_config(source, size=1, services=services)
                    async with pool.connection() as connection:
                        fetched = await query(connection, 'SELECT SUSER_SNAME(), ORIGINAL_LOGIN(), DB_NAME()')
                        row = fetched.result_sets[0].rows[0]
                        assert row == (name, name, 'master') and source.calls == 2
                    bad_source = Source()
                    bad_source.refresh = False
                    bad = tds.Pool.from_config(bad_source, size=1, services=services)
                    try:
                        async with bad.connection():
                            raise AssertionError('Stale credentials were accepted')
                    except tds.LoginRejected as refusal:
                        numbers = [e.number for e in refusal.errors]
                        assert 18456 in numbers and bad_source.calls == 2
                    results.append(dict(version=version, mars=mars, changed_source_reads=source.calls,
                        unchanged_source_reads=bad_source.calls, stale_login_errors=numbers,
                        principal_verified=True, passed=True))
                    lab.write_private(configure.ARTIFACTS/'followup-sql-refresh.json', results)
                    print(f'SQL refresh {version} MARS={mars}: passed', flush=True)
                finally:
                    if pool is not None:
                        await pool.close()
                    if bad is not None:
                        await bad.close()
                    await query(admin, f'DROP LOGIN [{name}]')
                    lab.write_private(configure.SECRET/'followup-login.json', dict(login=name, active=False))
        fetched = await query(admin, "SELECT COUNT(*) FROM sys.server_principals WHERE name LIKE 'tds_followup_%'")
        assert fetched.result_sets[0].rows[0] == (0,)
    return results


def sql_lifecycle():
    """Run existing live rotation/recovery tests through a private SSH tunnel."""
    import contextlib
    import io
    import socket
    import subprocess
    import sys
    import time
    import pytest

    configure.deadline()
    c = campaign.config('macos', 'sql')
    inventory = lab.read(configure.HERE/'gcp.json')['inventory']
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    tunnel = subprocess.Popen(['ssh', '-F', str(configure.SECRET/'ssh_config'), '-N',
        '-o', 'ExitOnForwardFailure=yes', '-L', f'127.0.0.1:{port}:{inventory["sql"]["internal_ip"]}:1433',
        'tds-linux'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    break
            except OSError:
                if tunnel.poll() is not None:
                    raise RuntimeError('SSH tunnel failed')
                time.sleep(0.1)
        else:
            raise TimeoutError('SSH tunnel readiness')
        sys.path.insert(0, str(campaign.ROOT/'clients/python/tests'))
        import conftest

        @pytest.fixture
        def server():
            return dict(host='127.0.0.1', port=port, user='sa',
                password=conftest.Secret(c['password']),
                ssl_context=ssl.create_default_context(cafile=c['ca_file']),
                server_hostname=c['server_name'])

        conftest.server = server
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = pytest.main([str(campaign.ROOT/'clients/python/tests/test_config_live.py'), '-q', '--tb=short'])
        result = campaign.redact(dict(exit=int(code), output=output.getvalue()), configure.credentials().values())
        lab.write_private(configure.ARTIFACTS/'followup-sql-lifecycle.json', result)
        print('GCP live SQL lifecycle suite exit:', int(code), flush=True)
        if code:
            raise RuntimeError('Live SQL lifecycle tests failed')
    finally:
        tunnel.terminate()
        try:
            tunnel.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tunnel.kill()
            tunnel.wait()


def rust_lifecycle():
    """Run Rust's existing live recovery/rotation suite against the Windows lab."""
    import os
    import socket
    import subprocess
    import time

    configure.deadline()
    c = campaign.config('macos', 'sql')
    inventory = lab.read(configure.HERE/'gcp.json')['inventory']
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    tunnel = subprocess.Popen(['ssh', '-F', str(configure.SECRET/'ssh_config'), '-N',
        '-o', 'ExitOnForwardFailure=yes', '-L', f'127.0.0.1:{port}:{inventory["sql"]["internal_ip"]}:1433',
        'tds-linux'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    break
            except OSError:
                if tunnel.poll() is not None:
                    raise RuntimeError('SSH tunnel failed')
                time.sleep(0.1)
        else:
            raise TimeoutError('SSH tunnel readiness')
        c['port'] = port
        path = configure.SECRET/'rust-live-config.json'
        lab.write_private(path, c)
        result = subprocess.run(['cargo', 'test', '--offline', '--all-features', '--test',
            'live_recovery', '--', '--ignored', '--test-threads=1'],
            cwd=campaign.ROOT/'clients/rust', env={**os.environ, 'TDS_LIVE_CONFIG': str(path)},
            capture_output=True, text=True, timeout=180)
        lab.write_private(configure.ARTIFACTS/'followup-rust-lifecycle.json', campaign.redact(
            dict(exit=result.returncode, stdout=result.stdout, stderr=result.stderr), configure.credentials().values()))
        print('GCP live Rust recovery/rotation suite exit:', result.returncode, flush=True)
        if result.returncode:
            raise RuntimeError('Live Rust recovery/rotation tests failed')
    finally:
        tunnel.terminate()
        try:
            tunnel.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tunnel.kill()
            tunnel.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenario', choices=['sql-refresh', 'sql-lifecycle', 'rust-lifecycle'])
    args = parser.parse_args()
    try:
        if args.scenario == 'sql-refresh':
            asyncio.run(sql_refresh())
        elif args.scenario == 'sql-lifecycle':
            sql_lifecycle()
        else:
            rust_lifecycle()
    except Exception as failure:
        # Do not echo SQL/provider diagnostics, which may contain credentials.
        lab.write_private(configure.ARTIFACTS/'followup-failure.json', dict(
            scenario=args.scenario, error_type=type(failure).__name__))
        raise SystemExit('Follow-up failed; protected scenario checkpoint records the phase/type') from None


if __name__ == '__main__':
    main()
