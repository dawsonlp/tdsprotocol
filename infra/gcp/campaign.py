#!/usr/bin/env python3
"""Repeatable login probes; protected raw results and asserted session evidence.

This command never provisions, tears down or accepts the campaign as complete.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import subprocess
import uuid

import configure
import lab

ROOT=Path(__file__).resolve().parents[2]


def redact(value,secrets):
    if isinstance(value,dict):return {key:redact(item,secrets) for key,item in value.items()}
    if isinstance(value,list):return [redact(item,secrets) for item in value]
    if isinstance(value,str):
        for secret in secrets:value=value.replace(secret,'[redacted]')
    return value


def config(location,method,identity='domain',version='7.4',mars=False,provider=None):
    secrets=configure.credentials()
    inventory=lab.read(configure.HERE/'gcp.json')['inventory']
    sql=inventory['sql']
    result=dict(host=sql['external_ip'] if location=='macos' else 'tdssql.tds.test',
                port=1433,server_name='tdssql.tds.test',
                ca_file=str(configure.SECRET/'ca.pem') if location=='macos' else '/home/tds/ca.pem',
                method=method,provider=provider or ('native' if location=='windows' else 'portable'),tds_version=version,mars=mars,
                username='sa' if method=='sql' else ('TDSSQL\\Administrator' if identity=='local' else 'tdsuser@TDS.TEST' if method!='ntlm' else 'TDS\\tdsuser'),
                password=secrets['sql_password' if method=='sql' else 'admin_password' if identity=='local' else 'user_password'],
                spn='MSSQLSvc/tdssql.tds.test:1433',kdc_url='tcp://10.43.1.4:88')
    if location=='windows' and result['provider']=='native' and method!='sql':
        # The controller supplies the OS task logon password separately. The
        # native Rust process receives no application username or password.
        del result['username'];del result['password']
    return result


def probe(location,client,configuration,expected_scheme=None):
    payload=json.dumps(configuration)
    if location=='macos':
        args=([str(ROOT/'clients/rust/target/debug/examples/login_probe')] if client=='rust' else
              [str(ROOT/'clients/python/.venv/bin/python'),str(configure.HERE/'scripts/python-probe.py')])
        result=subprocess.run(args,input=payload,text=True,capture_output=True,timeout=60)
    elif location=='linux':
        command=('/home/tds/tdsprotocol/clients/rust/target/debug/examples/login_probe' if client=='rust' else
                 '/home/tds/tdsprotocol/clients/python/.venv/bin/python /home/tds/python-probe.py')
        result=configure.ssh('linux',command,payload,check=False)
    elif location=='windows':
        payload=json.dumps(dict(client=client,config=configuration,user_password=configure.credentials()['user_password']))
        result=configure.ssh('windows','powershell.exe -NoProfile -NonInteractive -File C:/tds/windows-probe.ps1',payload,check=False)
        if result.returncode==0:
            raw=json.loads(result.stdout.strip().lstrip('\ufeff'))
        else:raw=dict(exit=result.returncode,stdout=result.stdout,stderr=result.stderr)
    else:raise ValueError('Unknown location')
    if location!='windows':raw=dict(exit=result.returncode,stdout=result.stdout,stderr=result.stderr)
    raw=redact(raw,configure.credentials().values())
    lab.write_private(configure.ARTIFACTS/f'probe-{location}-{client}-{uuid.uuid4().hex}.json',dict(location=location,client=client,method=configuration['method'],version=configuration.get('tds_version'),mars=configuration.get('mars'),raw=raw))
    evidence=None
    if raw['exit']==0:
        evidence=json.loads(raw['stdout'].strip().lstrip('\ufeff').splitlines()[-1])
        expected='sa' if configuration['method']=='sql' else ('TDSSQL\\Administrator' if configuration.get('username','').upper().startswith('TDSSQL\\') else 'TDS\\tdsuser')
        scheme='SQL' if configuration['method']=='sql' else 'NTLM' if configuration['method']=='ntlm' else 'KERBEROS'
        if location=='windows' and client=='sqlclient':scheme='KERBEROS'
        if expected_scheme is not None:scheme=expected_scheme
        assert evidence['principal'].lower()==expected.lower(),evidence
        assert evidence['original_login'].lower()==expected.lower(),evidence
        assert evidence['auth_scheme']==scheme,evidence
        assert evidence['encrypted'].upper()=='TRUE',evidence
        assert evidence['transport'] in ['TCP','Session'],evidence
        assert evidence['database']=='master',evidence
        if client=='rust':assert evidence['closed'] is True,evidence
        if client=='rust' and location=='windows':assert evidence['native_workers_after_close']==0,evidence
        if client=='python' and configuration['method']!='sql':
            assert evidence['provider_complete'] is True,evidence
            assert evidence['windows_login_payloads_redacted'] is True,evidence
    return raw,evidence


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('location',choices=['macos','linux','windows'])
    parser.add_argument('--client',choices=['python','rust','sqlclient'],default='rust')
    parser.add_argument('--full',action='store_true',help='Both TDS versions and MARS modes')
    parser.add_argument('--portable',action='store_true',help='Explicit Windows credentials: Rust portable adapter; pyspnego selects its implementation')
    args=parser.parse_args();configure.deadline()
    if args.location=='linux':configure.copy('linux',configure.HERE/'scripts/python-probe.py','/home/tds/python-probe.py')
    if args.location=='windows':
        if args.client=='python':configure.copy('windows',configure.HERE/'scripts/python-probe.py','C:/tds/python-probe.py')
        configure.copy('windows',configure.HERE/'scripts/windows-probe.ps1','C:/tds/windows-probe.ps1')
        configure.copy('windows',configure.HERE/'scripts/windows-task-rights.ps1','C:/tds/windows-task-rights.ps1')
        configure.ssh('windows','powershell.exe -NoProfile -NonInteractive -File C:/tds/windows-task-rights.ps1')
    output=[]
    methods=[('sql','domain'),('ntlm','local'),('ntlm','domain')]
    if args.location=='linux':methods.extend([('kerberos','domain'),('negotiate','domain')])
    if args.location=='windows':
        if args.client=='sqlclient':methods=[('negotiate','domain')]
        elif args.portable:methods.extend([('kerberos','domain'),('negotiate','domain')])
        else:methods=[(method,'domain') for method in ['ntlm','kerberos','negotiate']]
    for method,identity in methods:
        for version in (['7.4','8.0'] if args.full else ['7.4']):
            for mars in ([False,True] if args.full else [False]):
                configuration=config(args.location,method,identity,version,mars,'portable' if args.portable else None)
                raw,evidence=probe(args.location,args.client,configuration)
                provider='sql' if method=='sql' else configuration['provider']
                if evidence and args.client=='python' and method!='sql':
                    provider=evidence['authentication_provider']
                item=dict(location=args.location,client=args.client,method=method,identity=identity,
                          provider=provider,
                          credential_source='signed-in' if method!='sql' and configuration['provider']=='native' else 'explicit',
                          version=version,mars=mars,evidence=evidence,raw=raw)
                output.append(item)
                print(json.dumps({key:value for key,value in item.items() if key!='raw'}),flush=True)
                stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
                lab.write_private(configure.ARTIFACTS/f'campaign-{args.location}-{args.client}-{stamp}.json',output)
                if raw['exit']!=0:raise SystemExit('Probe failed; inspect protected redacted artifact before continuing')


if __name__=='__main__':main()
