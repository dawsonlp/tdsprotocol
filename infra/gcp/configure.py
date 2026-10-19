#!/usr/bin/env python3
"""Configure disposable guests using verified SSH and stdin-only secrets.

Run with clients/python/.venv/bin/python for its established cryptography dependency.
No secret/error payload is printed. Diagnostic files remain ignored/protected.
"""
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import urllib.error

import lab

HERE=Path(__file__).resolve().parent
SECRET=HERE/'secrets'
ARTIFACTS=HERE/'artifacts'


def deadline():
    expires=dt.datetime.fromisoformat(lab.read(HERE/'campaign.tfvars.json')['expires_at'])
    if dt.datetime.now(dt.timezone.utc) >= expires-dt.timedelta(minutes=10):
        raise SystemExit('Safety expiry is close; review cost/window before continuing')


def credentials():
    path=SECRET/'credentials.json'
    if not path.exists():
        lab.write_private(path,{key:'Tds!'+secrets.token_urlsafe(24) for key in ['admin_password','user_password','sql_password','pfx_password']})
    return lab.read(path)


def trust(roles=None):
    inventory=lab.read(HERE/'gcp.json')['inventory']
    project=lab.read(HERE/'campaign.tfvars.json')['project_id']
    lines=[]
    config=[]
    for role,vm in inventory.items():
        if roles is not None and role not in roles:continue
        for attempt in range(40):
            deadline()
            try:
                value=lab.api(f"compute.googleapis.com/compute/v1/projects/{project}/zones/{vm['zone']}/instances/{vm['name']}/getGuestAttributes?queryPath=tds/hostkey",project)
                break
            except urllib.error.HTTPError as error:
                if error.code!=404 or attempt==39:raise
                if attempt%4==0:print(f'{role}: waiting for public SSH bootstrap',flush=True)
                time.sleep(15)
        items=value.get('queryValue',{}).get('items',[])
        key=next((item['value'].strip() for item in items if item['key']=='hostkey'),'')
        if not key.startswith('ssh-ed25519 '): raise RuntimeError(f'{role}: bootstrap host key is not ready')
        alias=vm['name']
        lines.append(f'{alias} {key}')
        address=vm['external_ip'] if role=='linux' else vm['internal_ip']
        user='tds' if role=='linux' else 'Administrator'
        text=f'Host tds-{role}\n  HostName {address}\n  HostKeyAlias {alias}\n  User {user}\n'
        text+=f'  IdentityFile {SECRET}/runner_ed25519\n  IdentitiesOnly yes\n  StrictHostKeyChecking yes\n  UserKnownHostsFile {HERE}/known_hosts\n  ConnectTimeout 15\n  ServerAliveInterval 15\n'
        if role!='linux': text+='  ProxyJump tds-linux\n'
        config.append(text)
    (HERE/'known_hosts').write_text('\n'.join(lines)+'\n')
    path=SECRET/'ssh_config';path.write_text('\n'.join(config));path.chmod(0o600)
    print('Verified guest SSH host keys through the authenticated cloud API')


def ssh(role,command,stdin=None,check=True):
    deadline()
    result=subprocess.run(['ssh','-F',str(SECRET/'ssh_config'),f'tds-{role}',command],
                          input=stdin,capture_output=True,text=True,timeout=2400)
    ARTIFACTS.mkdir(mode=0o700,exist_ok=True)
    # Keep diagnostics private for inspection/redaction. Never echo raw guest
    # exceptions: PowerShell/installer errors can contain the supplied payload.
    lab.write_private(ARTIFACTS/f'{role}-last-command.json',{'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
    if check and result.returncode: raise RuntimeError(f'{role}: command failed ({result.returncode}); inspect protected diagnostics')
    return result


def copy(role,path,target):
    result=subprocess.run(['scp','-q','-F',str(SECRET/'ssh_config'),str(path),f'tds-{role}:{target}'],capture_output=True,text=True,timeout=300)
    if result.returncode: raise RuntimeError(f'{role}: file transfer failed; no guest configuration attempted')


def step(role,name):
    payload=credentials()|{'step':name,'computer_name':{'sql':'tdssql','windows':'tdswin','dc':'tdsdc'}[role]}
    result=ssh(role,'powershell.exe -NoProfile -NonInteractive -File C:/tds/configure.ps1',json.dumps(payload))
    print(f'{role}: {name} completed')
    if 'REBOOT' in result.stdout:
        ssh(role,'powershell.exe -NoProfile -NonInteractive -Command "Restart-Computer -Force"',check=False)
        # Reboot has to actually disconnect before readiness can prove recovery.
        for attempt in range(60):
            time.sleep(5);deadline()
            if attempt<3: continue
            probe=ssh(role,'powershell.exe -NoProfile -NonInteractive -Command "Write-Output ready"',check=False)
            if probe.returncode==0: return True
        raise RuntimeError(f'{role}: reboot readiness deadline exceeded')
    return False


def certificates():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtendedKeyUsageOID,NameOID
    if (SECRET/'sql.pfx').exists(): return
    now=dt.datetime.now(dt.timezone.utc)
    ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Disposable TDS GCP CA')])
    ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True)
        .sign(ca_key,hashes.SHA256()))
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'tdssql.tds.test')]))
        .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=True,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=False,decipher_only=False),critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('tdssql.tds.test'),x509.IPAddress(ipaddress.ip_address('10.43.1.5'))]),critical=False)
        .sign(ca_key,hashes.SHA256()))
    for path,data in [(SECRET/'ca.pem',ca.public_bytes(serialization.Encoding.PEM)),
                      (SECRET/'sql.pfx',pkcs12.serialize_key_and_certificates(b'tdssql',key,cert,[ca],serialization.BestAvailableEncryption(credentials()['pfx_password'].encode())))]:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'wb') as f:f.write(data)


def upload(role):
    for attempt in range(8):
        try:
            ssh(role,'powershell.exe -NoProfile -NonInteractive -Command "New-Item -ItemType Directory -Force C:/tds | Out-Null"')
            break
        except RuntimeError:
            if attempt==7:raise
            print(f'{role}: waiting for SSH readiness',flush=True);time.sleep(10)
    copy(role,HERE/'scripts/configure.ps1','C:/tds/configure.ps1')
    if role=='sql':copy(role,HERE/'scripts/sql-update.ps1','C:/tds/sql-update.ps1')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['trust','dc','users','join','install','patch','sql','all'])
    args=parser.parse_args();deadline()
    if args.command=='trust':return trust()
    if args.command=='all':
        trust({'dc','sql','linux'})
        upload('dc');upload('sql')
        for _ in range(3):
            if not step('dc','dc'):break
        else: raise RuntimeError('DC did not converge')
        # AD services can take time to settle following promotion/reboot.
        for attempt in range(20):
            try: step('dc','users');break
            except RuntimeError:
                if attempt==19:raise
                time.sleep(10)
        step('sql','join');step('dc','users')
        step('sql','install')
        step('sql','patch')
        certificates();copy('sql',SECRET/'sql.pfx','C:/tds/sql.pfx');copy('sql',SECRET/'ca.pem','C:/tds/ca.pem')
        step('sql','sql')
        print('Domain/SQL configuration completed; independent login readiness still must pass')
    else:
        role='dc' if args.command in ['dc','users'] else 'sql'
        upload(role);step(role,args.command)


if __name__=='__main__':main()
