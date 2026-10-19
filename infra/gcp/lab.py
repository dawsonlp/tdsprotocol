#!/usr/bin/env python3
"""Transient GCP lab control. Every cloud call names the dedicated project.

Test invocation and review do NOT destroy the lab. Use destroy explicitly after
acceptance, or on campaign abandonment. Expiry remains the independent fallback.
Credentials and Terraform state stay local; gcloud tokens exist only in memory.
"""
import argparse
import datetime as dt
import ipaddress
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

HERE = Path(__file__).resolve().parent
UTC = dt.timezone.utc
LIMIT = 10.0
RESERVE = 2.0


def read(path):
    return json.loads(path.read_text())


def write_private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def token():
    return subprocess.run(['gcloud', 'auth', 'print-access-token'], check=True,
                          capture_output=True, text=True).stdout.strip()


def api(path, project):
    request = urllib.request.Request('https://' + path, headers={
        'Authorization': 'Bearer ' + token(), 'x-goog-user-project': project})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def terraform(*args, root=HERE, capture=False):
    command = ['terraform', f'-chdir={root}', *args]
    return subprocess.run(command, check=True, env={**os.environ, 'GOOGLE_OAUTH_ACCESS_TOKEN': token()},
                          capture_output=capture, text=True)


def estimate(configuration, ledger, now):
    """Conservative allocation/runtime model; never mistake billing delay for $0.

    All four fixed-size VMs together are reserved at $1/hour, even while the
    Windows runner is absent. Add $1 transfer/uncertainty and $2 cleanup reserve.
    Prior retired deployments must be accounted separately in the ledger.
    """
    expiry = dt.datetime.fromisoformat(configuration['expires_at'].replace('Z', '+00:00'))
    start = dt.datetime.fromisoformat(ledger.get('first_paid_start', now.isoformat()))
    if start.tzinfo is None or expiry.tzinfo is None or start > now:
        raise ValueError('UTC-aware timestamps required')
    remaining = (expiry-now).total_seconds()/3600
    hours = (expiry-start).total_seconds()/3600
    if not 0 < remaining <= 4 or hours <= 0:
        raise ValueError('Expiry must be future and at most four hours away')
    prior = float(ledger.get('retired_cost_upper_bound_usd', 0))
    if prior < 0 or not all(map(math.isfinite, [prior,hours])):
        raise ValueError('Invalid campaign cost history')
    total = prior + hours + 1 + RESERVE
    if total > LIMIT:
        raise ValueError('Projected campaign cost plus cleanup reserve exceeds $10')
    return {'allocated_hours': round(hours, 4), 'modeled_total_including_reserves_usd': round(total, 4),
            'remaining_hours': round(remaining, 4), 'target_usd': 1, 'ceiling_usd': LIMIT,
            'note': 'Planning guard; not a guaranteed cloud billing cap'}


def validate_plan(plan, configuration):
    allowed={'google_compute_network','google_compute_subnetwork','google_compute_firewall',
             'google_compute_instance','google_service_account','terraform_data'}
    count=0
    for resource in plan.get('resource_changes',[]):
        if resource.get('mode')=='data': continue
        kind=resource['type']; value=resource['change'].get('after')
        if 'delete' in resource['change'].get('actions',[]):
            raise ValueError('Apply refuses resource deletion/replacement; use explicit reviewed teardown')
        if kind not in allowed: raise ValueError('Unpriced resource type in plan')
        if value is None: continue
        if kind!='terraform_data' and value.get('project') != configuration['project_id']:
            raise ValueError('Plan references a different project')
        if kind=='google_compute_instance':
            count+=1
            scheduling=value['scheduling'][0]
            disk=value['boot_disk'][0]
            params=disk['initialize_params'][0]
            if (value['machine_type']!='e2-standard-2' or scheduling['instance_termination_action']!='DELETE'
                    or scheduling['termination_time']!=configuration['expires_at'] or not disk['auto_delete']):
                raise ValueError('VM does not match the fixed price/expiry contract')
            if params['type']!='pd-standard' or params['size']>64:
                raise ValueError('Unpriced boot disk')
            image=params['image']
            if not any(f'/projects/{source}/global/images/' in image for source in ['windows-cloud','ubuntu-os-cloud']):
                raise ValueError('Unpriced or paid SQL image')
            if len(value['network_interface'])!=1 or len(value['network_interface'][0]['access_config'])!=1:
                raise ValueError('Unexpected IP allocation')
            if value['service_account'][0].get('scopes'):
                raise ValueError('Guest has cloud API scopes')
        if kind=='google_compute_firewall':
            ranges=value.get('source_ranges',[])
            if ranges not in [[configuration['client_cidr']],['10.43.1.0/24']]:
                raise ValueError('Unexpected ingress range')
    if count>4: raise ValueError('Too many VMs for the campaign price model')
    return count


def prepare():
    state = HERE/'campaign.tfvars.json'
    if state.exists():
        raise SystemExit('Campaign inputs already exist; preserve their original expiry and cost history')
    project = read(HERE/'project/campaign.tfvars.json')['project_id']
    if not project.startswith('tds-rust-auth-'):
        raise SystemExit('Refusing an existing/non-lab project')
    secrets = HERE/'secrets'
    secrets.mkdir(mode=0o700, exist_ok=True)
    key = secrets/'runner_ed25519'
    if not key.exists():
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
    with urllib.request.urlopen('https://api.ipify.org', timeout=20) as response:
        address = str(ipaddress.IPv4Address(response.read().decode().strip()))
    images = {}
    for role, source, family in [('windows', 'windows-cloud', 'windows-2022-core'),
                                  ('linux', 'ubuntu-os-cloud', 'ubuntu-2404-lts-amd64')]:
        image = api(f'compute.googleapis.com/compute/v1/projects/{source}/global/images/family/{family}', project)
        if image.get('status') != 'READY':
            raise SystemExit('Image is not ready')
        images[role] = image['selfLink']
    now = dt.datetime.now(UTC)
    configuration = dict(project_id=project, campaign_id='auth-'+project.rsplit('-', 1)[1],
                         client_cidr=address+'/32', expires_at=(now+dt.timedelta(hours=4)).isoformat().replace('+00:00','Z'),
                         ssh_public_key=key.with_suffix('.pub').read_text().strip(),
                         windows_image=images['windows'], linux_image=images['linux'], enable_windows_runner=False)
    write_private(state, configuration)
    print(json.dumps(configuration, indent=2))  # Public deployment inputs only.


def outputs():
    return {k:v['value'] for k,v in json.loads(terraform('output','-json',capture=True).stdout).items()}


def inventory(configuration):
    project=configuration['project_id']
    collections=['instances','disks','addresses','snapshots','forwardingRules','routers','firewalls','subnetworks']
    result={}
    for kind in collections:
        if kind in ['snapshots','firewalls']:
            data=api(f'compute.googleapis.com/compute/v1/projects/{project}/global/{kind}',project)
            result[kind]=[item['name'] for item in data.get('items',[])]
        else:
            data=api(f'compute.googleapis.com/compute/v1/projects/{project}/aggregated/{kind}',project)
            result[kind]=[item['name'] for scope in data.get('items',{}).values() for item in scope.get(kind,[])]
    data=api(f'compute.googleapis.com/compute/v1/projects/{project}/global/networks',project)
    result['networks']=[item['name'] for item in data.get('items',[])]
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['prepare','cost','plan','apply','status','destroy','verify-destroy'])
    args=parser.parse_args()
    if args.command=='prepare': return prepare()
    configuration=read(HERE/'campaign.tfvars.json')
    if not configuration['project_id'].startswith('tds-rust-auth-'): raise SystemExit('Not a dedicated lab project')
    ledger_path=HERE/'artifacts/cost-ledger.json'
    ledger=read(ledger_path) if ledger_path.exists() else {}
    if args.command in ['cost','plan','apply']:
        report=estimate(configuration,ledger,dt.datetime.now(UTC))
        print(json.dumps(report,indent=2),flush=True)
        if args.command=='cost': return
        terraform('plan','-input=false','-no-color','-var-file=campaign.tfvars.json','-out=campaign.tfplan')
        plan=json.loads(terraform('show','-json','campaign.tfplan',capture=True).stdout)
        count=validate_plan(plan,configuration)
        print(f'Validated fixed resource/cost/expiry contract for {count} VMs',flush=True)
        if args.command=='apply':
            if 'first_paid_start' not in ledger:
                ledger['first_paid_start']=dt.datetime.now(UTC).isoformat()
                write_private(ledger_path,ledger)  # Reserve before creating any paid resources.
            terraform('apply','-input=false','-no-color','campaign.tfplan')
            write_private(HERE/'gcp.json',outputs())
    elif args.command=='status':
        print(json.dumps({'inventory':inventory(configuration),'expiry':configuration['expires_at'],
                          'ledger':ledger},indent=2))
    elif args.command=='destroy':
        terraform('destroy','-input=false','-auto-approve','-no-color','-var-file=campaign.tfvars.json')
        # Never delete state here. Review and verify inventory first.
    elif args.command=='verify-destroy':
        result=inventory(configuration)
        state=terraform('state','list',capture=True).stdout.strip()
        print(json.dumps({'inventory':result,'terraform_state':state},indent=2))
        if state or any(result.values()): raise SystemExit('Resources remain; preserve state and investigate')


if __name__=='__main__': main()
