"""Reproduce password-change/recovery with an isolated disposable SQL login.

Use clients/python/.venv/bin/python from repo root. Credentials are generated in
memory, never printed, and the login is dropped in finally. Uses the existing
Docker test endpoint, test CA and ignored administrator credential configuration.
"""
import asyncio, ssl, sys, secrets, uuid
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(root/'clients/python'),str(root/'clients/python/tests')]
import tds
from conftest import HOST,PORT,TEST_CA,_password,fetch
from test_session_recovery_live import Relay

async def go():
    server=dict(host=HOST,port=PORT,user='sa',password=_password(),ssl_context=ssl.create_default_context(cafile=TEST_CA))
    name='tds_probe_'+uuid.uuid4().hex
    old='Old_Aa1!'+secrets.token_urlsafe(24)
    new='New_Aa1!'+secrets.token_urlsafe(24)
    admin=await tds.connect(**server)
    try:
        channel=admin.serial_channel()
        await fetch(channel,f"CREATE LOGIN [{name}] WITH PASSWORD = '{old}', CHECK_POLICY=OFF")
        async with Relay(server) as relay:
            config={**server,'user':name,'password':old,'port':relay.port}
            connection=await tds.connect(**config,new_password=new)
            try:
                ch=connection.serial_channel()
                assert (await fetch(ch,'SELECT 1')).result_sets[0].rows==((1,),)
                print('password-change login succeeded', flush=True)
                relay.cut()
                await connection._reading
                try:
                    await connection.recover()
                    print('recovery succeeded', flush=True)
                except Exception as failure:
                    cause=failure.__cause__
                    number=getattr(cause,'number',None)
                    print('recovery failed:',type(failure).__name__, 'direct cause:',type(cause).__name__, 'number:',number,flush=True)
            finally:
                await connection.close()
    finally:
        try:
            await fetch(channel, f'DROP LOGIN [{name}]')
        finally:
            await admin.close()
if __name__ == '__main__':
    try:
        asyncio.run(go())
    except Exception as failure:
        print('probe/setup/cleanup failed:', type(failure).__name__, flush=True)
        raise SystemExit(1) from None
