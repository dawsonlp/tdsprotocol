"""Independent established-client witness. Protected JSON enters over stdin."""
import asyncio
import base64
import io
import json
import ssl
import sys
import time
import uuid

import tds
from tds.adapters.spnego import Spnego
from tds.capture import Capture

PROGRESS = False
PROGRESS_FILE = None
PROBE_BEGAN = time.monotonic()


def progress(phase):
    if PROGRESS:
        evidence = {'phase': phase, 'elapsed_ms': round((time.monotonic()-PROBE_BEGAN)*1000)}
        print(json.dumps(evidence), flush=True)
        if PROGRESS_FILE:
            with open(PROGRESS_FILE, 'a', encoding='utf-8') as stream:
                stream.write(json.dumps(evidence) + '\n')


async def fetch(channel, request):
    async with await channel.exchange(tds.Batch(request) if isinstance(request, str) else request) as response:
        return await response.fetch()


async def lifecycle(connection, channel):
    progress('transaction-start')
    await fetch(channel, 'CREATE TABLE #auth_transaction(n int)')
    await fetch(channel, tds.transactions.Begin())
    assert connection.session.transaction
    await fetch(channel, 'INSERT #auth_transaction VALUES(42)')
    await fetch(channel, tds.transactions.Rollback())
    assert not connection.session.transaction
    assert (await fetch(channel, 'SELECT COUNT(*) FROM #auth_transaction')).result_sets[0].rows == ((0,),)
    progress('rollback-complete')
    response = await channel.exchange(tds.Batch("WAITFOR DELAY '00:00:10'; SELECT 99"))
    await asyncio.sleep(0.1)
    await response.close()
    progress('attention-closed')
    assert (await fetch(channel, 'SELECT 42')).result_sets[0].rows == ((42,),)


async def pool_lifecycle(options, expected):
    progress('pool-start')
    async with tds.Pool(**options, size=1) as pool:
        async with pool.connection() as first:
            old = first.serial_channel()
            await fetch(old, 'CREATE TABLE #auth_pool_reset(n int)')
            spid = (await fetch(old, 'SELECT @@SPID')).result_sets[0].rows[0][0]
        async with pool.connection() as second:
            try:
                await old.exchange(tds.Batch('SELECT 0'))
            except (tds.ChannelClosed, tds.SerialChannelMisuse, tds.OutOfTurn):
                pass
            else:
                raise AssertionError('Old lease retained SQL authority')
            async with second.serial_channel() as channel:
                row = (await fetch(channel, "SELECT @@SPID, OBJECT_ID('tempdb..#auth_pool_reset'), SUSER_SNAME()")).result_sets[0].rows[0]
                assert row[0] == spid and row[1] is None and row[2].lower() == expected.lower()
    progress('pool-complete')


async def encryption_smoke(options, key_dir):
    progress('ae-start')
    from tds.encryption import Encryption, LocalKeyStore
    keys = LocalKeyStore(key_dir)
    wrapped = keys.encrypt_column_key('master.pem').hex()
    database = 'tds_auth_ae_python_' + uuid.uuid4().hex
    async with await tds.connect(**options) as admin:
        async with admin.serial_channel() as setup:
            await fetch(setup, f'CREATE DATABASE {database}')
            progress('ae-database-created')
            try:
                await fetch(setup, f"USE {database}; CREATE COLUMN MASTER KEY cmk WITH (KEY_STORE_PROVIDER_NAME=N'TDS_LOCAL_KEYS',KEY_PATH=N'master.pem'); CREATE COLUMN ENCRYPTION KEY cek WITH VALUES (COLUMN_MASTER_KEY=cmk,ALGORITHM='RSA_OAEP',ENCRYPTED_VALUE=0x{wrapped})")
                # Compile the table only after the key-creation batch completes.
                await fetch(setup, "CREATE TABLE dbo.auth_ae(v int ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY=cek,ENCRYPTION_TYPE=DETERMINISTIC,ALGORITHM='AEAD_AES_256_CBC_HMAC_SHA_256'))")
                async with await Encryption([keys]).connect(**{**options, 'database': database}) as connection:
                    progress('ae-connected')
                    async with connection.serial_channel() as channel:
                        await fetch(channel, tds.transactions.Begin())
                        text = tds.types.nvarchar(tds.types.MAX)
                        await fetch(channel, tds.Call(tds.Builtin.SP_EXECUTESQL,
                            tds.Param('@stmt', text, 'INSERT dbo.auth_ae VALUES(@v)'),
                            tds.Param('@params', text, '@v int'), tds.Param('@v', tds.types.int, 42)))
                        progress('ae-inserted')
                        assert (await fetch(channel, 'SELECT v FROM dbo.auth_ae')).result_sets[0].rows == ((42,),)
                        assert connection.key_statistics.unwraps == connection.key_statistics.live_columns == 1
                        await fetch(channel, tds.transactions.Commit())
                        assert connection.key_statistics.live_columns == connection.key_statistics.live_masters == 0
                        progress('ae-committed')
            finally:
                await fetch(setup, f'USE master; ALTER DATABASE {database} SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE {database}')
                progress('ae-cleaned')


async def main(config):
    global PROGRESS, PROGRESS_FILE
    PROGRESS = config.get('progress', False)
    PROGRESS_FILE = config.get('progress_file')
    progress('probe-start')
    recorded = io.StringIO()
    options = dict(host=config['host'], port=config.get('port',1433),
                   ssl_context=ssl.create_default_context(cafile=config['ca_file']),
                   server_hostname=config['server_name'], database='master',
                   mars=config.get('mars',False), tds_version=config.get('tds_version','7.4'))
    options['capture'] = Capture(recorded)
    timeout_ms = config.get('timeout_ms', 15000)
    if not 0 < timeout_ms <= 60000:
        raise ValueError('timeout must be between 1 and 60000 milliseconds')
    options['timeout'] = timeout_ms / 1000
    witness = None
    if config['method']=='sql':
        options.update(user=config['username'],password=config['password'])
    else:
        provider=Spnego(config.get('username'),config.get('password'),config['method'])
        if config.get('binding')=='bad':
            class IncorrectBinding:
                def begin(self,host,port):
                    import spnego
                    from spnego.channel_bindings import GssChannelBindings
                    return spnego.client(config['username'],config['password'],hostname=f'{host}:{port}',service='MSSQLSvc',protocol=config['method'],channel_bindings=GssChannelBindings(application_data=b'tls-server-end-point:'+b'\x00'*32))
            provider=IncorrectBinding()
        class Witness:
            context = None
            def begin(self, host, port):
                progress('provider-begin-start')
                self.context = provider.begin(config.get('auth_host', host), port)
                progress('provider-begin-complete')
                return self.context
        witness = Witness()
        options['login']=tds.WindowsLogin(witness)
    async with await tds.connect(**options) as connection:
        progress('login-accepted')
        async with connection.serial_channel() as channel:
            async with await channel.exchange(tds.Batch("SELECT SUSER_SNAME(), ORIGINAL_LOGIN(), DB_NAME(), net_transport, auth_scheme, encrypt_option, @@SPID FROM sys.dm_exec_connections WHERE session_id=@@SPID AND parent_connection_id IS NULL")) as response:
                fetched=await response.fetch()
                row=fetched.result_sets[0].rows[0]
                result=dict(zip(['principal','original_login','database','transport','auth_scheme','encrypted','spid'],row))
                if witness is not None:
                    result['authentication_provider']=type(witness.context).__module__+'.'+type(witness.context).__name__
                    result['provider_complete']=witness.context.complete
                    packets=[json.loads(line) for line in recorded.getvalue().splitlines() if '"redacted"' in line]
                    assert packets and all(not any(base64.b64decode(p['bytes'])[8:]) for p in packets)
                    result['windows_login_payloads_redacted']=True
                    result['redacted_login_packets']=len(packets)
                if config.get('lifecycle'):
                    await lifecycle(connection, channel)
    base = {key:value for key,value in options.items() if key != 'capture'}
    if config.get('lifecycle'):
        await pool_lifecycle(base, result['principal'])
        result['transaction_attention_pool_reset'] = True
    if config.get('local_key_ae'):
        await encryption_smoke(base, config['ae_key_dir'])
        result['local_key_ae_transaction'] = True
    result['closed'] = True
    print(json.dumps(result))


if __name__=='__main__':
    asyncio.run(main(json.load(sys.stdin)))
