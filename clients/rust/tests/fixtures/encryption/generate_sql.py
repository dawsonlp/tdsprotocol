"""Public scalar/normalization/SqlClient exchange fixtures. No server or secrets.
PYTHONPATH=clients/python:clients/python/tests clients/python/.venv/bin/python clients/rust/tests/fixtures/encryption/generate_sql.py
"""
import json
from dataclasses import replace
from pathlib import Path
import tds
from tds import types
from tds.requests import Context
from tds.encryption.normalize import normalize, denormalize
from test_encryption_live import TYPES
from test_encryption_dotnet_live import case, text, as_sqlclient_has_it
from test_types import LATIN1
out=[]
context=Context(0,1,LATIN1.raw)
for i,(declared,base,collation,values) in enumerate(TYPES):
    if isinstance(base, types.Character): base=replace(base,collation=LATIN1)
    def rpc(value):
        return tds.Call('fixture',tds.Param('@v',base,value)).encode(context,False).body.hex()
    entries=[]
    for value in [*values,None]:
        plain=normalize(base,value,LATIN1) if value is not None else None
        entries.append(dict(rpc=rpc(value),normal=plain.hex() if plain is not None else None,
            decoded_rpc=rpc(denormalize(base,plain)) if plain is not None else rpc(None),
            net_rpc=rpc(as_sqlclient_has_it(value))))
    out.append(dict(declared=declared,collation=collation,spec={**case(i,declared,base),
        'values':[text(declared.split('(')[0],v) for v in values]},entries=entries,
        expected_net=[text(declared.split('(')[0],as_sqlclient_has_it(v)) for v in [*values,None]]))
Path(__file__).with_name('sql.json').write_text(json.dumps(out,indent=2)+'\n')
print(len(out),'SQL type cases')
from test_encryption import COLMETADATA, ROW, KEY_TABLE
output=(bytes.fromhex('AC 01 00 02')+'@s'.encode('utf-16-le')+bytes.fromhex('01 00000000 0008 A54100 00000000 2604 02 01 01 0200 0707'))
Path(__file__).with_name('wire.json').write_text(json.dumps(dict(columns_row=(COLMETADATA+ROW).hex(),output=output.hex(),ordinal_offset=3+len(KEY_TABLE)+9),indent=2)+'\n')
import base64, hashlib, struct
from tds.encryption.cell import CellKey
from tds.encryption.backend import CryptographyBackend
key=CellKey(hashlib.sha256(b'public disposable CEK 0').digest(),CryptographyBackend())
canary='TDS_ENCRYPTED_PLAINTEXT_CANARY_42'
good=key.encrypt(canary.encode('utf-16-le'),True)
bad=good[:-1]+bytes([good[-1]^1])
wrapped=base64.b64decode(json.loads(Path(__file__).with_name('python.json').read_text())['wrapped'][0])
short=lambda s:bytes([len(s)])+s.encode('utf-16-le')
long=lambda s:struct.pack('<H',len(s))+s.encode('utf-16-le')
table=bytes.fromhex('0100 06000000 01000000 01000000')+bytes(range(8))+bytes([1])+struct.pack('<H',len(wrapped))+wrapped+short('TDS_LOCAL_KEYS')+long('master.pem')+short('RSA_OAEP')
meta=bytes.fromhex('810100')+table+bytes.fromhex('00000000 0108 A5 8100 0000 00000000 E7 8000')+LATIN1.raw+bytes.fromhex('02 01 01')+short('v')
row=lambda c:bytes([0xd1])+struct.pack('<H',len(c))+c
stream=meta+row(good)+row(bad)+bytes.fromhex('D1 FFFF')+row(good)+bytes.fromhex('FD10000000')+struct.pack('<Q',4)
Path(__file__).with_name('authenticated.json').write_text(json.dumps(dict(canary=canary,body=stream.hex()),indent=2)+'\n')
