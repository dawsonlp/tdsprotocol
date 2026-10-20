"""Intentionally public fixed P-384 inputs; production Python session/package code.

--check <Rust-output> decrypts Rust's random package using the Python session.
"""
import base64
import hashlib
import json
import struct
import sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[3]/"python"))
from tds.encryption.backend import CryptographyBackend
from tds.encryption import enclave
from tds.requests import Batch,Call,Builtin,Context

class Fixed(CryptographyBackend):
    def ecdh_p384(self):
        key=self._ec.derive_private_key(1,self._ec.SECP384R1())
        point=key.public_key().public_numbers()
        return key,point.x.to_bytes(48,"big"),point.y.to_bytes(48,"big")
backend=Fixed()
parameters,private=enclave.attestation_parameters(backend)
peer=backend._ec.derive_private_key(2,backend._ec.SECP384R1())
point=peer.public_key().public_numbers()
blob=enclave._blob(point.x.to_bytes(48,"big"),point.y.to_bytes(48,"big"))
handle=b"session1"
info=struct.pack("<II",0,16+len(blob))+handle+struct.pack("<II",len(blob),0)+blob
session=enclave.session(info,private,backend)
statement="SELECT encrypted WHERE encrypted LIKE @v -- λ 😀"
root=bytes([3])*32
keys=[(5,b"version1",7,root)]
encode=lambda b:base64.b64encode(b).decode()
if len(sys.argv)>1 and sys.argv[1]=="--verify":
    data=json.loads((HERE/"enclave.json").read_text())
    assert base64.b64decode(data["parameters"])==parameters
    assert base64.b64decode(data["info"])==info
    assert session.key.decrypt(base64.b64decode(data["package"])[8:])==base64.b64decode(data["plaintext"])
    print("Python verified saved enclave session and authenticated package")
elif len(sys.argv)>1 and sys.argv[1]=="--check":
    for file in sys.argv[2:]:
        package=base64.b64decode(json.loads(Path(file).read_text())["package"])
        assert package[:8]==handle
        body=session.key.decrypt(package[8:])
        assert struct.unpack_from("<q",body,16)[0]==1
        assert body[24:56]==hashlib.sha256(statement.encode("utf-16-le")).digest()
        assert body[56:]==struct.pack("<I",5)+b"version1"+struct.pack("<H",7)+root
    print("Python decrypted and verified Rust enclave packages:",len(sys.argv)-2)
else:
    package=session.package(statement,keys)
    context=Context(0,1,b"",2)
    output=dict(parameters=encode(parameters),info=encode(info),package=encode(package),plaintext=encode(session.key.decrypt(package[8:])),statement=statement,
                batch=encode(Batch("SELECT 1",b"package").encode(context,False).body),
                rpc=encode(Call(Builtin.SP_EXECUTESQL,enclave_package=b"package").encode(context,False).body))
    # Controlled-peer description response. Ordinary columns still have the
    # negotiated AE key-table count (zero). Values come from public Python keys.
    key_fixture=json.loads((HERE/"key_providers.json").read_text())
    old_fixture=json.loads((HERE.parent/"encryption/python.json").read_text())
    from tds.encryption.keys import LocalKeyStore
    local=LocalKeyStore(HERE.parent/"encryption");local.name="TDS_TEST"
    wrapped=base64.b64decode(old_fixture["wrapped"][0])
    coll=bytes.fromhex("0904D00034")
    def result(types,rows,more):
        meta=b"\x81"+struct.pack("<HH",len(types),0)
        for typ in types:
            info={"i":b"\x26\x04","b":b"\x68\x01","x":b"\xa5\x40\x1f","s":b"\xe7\x40\x1f"+coll}[typ]
            meta+=bytes(4)+b"\x01\x00"+info+b"\x01v\x00"
        for row in rows:
            meta+=b"\xd1"
            for typ,value in zip(types,row):
                if typ=="i": meta+=b"\x04"+struct.pack("<I",value)
                elif typ=="b":meta+=b"\x01"+bytes([value])
                else:
                    data=value.encode("utf-16-le") if typ=="s" else value
                    meta+=struct.pack("<H",len(data))+data
        return meta+b"\xfd"+struct.pack("<HHQ",1 if more else 0,0,0)
    def description(signature):
        return (result("iiiixxsssbx",[(0,5,7,1,b"version1",wrapped,"TDS_TEST","master.pem","RSA_OAEP",True,signature)],True)
                +result("isiiii",[(1,"@v",2,2,0,1)],True)+result("x",[(info,)],False))
    output["description"]=encode(description(local.sign_master_key_metadata("master.pem")))
    output["description_denied"]=encode(description(bytes(256)))
    # The same description with the vault-wrapped key and vault metadata signature.
    vault_wrapped=base64.b64decode(key_fixture["wrapped"])
    output["description_vault"]=encode(
        result("iiiixxsssbx",[(0,5,7,1,b"version1",vault_wrapped,"AZURE_KEY_VAULT",key_fixture["path"],"RSA_OAEP",True,
                               base64.b64decode(key_fixture["metadata_signature"]))],True)
        +result("isiiii",[(1,"@v",2,2,0,1)],True)+result("x",[(info,)],False))
    output["column_root"]=encode(hashlib.sha256(b"public disposable CEK 0").digest())
    (HERE/"enclave.json").write_text(json.dumps(output,indent=2)+"\n")
    print("Generated Python fixed-P384 session, package and version-two batch/RPC")
