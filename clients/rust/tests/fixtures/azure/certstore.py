"""Windows acceptance helper: production Python CNG provider, public test roots.

Called by the ignored Rust native test after a dedicated non-exportable RSA
certificate has been provisioned. Creates/deletes no certificates or resources.
"""
import base64
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[4]/"python"))
from tds.encryption.certstore import WindowsCertificateStore
if sys.platform!="win32":
    raise SystemExit("This acceptance helper requires Windows")
data=json.load(sys.stdin)
store=WindowsCertificateStore()
path=data["path"]
decode=lambda name:base64.b64decode(data[name])
assert store.decrypt_column_key(path,"RSA_OAEP",decode("wrapped"))==decode("root")
assert store.verify_master_key_metadata(path,True,decode("signature"))
assert not store.verify_master_key_metadata(path,False,decode("signature"))
print(json.dumps(dict(wrapped=base64.b64encode(store.encrypt_column_key(path,decode("root"))).decode(),
                      signature=base64.b64encode(store.sign_master_key_metadata(path)).decode())))
