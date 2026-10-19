"""Compare Rust's artificial FEDAUTH fixtures with Python's actual encoders.

From the repository root, use clients/python/.venv/bin/python on this file.
The default checks the retained fixture; --write explicitly regenerates it.
No credentials, SDK, network or server are used. Empty tokens are wire vectors,
not a claim that an opening/provider should accept an empty credential.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(ROOT / "clients/python"))
from tds.logins import EntraLogin, EntraToken, Workflow, fed_auth_feature, fed_auth_token
from tds.tokens import _fed_auth_info


def fixture():
    cases = []
    tokens = {"ascii": "artificial.access-token", "unicode": "artificial-λ-🔑", "empty": ""}
    for name, token in tokens.items():
        for with_nonce in (False, True):
            nonce = bytes(range(32)) if with_nonce else None
            for echo in (False, True):
                cases.append(dict(
                    id=f"upfront-{name}-nonce{int(with_nonce)}-echo{int(echo)}", scenario="A01",
                    kind="upfront", token=token, echo=echo, nonce=nonce.hex() if nonce else None,
                    expected=fed_auth_feature(EntraToken(token), token, echo, nonce).hex()))
            cases.append(dict(
                id=f"message-{name}-nonce{int(with_nonce)}", scenario="A01", kind="message",
                token=token, nonce=nonce.hex() if nonce else None,
                expected=fed_auth_token(token, nonce).hex()))
    for workflow in Workflow:
        for echo in (False, True):
            cases.append(dict(
                id=f"deferred-{workflow.name.lower()}-echo{int(echo)}", scenario="A01",
                kind="deferred", workflow=int(workflow), echo=echo,
                expected=fed_auth_feature(EntraLogin(lambda *_: "unused", workflow), None, echo, None).hex()))
    info_cases = []
    # Values and directories include valid and unusual but sliceable Python
    # inputs. Compare behavior; these do not certify a service's accepted data.
    for name, options, data in [
        ("normal", [(1, 6, 22), (2, 6, 28)], "stsdbλ".encode("utf-16-le")),
        ("missing", [], b""),
        ("duplicate", [(2, 2, 22), (2, 2, 24)], b"A\x00B\x00"),
        ("odd-surrogate", [(1, 3, 13)], b"\x00\xd8\xff"),
        ("clipped", [(1, 90, 99), (2, 90, 21)], b"abcdef"),
    ]:
        record = SimpleNamespace(options=[SimpleNamespace(id=i, length=n, offset=o) for i,n,o in options], data=data)
        expected = _fed_auth_info(record)
        body = len(options).to_bytes(4, "little") + b"".join(
            bytes([i]) + n.to_bytes(4,"little") + o.to_bytes(4,"little") for i,n,o in options) + data
        token = b"\xee" + len(body).to_bytes(4,"little") + body
        info_cases.append(dict(id=name, scenario="A04", token=token.hex(),
                               sts_url=expected.get(1,""), resource=expected.get(2,"")))
    return dict(schema=1, scope="Artificial public FEDAUTH wire vectors; no live acceptance",
                sources={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in [ROOT / "clients/python/tds/logins.py", ROOT / "clients/python/tds/tokens.py"]},
                cases=cases, info_cases=info_cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    data = json.dumps(fixture(), indent=2, ensure_ascii=False) + "\n"
    destination = HERE / "wire.json"
    if args.write:
        destination.write_text(data)
    elif not destination.exists() or destination.read_text() != data:
        raise SystemExit("Python FEDAUTH fixture drift: review source/behavior before --write")
    print(f"{len(json.loads(data)['cases'])} Python FEDAUTH vectors {'written' if args.write else 'match'}")


if __name__ == "__main__":
    main()
