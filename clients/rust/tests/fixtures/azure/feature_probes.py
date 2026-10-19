"""Retain Python production feature-request bytes; policy intentionally differs.
No Python production behavior is changed and no server or credentials are used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(ROOT / "clients/python"))
from tds.login7 import Feature, FeatureList, feature_list
from tds.wire import Writer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    cases = []
    for feature in (Feature.GLOBAL_TRANSACTIONS, Feature.AZURE_SQL_SUPPORT,
                    Feature.AZURE_DNS_CACHING, Feature.ENHANCED_ROUTING):
        writer = Writer(False)
        FeatureList().write(writer, feature_list([feature]))
        cases.append(dict(id=int(feature), encoded=bytes(writer.buf).hex()))
    data = dict(scope="Python wire parity; enabled acknowledgement is a Rust refusal",
                python_source_sha256=hashlib.sha256((ROOT / "clients/python/tds/login7.py").read_bytes()).hexdigest(), cases=cases)
    output = json.dumps(data, indent=2) + "\n"
    destination = HERE / "feature_probes.json"
    if args.write:
        destination.write_text(output)
    elif destination.read_text() != output:
        raise SystemExit("Python request fixture drift")
    print("Four Python feature request encodings match")


if __name__ == "__main__":
    main()
