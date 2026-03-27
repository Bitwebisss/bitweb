#!/usr/bin/env python3
# run from repo root: python3 fix_bip341_vectors.py

import json, sys, os

sys.path.insert(0, "functional")
from test_framework.segwit_addr import decode, encode

OLD_HRP = "bc"
NEW_HRP = "bte"

json_path = "src/test/data/bip341_wallet_vectors.json"

with open(json_path) as f:
    data = json.load(f)

for case in data.get("scriptPubKey", []):
    addr = case.get("expected", {}).get("bip350Address", "")
    if addr:
        witver, witprog = decode(OLD_HRP, addr)
        assert witver is not None, f"Failed to decode: {addr}"
        case["expected"]["bip350Address"] = encode(NEW_HRP, witver, witprog)

with open(json_path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")

print("Done")