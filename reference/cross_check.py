import json, sys, vortex_ref as V
vec = json.load(open(sys.argv[1])); bad = 0; rt = 0
for v in vec:
    m = bytes.fromhex(v["m"]); k = v["key"]
    if v.get("seal"):
        got = V.seal(m, k, bytes.fromhex(v["salt"]), bytes.fromhex(v["nonce"]))
        ok = got.hex() == v["c"] and V.open_(got, k) == m and V.open_(got[:-1] + bytes([got[-1] ^ 1]), k) is None
    else:
        sk = V.raw_key(k); got = V.encrypt(m, sk, v["R"])
        ok = got.hex() == v["c"]
        if len(m) <= 5000: ok = ok and V.decrypt(got, sk, v["R"]) == m; rt += 1
    if not ok: bad += 1; print("DIFFERS", v["key"], len(m), v.get("R"))
print(f"{len(vec)} vectors, {bad} differ, {rt} raw round trips checked")
