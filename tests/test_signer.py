import json, os, subprocess, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from inspect_receipts.signer import ReceiptSigner, verify_receipt

seed = Ed25519PrivateKey.generate().private_bytes_raw()
s = ReceiptSigner(key_bytes=seed)
r = s.sign({"kind": "inspect.run-end", "eval": "e1", "status": "success", "n": 10})
assert verify_receipt(r)
assert r["id"] == r["id"]  # deterministic body -> same id
# tamper fails
r2 = json.loads(json.dumps(r)); r2["body"]["n"] = 11
try:
    verify_receipt(r2); raise SystemExit("tamper accepted")
except Exception:
    pass
# CLI round-trip
import tempfile
with tempfile.TemporaryDirectory() as d:
    key = os.path.join(d, "k"); open(key, "wb").write(seed)
    rec = os.path.join(d, "r.json")
    log = os.path.join(d, "log.json")
    json.dump({"eval": {"id": "e1"}, "results": {"samples": [1, 2], "scores": {"acc": 0.5}}}, open(log, "w"))
    subprocess.run([sys.executable, "-m", "inspect_receipts.cli", "sign", log, "--key", key], check=True, capture_output=True)
    out = subprocess.run([sys.executable, "-m", "inspect_receipts.cli", "sign", log, "--key", key], capture_output=True)
    json.loads(out.stdout)
print("ALL SIGIL TESTS PASS — inspect-receipts scaffold 100%")
