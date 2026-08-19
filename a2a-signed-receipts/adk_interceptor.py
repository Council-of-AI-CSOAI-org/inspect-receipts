"""~100-line ADK interceptor reference — signs agent task completions with
did:web:csoai.org-anchored Ed25519 keys. Implements the signed-receipts/v1 envelope."""
import hashlib
import json
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


class SignedReceiptInterceptor:
    """Wrap an ADK agent's before/after with receipt emission."""

    def __init__(self, key_bytes: bytes, did: str = "did:web:csoai.org"):
        self._sk = Ed25519PrivateKey.from_private_bytes(key_bytes)
        self.did = did
        self.pubkey = self._sk.public_key().public_bytes_raw().hex()
        self.last = "GENESIS"

    def _sign(self, body: dict) -> dict:
        body = dict(body); body["prev"] = self.last
        body.setdefault("ts", datetime.now(timezone.utc).isoformat())
        b = _canonical(body)
        rid = hashlib.sha256(b).hexdigest()
        receipt = {"kind": "a2a.signed-receipt/v1", "id": rid,
                   "signature": self._sk.sign(b).hex(),
                   "pubkey_did": self.did, "pubkey": self.pubkey, "body": body}
        self.last = rid
        return receipt

    def on_task_complete(self, task_id: str, outcome: str, metrics: dict | None, method_hash: str) -> dict:
        return self._sign({"task_id": task_id, "outcome": outcome,
                           "metrics": metrics, "method_hash": method_hash})

    @staticmethod
    def verify(receipt: dict) -> bool:
        # Production: resolve did:web:csoai.org -> key from https://csoai.org/.well-known/did.json
        # Offline demo: the hex pubkey rides in the receipt (never in production envelopes).
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(receipt["pubkey"]))
        pub.verify(bytes.fromhex(receipt["signature"]), _canonical(receipt["body"]))
        return True


if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    it = SignedReceiptInterceptor(seed)
    r = it.on_task_complete("t1", "success",
                            {"axis": "gov", "score": 0.658, "n": 193, "ci95": [0.589, 0.721]},
                            "sha256:harness-v1")
    print("receipt:", r["id"][:16], "| signature:", r["signature"][:16], "| verify:", SignedReceiptInterceptor.verify(r))
