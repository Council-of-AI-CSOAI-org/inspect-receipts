"""Receipt signer — Ed25519 over sha256(canonical body). No secrets in code;
key comes from env (INSPECT_RECEIPTS_KEY) or an explicit path."""
import hashlib
import json
import os
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


class ReceiptSigner:
    def __init__(self, key_path: str | None = None, key_bytes: bytes | None = None):
        if key_bytes:
            self._sk = Ed25519PrivateKey.from_private_bytes(key_bytes)
        elif key_path:
            self._sk = Ed25519PrivateKey.from_private_bytes(open(key_path, "rb").read())
        else:
            env = os.environ.get("INSPECT_RECEIPTS_KEY")
            if not env:
                raise RuntimeError("no key: pass key_path, key_bytes, or INSPECT_RECEIPTS_KEY (32-byte seed)")
            import base64
            self._sk = Ed25519PrivateKey.from_private_bytes(base64.b64decode(env))
        self.pubkey = self._sk.public_key().public_bytes_raw().hex()

    def sign(self, body: dict, prev: str = "GENESIS") -> dict:
        body = dict(body)
        body.setdefault("prev", prev)
        body.setdefault("ts", datetime.now(timezone.utc).isoformat())
        body_b = _canonical(body)
        rid = hashlib.sha256(body_b).hexdigest()
        return {"id": rid, "signature": self._sk.sign(body_b).hex(),
                "pubkey": self.pubkey, "body": body}


def verify_receipt(receipt: dict) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(receipt["pubkey"]))
    pub.verify(bytes.fromhex(receipt["signature"]), _canonical(receipt["body"]))
    assert hashlib.sha256(_canonical(receipt["body"])).hexdigest() == receipt["id"]
    return True
