"""Receipt construction, canonicalisation, signing and verification.

Register: a receipt is non-repudiable evidence of WHAT WAS CLAIMED AND WHEN —
it is not proof that an eval is honest, uncontaminated, or correct. Measurement,
not certification.

Schema: csoai.inspect-receipt/0.1
Canonical bytes: UTF-8 JSON, sorted keys, no whitespace — hashed with SHA-256,
signed with Ed25519. The signing key NEVER ships with this package; the verifier
needs only the public key (inline `signer_public_key` or the did:web document
named by `kid`).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA = "csoai.inspect-receipt/0.1"

ENV_ENABLE = "INSPECT_RECEIPTS"          # "1" enables emission
ENV_KEY = "INSPECT_RECEIPTS_KEY"         # path to a 32-byte Ed25519 seed file
ENV_KID = "INSPECT_RECEIPTS_KID"         # e.g. did:web:example.org#eval-1
ENV_OUT = "INSPECT_RECEIPTS_DIR"         # output dir (default: ./receipts)


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class Signer:
    key: Ed25519PrivateKey
    kid: str

    @classmethod
    def from_env(cls) -> "Signer | None":
        key_path = os.environ.get(ENV_KEY)
        if not key_path:
            return None
        seed = Path(key_path).read_bytes()
        if len(seed) != 32:
            raise ValueError(f"{ENV_KEY} must point at a 32-byte Ed25519 seed file")
        kid = os.environ.get(ENV_KID, "unpublished-key")
        return cls(key=Ed25519PrivateKey.from_private_bytes(seed), kid=kid)

    @property
    def public_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization

        return self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()

    def sign(self, payload: dict) -> dict:
        """Return payload + content_id + signature envelope (payload not mutated)."""
        body = dict(payload)
        body["content_id"] = sha256_hex(canonical_bytes(payload))
        sig = self.key.sign(canonical_bytes(body))
        return {
            **body,
            "signature": {
                "alg": "Ed25519",
                "kid": self.kid,
                "signer_public_key": self.public_hex,
                "sig": sig.hex(),
                "signed_over": "canonical JSON of receipt minus this signature object",
            },
        }


def verify(receipt: dict) -> tuple[bool, str]:
    """Offline verification: recompute content_id, check Ed25519 signature.

    Returns (valid, reason). Uses only the receipt's embedded public key —
    callers who want key-trust should ALSO resolve `kid` (e.g. a did:web
    document) and compare the published key with `signer_public_key`.
    """
    try:
        sig_env = receipt["signature"]
        body = {k: v for k, v in receipt.items() if k != "signature"}
        unsigned = {k: v for k, v in body.items() if k != "content_id"}
        expect_cid = sha256_hex(canonical_bytes(unsigned))
        if body.get("content_id") != expect_cid:
            return False, f"content_id mismatch (expected {expect_cid[:16]}…)"
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig_env["signer_public_key"]))
        pub.verify(bytes.fromhex(sig_env["sig"]), canonical_bytes(body))
        return True, f"VALID — signed by {sig_env.get('kid', 'unknown kid')}"
    except Exception as e:  # noqa: BLE001 — verification must never raise
        return False, f"INVALID — {type(e).__name__}: {e}"


def base_receipt(kind: str, data: dict) -> dict:
    return {
        "schema": SCHEMA,
        "kind": kind,  # "run" | "task"
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "register": (
            "Non-repudiable evidence of what was claimed and when. Not proof the "
            "eval is honest, uncontaminated, or correct. Measurement, not certification."
        ),
        **data,
    }


def out_dir() -> Path:
    d = Path(os.environ.get(ENV_OUT, "receipts"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_receipt(receipt: dict, stem: str) -> Path:
    path = out_dir() / f"{stem}.receipt.json"
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
