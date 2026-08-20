"""Receipt construction, canonicalisation, signing and verification.

Register: a receipt is non-repudiable evidence of WHAT WAS CLAIMED AND WHEN —
it is not proof that an eval is honest, uncontaminated, or correct. Measurement,
not certification. Nobody ranked pays; humans never pay.

Schema: csoai.inspect-receipt/0.2

What is signed
--------------
NOT the raw ``.eval`` bytes. The physical ``.eval`` layout is a
version-dependent zstd ZIP-of-JSON; hashing those bytes is fragile across
Inspect releases. Instead we canonicalise the **EvalLog object model** into a
stable field subset (eval id, task, model, dataset id, scores, timestamps),
serialise it as deterministic JSON (recursively sorted keys, no whitespace),
hash it with SHA-256, and sign that hash with Ed25519.

Trust
-----
The signing key NEVER ships with this package. It is provisioned by the owner
via ``INSPECT_RECEIPTS_KEY`` (a 0600 seed file). The public key is published at
``did:web:csoai.org`` (``https://csoai.org/.well-known/did.json``) so a stranger
can verify a receipt offline against a PUBLISHED key — not a key the receipt
vouches for itself. If no key is configured the hooks emit an **UNSIGNED**
receipt with an explicit status; a fabricated signature is never produced.
"""

from __future__ import annotations

import base64
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

SCHEMA = "csoai.inspect-receipt/0.2"

# The canonical published-key location for CSOAI receipts.
DID_WEB = "did:web:csoai.org"
DID_DOC_URL = "https://csoai.org/.well-known/did.json"
DEFAULT_KID = f"{DID_WEB}#keys-1"

ENV_ENABLE = "INSPECT_RECEIPTS"          # "1" enables emission
ENV_KEY = "INSPECT_RECEIPTS_KEY"         # path to a 32-byte Ed25519 seed file
ENV_KID = "INSPECT_RECEIPTS_KID"         # e.g. did:web:csoai.org#keys-1
ENV_OUT = "INSPECT_RECEIPTS_DIR"         # output dir (default: ./receipts)


# --------------------------------------------------------------------------- #
# Canonicalisation + hashing
# --------------------------------------------------------------------------- #
def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON: recursively sorted keys, no whitespace, UTF-8."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# EvalLog OBJECT-MODEL digest (the thing we actually sign)
# --------------------------------------------------------------------------- #
def _get(obj: Any, name: str, default: Any = None) -> Any:
    return getattr(obj, name, default) if obj is not None else default


def _scores_subset(results: Any) -> list[dict]:
    """Extract a stable, order-normalised view of the scores + metrics."""
    out: list[dict] = []
    for score in _get(results, "scores", []) or []:
        metrics = {}
        for mname, metric in (_get(score, "metrics", {}) or {}).items():
            metrics[mname] = _get(metric, "value", metric)
        out.append(
            {
                "name": _get(score, "name"),
                "scorer": _get(score, "scorer"),
                "reducer": _get(score, "reducer"),
                "metrics": metrics,
            }
        )
    # order-independent: sort by (name, scorer)
    out.sort(key=lambda s: (str(s.get("name")), str(s.get("scorer"))))
    return out


def eval_log_digest(log: Any) -> dict:
    """Canonical, version-stable subset of an EvalLog *object*.

    This is deliberately a small, human-auditable projection of the log — the
    identity of the measurement, not its full serialized form. New Inspect
    releases may reshape ``.eval`` on disk without changing this projection.
    """
    spec = _get(log, "eval")
    dataset = _get(spec, "dataset")
    results = _get(log, "results")
    stats = _get(log, "stats")

    sample_ids = _get(dataset, "sample_ids")
    if isinstance(sample_ids, list):
        # order-independent identity of the sample set
        sample_ids = sorted(sample_ids, key=str)

    return {
        "log_version": _get(log, "version"),
        "status": _get(log, "status"),
        "eval": {
            "eval_id": _get(spec, "eval_id"),
            "run_id": _get(spec, "run_id"),
            "created": _get(spec, "created"),
            "task": _get(spec, "task"),
            "task_id": _get(spec, "task_id"),
            "task_version": _get(spec, "task_version"),
            "model": _get(spec, "model"),
            "dataset": {
                "name": _get(dataset, "name"),
                "location": _get(dataset, "location"),
                "samples": _get(dataset, "samples"),
                "sample_ids": sample_ids,
                "shuffled": _get(dataset, "shuffled"),
            },
        },
        "results": {
            "total_samples": _get(results, "total_samples"),
            "completed_samples": _get(results, "completed_samples"),
            "scores": _scores_subset(results),
        },
        "stats": {
            "started_at": _get(stats, "started_at"),
            "completed_at": _get(stats, "completed_at"),
        },
    }


# --------------------------------------------------------------------------- #
# Signing
# --------------------------------------------------------------------------- #
@dataclass
class Signer:
    key: Ed25519PrivateKey
    kid: str

    @classmethod
    def from_env(cls) -> "Signer | None":
        """Build a signer from INSPECT_RECEIPTS_KEY, or None if unconfigured.

        None means: emit an UNSIGNED receipt. It NEVER means fabricate a key.
        """
        key_path = os.environ.get(ENV_KEY)
        if not key_path:
            return None
        seed = Path(key_path).read_bytes()
        if len(seed) != 32:
            raise ValueError(f"{ENV_KEY} must point at a 32-byte Ed25519 seed file")
        kid = os.environ.get(ENV_KID, DEFAULT_KID)
        return cls(key=Ed25519PrivateKey.from_private_bytes(seed), kid=kid)

    @property
    def public_hex(self) -> str:
        from cryptography.hazmat.primitives import serialization

        return (
            self.key.public_key()
            .public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            .hex()
        )

    def sign(self, payload: dict) -> dict:
        """Return payload + content_id + signature envelope (payload not mutated)."""
        body = dict(payload)
        body["content_id"] = sha256_hex(canonical_bytes(payload))
        sig = self.key.sign(canonical_bytes(body))
        return {
            **body,
            "signature": {
                "status": "SIGNED",
                "alg": "Ed25519",
                "kid": self.kid,
                "signer_public_key": self.public_hex,
                "sig": sig.hex(),
                "signed_over": "canonical JSON of receipt minus this signature object",
            },
        }


def unsigned(payload: dict) -> dict:
    """Return an UNSIGNED receipt: content_id present, an explicit status, no sig.

    Emitted when no signing key is provisioned. Verifiers must treat this as
    "content-addressed but NOT attributable to any key".
    """
    body = dict(payload)
    body["content_id"] = sha256_hex(canonical_bytes(payload))
    return {
        **body,
        "signature": {
            "status": "UNSIGNED",
            "alg": None,
            "kid": None,
            "reason": (
                f"no signing key configured (set {ENV_KEY} to a 32-byte Ed25519 "
                "seed); this receipt is content-addressed but unattributed"
            ),
        },
    }


# --------------------------------------------------------------------------- #
# did:web published-key resolution
# --------------------------------------------------------------------------- #
def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def public_keys_from_did_doc(doc: dict) -> dict[str, bytes]:
    """Map verificationMethod id -> raw 32-byte Ed25519 public key.

    Supports publicKeyJwk (OKP/Ed25519) and publicKeyMultibase (did:key z6Mk…).
    """
    keys: dict[str, bytes] = {}
    for vm in doc.get("verificationMethod", []) or []:
        vid = vm.get("id")
        jwk = vm.get("publicKeyJwk")
        if isinstance(jwk, dict) and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            try:
                keys[vid] = _b64url_decode(jwk["x"])
                continue
            except Exception:  # noqa: BLE001
                pass
        mb = vm.get("publicKeyMultibase")
        if isinstance(mb, str) and mb.startswith("z"):
            try:
                raw = _base58btc_decode(mb[1:])
                # multicodec ed25519-pub prefix 0xed 0x01
                if raw[:2] == b"\xed\x01":
                    keys[vid] = raw[2:34]
            except Exception:  # noqa: BLE001
                pass
    return keys


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc_decode(s: str) -> bytes:
    num = 0
    for ch in s:
        num = num * 58 + _B58.index(ch)
    full = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + full


def resolve_did_web(did_url: str = DID_DOC_URL) -> dict[str, bytes]:
    """Fetch a did:web document over HTTPS and return its Ed25519 public keys.

    Network access is required only for this trust step; core signing and the
    offline content check need no network.
    """
    import urllib.request

    req = urllib.request.Request(  # noqa: S310
        did_url,
        headers={"User-Agent": "inspect-receipts/0.2 (+https://csoai.org)", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        doc = json.loads(resp.read().decode("utf-8"))
    return public_keys_from_did_doc(doc)


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
def _check_content_id(receipt: dict) -> tuple[bool, str, dict]:
    body = {k: v for k, v in receipt.items() if k != "signature"}
    unsigned_body = {k: v for k, v in body.items() if k != "content_id"}
    expect_cid = sha256_hex(canonical_bytes(unsigned_body))
    if body.get("content_id") != expect_cid:
        return False, f"content_id mismatch (expected {expect_cid[:16]}…)", body
    return True, "", body


def verify(receipt: dict, published_key: bytes | None = None) -> tuple[bool, str]:
    """Offline verification.

    - Recomputes ``content_id`` from the canonical body.
    - For SIGNED receipts, checks the Ed25519 signature.
    - If ``published_key`` is given (32 raw bytes, e.g. from ``resolve_did_web``),
      the signature MUST verify under THAT key — this is the did:web trust path,
      where you verify against a published key rather than the one the receipt
      carries about itself. If omitted, the receipt's embedded
      ``signer_public_key`` is used (convenience / integrity only, not trust).

    Returns ``(valid, reason)`` and never raises.
    """
    try:
        sig_env = receipt.get("signature", {})
        status = sig_env.get("status")

        ok, reason, body = _check_content_id(receipt)
        if not ok:
            return False, f"INVALID — {reason}"

        if status == "UNSIGNED" or "sig" not in sig_env:
            return False, "UNSIGNED — content_id valid but receipt carries no signature"

        if published_key is not None:
            pub = Ed25519PublicKey.from_public_bytes(published_key)
            key_src = "published did:web key"
            embedded = sig_env.get("signer_public_key")
            if embedded and bytes.fromhex(embedded) != published_key:
                return False, "INVALID — embedded key does not match published did:web key"
        else:
            pub = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(sig_env["signer_public_key"])
            )
            key_src = "embedded key (NOT trust-anchored — resolve kid to trust)"

        pub.verify(bytes.fromhex(sig_env["sig"]), canonical_bytes(body))
        return True, f"VALID — signed by {sig_env.get('kid', 'unknown kid')} [{key_src}]"
    except Exception as e:  # noqa: BLE001 — verification must never raise
        return False, f"INVALID — {type(e).__name__}: {e}"


def verify_against_did_web(
    receipt: dict, did_url: str = DID_DOC_URL
) -> tuple[bool, str]:
    """Resolve the receipt's ``kid`` against a live did:web document and verify.

    This is the stranger's path: fetch the published key, require the signature
    to verify under it. Falls back to reporting clearly if the kid is not found.
    """
    try:
        sig_env = receipt.get("signature", {})
        kid = sig_env.get("kid")
        keys = resolve_did_web(did_url)
        published = keys.get(kid)
        if published is None:
            # kid may be a bare did:web with no fragment; try the first key
            if len(keys) == 1:
                published = next(iter(keys.values()))
            else:
                return False, (
                    f"INVALID — kid {kid!r} not found in {did_url} "
                    f"(available: {sorted(keys)})"
                )
        return verify(receipt, published_key=published)
    except Exception as e:  # noqa: BLE001
        return False, f"INVALID — could not resolve did:web: {type(e).__name__}: {e}"


# --------------------------------------------------------------------------- #
# Receipt envelope
# --------------------------------------------------------------------------- #
def base_receipt(kind: str, data: dict) -> dict:
    return {
        "schema": SCHEMA,
        "kind": kind,  # "run" | "task"
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "register": (
            "Non-repudiable evidence of what was claimed and when. Not proof the "
            "eval is honest, uncontaminated, or correct. Measurement, not certification."
        ),
        "verify": {
            "how": (
                "Recompute content_id over the canonical body, then verify the "
                "Ed25519 signature against the PUBLISHED key resolved from the "
                "signature.kid via did:web."
            ),
            "did": DID_WEB,
            "did_document": DID_DOC_URL,
            "command": "inspect-receipts verify <this-file> --did-web",
            "anchoring": (
                "Ed25519 signature + SHA-256 hash-chain only. Transparency-log / "
                "RFC3161 / OpenTimestamps anchoring is roadmap, not wired."
            ),
        },
        **data,
    }


def out_dir() -> Path:
    d = Path(os.environ.get(ENV_OUT, "receipts"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_receipt(receipt: dict, stem: str) -> Path:
    path = out_dir() / f"{stem}.receipt.json"
    path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path
