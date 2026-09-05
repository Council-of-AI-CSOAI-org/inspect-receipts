"""Receipt construction, canonicalisation, signing and verification.

Register: a receipt is non-repudiable evidence of WHAT WAS CLAIMED AND WHEN —
it is not proof that an eval is honest, uncontaminated, or correct. Measurement,
not certification. Nobody ranked pays; humans never pay.

Schema: csoai.inspect-receipt/0.3

Canonicalisation
----------------
``content_id = sha256(RFC8785-JCS(canonical_body))`` where the canonical body
excludes ``signature`` and ``content_id``. Implemented in ``canonical.jcs_bytes``.

Trust
-----
``verify()`` resolves ``signature.kid`` against a trust anchor (default: live
``did:web:csoai.org`` document). Self-embedded keys never verify as VALID.
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

from .canonical import canonical_bytes, jcs

SCHEMA = "csoai.inspect-receipt/0.3"

# THE TRUST ANCHOR IS THE EMITTER'S FIELD, NEVER THIS PACKAGE'S.
#
# These are CSOAI's own values. They are the default only because this estate publishes the
# package; they are not a property of the format. base_receipt() previously stamped them into
# every receipt unconditionally, so a third party emitting with this library produced receipts
# claiming did:web:csoai.org — our root asserted over someone else's evidence. That is the
# defect proofbundle#147 names: "a default in code outweighs a sentence in prose."
#
# Set INSPECT_RECEIPTS_DID and INSPECT_RECEIPTS_DID_DOC to emit under your own root. A verifier
# resolves the anchor from the receipt it was handed (verify.did_document), not from here.
ESTATE_DID_WEB = "did:web:csoai.org"
ESTATE_DID_DOC_URL = "https://csoai.org/.well-known/did.json"
ENV_DID = "INSPECT_RECEIPTS_DID"
ENV_DID_DOC = "INSPECT_RECEIPTS_DID_DOC"


def emitter_did() -> str:
    """The DID this installation signs under — the emitter's, not the format's."""
    return os.environ.get(ENV_DID, ESTATE_DID_WEB)


def emitter_did_doc() -> str:
    """The DID document URL this installation publishes its keys at."""
    return os.environ.get(ENV_DID_DOC, ESTATE_DID_DOC_URL)


# Retained for callers that imported them; they are this estate's values, not a default anchor.
DID_WEB = ESTATE_DID_WEB
DID_DOC_URL = ESTATE_DID_DOC_URL
# Eval / measurement-chain receipts: estate-chain key (pod-held, board chains + eval receipts).
DEFAULT_KID = f"{DID_WEB}#estate-chain-1"

ENV_ENABLE = "INSPECT_RECEIPTS"
ENV_KEY = "INSPECT_RECEIPTS_KEY"
ENV_KID = "INSPECT_RECEIPTS_KID"
ENV_OUT = "INSPECT_RECEIPTS_DIR"

FORBIDDEN_KIDS = frozenset({None, "", "unpublished-key"})


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Binding declaration (what kind of proof this receipt carries)
# --------------------------------------------------------------------------- #
def content_hash_binding(*, eval_log_sha256: str | None = None) -> dict[str, Any]:
    """Declare a content-hash binding — the verifier checks content_id, not Merkle."""
    out: dict[str, Any] = {"type": "content-hash", "digest_alg": "sha256"}
    if eval_log_sha256:
        out["eval_log_sha256"] = eval_log_sha256
    return out


# --------------------------------------------------------------------------- #
# EvalLog OBJECT-MODEL digest
# --------------------------------------------------------------------------- #
def _get(obj: Any, name: str, default: Any = None) -> Any:
    return getattr(obj, name, default) if obj is not None else default


def _scores_subset(results: Any) -> list[dict]:
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
    out.sort(key=lambda s: (str(s.get("name")), str(s.get("scorer"))))
    return out


def eval_log_digest(log: Any) -> dict:
    spec = _get(log, "eval")
    dataset = _get(spec, "dataset")
    results = _get(log, "results")
    stats = _get(log, "stats")

    sample_ids = _get(dataset, "sample_ids")
    if isinstance(sample_ids, list):
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
        body = dict(payload)
        body["content_id"] = sha256_hex(canonical_bytes(_unsigned_body(body)))
        sig = self.key.sign(canonical_bytes(body))
        return {
            **body,
            "signature": {
                "status": "SIGNED",
                "alg": "Ed25519",
                "kid": self.kid,
                "signer_public_key": self.public_hex,
                "sig": sig.hex(),
                "signed_over": "RFC 8785 JCS canonical JSON of receipt minus signature object",
            },
        }


def unsigned(payload: dict) -> dict:
    body = dict(payload)
    body["content_id"] = sha256_hex(canonical_bytes(_unsigned_body(body)))
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


def _unsigned_body(body: dict) -> dict:
    return {k: v for k, v in body.items() if k not in ("signature", "content_id")}


# --------------------------------------------------------------------------- #
# did:web published-key resolution
# --------------------------------------------------------------------------- #
def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def public_keys_from_did_doc(doc: dict) -> dict[str, bytes]:
    """Map trust-anchor aliases -> raw 32-byte Ed25519 public key.

    Indexes each key under:
      - verificationMethod ``id`` (full DID URL, e.g. ``did:web:csoai.org#estate-chain-1``)
      - JWK ``kid`` when present (e.g. ``csoai-estate-chain-1``)
      - bare fragment (e.g. ``estate-chain-1``)

    Receipt ``signature.kid`` MUST match one of these aliases.
    """
    keys: dict[str, bytes] = {}
    for vm in doc.get("verificationMethod", []) or []:
        vid = vm.get("id")
        jwk = vm.get("publicKeyJwk")
        raw: bytes | None = None
        if isinstance(jwk, dict) and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            try:
                raw = _b64url_decode(jwk["x"])
            except Exception:  # noqa: BLE001
                raw = None
        if raw is None:
            mb = vm.get("publicKeyMultibase")
            if isinstance(mb, str) and mb.startswith("z"):
                try:
                    decoded = _base58btc_decode(mb[1:])
                    if decoded[:2] == b"\xed\x01":
                        raw = decoded[2:34]
                except Exception:  # noqa: BLE001
                    raw = None
        if raw is None or not vid:
            continue
        keys[vid] = raw
        if isinstance(jwk, dict):
            jwk_kid = jwk.get("kid")
            if isinstance(jwk_kid, str) and jwk_kid:
                keys[jwk_kid] = raw
        if "#" in vid:
            keys[vid.split("#", 1)[1]] = raw
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
    import urllib.request

    req = urllib.request.Request(  # noqa: S310
        did_url,
        headers={
            "User-Agent": "inspect-receipts/0.2 (+https://councilof.ai)",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        doc = json.loads(resp.read().decode("utf-8"))
    return public_keys_from_did_doc(doc)


def _resolve_kid(kid: str | None, trust_keys: dict[str, bytes]) -> tuple[bytes | None, bool]:
    if kid in FORBIDDEN_KIDS:
        return None, False
    assert kid is not None
    if kid in trust_keys:
        return trust_keys[kid], True
    return None, False


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
@dataclass
class VerifyResult:
    """Three states, not two.

    ``valid`` stays a bool so existing callers keep working, but it is no longer the whole
    answer. ``state`` distinguishes the two facts a boolean collapses:

        VALID        the signature verifies over these bytes
        INVALID      the bytes disagree with their own signature — a finding about the receipt
        UNCHECKABLE  the check did not complete, so nothing was established either way

    Why this changed (2026-09-04). Konrad Gruszka measured this package independently on
    2026-08-20 and published the result in b7n0de/proofbundle INTEROP.md: a proofbundle receipt
    put through this verifier returned "INVALID — content_id mismatch", while the same package's
    receipt through his verifier returned "unsupported schema". His answer said "I do not speak
    this format". Ours said "this is forged".

    It was worse than the measurement showed. An unresolvable ``kid``, a did:web that would not
    resolve, and any unexpected exception all returned INVALID — so a DNS timeout was reported as
    a forgery. That is the exact failure this project exists to prevent, in its own code, on PyPI.

    A caller written against the old bool is now SAFER, not broken: UNCHECKABLE carries
    ``valid=False``, so nothing that previously passed starts passing.
    """

    valid: bool
    reason: str
    key_resolved: bool = False
    binding_checked: str | None = None
    state: str = "INVALID"

    @property
    def uncheckable(self) -> bool:
        return self.state == "UNCHECKABLE"


def _valid(reason: str, **kw) -> "VerifyResult":
    return VerifyResult(True, reason, state="VALID", **kw)


def _invalid(reason: str, **kw) -> "VerifyResult":
    """The bytes disagree with their own signature. A finding about the receipt."""
    return VerifyResult(False, f"INVALID — {reason}", state="INVALID", **kw)


def _uncheckable(reason: str, **kw) -> "VerifyResult":
    """The check did not complete. Never report this as a forgery."""
    return VerifyResult(False, f"UNCHECKABLE — {reason}", state="UNCHECKABLE", **kw)


def _check_content_id(receipt: dict) -> tuple[bool, str, dict]:
    body = {k: v for k, v in receipt.items() if k != "signature"}
    unsigned_body = _unsigned_body(body)
    expect_cid = sha256_hex(canonical_bytes(unsigned_body))
    if body.get("content_id") != expect_cid:
        return False, f"content_id mismatch (expected {expect_cid[:16]}…)", body
    return True, "", body


def _check_binding(receipt: dict) -> tuple[bool, str, str | None]:
    binding = receipt.get("binding")
    if not isinstance(binding, dict):
        return False, "missing or invalid binding field", None
    btype = binding.get("type")
    if btype == "content-hash":
        if binding.get("digest_alg") not in (None, "sha256"):
            return False, f"unsupported digest_alg {binding.get('digest_alg')!r}", None
        eval_sha = binding.get("eval_log_sha256")
        if eval_sha is not None:
            payload_sha = receipt.get("eval_log_sha256")
            if payload_sha != eval_sha:
                return False, "binding eval_log_sha256 does not match receipt field", None
        return True, "", "content-hash"
    if btype == "merkle":
        return False, "merkle binding declared but not verified by this verifier", None
    return False, f"unsupported binding type {btype!r}", None


def verify(
    receipt: dict,
    trust_keys: dict[str, bytes] | None = None,
) -> VerifyResult:
    """Offline verification with mandatory trust-anchor kid resolution.

    For SIGNED receipts ``trust_keys`` MUST be supplied (typically from
    ``resolve_did_web()``). Embedded ``signer_public_key`` alone never yields
    ``valid=True`` — strangers must resolve ``kid`` against a published anchor.
    """
    try:
        sig_env = receipt.get("signature", {})
        status = sig_env.get("status")

        # A foreign format is not a forgery. Checking content_id first meant any receipt from
        # another project failed as INVALID before we had established we could even read it.
        got_schema = receipt.get("schema")
        if got_schema is not None and not str(got_schema).startswith("csoai.inspect-receipt/"):
            return _uncheckable(
                f"unsupported schema {got_schema!r}, this verifier reads {SCHEMA!r} — "
                "nothing has been established about this receipt"
            )

        ok, reason, body = _check_content_id(receipt)
        if not ok:
            return _invalid(reason)

        b_ok, b_reason, binding_checked = _check_binding(receipt)
        if not b_ok:
            return _invalid(b_reason, binding_checked=None)

        if status == "UNSIGNED" or "sig" not in sig_env:
            # Nothing to check is not the same as failing a check.
            return VerifyResult(
                False,
                "UNSIGNED — content_id valid but receipt carries no signature",
                binding_checked=binding_checked,
                state="UNCHECKABLE",
            )

        kid = sig_env.get("kid")
        if trust_keys is None:
            # The caller supplied no keys. That is a fact about the call, not the receipt.
            return _uncheckable(
                f"no trust anchor; resolve kid {kid!r} via did:web "
                f"(use verify_against_did_web or pass trust_keys=)",
                key_resolved=False,
                binding_checked=binding_checked,
            )

        published, key_resolved = _resolve_kid(kid, trust_keys)
        if not key_resolved or published is None:
            # An unresolvable kid may mean a stale anchor as easily as a bad receipt. The
            # sibling verifier rules the same way: KEY_NOT_PINNED is UNCHECKABLE, not INVALID.
            return _uncheckable(
                f"kid {kid!r} not found in trust anchor "
                f"(available: {sorted(trust_keys)})",
                key_resolved=False,
                binding_checked=binding_checked,
            )

        embedded = sig_env.get("signer_public_key")
        if embedded and bytes.fromhex(embedded) != published:
            # This one IS a finding about the receipt: it embeds a key that contradicts the
            # published anchor. Not an unanswered question — a disagreement in the bytes.
            return VerifyResult(
                False,
                "INVALID — embedded key does not match published trust-anchor key",
                key_resolved=True,
                binding_checked=binding_checked,
                state="INVALID",
            )

        pub = Ed25519PublicKey.from_public_bytes(published)
        pub.verify(bytes.fromhex(sig_env["sig"]), canonical_bytes(body))
        return VerifyResult(
            True,
            f"VALID — signed by {kid} [published trust-anchor key]",
            key_resolved=True,
            binding_checked=binding_checked,
            state="VALID",
        )
    except Exception as e:  # noqa: BLE001
        # An unexpected error is a failure of this verifier, not evidence against the receipt.
        return _uncheckable(f"verifier error: {type(e).__name__}: {e}")


def verify_against_did_web(
    receipt: dict, did_url: str | None = None
) -> VerifyResult:
    """Stranger path: fetch the did:web document named BY THE RECEIPT and verify.

    The anchor is read from the receipt's own ``verify.did_document``. It used to default to
    this estate's document, which meant a stranger verifying someone else's receipt silently
    checked it against CSOAI's keys — and a receipt signed by a third party came back
    UNCHECKABLE or worse for the wrong reason. Passing ``did_url`` explicitly still wins, for
    the case where the caller has out-of-band knowledge of the issuer's key location.
    """
    if did_url is None:
        did_url = ((receipt or {}).get("verify") or {}).get("did_document")
    if not did_url:
        return _uncheckable(
            "receipt names no verify.did_document, and no did_url was supplied — "
            "there is no anchor to resolve, so nothing was established either way"
        )
    try:
        keys = resolve_did_web(did_url)
        return verify(receipt, trust_keys=keys)
    except Exception as e:  # noqa: BLE001
        # A DNS failure, a timeout or an unreachable host says nothing about the receipt.
        return _uncheckable(f"could not resolve did:web: {type(e).__name__}: {e}")


# --------------------------------------------------------------------------- #
# Receipt envelope
# --------------------------------------------------------------------------- #
def base_receipt(kind: str, data: dict) -> dict:
    eval_log_sha = data.get("eval_log_sha256")
    return {
        "schema": SCHEMA,
        "kind": kind,
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "register": (
            "Non-repudiable evidence of what was claimed and when. Not proof the "
            "eval is honest, uncontaminated, or correct. Measurement, not certification."
        ),
        "binding": content_hash_binding(eval_log_sha256=eval_log_sha),
        "verify": {
            "how": (
                "RFC 8785 JCS canonical body → content_id (sha256), then Ed25519 "
                "signature verified against signature.kid resolved from did:web."
            ),
            "canonicalization": "RFC 8785 (JCS)",
            "did": emitter_did(),
            "did_document": emitter_did_doc(),
            "command": "inspect-receipts verify <this-file> --did-web",
            "anchoring": (
                "Ed25519 signature + SHA-256 content-hash binding only. "
                "Merkle / RFC3161 / OpenTimestamps anchoring is optional profile, not wired here."
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
