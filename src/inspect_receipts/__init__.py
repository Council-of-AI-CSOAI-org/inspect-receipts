"""inspect-receipts: Ed25519-signed, offline-verifiable measurement receipts for
UK AISI Inspect eval runs.

Measurement, not certification. The signing key is owner-provisioned and never
ships here; public keys are published at did:web:csoai.org.
"""

from __future__ import annotations

from .canonical import canonical_bytes, jcs, jcs_bytes
from .receipt import (
    SCHEMA,
    Signer,
    VerifyResult,
    base_receipt,
    content_hash_binding,
    eval_log_digest,
    resolve_did_web,
    unsigned,
    verify,
    verify_against_did_web,
    verify_chain,
    ChainResult,
)

__version__ = "0.3.1"

__all__ = [
    "SCHEMA",
    "Signer",
    "VerifyResult",
    "ChainResult",
    "verify_chain",
    "base_receipt",
    "canonical_bytes",
    "content_hash_binding",
    "eval_log_digest",
    "jcs",
    "jcs_bytes",
    "resolve_did_web",
    "unsigned",
    "verify",
    "verify_against_did_web",
    "__version__",
]
