"""inspect-receipts: Ed25519-signed, offline-verifiable measurement receipts for
UK AISI Inspect eval runs.

Measurement, not certification. The signing key is owner-provisioned and never
ships here; public keys are published at did:web:csoai.org.
"""

from __future__ import annotations

from .receipt import (
    SCHEMA,
    Signer,
    base_receipt,
    canonical_bytes,
    eval_log_digest,
    resolve_did_web,
    unsigned,
    verify,
    verify_against_did_web,
)

__version__ = "0.2.0"

__all__ = [
    "SCHEMA",
    "Signer",
    "base_receipt",
    "canonical_bytes",
    "eval_log_digest",
    "resolve_did_web",
    "unsigned",
    "verify",
    "verify_against_did_web",
    "__version__",
]
