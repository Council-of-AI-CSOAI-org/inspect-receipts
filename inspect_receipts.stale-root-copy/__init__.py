"""inspect-receipts — Ed25519-signed receipts for UK AISI Inspect runs.

Hooks emit a signed receipt at run-start and run-end; a CLI signs/verifies any
Inspect log. Every receipt: id = sha256(canonical body), signature = Ed25519(id),
prev links the chain, method hash pins the harness version (Inspect scorer
semantics changed in 0.3.258 — hash it into receipts).

Coordinate-first: this package answers AISI Inspect issue #4413 (open since
3 Jul 2026) with a common receipt envelope. Measurement, not certification.
"""
from .hooks import run_start_hook, run_end_hook
from .signer import ReceiptSigner, verify_receipt
__version__ = "0.1.0"
__all__ = ["run_start_hook", "run_end_hook", "ReceiptSigner", "verify_receipt", "__version__"]
