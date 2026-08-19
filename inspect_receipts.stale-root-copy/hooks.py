"""Inspect hooks — emit signed receipts on run-start/run-end without forking core.
Compatible with Inspect 0.3.x hook entry points (inspect eval --hooks ...)."""
from __future__ import annotations
from .signer import ReceiptSigner


def run_start_hook(event):
    signer = ReceiptSigner()  # key from env INSPECT_RECEIPTS_KEY or key_path in config
    body = {"kind": "inspect.run-start", "eval": event.get("eval", {}).get("id"),
            "task": event.get("eval", {}).get("task"),
            "model": event.get("eval", {}).get("model"),
            "method_hash": event.get("_method_hash")}
    return signer.sign(body)


def run_end_hook(event):
    signer = ReceiptSigner()
    body = {"kind": "inspect.run-end", "eval": event.get("eval", {}).get("id"),
            "status": event.get("status"),
            "samples": len(event.get("samples", [])),
            "scorer_version": event.get("_scorer_version"),
            "method_hash": event.get("_method_hash")}
    return signer.sign(body)
