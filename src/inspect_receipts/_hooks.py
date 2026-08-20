"""Inspect AI lifecycle hooks that emit signed measurement receipts.

Registered via the ``inspect_ai`` setuptools entry-point group (see
``pyproject.toml``) — the same mechanism ``inspect-mlflow`` uses. Inspect imports
this module on startup and the ``@hooks``-decorated class self-registers.

Opt-in: set ``INSPECT_RECEIPTS=1``. Signing is provisioned by the owner via
``INSPECT_RECEIPTS_KEY`` (path to a 32-byte Ed25519 seed, mode 0600). With no key
the receipt is emitted UNSIGNED with an explicit status — never fabricated.

Emits:
  - one TASK receipt on ``on_task_end`` — canonical EvalLog object digest, signed
  - one RUN receipt  on ``on_run_end``  — every produced log digested + chained

What is signed is the canonical **EvalLog object model** (see receipt.py:
``eval_log_digest``), NOT the raw ``.eval`` ZIP bytes, which are version-volatile.

Hook data objects are owned by the framework and are never mutated here. A
receipt failure must never disrupt an eval: every emission is wrapped
defensively (in addition to Inspect's own guard around hooks).
"""

from __future__ import annotations

import os

from inspect_ai.hooks import Hooks, RunEnd, TaskEnd, hooks

from .receipt import (
    ENV_ENABLE,
    Signer,
    base_receipt,
    canonical_bytes,
    eval_log_digest,
    sha256_hex,
    unsigned,
    write_receipt,
)

# Lightweight per-process hash chain: each receipt links the previous one's
# content_id. This is the SHA-256 hash-chain referenced in the README.
_LAST_CID: str | None = None


def _enabled() -> bool:
    return os.environ.get(ENV_ENABLE, "") == "1"


def _envelope(payload: dict) -> dict:
    """Sign the payload if a key is configured, else return an UNSIGNED receipt."""
    signer = Signer.from_env()
    return signer.sign(payload) if signer is not None else unsigned(payload)


def _emit(kind: str, data: dict, stem: str) -> None:
    global _LAST_CID
    if data.get("prev") is None:
        data = {**data, "prev": _LAST_CID}
    receipt = _envelope(base_receipt(kind, data))
    _LAST_CID = receipt.get("content_id")
    write_receipt(receipt, stem)


def _digest_log(log: object) -> dict:
    """Canonical object-model digest of one EvalLog, plus its hash."""
    obj = eval_log_digest(log)
    return {
        "eval_log": obj,
        "eval_log_sha256": sha256_hex(canonical_bytes(obj)),
        "log_location": getattr(log, "location", None),
    }


@hooks(name="inspect_receipts", description="Signed measurement receipts for eval runs")
class ReceiptHooks(Hooks):
    """Emit an Ed25519-signed (or explicitly UNSIGNED) receipt per task and run."""

    def enabled(self) -> bool:
        return _enabled()

    async def on_task_end(self, data: TaskEnd) -> None:
        if not _enabled():
            return
        try:
            log = getattr(data, "log", None)
            payload = {
                "eval_id": getattr(data, "eval_id", None),
                "run_id": getattr(data, "run_id", None),
                **(_digest_log(log) if log is not None else {}),
            }
            _emit("task", payload, f"task-{payload.get('eval_id') or 'unknown'}")
        except Exception:  # noqa: BLE001 — a receipt failure must never break an eval
            pass

    async def on_run_end(self, data: RunEnd) -> None:
        if not _enabled():
            return
        try:
            logs = [_digest_log(log) for log in (getattr(data, "logs", None) or [])]
            exc = getattr(data, "exception", None)
            payload = {
                "run_id": getattr(data, "run_id", None),
                "exception": repr(exc) if exc else None,
                "logs": logs,
            }
            _emit("run", payload, f"run-{payload.get('run_id') or 'unknown'}")
        except Exception:  # noqa: BLE001
            pass
