"""Inspect AI lifecycle hooks that emit signed receipts.

Opt-in: set INSPECT_RECEIPTS=1 and INSPECT_RECEIPTS_KEY=/path/to/seed (32-byte
Ed25519 seed). Follows the wandb_weave / mlflow_tracking example-hook style.

Emits:
  - one TASK receipt on_task_end  (eval id, task spec digest, log file hash)
  - one RUN receipt  on_run_end   (run id, every produced log file hashed)

Hook data objects are owned by the framework and are never mutated here.
Failures never disrupt an eval: every emission is wrapped defensively (in
addition to Inspect's own try/except around hooks).
"""

from __future__ import annotations

import os

from inspect_ai.hooks import Hooks, RunEnd, TaskEnd, hooks

from .receipt import ENV_ENABLE, Signer, base_receipt, sha256_file, write_receipt


def _enabled() -> bool:
    return os.environ.get(ENV_ENABLE, "") == "1"


@hooks(name="inspect_receipts", description="Signed measurement receipts for eval runs")
class ReceiptHooks(Hooks):
    """Emit an Ed25519-signed receipt for each task and each run."""

    async def on_task_end(self, data: TaskEnd) -> None:
        if not _enabled():
            return
        try:
            signer = Signer.from_env()
            if signer is None:
                return
            log = getattr(data, "log", None)
            location = getattr(log, "location", None) if log is not None else None
            payload = base_receipt(
                "task",
                {
                    "eval_id": getattr(data, "eval_id", None),
                    "run_id": getattr(data, "run_id", None),
                    "log_location": location,
                    "log_sha256": sha256_file(location) if location and os.path.exists(location) else None,
                },
            )
            write_receipt(signer.sign(payload), f"task-{payload.get('eval_id') or 'unknown'}")
        except Exception:  # noqa: BLE001 — a receipt failure must never break an eval
            pass

    async def on_run_end(self, data: RunEnd) -> None:
        if not _enabled():
            return
        try:
            signer = Signer.from_env()
            if signer is None:
                return
            logs = []
            for log in list(getattr(data, "logs", []) or []):
                location = getattr(log, "location", None)
                logs.append(
                    {
                        "location": location,
                        "sha256": sha256_file(location) if location and os.path.exists(location) else None,
                    }
                )
            payload = base_receipt(
                "run",
                {
                    "run_id": getattr(data, "run_id", None),
                    "exception": repr(getattr(data, "exception", None)) if getattr(data, "exception", None) else None,
                    "logs": logs,
                },
            )
            write_receipt(signer.sign(payload), f"run-{payload.get('run_id') or 'unknown'}")
        except Exception:  # noqa: BLE001
            pass
