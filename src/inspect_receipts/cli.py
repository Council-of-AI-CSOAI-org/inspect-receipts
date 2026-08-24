"""CLI: keygen, sign an Inspect log, and offline/did:web verification.

  inspect-receipts keygen <seed-file>
      Create a 32-byte Ed25519 seed (mode 0600). Publish only the PUBLIC key.

  inspect-receipts sign <log.eval|log.json> [--key SEED] [--out FILE]
      Build a receipt from an Inspect EvalLog. Canonicalises the EvalLog OBJECT
      MODEL (not raw .eval bytes), then signs with the seed at --key or
      $INSPECT_RECEIPTS_KEY. With no key, writes an UNSIGNED receipt.

  inspect-receipts verify <receipt.json> [...] [--did-web [URL]]
      Recompute content_id and verify the Ed25519 signature. With --did-web the
      signature must verify under the PUBLISHED key resolved from the receipt's
      kid (default did document: https://csoai.org/.well-known/did.json).
      Exit 1 on any failure.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path

from .receipt import (
    DID_DOC_URL,
    Signer,
    base_receipt,
    canonical_bytes,
    eval_log_digest,
    sha256_hex,
    unsigned,
    verify,
    verify_against_did_web,
)


def _load_eval_log(path: str) -> object:
    """Load an EvalLog via Inspect when available; else a permissive shim.

    The shim lets ``sign`` work on a plain-JSON export in environments without a
    full Inspect install; ``eval_log_digest`` reads attributes defensively.
    """
    try:
        from inspect_ai.log import read_eval_log

        return read_eval_log(path)
    except Exception:  # noqa: BLE001
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return _shim(data)


class _shim:
    """Attribute view over a dict (recursive) so getattr-based digest works."""

    def __init__(self, d: object):
        self._d = d if isinstance(d, dict) else {}

    def __getattr__(self, name: str):
        v = self._d.get(name)
        return _shim(v) if isinstance(v, dict) else v


def _cmd_keygen(rest: list[str]) -> int:
    if len(rest) != 1:
        print("usage: inspect-receipts keygen <seed-file>")
        return 2
    path = Path(rest[0])
    if path.exists():
        print(f"refusing to overwrite existing key: {path}")
        return 1
    path.write_bytes(secrets.token_bytes(32))
    os.chmod(path, 0o600)
    print(f"wrote 32-byte Ed25519 seed to {path} (mode 0600)")
    print("Publish the PUBLIC key (e.g. in a did:web document) — never this file.")
    return 0


def _cmd_sign(rest: list[str]) -> int:
    key_path = None
    out = None
    logs: list[str] = []
    it = iter(rest)
    for a in it:
        if a == "--key":
            key_path = next(it, None)
        elif a == "--out":
            out = next(it, None)
        else:
            logs.append(a)
    if len(logs) != 1:
        print("usage: inspect-receipts sign <log> [--key SEED] [--out FILE]")
        return 2

    if key_path:
        os.environ["INSPECT_RECEIPTS_KEY"] = key_path
    log = _load_eval_log(logs[0])
    obj = eval_log_digest(log)
    payload = base_receipt(
        "task",
        {
            "eval_id": getattr(getattr(log, "eval", None), "eval_id", None),
            "run_id": getattr(getattr(log, "eval", None), "run_id", None),
            "eval_log": obj,
            "eval_log_sha256": sha256_hex(canonical_bytes(obj)),
            "log_location": getattr(log, "location", logs[0]),
            "prev": None,
        },
    )
    signer = Signer.from_env()
    receipt = signer.sign(payload) if signer is not None else unsigned(payload)
    text = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print(f"wrote {receipt['signature']['status'].lower()} receipt to {out}")
    else:
        sys.stdout.write(text)
    return 0


def _cmd_verify(rest: list[str]) -> int:
    did_web = False
    did_url = DID_DOC_URL
    files: list[str] = []
    it = iter(rest)
    for a in it:
        if a == "--did-web":
            did_web = True
        elif a.startswith("http://") or a.startswith("https://") or a.startswith("file://"):
            did_url = a  # optional custom did document URL
        else:
            files.append(a)
    if not files:
        print("usage: inspect-receipts verify <receipt.json> [...] [--did-web [URL]]")
        return 2
    failed = 0
    for p in files:
        receipt = json.loads(Path(p).read_text(encoding="utf-8"))
        if did_web:
            result = verify_against_did_web(receipt, did_url)
        else:
            result = verify(receipt)
        print(f"{p}: {result.reason}")
        failed += 0 if result.valid else 1
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(__doc__)
        return 2
    cmd, rest = args[0], args[1:]
    if cmd == "keygen":
        return _cmd_keygen(rest)
    if cmd == "sign":
        return _cmd_sign(rest)
    if cmd == "verify":
        return _cmd_verify(rest)
    print(f"unknown command: {cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
