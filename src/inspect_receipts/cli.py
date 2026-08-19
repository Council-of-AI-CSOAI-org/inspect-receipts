"""CLI: keygen + offline verification.

  inspect-receipts keygen  <seed-file>          # create a 32-byte Ed25519 seed (0600)
  inspect-receipts verify  <receipt.json> [...] # offline verify; exit 1 on any failure
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path

from .receipt import verify


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(__doc__)
        return 2
    cmd, rest = args[0], args[1:]

    if cmd == "keygen":
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

    if cmd == "verify":
        if not rest:
            print("usage: inspect-receipts verify <receipt.json> [...]")
            return 2
        failed = 0
        for p in rest:
            receipt = json.loads(Path(p).read_text(encoding="utf-8"))
            ok, reason = verify(receipt)
            print(f"{p}: {reason}")
            failed += 0 if ok else 1
        return 1 if failed else 0

    print(f"unknown command: {cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
