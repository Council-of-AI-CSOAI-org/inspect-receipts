"""CLI: inspect-receipts sign <log.json> / verify <receipt.json>
Mirrors the requested `inspect log sign/verify` surface without forking core."""
import argparse
import json
import sys
from .signer import ReceiptSigner, verify_receipt


def main(argv=None):
    ap = argparse.ArgumentParser(prog="inspect-receipts")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_sign = sub.add_parser("sign"); p_sign.add_argument("log"); p_sign.add_argument("--key", default=None)
    p_ver = sub.add_parser("verify"); p_ver.add_argument("receipt")
    p_key = sub.add_parser("newkey"); p_key.add_argument("out")
    args = ap.parse_args(argv)
    if args.cmd == "sign":
        log = json.load(open(args.log))
        body = {"kind": "inspect.log", "eval": log.get("eval", {}).get("id"),
                "n_samples": len(log.get("results", {}).get("samples", [])),
                "scores": log.get("results", {}).get("scores", {})}
        r = ReceiptSigner(key_path=args.key).sign(body)
        print(json.dumps(r, indent=2)); return 0
    if args.cmd == "verify":
        r = json.load(open(args.receipt))
        verify_receipt(r); print("SIGNATURE VALID — verified offline"); return 0
    if args.cmd == "newkey":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        seed = Ed25519PrivateKey.generate().private_bytes_raw()
        open(args.out, "wb").write(seed)
        print(f"new 32-byte Ed25519 seed written to {args.out} (chmod 600 it)"); return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
