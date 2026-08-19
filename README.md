# inspect-receipts — Ed25519-signed receipts for Inspect runs

Hooks emit a signed receipt at run-start/run-end; a CLI signs/verifies any Inspect
log. No core fork: hooks entry point + a small signer package.

- **Receipt**: `id = sha256(canonical body)` · `signature = Ed25519(id)` · `prev` links
  the chain · `method_hash` pins the harness version (Inspect 0.3.258 changed scorer
  semantics — hash scorers into receipts).
- **Trust**: `did:web:csoai.org` (`https://csoai.org/.well-known/did.json`) anchors
  the key. Verify offline, forever.
- **CLI**: `python -m inspect_receipts.cli sign log.json --key k` ·
  `verify receipt.json` · `newkey out.seed` (chmod 600).
- **Hooks**: `run_start_hook` / `run_end_hook` — wire via Inspect hook config, key
  from `INSPECT_RECEIPTS_KEY` (env, 0600) or key_path.

Status: scaffold 0.1.0 (tests pass). Coordinate-first: answers AISI Inspect issue
#4413 with a common receipt envelope — merge of efforts > format war.
