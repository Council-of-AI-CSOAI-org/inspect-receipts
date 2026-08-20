# inspect-receipts — Ed25519-signed measurement receipts for Inspect

UK AISI's [Inspect](https://github.com/UKGovernmentBEIS/inspect_ai) is the
standard eval framework, but it has no cryptographic signing of results.
`inspect-receipts` fills that gap: a small, dependency-light package that hooks
Inspect's lifecycle and emits an **Ed25519-signed, hash-chained,
offline-verifiable measurement receipt** for every task and run.

> **Doctrine:** *measurement, not certification.* A receipt is non-repudiable
> evidence of **what was claimed and when** — not proof that an eval is honest,
> uncontaminated, or correct. Deterministic. Nobody ranked pays; humans never pay.

This repo open-sources the **receipt format + exporter** only. The axes,
predicates, and benchmarks stay closed and are not in this repo.

## How it works

- **Hook, no fork.** Registers through Inspect's `inspect_ai` setuptools
  entry-point group (the same mechanism [`inspect-mlflow`](https://github.com/meridianlabs-ai/inspect_mlflow)
  uses). Inspect imports the module and the `@hooks`-decorated class
  self-registers, hooking the real lifecycle: `on_task_end` and `on_run_end`.
- **Signs the EvalLog *object model*, not raw `.eval` bytes.** The physical
  `.eval` file is a version-dependent zstd ZIP-of-JSON; hashing those bytes is
  fragile across Inspect releases. Instead the receipt canonicalises a stable
  field subset of the `EvalLog` object — eval id, run id, task, model, dataset
  identity, scores/metrics, timestamps — into deterministic JSON (recursively
  sorted keys, no whitespace), then `SHA-256`-hashes and Ed25519-signs *that*.
- **Content-addressed + hash-chained.** `content_id = sha256(canonical body)`;
  each receipt's `prev` links the previous receipt's `content_id`.
- **Verify against a *published* key.** Signatures are verifiable offline
  against the CSOAI board-attestation key published at **`did:web:csoai.org`**
  (`https://csoai.org/.well-known/did.json`, `verificationMethod` /
  `publicKeyJwk`) — the same key path the live board `/api/gspc` uses. A stranger
  verifies against the published key, not a key the receipt vouches for itself.
- **No private key ever ships.** The signing key is provisioned by the owner via
  `INSPECT_RECEIPTS_KEY` (a 0600 seed file / secret). With **no** key configured,
  the hook emits an **UNSIGNED** receipt with an explicit `status` — a signature
  is never fabricated.

## Install

```bash
pip install inspect-receipts        # once published to PyPI (owner-gated)
# or from source:
pip install -e .
```

## Emit receipts from an eval run

Opt-in via env; the hook does nothing unless `INSPECT_RECEIPTS=1`.

```bash
export INSPECT_RECEIPTS=1
export INSPECT_RECEIPTS_KEY=/run/secrets/inspect_receipts_ed25519.seed  # owner-provisioned, 0600
export INSPECT_RECEIPTS_KID="did:web:csoai.org#keys-1"                   # optional; default keys-1
export INSPECT_RECEIPTS_DIR=./receipts                                   # optional; default ./receipts

inspect eval my_task.py --model openai/gpt-4o
# -> ./receipts/task-<id>.receipt.json and run-<id>.receipt.json
```

## Verify (what a UK AISI maintainer runs)

```bash
# offline integrity + signature (embedded key — integrity only)
inspect-receipts verify receipts/task-*.receipt.json

# trust path: fetch the PUBLISHED key from did:web:csoai.org and require the
# signature to verify under it
inspect-receipts verify receipts/task-*.receipt.json --did-web
```

`verify` exits non-zero on any failure. UNSIGNED receipts report as UNSIGNED and
fail (they are content-addressed but not attributable to a key).

## CLI

```
inspect-receipts keygen <seed-file>            # 32-byte Ed25519 seed, mode 0600 (publish only the PUBLIC key)
inspect-receipts sign  <log.eval> [--key SEED] [--out FILE]   # receipt from an EvalLog object
inspect-receipts verify <receipt.json> [...] [--did-web [URL]]
```

## What is and isn't anchored

**Real today:** Ed25519 signatures + a SHA-256 content-address and per-run
hash-chain, verifiable offline against the `did:web:csoai.org` published key.

**Roadmap / optional (NOT wired):** transparency-log inclusion (Rekor),
RFC 3161 timestamping, and OpenTimestamps anchoring. These are not implemented;
no receipt claims them. Do not rely on any timestamp-authority anchoring here.

## Receipt shape (abridged)

```json
{
  "schema": "csoai.inspect-receipt/0.2",
  "kind": "task",
  "issued_at": "2026-08-20T01:39:22Z",
  "eval_id": "…", "run_id": "…", "prev": null,
  "eval_log": { "status": "success", "eval": { "eval_id": "…", "task": "…", "model": "…", "dataset": {…} }, "results": {…}, "stats": {…} },
  "eval_log_sha256": "…",
  "content_id": "sha256(canonical body)",
  "verify": { "did": "did:web:csoai.org", "command": "inspect-receipts verify <file> --did-web", "anchoring": "Ed25519 + SHA-256 hash-chain only; Rekor/RFC3161/OTS are roadmap." },
  "signature": { "status": "SIGNED", "alg": "Ed25519", "kid": "did:web:csoai.org#keys-1", "signer_public_key": "…", "sig": "…" }
}
```

## Tests

```bash
pip install -e ".[test]"
pytest -q            # or: python tests/test_receipt.py
```

## Status

`0.2.0`. Coordinate-first: answers Inspect issue
[#4413](https://github.com/UKGovernmentBEIS/inspect_ai/issues/4413) with a common
signed-receipt envelope. License: Apache-2.0.
