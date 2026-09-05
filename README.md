# inspect-receipts — Ed25519-signed measurement receipts for Inspect

[![22 axes measured · 14 model fleets · 3 public leader scores · 8 fact runs · TIE is TIE · not a certificate. Three states only: VALID · INVALID · UNCHECKABLE.](https://councilof.ai/badge/gspc.svg)](https://councilof.ai/gspc-verify)

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
- **RFC 8785 JCS canonicalisation.** `content_id = sha256(JCS(canonical body))` —
  UTF-16 code-unit key order, ECMAScript number formatting, `\u` escaping. Not
  Python `json.dumps(sort_keys=True)`.
- **Content-addressed + hash-chained.** Each receipt declares a `binding` field
  (`content-hash` today; `merkle` is an optional profile). Verifiers report
  `binding_checked` — what was actually checked, not only pass/fail.
- **Verify against a *published* key (mandatory).** `verify()` fails closed unless
  `signature.kid` resolves in the trust anchor (default: **`did:web:csoai.org`**
  at `https://csoai.org/.well-known/did.json`). Self-embedded keys never return
  `valid=True`. Default signing kid: `did:web:csoai.org#estate-chain-1` (eval /
  measurement-chain receipts; aligns with the live four-key did document).
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
export INSPECT_RECEIPTS_KID="did:web:csoai.org#estate-chain-1"           # optional; default estate-chain-1
export INSPECT_RECEIPTS_DIR=./receipts                                   # optional; default ./receipts

inspect eval my_task.py --model openai/gpt-4o
# -> ./receipts/task-<id>.receipt.json and run-<id>.receipt.json
```

## Verify (what a UK AISI maintainer runs)

```bash
# Requires trust-anchor resolution (fails closed without --did-web)
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
  "binding": { "type": "content-hash", "digest_alg": "sha256" },
  "verify": { "did": "did:web:csoai.org", "canonicalization": "RFC 8785 (JCS)", "command": "inspect-receipts verify <file> --did-web" },
  "signature": { "status": "SIGNED", "alg": "Ed25519", "kid": "did:web:csoai.org#estate-chain-1", "signer_public_key": "…", "sig": "…" }
}
```

## Tests

```bash
pip install -e ".[test]"
pytest -q            # or: python tests/test_receipt.py
```

## Status

`0.2.1`. Coordinate-first: answers Inspect issue
[#4413](https://github.com/UKGovernmentBEIS/inspect_ai/issues/4413) with a common
signed-receipt envelope. License: Apache-2.0.

## Where these properties were worked out

Four of the properties this package documents as design decisions were not arrived at here.
They came out of a public measurement series with [proofbundle](https://github.com/b7n0de/proofbundle),
run against named commits in both directions:

- **RFC 8785 canonicalisation (R1)** — [proofbundle#147](https://github.com/b7n0de/proofbundle/issues/147).
  Our encoder ran `ensure_ascii=True` while claiming JCS; it diverged on 4 of the 6 named
  vectors. Corrected in 0.3.0, which changes `content_id` for any non-ASCII body.
- **A foreign schema id is its own outcome, not invalid (R2)** — same issue, E1.
- **`binding_checked` is true only when the digest was present *and* compared (R3)** — same issue, E2.
- **Key resolution fails closed (R4)** — the key-resolution probes in that series.

The envelope profile is `proofbundle/receipt-envelope-profile/v0.1`, which lives in
[proofbundle](https://github.com/b7n0de/proofbundle/blob/main/docs/RECEIPT_ENVELOPE_PROFILE.md)
and is archived at [10.5281/zenodo.22209671](https://doi.org/10.5281/zenodo.22209671). It keeps
its name and its home there; this is an independent implementation of it, not a second copy of
the profile. Conformance is shown by running that profile's probes and posting the result — it
is never conferred, and no party is appointed to judge another's.

The trust anchor is the emitter's field. `did:web:csoai.org` is CSOAI's value, not the format's;
set `INSPECT_RECEIPTS_DID` / `INSPECT_RECEIPTS_DID_DOC` to emit under your own root.
