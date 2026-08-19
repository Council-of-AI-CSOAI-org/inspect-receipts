# inspect-receipts

**Ed25519-signed measurement receipts for [Inspect AI](https://inspect.aisi.org.uk) eval runs.**
A receipt is non-repudiable evidence of *what was claimed and when* — not proof the eval is
honest, uncontaminated, or correct. Measurement, not certification.

Opt-in lifecycle hooks (in the `wandb_weave.py` / `mlflow_tracking.py` example style) that emit:

- a **task receipt** on `on_task_end` — eval id + SHA-256 of the produced log
- a **run receipt** on `on_run_end` — run id + SHA-256 of every produced log

Each receipt is canonical JSON (sorted keys), content-addressed (SHA-256) and signed
(Ed25519). Anyone can verify **offline** — no account, no service, no fee:

```bash
inspect-receipts verify receipts/run-*.receipt.json
```

## Quickstart

```bash
pip install inspect-receipts

# one-time: create a signing seed (keep private; publish only the public key)
inspect-receipts keygen ~/.inspect-receipts.seed

export INSPECT_RECEIPTS=1
export INSPECT_RECEIPTS_KEY=~/.inspect-receipts.seed
export INSPECT_RECEIPTS_KID="did:web:your-domain.example#eval-1"   # optional but recommended
inspect eval my_task.py --model ...
# → receipts/task-<eval_id>.receipt.json + receipts/run-<run_id>.receipt.json
```

## Key trust

The receipt embeds the signer's public key, so `verify` proves integrity + signature
offline. To prove *who* signed, publish the public key at a stable identity — e.g. a
`did:web` document — and set `INSPECT_RECEIPTS_KID` to that key id. Verifiers then
compare the receipt's `signer_public_key` against the published document.

## Design rules

- **Opt-in** (`INSPECT_RECEIPTS=1`) — zero behaviour change otherwise.
- **Never breaks an eval** — every emission is defensively wrapped.
- **No key ever ships** — the package holds no key material; `keygen` writes a local 0600 seed.
- **Honest register** — every receipt carries: *"Not proof the eval is honest, uncontaminated,
  or correct."*

## Status

v0.1 scaffold, offered upstream coordinate-first (see Inspect issue #4413 discussion —
complementary to, not competing with, other receipt hooks). Apache-2.0.
