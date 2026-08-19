# Draft comment for UKGovernmentBEIS/inspect_ai issue #4413 (post ONLY after owner nod)

> +1 to this pattern — we'd find it genuinely useful, and we've been building in the same
> direction. To support the case for a receipts-style example hook: we've scaffolded a small
> opt-in hooks package (`inspect-receipts`, Apache-2.0) in the `wandb_weave.py` /
> `mlflow_tracking.py` style — `on_task_end` / `on_run_end` emit canonical-JSON,
> SHA-256-content-addressed, Ed25519-signed receipts over the produced log hashes, with an
> offline `verify` CLI and optional `did:web` key binding. Same register as proposed here:
> non-repudiable evidence of what was claimed and when — not proof the eval is honest or
> uncontaminated.
>
> We see this as complementary to the proofbundle proposal (different signing backends, same
> hook shape) — happy to align on a common receipt envelope if that's useful, contribute ours
> as an example hook, or simply keep it as an external package the docs can point to.
> Whatever the maintainers prefer. Repo: <link when public>.

Etiquette checklist (standing firewalls):
- [ ] One genuine PR per upstream — this comment first, PR only if invited
- [ ] Never claim AISI usage/endorsement
- [ ] Complementary-to-#4413-author framing (they proposed proofbundle; do not step on it)
- [ ] Measurement-not-certification register verbatim in any contributed docs
