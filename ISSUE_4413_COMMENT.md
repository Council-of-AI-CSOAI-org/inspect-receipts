# Coordinate-first comment (draft) for Inspect issue #4413 — NOT POSTED, owner nod first
> Hi — dropping a coordinate-first note before any PR, per good upstream practice.
> We've been building signed measurement receipts for agent eval runs and hit the
> same gap this issue describes. Proposal: a common receipt envelope both efforts
> can merge on:
> - run-start/run-end hooks emitting a receipt: id = sha256(canonical body),
>   Ed25519 signature, prev-chain, method_hash (scorer/harness version pinned —
>   note Inspect 0.3.258 changed scorer semantics).
> - identity anchored to did:web (our root: https://csoai.org/.well-known/did.json)
>   + optional RFC 3161 timestamp; supersession chains instead of re-signs.
> - a small stats package (Wilson CIs, MDE, optional BH/Holm) so the receipt is a
>   complete evidence unit, plus an appeals path.
> Scaffold lives at github.com/CSOAI-ORG/inspect-receipts. Happy to adapt the
> envelope to what this repo prefers — merge of efforts beats a format war at two
> stars vs zero. No PR sent without maintainer reply.
