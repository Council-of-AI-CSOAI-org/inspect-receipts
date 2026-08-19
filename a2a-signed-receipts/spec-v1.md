# A2A `signed-receipts/v1` — extension spec (draft, PR-ready)
Fills the deliberately-open key-trust gap in A2A §8.4 with did:web identity.

## 1 · Purpose
A2A Agent Cards describe capabilities; nothing signs WHAT THE AGENT DID. This
extension attaches a signed receipt to task completions: id = sha256(canonical body),
Ed25519 signature, prev-chain, method_hash, optional RFC 3161 timestamp.

## 2 · Trust root
- Key anchored by **did:web:csoai.org** (`https://csoai.org/.well-known/did.json`).
- Verify: resolve did → public key → verify signature. Offline, forever, no account.

## 3 · Envelope (JSON, added to task completion / card)
```json
{
  "kind": "a2a.signed-receipt/v1",
  "id": "<sha256(canonical body)>",
  "signature": "<ed25519 hex>",
  "pubkey_did": "did:web:csoai.org",
  "body": {
    "task_id": "...", "agent_card": "did:web:csoai.org#agent",
    "outcome": "success|failure|unmeasured",
    "metrics": {"axis": "gov", "score": 0.658, "n": 193, "ci95": [0.589, 0.721]},
    "method_hash": "<harness+scorer version hash>",
    "prev": "<prior receipt id>"
  }
}
```
- UNMEASURED stays UNMEASURED — an outcome of "unmeasured" is never scored.

## 4 · Interop
Compatible with the inspect-receipts envelope (same canonicalization: sorted keys,
compact JSON). Supersession = new receipt with prev = old id (never re-sign).

## 5 · Status
DRAFT — coordinate-first with the A2A WG before any registry change.
