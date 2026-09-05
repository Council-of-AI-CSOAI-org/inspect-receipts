"""R1 canonicalisation and the emitter's trust anchor — both from proofbundle#147.

Two defects this file pins, each of which passed every existing test:

  · canonical_bytes() ran the JCS encoder with ensure_ascii=True while the module docstring
    claimed RFC 8785 and claimed verification against #147's divergence vectors. Escaping is
    precisely where the forms part, so the claim was false for every non-ASCII body — and true
    for every ASCII one, which is why the suite stayed green.

  · base_receipt() stamped did:web:csoai.org into every receipt regardless of who emitted it,
    and verify_against_did_web() defaulted to this estate's DID document. A third party using
    the library produced receipts asserting our root over their evidence, and a stranger
    verifying a third party's receipt silently checked it against our keys.
"""

from __future__ import annotations

import jcs
import pytest

from inspect_receipts.canonical import canonical_bytes
from inspect_receipts import receipt as R

# The vectors named in proofbundle#147, plus the two that always agreed.
VECTORS = [
    {"café": 1},
    {"a": "naïve", "b": "ascii"},
    {"emoji": "🎯"},
    {"é": 1, "e": 2},
    {"ascii_only": 1},
    {"n": 1.0, "big": 1e21},
]


@pytest.mark.parametrize("v", VECTORS, ids=lambda v: str(v)[:24])
def test_canonical_bytes_is_rfc8785(v):
    # The library's own normative entry point is the oracle; we must equal it exactly.
    assert canonical_bytes(v) == jcs.canonicalize(v)


def test_non_ascii_is_not_escaped():
    # The specific failure: é instead of é. RFC 8785 §3.2.2.2 uses minimal escaping.
    assert canonical_bytes({"café": 1}) == b'{"caf\xc3\xa9":1}'
    assert b"\\u00e9" not in canonical_bytes({"café": 1})


def test_schema_moved_because_content_id_changed():
    # Old receipts do not re-verify under the new form. They are not edited; the id moves so a
    # verifier can tell them apart and report an old one as its own outcome, not as invalid.
    assert R.SCHEMA == "csoai.inspect-receipt/0.3"


def test_receipt_carries_the_emitters_anchor_not_a_baked_in_one(monkeypatch):
    monkeypatch.setenv(R.ENV_DID, "did:web:example.org")
    monkeypatch.setenv(R.ENV_DID_DOC, "https://example.org/.well-known/did.json")
    r = R.base_receipt("test", {"eval_log_sha256": "0" * 64})
    assert r["verify"]["did"] == "did:web:example.org"
    assert r["verify"]["did_document"] == "https://example.org/.well-known/did.json"
    assert "csoai" not in str(r["verify"]).lower()


def test_estate_values_are_the_default_but_not_the_format(monkeypatch):
    monkeypatch.delenv(R.ENV_DID, raising=False)
    monkeypatch.delenv(R.ENV_DID_DOC, raising=False)
    assert R.base_receipt("test", {})["verify"]["did"] == R.ESTATE_DID_WEB


def test_verify_resolves_the_anchor_named_by_the_receipt(monkeypatch):
    seen: list[str] = []

    def fake_resolve(url):
        seen.append(url)
        return {}

    monkeypatch.setattr(R, "resolve_did_web", fake_resolve)
    R.verify_against_did_web(
        {"verify": {"did_document": "https://example.org/.well-known/did.json"}}
    )
    assert seen == ["https://example.org/.well-known/did.json"], (
        "verifier must resolve the receipt's own anchor, never this estate's by default"
    )


def test_no_anchor_named_is_uncheckable_not_invalid():
    res = R.verify_against_did_web({"verify": {}})
    assert res.state == "UNCHECKABLE"
