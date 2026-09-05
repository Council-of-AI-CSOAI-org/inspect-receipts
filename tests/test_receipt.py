"""Round-trip tests: build a receipt from a sample EvalLog object, verify it.

Runnable with pytest or as a plain script. Uses a real inspect_ai EvalLog object
when available; falls back to a duck-typed stand-in.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from inspect_receipts.canonical import canonical_bytes, jcs  # noqa: E402
from inspect_receipts.receipt import (  # noqa: E402
    DEFAULT_KID,
    Signer,
    VerifyResult,
    base_receipt,
    content_hash_binding,
    eval_log_digest,
    public_keys_from_did_doc,
    sha256_hex,
    unsigned,
    verify,
)


def _live_did_doc() -> dict:
    """Minimal mirror of https://csoai.org/.well-known/did.json (2026-08-24 stack)."""
    return {
        "id": "did:web:csoai.org",
        "verificationMethod": [
            {
                "id": "did:web:csoai.org#site-release-1",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "03g9l-dVNGVEAVVWQrJU9aLtkYTN3uARd52P7DEq-8g",
                    "kid": "csoai-site-release-1",
                },
            },
            {
                "id": "did:web:csoai.org#estate-chain-1",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "M0cuAmhx2yDNvZnnbEdTLr_PhLN6vtWyYNrjWJ31aW0",
                    "kid": "csoai-estate-chain-1",
                },
            },
            {
                "id": "did:web:csoai.org#board-attestation-1",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "k2fPWb6ctyu8l5at8FYgHsHFit_qoT-DssW3VNbCAXA",
                    "kid": "csoai-board-attestation-1",
                },
            },
            {
                "id": "did:web:csoai.org#card-attestation-1",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "1MsOqhbV9Qv3Yzo2qjT-CaVeEkuTFt7Sq9sSK7nDfjg",
                    "kid": "csoai-card-attestation-1",
                },
            },
        ],
    }


def _trust_keys_for_signer(signer: Signer) -> dict[str, bytes]:
    pub_raw = signer.key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {signer.kid: pub_raw, signer.kid.split("#", 1)[-1]: pub_raw}


def _sample_eval_log() -> object:
    try:
        from inspect_ai.log._log import (
            EvalConfig,
            EvalDataset,
            EvalLog,
            EvalMetric,
            EvalResults,
            EvalScore,
            EvalSpec,
            EvalStats,
        )

        spec = EvalSpec(
            eval_id="eval-abc",
            run_id="run-xyz",
            created="2026-08-20T00:00:00+00:00",
            task="math_word_problems",
            task_id="task-123",
            task_version=0,
            model="openai/gpt-4o",
            dataset=EvalDataset(name="gsm8k", location="hf://gsm8k", samples=2, sample_ids=[1, 2]),
            config=EvalConfig(),
        )
        results = EvalResults(
            total_samples=2,
            completed_samples=2,
            scores=[
                EvalScore(
                    name="accuracy",
                    scorer="match",
                    metrics={"accuracy": EvalMetric(name="accuracy", value=0.5)},
                )
            ],
        )
        stats = EvalStats(
            started_at="2026-08-20T00:00:00+00:00",
            completed_at="2026-08-20T00:01:00+00:00",
        )
        return EvalLog(
            eval=spec, results=results, stats=stats, status="success", location="mem://log.eval"
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[note] using duck-typed EvalLog stand-in ({exc})")

        class _O:
            def __init__(self, **kw):
                self.__dict__.update(kw)

        return _O(
            version=2,
            status="success",
            location="mem://log.eval",
            eval=_O(
                eval_id="eval-abc",
                run_id="run-xyz",
                created="2026-08-20T00:00:00+00:00",
                task="math_word_problems",
                task_id="task-123",
                task_version=0,
                model="openai/gpt-4o",
                dataset=_O(name="gsm8k", location="hf://gsm8k", samples=2, sample_ids=[1, 2], shuffled=False),
            ),
            results=_O(
                total_samples=2,
                completed_samples=2,
                scores=[_O(name="accuracy", scorer="match", reducer=None, metrics={"accuracy": _O(value=0.5)})],
            ),
            stats=_O(started_at="2026-08-20T00:00:00+00:00", completed_at="2026-08-20T00:01:00+00:00"),
        )


def test_jcs_known_answer_vectors():
    """RFC 8785 divergence vectors from proofbundle#147.

    CORRECTED. This test previously asserted the ESCAPED form —
    ``{"\\ud83d\\ude00":2,"\\ufffd":1}`` — as the expected answer. That is the
    ``ensure_ascii=True`` output the encoder happened to produce, not RFC 8785. The test
    therefore pinned the defect in place while its own name promised conformance to the
    specification, which is why the false claim in canonical.py survived a green suite for as
    long as it did.

    RFC 8785 §3.2.2.2 serialises strings with minimal escaping over raw UTF-8, so a non-ASCII
    character appears as itself. The KEY ORDER was already right in both forms and is unchanged
    here: sorting is by UTF-16 code unit, and U+1F600 leads with the high surrogate 0xD83D,
    which sorts before U+FFFD.
    """
    assert jcs({"\ufffd": 1, "\U0001f600": 2}) == '{"\U0001f600":2,"\ufffd":1}'
    assert jcs({"a": 1e-07}) == '{"a":1e-7}'
    assert jcs({"a": 2.0}) == '{"a":2}'


def test_digest_is_deterministic():
    log = _sample_eval_log()
    d1, d2 = eval_log_digest(log), eval_log_digest(log)
    assert canonical_bytes(d1) == canonical_bytes(d2)
    assert d1["eval"]["eval_id"] == "eval-abc"
    assert d1["results"]["scores"][0]["metrics"]["accuracy"] == 0.5


def test_sign_and_verify_roundtrip():
    log = _sample_eval_log()
    obj = eval_log_digest(log)
    payload = base_receipt(
        "task",
        {"eval_id": "eval-abc", "eval_log": obj, "eval_log_sha256": sha256_hex(canonical_bytes(obj)), "prev": None},
    )
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    kid = DEFAULT_KID
    signer = Signer(key=Ed25519PrivateKey.from_private_bytes(seed), kid=kid)
    receipt = signer.sign(payload)
    assert receipt["binding"]["type"] == "content-hash"

    trust = _trust_keys_for_signer(signer)
    result = verify(receipt, trust_keys=trust)
    assert result.valid, result.reason
    assert result.key_resolved
    assert result.binding_checked == "content-hash"


def test_unpublished_key_fails_closed():
    log = _sample_eval_log()
    obj = eval_log_digest(log)
    payload = base_receipt("task", {"eval_id": "eval-abc", "eval_log": obj, "prev": None})
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    signer = Signer(key=Ed25519PrivateKey.from_private_bytes(seed), kid="unpublished-key")
    receipt = signer.sign(payload)

    r1 = verify(receipt)
    assert not r1.valid
    assert not r1.key_resolved

    r2 = verify(receipt, trust_keys=_trust_keys_for_signer(signer))
    assert not r2.valid


def test_self_signed_without_trust_anchor_fails_closed():
    log = _sample_eval_log()
    obj = eval_log_digest(log)
    payload = base_receipt("task", {"eval_id": "eval-abc", "eval_log": obj, "prev": None})
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    signer = Signer(key=Ed25519PrivateKey.from_private_bytes(seed), kid=DEFAULT_KID)
    receipt = signer.sign(payload)

    result = verify(receipt)
    assert not result.valid
    assert "no trust anchor" in result.reason


def test_unknown_kid_fails_closed():
    log = _sample_eval_log()
    obj = eval_log_digest(log)
    payload = base_receipt("task", {"eval_id": "eval-abc", "eval_log": obj, "prev": None})
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    signer = Signer(key=Ed25519PrivateKey.from_private_bytes(seed), kid="did:web:csoai.org#missing-key")
    receipt = signer.sign(payload)

    keys = public_keys_from_did_doc(_live_did_doc())
    result = verify(receipt, trust_keys=keys)
    assert not result.valid
    assert not result.key_resolved


def test_tamper_is_rejected():
    log = _sample_eval_log()
    obj = eval_log_digest(log)
    payload = base_receipt("task", {"eval_id": "eval-abc", "eval_log": obj, "prev": None})
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    signer = Signer(key=Ed25519PrivateKey.from_private_bytes(seed), kid=DEFAULT_KID)
    receipt = signer.sign(payload)
    receipt["eval_log"]["results"]["scores"][0]["metrics"]["accuracy"] = 0.99
    result = verify(receipt, trust_keys=_trust_keys_for_signer(signer))
    assert not result.valid


def test_unsigned_receipt_has_no_fabricated_signature():
    obj = eval_log_digest(_sample_eval_log())
    receipt = unsigned(base_receipt("task", {"eval_id": "eval-abc", "eval_log": obj}))
    assert receipt["signature"]["status"] == "UNSIGNED"
    assert "sig" not in receipt["signature"]
    result = verify(receipt)
    assert not result.valid and "UNSIGNED" in result.reason


def test_did_doc_key_parsing_live_stack():
    keys = public_keys_from_did_doc(_live_did_doc())
    assert "did:web:csoai.org#estate-chain-1" in keys
    assert "csoai-estate-chain-1" in keys
    assert "estate-chain-1" in keys
    assert "csoai-board-attestation-1" in keys
    assert keys["did:web:csoai.org#board-attestation-1"] == keys["csoai-board-attestation-1"]
    assert DEFAULT_KID in keys or DEFAULT_KID.split("#", 1)[1] in keys


def test_default_kid_matches_live_did():
    assert DEFAULT_KID == "did:web:csoai.org#estate-chain-1"
    keys = public_keys_from_did_doc(_live_did_doc())
    assert DEFAULT_KID in keys


def test_cli_sign_verify_roundtrip():
    log = _sample_eval_log()
    with tempfile.TemporaryDirectory() as d:
        log_json = os.path.join(d, "log.json")
        json.dump(
            {
                "version": 2,
                "status": "success",
                "eval": {
                    "eval_id": "eval-abc",
                    "run_id": "run-xyz",
                    "task": "t",
                    "model": "m",
                    "dataset": {"name": "gsm8k", "samples": 2, "sample_ids": [1, 2]},
                },
                "results": {"total_samples": 2, "completed_samples": 2, "scores": []},
                "stats": {
                    "started_at": "2026-08-20T00:00:00+00:00",
                    "completed_at": "2026-08-20T00:01:00+00:00",
                },
            },
            open(log_json, "w"),
        )
        seed_bytes = Ed25519PrivateKey.generate().private_bytes_raw()
        key = os.path.join(d, "seed")
        open(key, "wb").write(seed_bytes)
        pub = Ed25519PrivateKey.from_private_bytes(seed_bytes).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        pub_b64 = base64.urlsafe_b64encode(pub).decode().rstrip("=")
        did_doc = os.path.join(d, "did.json")
        doc = _live_did_doc()
        for vm in doc["verificationMethod"]:
            if vm["id"] == DEFAULT_KID:
                vm["publicKeyJwk"]["x"] = pub_b64
        json.dump(doc, open(did_doc, "w"))
        rec = os.path.join(d, "r.json")
        env = {
            **os.environ,
            "PYTHONPATH": os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"
            ),
            "INSPECT_RECEIPTS_KID": DEFAULT_KID,
        }
        subprocess.run(
            [sys.executable, "-m", "inspect_receipts.cli", "sign", log_json, "--key", key, "--out", rec],
            check=True,
            capture_output=True,
            env=env,
        )
        out = subprocess.run(
            [
                sys.executable,
                "-m",
                "inspect_receipts.cli",
                "verify",
                rec,
                "--did-web",
                f"file://{did_doc}",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        assert out.returncode == 0, out.stdout + out.stderr
        assert "VALID" in out.stdout


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("ALL RECEIPT TESTS PASS")


# --- three-state discipline -------------------------------------------------
# Added 2026-09-04 after Konrad Gruszka (b7n0de) measured this package independently on
# 2026-08-20 and published the result: a proofbundle receipt through this verifier returned
# "INVALID — content_id mismatch", while our receipt through his returned "unsupported schema".
# His verifier said "I do not speak this format". Ours said "this is forged".

def test_foreign_schema_is_uncheckable_not_invalid():
    """The exact case Konrad measured. A format we do not read is not a forgery."""
    from inspect_receipts.receipt import verify
    r = verify({"schema": "proofbundle/v0.1", "content_id": "x", "signature": {}})
    assert r.state == "UNCHECKABLE", r.reason
    assert r.valid is False          # a caller written against the bool stays safe
    assert "unsupported schema" in r.reason


def test_tampered_bytes_are_still_invalid():
    """The fix must not soften a real finding."""
    from inspect_receipts.receipt import verify
    r = verify({
        "schema": "csoai.inspect-receipt/0.2", "content_id": "deadbeef",
        "signature": {"status": "SIGNED", "sig": "AA", "kid": "k"},
    })
    assert r.state == "INVALID", r.reason


def test_missing_trust_anchor_is_uncheckable():
    """No keys supplied is a fact about the call, not about the receipt."""
    import inspect_receipts.receipt as m
    r = m._uncheckable("no trust anchor; resolve kid 'k' via did:web")
    assert r.state == "UNCHECKABLE" and r.valid is False


def test_uncheckable_never_reports_as_valid():
    """UNCHECKABLE must never be truthy — nothing that failed before starts passing."""
    import inspect_receipts.receipt as m
    for r in (m._uncheckable("x"), m._invalid("y")):
        assert r.valid is False
    assert m._valid("z").valid is True and m._valid("z").state == "VALID"
