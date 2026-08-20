"""Round-trip tests: build a receipt from a sample EvalLog object, verify it.

Runnable with pytest or as a plain script. Uses a real inspect_ai EvalLog object
when available (the supported path); falls back to a duck-typed stand-in that
exposes the same attribute shape ``eval_log_digest`` reads.
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

from inspect_receipts.receipt import (  # noqa: E402
    Signer,
    base_receipt,
    canonical_bytes,
    eval_log_digest,
    public_keys_from_did_doc,
    sha256_hex,
    unsigned,
    verify,
)


def _sample_eval_log() -> object:
    """A real inspect_ai EvalLog object; else a duck-typed stand-in."""
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


def test_digest_is_deterministic():
    log = _sample_eval_log()
    d1, d2 = eval_log_digest(log), eval_log_digest(log)
    assert canonical_bytes(d1) == canonical_bytes(d2)
    assert d1["eval"]["eval_id"] == "eval-abc"
    assert d1["results"]["scores"][0]["metrics"]["accuracy"] == 0.5
    # object model, not raw bytes: no zip/zstd artefact leaks in
    assert "eval" in d1 and "dataset" in d1["eval"]


def test_sign_and_verify_roundtrip():
    log = _sample_eval_log()
    obj = eval_log_digest(log)
    payload = base_receipt(
        "task",
        {"eval_id": "eval-abc", "eval_log": obj, "eval_log_sha256": sha256_hex(canonical_bytes(obj)), "prev": None},
    )
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    signer = Signer(key=Ed25519PrivateKey.from_private_bytes(seed), kid="did:web:csoai.org#keys-1")
    receipt = signer.sign(payload)

    ok, reason = verify(receipt)
    assert ok, reason

    # verify against the matching PUBLISHED key (did:web trust path, offline)
    pub_raw = signer.key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    ok, reason = verify(receipt, published_key=pub_raw)
    assert ok, reason

    # a DIFFERENT published key must be rejected
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    ok, _ = verify(receipt, published_key=other)
    assert not ok


def test_tamper_is_rejected():
    log = _sample_eval_log()
    obj = eval_log_digest(log)
    payload = base_receipt("task", {"eval_id": "eval-abc", "eval_log": obj, "prev": None})
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    receipt = Signer(key=Ed25519PrivateKey.from_private_bytes(seed), kid="k").sign(payload)
    receipt["eval_log"]["results"]["scores"][0]["metrics"]["accuracy"] = 0.99
    ok, _ = verify(receipt)
    assert not ok


def test_unsigned_receipt_has_no_fabricated_signature():
    obj = eval_log_digest(_sample_eval_log())
    receipt = unsigned(base_receipt("task", {"eval_id": "eval-abc", "eval_log": obj}))
    assert receipt["signature"]["status"] == "UNSIGNED"
    assert "sig" not in receipt["signature"]
    ok, reason = verify(receipt)
    assert not ok and "UNSIGNED" in reason


def test_did_doc_key_parsing():
    # matches the live https://csoai.org/.well-known/did.json shape
    x = base64.urlsafe_b64encode(b"\x01" * 32).decode().rstrip("=")
    doc = {
        "verificationMethod": [
            {
                "id": "did:web:csoai.org#keys-1",
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x},
            }
        ]
    }
    keys = public_keys_from_did_doc(doc)
    assert keys["did:web:csoai.org#keys-1"] == b"\x01" * 32


def test_cli_sign_verify_roundtrip():
    log = _sample_eval_log()
    with tempfile.TemporaryDirectory() as d:
        # export a plain-JSON log the CLI shim can read without inspect_ai
        log_json = os.path.join(d, "log.json")
        json.dump(
            {
                "version": 2,
                "status": "success",
                "eval": {"eval_id": "eval-abc", "run_id": "run-xyz", "task": "t", "model": "m",
                          "dataset": {"name": "gsm8k", "samples": 2, "sample_ids": [1, 2]}},
                "results": {"total_samples": 2, "completed_samples": 2, "scores": []},
                "stats": {"started_at": "2026-08-20T00:00:00+00:00", "completed_at": "2026-08-20T00:01:00+00:00"},
            },
            open(log_json, "w"),
        )
        key = os.path.join(d, "seed")
        open(key, "wb").write(Ed25519PrivateKey.generate().private_bytes_raw())
        rec = os.path.join(d, "r.json")
        env = {**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")}
        subprocess.run(
            [sys.executable, "-m", "inspect_receipts.cli", "sign", log_json, "--key", key, "--out", rec],
            check=True, capture_output=True, env=env,
        )
        out = subprocess.run(
            [sys.executable, "-m", "inspect_receipts.cli", "verify", rec],
            capture_output=True, text=True, env=env,
        )
        assert out.returncode == 0, out.stdout + out.stderr
        assert "VALID" in out.stdout


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("ALL RECEIPT TESTS PASS")
