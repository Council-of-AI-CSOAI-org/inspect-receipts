"""GHSA-ph7v-hpjr-8qj6: a set of receipts must verify as one complete, ordered chain."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

from inspect_receipts.receipt import DEFAULT_KID, Signer, base_receipt, unsigned, verify_chain  # noqa: E402


def _signer():
    return Signer(key=Ed25519PrivateKey.generate(), kid=DEFAULT_KID)


def _trust(signer):
    raw = signer.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {signer.kid: raw, signer.kid.split("#", 1)[-1]: raw}


def _chain(signer, n=3, chain_id="c1", with_seq=True):
    out, prev = [], None
    for i in range(n):
        data = {"eval_id": f"e{i}", "prev": prev}
        if with_seq:
            data["chain"] = {"id": chain_id, "seq": i}
        r = signer.sign(base_receipt("task", data))
        out.append(r)
        prev = r["content_id"]
    return out


def test_complete_chain_is_valid():
    s = _signer(); rs = _chain(s)
    res = verify_chain(rs, _trust(s))
    assert res.valid and res.state == "VALID", res.reason
    assert res.order == tuple(r["content_id"] for r in rs)
    assert not res.tail_checked and "tail not checked" in res.reason


def test_dropped_middle_receipt_is_invalid():  # advisory PoC step 3
    s = _signer(); r1, r2, r3 = _chain(s)
    res = verify_chain([r1, r3], _trust(s))
    assert not res.valid and res.state == "INVALID", res.reason


def test_dropped_first_receipt_is_invalid_unless_partial():
    s = _signer(); r1, r2, r3 = _chain(s)
    assert verify_chain([r2, r3], _trust(s)).state == "INVALID"
    assert verify_chain([r2, r3], _trust(s), require_genesis=False).valid


def test_reorder_is_recovered_from_links_and_rejected_when_ordered():  # PoC step 4
    s = _signer(); r1, r2, r3 = _chain(s)
    res = verify_chain([r3, r1, r2], _trust(s))
    assert res.valid and res.order == (r1["content_id"], r2["content_id"], r3["content_id"])
    assert verify_chain([r3, r1, r2], _trust(s), ordered=True).state == "INVALID"
    assert verify_chain([r1, r2, r3], _trust(s), ordered=True).valid


def test_truncated_tail_detected_against_published_head():
    s = _signer(); r1, r2, r3 = _chain(s)
    assert verify_chain([r1, r2], _trust(s)).valid  # undetectable from the receipts alone
    assert verify_chain([r1, r2], _trust(s), expected_head=r3["content_id"]).state == "INVALID"
    assert verify_chain([r1, r2], _trust(s), expected_count=3).state == "INVALID"
    ok = verify_chain([r1, r2, r3], _trust(s), expected_head=r3["content_id"], expected_count=3)
    assert ok.valid and ok.tail_checked


def test_fork_duplicate_and_second_chain_are_invalid():
    s = _signer(); r1, r2, r3 = _chain(s)
    alt = s.sign(base_receipt("task", {"eval_id": "alt", "prev": r1["content_id"], "chain": {"id": "c1", "seq": 1}}))
    assert "fork" in verify_chain([r1, r2, alt], _trust(s)).reason
    assert "duplicate" in verify_chain([r1, r2, r2], _trust(s)).reason
    other = _chain(s, 2, chain_id="c2")
    assert verify_chain([r1, r2, r3] + other, _trust(s)).state == "INVALID"


def test_seq_gap_and_chain_id_change_are_invalid():
    s = _signer()
    a = s.sign(base_receipt("task", {"prev": None, "chain": {"id": "c", "seq": 0}}))
    b = s.sign(base_receipt("task", {"prev": a["content_id"], "chain": {"id": "c", "seq": 2}}))
    assert "seq" in verify_chain([a, b], _trust(s)).reason
    c = s.sign(base_receipt("task", {"prev": a["content_id"], "chain": {"id": "d", "seq": 1}}))
    assert "chain.id" in verify_chain([a, c], _trust(s)).reason


def test_legacy_receipts_without_seq_still_chain():
    s = _signer(); rs = _chain(s, with_seq=False)
    assert verify_chain(rs, _trust(s)).valid
    assert verify_chain([rs[0], rs[2]], _trust(s)).state == "INVALID"


def test_tampered_member_fails_the_chain():
    s = _signer(); r1, r2, r3 = _chain(s)
    r2 = json.loads(json.dumps(r2)); r2["eval_id"] = "forged"
    assert verify_chain([r1, r2, r3], _trust(s)).state == "INVALID"


def test_unchecked_members_never_make_a_valid_chain():
    s = _signer(); rs = _chain(s)
    assert not verify_chain(rs).valid  # no trust anchor supplied


def test_unsigned_chain_is_not_valid():
    a = unsigned(base_receipt("task", {"prev": None}))
    b = unsigned(base_receipt("task", {"prev": a["content_id"]}))
    assert not verify_chain([a, b]).valid


def test_empty_set_is_uncheckable():
    assert verify_chain([]).state == "UNCHECKABLE"


def test_hooks_emit_chain_id_and_seq():
    import importlib
    import types
    if "inspect_ai.hooks" not in sys.modules:
        try:
            import inspect_ai.hooks  # noqa: F401
        except Exception:
            fake = types.ModuleType("inspect_ai.hooks")
            class Hooks: ...
            fake.Hooks, fake.RunEnd, fake.TaskEnd = Hooks, object, object
            fake.hooks = lambda **kw: (lambda cls: cls)
            sys.modules.setdefault("inspect_ai", types.ModuleType("inspect_ai"))
            sys.modules["inspect_ai.hooks"] = fake
    with tempfile.TemporaryDirectory() as d:
        old = {k: os.environ.get(k) for k in ("INSPECT_RECEIPTS_DIR", "INSPECT_RECEIPTS_KEY")}
        os.environ["INSPECT_RECEIPTS_DIR"] = d
        os.environ.pop("INSPECT_RECEIPTS_KEY", None)
        try:
            h = importlib.reload(importlib.import_module("inspect_receipts._hooks"))
            h._emit("task", {"eval_id": "a"}, "t-a")
            h._emit("task", {"eval_id": "b"}, "t-b")
            h._emit("run", {"run_id": "r"}, "run-r")
            rs = [json.load(open(os.path.join(d, f"{n}.receipt.json"))) for n in ("t-a", "t-b", "run-r")]
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    assert [r["chain"]["seq"] for r in rs] == [0, 1, 2]
    assert len({r["chain"]["id"] for r in rs}) == 1
    assert rs[0]["prev"] is None and rs[1]["prev"] == rs[0]["content_id"] and rs[2]["prev"] == rs[1]["content_id"]


def test_cli_chain_flag_exit_codes():
    s = _signer(); r1, r2, r3 = _chain(s)
    with tempfile.TemporaryDirectory() as d:
        paths = []
        for i, r in enumerate((r1, r2, r3)):
            p = os.path.join(d, f"r{i}.json")
            with open(p, "w") as f:
                f.write(json.dumps(r))
            paths.append(p)
        env = {**os.environ, "PYTHONPATH": SRC}
        out = subprocess.run([sys.executable, "-m", "inspect_receipts.cli", "verify", "--chain", paths[0], paths[2]],
                             capture_output=True, text=True, env=env)
        assert out.returncode == 1 and "chain: INVALID" in out.stdout, out.stdout + out.stderr
