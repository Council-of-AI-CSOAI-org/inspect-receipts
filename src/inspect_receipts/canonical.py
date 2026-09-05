"""RFC 8785 JSON Canonicalization Scheme (JCS) — normative for content_id.

Python's ``json.dumps(sort_keys=True)`` is JCS-like but not JCS: key order follows
Unicode code points (not UTF-16 code units), numbers follow Python formatting, and
non-ASCII may appear unescaped. Both sides of the proofbundle interop gate must
compute the same digest — this module is that single normative form.

R1, settled by measurement (proofbundle#147). This module previously ran the encoder
with ``ensure_ascii=True`` while its own docstring claimed RFC 8785 and claimed to be
verified against that issue's divergence vectors. It was not: escaping is exactly where
the two forms part company, and the encoder diverged on 4 of the 6 named vectors —

    {"café": 1}       ->  {"caf\\u00e9":1}          RFC 8785: {"café":1}
    {"emoji": "🎯"}    ->  {"emoji":"\\ud83c\\udfaf"}  RFC 8785: {"emoji":"🎯"}
    {"é":1,"e":2}     ->  {"e":2,"\\u00e9":1}        RFC 8785: {"e":2,"é":1}

ASCII-only bodies and ECMAScript number formatting already agreed, which is why every
existing test passed and the claim survived. RFC 8785 §3.2.2.2 serialises strings with
minimal escaping over raw UTF-8; ``ensure_ascii=True`` is a different, unnamed profile.

We now call the library's own normative entry point, ``jcs.canonicalize``, rather than
configuring an encoder ourselves — there is then no local flag that can drift away from
the specification again.

CONSEQUENCE, stated rather than buried: content_id changes for any body containing a
non-ASCII byte. Receipts already signed under the old form do not re-verify under this
one. They are not edited — the schema id moves to csoai.inspect-receipt/0.3 so a verifier
can tell the two apart and report an old receipt as its own outcome instead of as invalid.
"""

from __future__ import annotations

from typing import Any

import jcs as _jcs


def jcs_bytes(obj: Any) -> bytes:
    """Return UTF-8 bytes of the RFC 8785 canonical JSON text."""
    return _jcs.canonicalize(obj)


def jcs(obj: Any) -> str:
    """Return the RFC 8785 canonical JSON text for *obj*."""
    return jcs_bytes(obj).decode("utf-8")


def canonical_bytes(obj: Any) -> bytes:
    """Alias used throughout receipt signing and verification."""
    return jcs_bytes(obj)
