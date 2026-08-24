"""RFC 8785 JSON Canonicalization Scheme (JCS) — normative for content_id.

Python's ``json.dumps(sort_keys=True)`` is JCS-like but not JCS: key order follows
Unicode code points (not UTF-16 code units), numbers follow Python formatting, and
non-ASCII may appear unescaped. Both sides of the proofbundle interop gate must
compute the same digest — this module is that single normative form.

Implementation: WebPKI ``jcs`` encoder (UTF-16-BE key sort, ECMAScript numbers,
``\\uXXXX`` escaping). Verified against the divergence vectors in proofbundle#147.
"""

from __future__ import annotations

from typing import Any

from jcs._jcs import JSONEncoder

_ENCODER = JSONEncoder(sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def jcs(obj: Any) -> str:
    """Return the RFC 8785 canonical JSON text for *obj*."""
    return _ENCODER.encode(obj)


def jcs_bytes(obj: Any) -> bytes:
    """Return UTF-8 bytes of the RFC 8785 canonical JSON text."""
    return jcs(obj).encode("utf-8")


def canonical_bytes(obj: Any) -> bytes:
    """Alias used throughout receipt signing and verification."""
    return jcs_bytes(obj)
