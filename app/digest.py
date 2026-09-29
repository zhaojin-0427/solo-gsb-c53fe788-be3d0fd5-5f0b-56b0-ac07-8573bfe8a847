"""Content-Digest handling per RFC 9530."""
from __future__ import annotations

import hashlib
from typing import Dict

from http_sfv import Dictionary

#: digest algorithm name -> hashlib name
DIGEST_ALGORITHMS: Dict[str, str] = {
    "sha-256": "sha256",
    "sha-512": "sha512",
}


def compute_content_digest(body: bytes, algorithm: str = "sha-256") -> str:
    """Return a serialised Content-Digest field value for ``body``."""
    from http_sfv import Item

    if algorithm not in DIGEST_ALGORITHMS:
        raise ValueError(f"unsupported digest algorithm {algorithm!r}")
    digest = hashlib.new(DIGEST_ALGORITHMS[algorithm], body).digest()
    d = Dictionary()
    d[algorithm] = Item(digest)
    return str(d)


def verify_content_digest(
    raw_field: str, body: bytes, allowed_algorithms=None
) -> str:
    """Validate a client-submitted Content-Digest header against ``body``.

    Returns the canonical serialised field value.  Raises ``ValueError``
    with a stable *code* attribute on failure.
    """
    allowed = tuple(allowed_algorithms or DIGEST_ALGORITHMS.keys())
    try:
        parsed = Dictionary()
        parsed.parse(raw_field.encode("latin-1"))
    except ValueError as exc:
        err = ValueError(f"Content-Digest is not a valid SF dictionary: {exc}")
        err.code = "malformed_content_digest"
        raise err

    if not parsed:
        err = ValueError("Content-Digest contains no digest members")
        err.code = "content_digest_missing"
        raise err

    checked = []
    for name, member in parsed.items():
        from http_sfv import Item

        if not isinstance(member, Item) or not isinstance(member.value, bytes):
            err = ValueError(f"Content-Digest member {name!r} is not a byte sequence")
            err.code = "content_digest_unsupported"
            raise err
        if name not in DIGEST_ALGORITHMS:
            err = ValueError(f"unsupported Content-Digest algorithm {name!r}")
            err.code = "content_digest_unsupported"
            raise err
        if name not in allowed:
            err = ValueError(f"Content-Digest algorithm {name!r} is not allowed")
            err.code = "content_digest_unsupported"
            raise err
        expected = hashlib.new(DIGEST_ALGORITHMS[name], body).digest()
        if member.value != expected:
            err = ValueError(f"Content-Digest member {name!r} does not match the body")
            err.code = "content_digest_mismatch"
            raise err
        checked.append(name)

    return str(parsed)
