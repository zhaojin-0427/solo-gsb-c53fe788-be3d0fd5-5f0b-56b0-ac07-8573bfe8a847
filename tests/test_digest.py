"""Content-Digest tests (RFC 9530)."""
from __future__ import annotations

import hashlib

import pytest

from app.digest import compute_content_digest, verify_content_digest


def test_rfc9530_known_vector():
    # RFC 9530 example body -> sha-256 digest.
    body = b"hello world"
    field = compute_content_digest(body)
    from http_sfv import Dictionary

    d = Dictionary()
    d.parse(field.encode())
    member = d["sha-256"]
    assert member.value == hashlib.sha256(body).digest()
    assert verify_content_digest(field, body) == field


def test_sha512_roundtrip():
    body = b"abc" * 1000
    field = compute_content_digest(body, "sha-512")
    assert "sha-512=:" in field
    assert verify_content_digest(field, body)


def test_tampered_body_fails():
    field = compute_content_digest(b"hello")
    with pytest.raises(ValueError) as exc:
        verify_content_digest(field, b"hellp")
    assert exc.value.code == "content_digest_mismatch"


def test_unknown_algorithm_fails():
    with pytest.raises(ValueError) as exc:
        verify_content_digest("md5=:aaaa:", b"x")
    assert exc.value.code == "content_digest_unsupported"


def test_malformed_field_fails():
    with pytest.raises(ValueError) as exc:
        verify_content_digest("not a dictionary !!", b"x")
    assert exc.value.code == "malformed_content_digest"
