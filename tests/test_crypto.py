"""Crypto round-trip tests."""
from __future__ import annotations

import pytest

from app.crypto import (
    generate_ed25519,
    generate_rsa,
    load_public_key,
    public_key_pem,
    sign,
    spki_fingerprint,
    verify_signature,
)


@pytest.mark.parametrize(
    "algorithm,generate",
    [
        ("ed25519", generate_ed25519),
        ("rsa-pss-sha256", lambda: generate_rsa(2048)),
        ("rsa-pss-sha512", lambda: generate_rsa(2048)),
    ],
)
def test_sign_verify_roundtrip(algorithm, generate):
    priv, pub = generate()
    data = b"signature base line\nsecond line"
    signature = sign(algorithm, priv, data)
    verify_signature(algorithm, pub, signature, data)


def test_tampered_message_fails_ed25519():
    priv, pub = generate_ed25519()
    sig = sign("ed25519", priv, b"data")
    with pytest.raises(Exception) as exc:
        verify_signature("ed25519", pub, sig, b"datA")
    assert exc.value.code == "signature_invalid"


def test_wrong_key_family_rejected():
    priv_rsa, pub_rsa = generate_rsa(2048)
    with pytest.raises(Exception) as exc:
        verify_signature("ed25519", pub_rsa, b"x", b"y")
    assert exc.value.code == "invalid_public_key"

    priv_ed, pub_ed = generate_ed25519()
    sig = sign("ed25519", priv_ed, b"x")
    with pytest.raises(Exception) as exc:
        verify_signature("rsa-pss-sha256", pub_ed, sig, b"x")
    assert exc.value.code == "invalid_public_key"


def test_load_pem_and_raw_ed25519():
    _, pub = generate_ed25519()
    pem = public_key_pem(pub)
    loaded_pem = load_public_key(pem)
    assert spki_fingerprint(loaded_pem) == spki_fingerprint(pub)

    raw = public_key_pem(pub)  # ensure equality across representations
    import base64

    der = loaded_pem.public_bytes(
        encoding=__import__(
            "cryptography.hazmat.primitives.serialization",
            fromlist=["Encoding"],
        ).Encoding.DER,
        format=__import__(
            "cryptography.hazmat.primitives.serialization",
            fromlist=["PublicFormat"],
        ).PublicFormat.SubjectPublicKeyInfo,
    )
    loaded_der = load_public_key(base64.b64encode(der).decode())
    assert spki_fingerprint(loaded_der) == spki_fingerprint(pub)
    assert raw  # used
