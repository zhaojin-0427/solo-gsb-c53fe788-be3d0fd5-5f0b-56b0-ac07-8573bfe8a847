"""Cryptographic primitives: Ed25519 and RSA-PSS verification (RFC 9421)."""
from __future__ import annotations

import base64
import hashlib
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

#: RFC 9421 algorithm name -> (key family, hash class)
ALGORITHMS = {
    "ed25519": ("ed25519", None),
    "rsa-pss-sha256": ("rsa", hashes.SHA256),
    "rsa-pss-sha512": ("rsa", hashes.SHA512),
}


class CryptoError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def load_public_key(pem_or_spki: str):
    """Load an SPKI public key from PEM text, raw base64 SPKI, or Ed25519 raw."""
    text = pem_or_spki.strip()

    # PEM body.
    if "-----BEGIN" in text:
        try:
            key = serialization.load_pem_public_key(text.encode("ascii"))
        except Exception as exc:
            raise CryptoError("invalid_public_key", f"invalid PEM public key: {exc}")
    else:
        try:
            raw = base64.b64decode(text, validate=True)
        except Exception as exc:
            raise CryptoError(
                "invalid_public_key",
                "public key must be PEM or base64-encoded SPKI/raw bytes",
            ) from exc
        # 32 bytes -> raw Ed25519 public key.
        if len(raw) == 32:
            try:
                return ed25519.Ed25519PublicKey.from_public_bytes(raw)
            except Exception as exc:
                raise CryptoError(
                    "invalid_public_key", f"invalid raw Ed25519 key: {exc}"
                )
        try:
            key = serialization.load_der_public_key(raw)
        except Exception as exc:
            raise CryptoError(
                "invalid_public_key", f"invalid DER (SPKI) public key: {exc}"
            )

    if not isinstance(
        key,
        (ed25519.Ed25519PublicKey, rsa.RSAPublicKey),
    ):
        raise CryptoError(
            "invalid_public_key",
            f"unsupported public key type {type(key).__name__}",
        )
    return key


def key_family(key) -> str:
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ed25519"
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa"
    return "unknown"


def spki_fingerprint(key) -> str:
    """SHA-256 hex digest of the DER SubjectPublicKeyInfo."""
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def verify_signature(algorithm: str, public_key, signature: bytes, message: bytes) -> None:
    """Verify ``signature`` over ``message``; raise CryptoError on failure."""
    if algorithm not in ALGORITHMS:
        raise CryptoError("algorithm_unsupported", f"unknown algorithm {algorithm!r}")

    family, hash_cls = ALGORITHMS[algorithm]
    actual_family = key_family(public_key)
    if family != actual_family:
        raise CryptoError(
            "invalid_public_key",
            f"algorithm {algorithm!r} requires an {family} key, got {actual_family}",
        )

    try:
        if family == "ed25519":
            public_key.verify(signature, message)
        else:
            digest = hashlib.new(hash_cls.name)
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hash_cls()),
                    salt_length=digest.digest_size,
                ),
                hash_cls(),
            )
    except InvalidSignature:
        raise CryptoError("signature_invalid", "cryptographic signature verification failed")
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError("signature_invalid", f"signature could not be processed: {exc}")


# ---------------------------------------------------------------------------
# Signing helpers (used by the demo client and by tests)
# ---------------------------------------------------------------------------


def generate_ed25519() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def generate_rsa(key_size: int = 2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return priv, priv.public_key()


def public_key_pem(key) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def private_key_pem(key) -> str:
    """Serialise a private key as unencrypted PKCS#8 PEM (server-side storage)."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def load_private_key(pem: str):
    """Load an unencrypted PKCS#8 PEM private key."""
    try:
        return serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    except Exception as exc:
        raise CryptoError("invalid_private_key", f"invalid PEM private key: {exc}")


def sign(algorithm: str, private_key, data: bytes) -> bytes:
    family, hash_cls = ALGORITHMS[algorithm]
    if family == "ed25519":
        return private_key.sign(data)
    digest = hashlib.new(hash_cls.name)
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hash_cls()),
            salt_length=digest.digest_size,
        ),
        hash_cls(),
    )
