"""Versioned, offline-verifiable acceptance receipts.

When ``/verify`` formally accepts a request the server issues a *receipt*:
a canonical, versioned payload binding

* a deterministic SHA-256 digest of the normalised verification input,
* the signer ``keyid`` and the key version that verified,
* the policy version that was enforced,
* the acceptance time, and
* a unique receipt id,

signed with the server's own Ed25519 receipt-signing key and persisted in
the same database transaction as the nonce claim.  Historical public keys
stay published (``GET /receipts/keys``) so receipts keep verifying offline
even after the server signing key is rotated.

This module intentionally depends only on the standard library and
``cryptography`` so the standalone offline verifier
(``tools/verify_receipt.py``) can reuse it without the server or database.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature

#: Version tag of the canonical receipt payload format (first payload line).
PAYLOAD_VERSION = "receipt/v1"

#: Version tag of the canonical revocation payload format (first payload line).
REVOCATION_PAYLOAD_VERSION = "receipt-revocation/v1"

#: Logical keyid of the server receipt-signing key (its versions rotate).
RECEIPT_KEYID = "receipt-signing"

#: Canonical field order after the version line.
PAYLOAD_FIELDS = (
    "receipt_id",
    "key_id",
    "issued_at",
    "keyid",
    "key_version",
    "policy_version",
    "algorithm",
    "label",
    "nonce",
    "input_digest",
)

#: Canonical field order of a revocation record after the version line.
REVOCATION_FIELDS = (
    "revocation_id",
    "key_id",
    "receipt_id",
    "sequence",
    "revision",
    "receipt_payload_sha256",
    "reason",
    "effective_at",
    "revoked_at",
)


class ReceiptFormatError(ValueError):
    """Raised when a receipt (or revocation) payload is not well-formed."""


# ---------------------------------------------------------------------------
# Deterministic digest of the verification input
# ---------------------------------------------------------------------------


def normalize_envelope(request_json: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a /verify request body to the canonical envelope shape.

    Accepts both ``signature_input`` and ``Signature-Input`` spellings and
    both header forms (``{"name", "value"}`` objects or ``[name, value]``
    pairs); header order is preserved.  Idempotent: an already-normalised
    envelope maps to itself, so the server (which normalises while parsing)
    and the offline tool (which starts from the raw request) agree.
    """
    headers: List[List[Any]] = []
    for h in request_json.get("headers") or []:
        if isinstance(h, dict):
            headers.append([h.get("name"), h.get("value", "")])
        else:
            headers.append([h[0], h[1]])
    return {
        "method": request_json.get("method"),
        "target_uri": request_json.get("target_uri"),
        "headers": headers,
        "body": request_json.get("body"),
        "signature_input": request_json.get("signature_input")
        or request_json.get("Signature-Input"),
        "signature": request_json.get("signature") or request_json.get("Signature"),
    }


def canonical_envelope_json(envelope: Dict[str, Any]) -> str:
    """Serialise the normalised envelope deterministically (sorted keys)."""
    return json.dumps(
        normalize_envelope(envelope),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def input_digest(envelope: Dict[str, Any]) -> str:
    """Deterministic ``sha256:<base64>`` digest of the verification input."""
    canonical = canonical_envelope_json(envelope).encode("utf-8")
    digest = hashlib.sha256(canonical).digest()
    return "sha256:" + base64.b64encode(digest).decode("ascii")


# ---------------------------------------------------------------------------
# Canonical payload
# ---------------------------------------------------------------------------


def build_payload(
    *,
    receipt_id: str,
    key_id: str,
    issued_at: int,
    keyid: str,
    key_version: int,
    policy_version: int,
    algorithm: str,
    label: str,
    nonce: Optional[str],
    input_digest: str,
) -> str:
    """Build the canonical ``receipt/v1`` payload that gets signed."""
    values = {
        "receipt_id": str(receipt_id),
        "key_id": str(key_id),
        "issued_at": str(int(issued_at)),
        "keyid": keyid,
        "key_version": str(int(key_version)),
        "policy_version": str(int(policy_version)),
        "algorithm": algorithm,
        "label": label,
        "nonce": nonce or "",
        "input_digest": input_digest,
    }
    lines = [PAYLOAD_VERSION]
    for name in PAYLOAD_FIELDS:
        value = values[name]
        if "\n" in value or "\r" in value:
            raise ReceiptFormatError(
                f"receipt field {name!r} must not contain newlines"
            )
        lines.append(f"{name}: {value}")
    return "\n".join(lines)


def parse_payload(payload: str) -> Dict[str, Any]:
    """Parse and strictly validate a canonical payload.

    Raises ``ReceiptFormatError`` unless the payload has exactly the
    versioned field set in canonical order.
    """
    if not isinstance(payload, str):
        raise ReceiptFormatError("receipt payload must be a string")
    lines = payload.split("\n")
    if lines[0] != PAYLOAD_VERSION:
        raise ReceiptFormatError(
            f"unsupported receipt payload version {lines[0]!r} "
            f"(expected {PAYLOAD_VERSION!r})"
        )
    fields = lines[1:]
    if len(fields) != len(PAYLOAD_FIELDS):
        raise ReceiptFormatError(
            f"receipt payload must have {len(PAYLOAD_FIELDS)} fields, "
            f"got {len(fields)}"
        )
    out: Dict[str, Any] = {}
    for line, expected in zip(fields, PAYLOAD_FIELDS):
        name, sep, value = line.partition(": ")
        if not sep or name != expected:
            raise ReceiptFormatError(
                f"receipt payload field {expected!r} missing or out of order"
            )
        out[expected] = value
    try:
        out["issued_at"] = int(out["issued_at"])
        out["key_version"] = int(out["key_version"])
        out["policy_version"] = int(out["policy_version"])
    except ValueError as exc:
        raise ReceiptFormatError(f"receipt payload has a non-integer field: {exc}")
    out["nonce"] = out["nonce"] or None
    return out


# ---------------------------------------------------------------------------
# Signature over the payload
# ---------------------------------------------------------------------------


def sign_payload(private_key, payload: str) -> str:
    """Ed25519-sign the canonical payload; return standard base64."""
    return base64.b64encode(private_key.sign(payload.encode("utf-8"))).decode("ascii")


def verify_payload_signature(public_key, payload: str, signature_b64: str) -> bool:
    """Verify an Ed25519 receipt signature over the canonical payload."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False
    try:
        public_key.verify(signature, payload.encode("utf-8"))
    except InvalidSignature:
        return False
    return True


def receipt_document(*, payload: str, signature: str, issued_at: str) -> Dict[str, Any]:
    """Shape the API receipt object; convenience fields mirror the payload.

    The signed ``payload`` is authoritative — every other field is derived
    from it so mirrors can never disagree with what was signed.
    """
    fields = parse_payload(payload)
    return {
        "receipt_id": fields["receipt_id"],
        "key_id": fields["key_id"],
        "issued_at": issued_at,
        "issued_at_unix": fields["issued_at"],
        "payload": payload,
        "payload_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "signature": signature,
        "input_digest": fields["input_digest"],
        "context": {
            "keyid": fields["keyid"],
            "key_version": fields["key_version"],
            "policy_version": fields["policy_version"],
            "algorithm": fields["algorithm"],
            "label": fields["label"],
            "nonce": fields["nonce"],
        },
    }


def payload_sha256(payload: str) -> str:
    """Hex SHA-256 of the exact canonical payload bytes (tamper evidence)."""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Revocation records — immutable, sequenced, server-signed
#
# A revocation binds to *one* acceptance receipt (receipt_id plus the
# receipt payload hash) so a signed revocation can never be replayed onto a
# different receipt, and carries both the requested effective time and the
# server revocation time so offline time-travel checks are possible.
# ---------------------------------------------------------------------------


def build_revocation_payload(
    *,
    revocation_id: str,
    key_id: str,
    receipt_id: str,
    sequence: int,
    revision: int,
    receipt_payload_sha256: str,
    reason: str,
    effective_at: int,
    revoked_at: int,
) -> str:
    """Build the canonical ``receipt-revocation/v1`` payload that gets signed."""
    values = {
        "revocation_id": str(revocation_id),
        "key_id": str(key_id),
        "receipt_id": str(receipt_id),
        "sequence": str(int(sequence)),
        "revision": str(int(revision)),
        "receipt_payload_sha256": receipt_payload_sha256,
        "reason": reason,
        "effective_at": str(int(effective_at)),
        "revoked_at": str(int(revoked_at)),
    }
    lines = [REVOCATION_PAYLOAD_VERSION]
    for name in REVOCATION_FIELDS:
        value = values[name]
        if "\n" in value or "\r" in value:
            raise ReceiptFormatError(
                f"revocation field {name!r} must not contain newlines"
            )
        lines.append(f"{name}: {value}")
    return "\n".join(lines)


def parse_revocation_payload(payload: str) -> Dict[str, Any]:
    """Parse and strictly validate a canonical revocation payload.

    Raises ``ReceiptFormatError`` unless the payload has exactly the
    versioned field set in canonical order.
    """
    if not isinstance(payload, str):
        raise ReceiptFormatError("revocation payload must be a string")
    lines = payload.split("\n")
    if lines[0] != REVOCATION_PAYLOAD_VERSION:
        raise ReceiptFormatError(
            f"unsupported revocation payload version {lines[0]!r} "
            f"(expected {REVOCATION_PAYLOAD_VERSION!r})"
        )
    fields = lines[1:]
    if len(fields) != len(REVOCATION_FIELDS):
        raise ReceiptFormatError(
            f"revocation payload must have {len(REVOCATION_FIELDS)} fields, "
            f"got {len(fields)}"
        )
    out: Dict[str, Any] = {}
    for line, expected in zip(fields, REVOCATION_FIELDS):
        name, sep, value = line.partition(": ")
        if not sep or name != expected:
            raise ReceiptFormatError(
                f"revocation payload field {expected!r} missing or out of order"
            )
        out[expected] = value
    try:
        out["sequence"] = int(out["sequence"])
        out["revision"] = int(out["revision"])
        out["effective_at"] = int(out["effective_at"])
        out["revoked_at"] = int(out["revoked_at"])
    except ValueError as exc:
        raise ReceiptFormatError(
            f"revocation payload has a non-integer field: {exc}"
        )
    return out


def revocation_document(*, payload: str, signature: str) -> Dict[str, Any]:
    """Shape the API revocation object; every field mirrors the signed payload."""
    fields = parse_revocation_payload(payload)
    return {
        "revocation_id": fields["revocation_id"],
        "key_id": fields["key_id"],
        "receipt_id": fields["receipt_id"],
        "sequence": fields["sequence"],
        "revision": fields["revision"],
        "receipt_payload_sha256": fields["receipt_payload_sha256"],
        "reason": fields["reason"],
        "effective_at": fields["effective_at"],
        "revoked_at": fields["revoked_at"],
        "payload": payload,
        "payload_sha256": payload_sha256(payload),
        "signature": signature,
    }
