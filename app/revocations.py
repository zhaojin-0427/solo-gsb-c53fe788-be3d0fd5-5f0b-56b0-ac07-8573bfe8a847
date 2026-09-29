"""Versioned, offline-verifiable receipt-revocation records (audit chain).

When an administrator revokes an acceptance receipt the server appends one
*revocation record*: a canonical, versioned payload binding

* a unique revocation id and a **global, gapless sequence number**,
* the revoked ``receipt_id`` and the receipt revision after the revocation,
* the human/machine ``reason`` and the ``effective_at`` time from which the
  revocation takes effect (may be in the past or scheduled in the future),
* the server-side recording time ``revoked_at``,
* the receipt-signing key version that signed the record, and
* a **hash link to the previous revocation record** (``prev_seq`` /
  ``prev_payload_sha256``), so the table forms a tamper-evident audit chain,

signed with the server's Ed25519 receipt-signing key and persisted in the
same database transaction as the receipt revision bump.  Records are
immutable (the database rejects UPDATE/DELETE) and everything lives in
PostgreSQL, so restart and concurrent execution yield identical results.

This module intentionally depends only on the standard library and
``cryptography`` (via ``app.receipts`` helpers) so the standalone offline
verifier (``tools/verify_receipt.py``) can reuse it without the server or
database.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from .receipts import sign_payload, verify_payload_signature  # noqa: F401

#: Version tag of the canonical revocation payload format (first line).
PAYLOAD_VERSION = "revocation/v1"

#: Canonical field order after the version line.
PAYLOAD_FIELDS = (
    "revocation_id",
    "revocation_seq",
    "receipt_id",
    "receipt_revision",
    "reason",
    "effective_at",
    "revoked_at",
    "key_id",
    "command_id",
    "prev_seq",
    "prev_payload_sha256",
)


class RevocationFormatError(ValueError):
    """Raised when a revocation payload is not well-formed."""


def payload_sha256(payload: str) -> str:
    """SHA-256 hex digest of a canonical payload — the audit-chain link."""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Canonical payload
# ---------------------------------------------------------------------------


def build_payload(
    *,
    revocation_id: str,
    revocation_seq: int,
    receipt_id: str,
    receipt_revision: int,
    reason: str,
    effective_at: int,
    revoked_at: int,
    key_id: str,
    command_id: Optional[str],
    prev_seq: int,
    prev_payload_sha256: Optional[str],
) -> str:
    """Build the canonical ``revocation/v1`` payload that gets signed."""
    values = {
        "revocation_id": str(revocation_id),
        "revocation_seq": str(int(revocation_seq)),
        "receipt_id": str(receipt_id),
        "receipt_revision": str(int(receipt_revision)),
        "reason": reason,
        "effective_at": str(int(effective_at)),
        "revoked_at": str(int(revoked_at)),
        "key_id": str(key_id),
        "command_id": command_id or "",
        "prev_seq": str(int(prev_seq)),
        "prev_payload_sha256": prev_payload_sha256 or "",
    }
    lines = [PAYLOAD_VERSION]
    for name in PAYLOAD_FIELDS:
        value = values[name]
        if "\n" in value or "\r" in value:
            raise RevocationFormatError(
                f"revocation field {name!r} must not contain newlines"
            )
        lines.append(f"{name}: {value}")
    return "\n".join(lines)


def parse_payload(payload: str) -> Dict[str, Any]:
    """Parse and strictly validate a canonical revocation payload.

    Raises ``RevocationFormatError`` unless the payload has exactly the
    versioned field set in canonical order.
    """
    if not isinstance(payload, str):
        raise RevocationFormatError("revocation payload must be a string")
    lines = payload.split("\n")
    if lines[0] != PAYLOAD_VERSION:
        raise RevocationFormatError(
            f"unsupported revocation payload version {lines[0]!r} "
            f"(expected {PAYLOAD_VERSION!r})"
        )
    fields = lines[1:]
    if len(fields) != len(PAYLOAD_FIELDS):
        raise RevocationFormatError(
            f"revocation payload must have {len(PAYLOAD_FIELDS)} fields, "
            f"got {len(fields)}"
        )
    out: Dict[str, Any] = {}
    for line, expected in zip(fields, PAYLOAD_FIELDS):
        name, sep, value = line.partition(": ")
        if not sep or name != expected:
            raise RevocationFormatError(
                f"revocation payload field {expected!r} missing or out of order"
            )
        out[expected] = value
    try:
        out["revocation_seq"] = int(out["revocation_seq"])
        out["receipt_revision"] = int(out["receipt_revision"])
        out["effective_at"] = int(out["effective_at"])
        out["revoked_at"] = int(out["revoked_at"])
        out["prev_seq"] = int(out["prev_seq"])
    except ValueError as exc:
        raise RevocationFormatError(
            f"revocation payload has a non-integer field: {exc}"
        )
    out["command_id"] = out["command_id"] or None
    out["prev_payload_sha256"] = out["prev_payload_sha256"] or None
    if out["revocation_seq"] < 1:
        raise RevocationFormatError("revocation_seq must be >= 1")
    if (out["prev_seq"] == 0) != (out["prev_payload_sha256"] is None):
        raise RevocationFormatError(
            "prev_seq and prev_payload_sha256 must both be set, or both be "
            "empty on the genesis record"
        )
    if out["prev_seq"] != out["revocation_seq"] - 1:
        raise RevocationFormatError(
            "prev_seq must equal revocation_seq - 1 (gapless chain)"
        )
    return out


# ---------------------------------------------------------------------------
# API document
# ---------------------------------------------------------------------------


def revocation_document(
    *,
    payload: str,
    signature: str,
    effective_at: str,
    revoked_at: str,
) -> Dict[str, Any]:
    """Shape the API revocation object; convenience fields mirror the payload.

    The signed ``payload`` is authoritative — every other field is derived
    from it so mirrors can never disagree with what was signed.
    """
    fields = parse_payload(payload)
    return {
        "revocation_id": fields["revocation_id"],
        "revocation_seq": fields["revocation_seq"],
        "receipt_id": fields["receipt_id"],
        "receipt_revision": fields["receipt_revision"],
        "reason": fields["reason"],
        "key_id": fields["key_id"],
        "command_id": fields["command_id"],
        "effective_at": effective_at,
        "effective_at_unix": fields["effective_at"],
        "revoked_at": revoked_at,
        "revoked_at_unix": fields["revoked_at"],
        "prev_seq": fields["prev_seq"] or None,
        "prev_payload_sha256": fields["prev_payload_sha256"],
        "payload": payload,
        "payload_sha256": payload_sha256(payload),
        "signature": signature,
    }
