"""Pydantic models for the verification and admin APIs."""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Union

from pydantic import BaseModel, Field

HeaderInput = Union[Dict[str, str], List[str]]


class VerifyRequest(BaseModel):
    method: str = Field(..., description='HTTP method, e.g. "POST"')
    target_uri: str = Field(..., description="Absolute target (request) URI")
    headers: List[HeaderInput] = Field(
        default_factory=list,
        description="Ordered raw header fields as {name, value} or [name, value]",
    )
    body: Optional[str] = Field(
        None, description="Request body, base64 (standard alphabet with padding)"
    )
    signature_input: str = Field(..., alias="Signature-Input")
    signature: str = Field(..., alias="Signature")

    model_config = {"populate_by_name": True}


class Policy(BaseModel):
    required_components: List[str]
    required_algorithms: List[str]
    clock_skew_seconds: int = Field(..., ge=0, le=86400)
    max_age_seconds: int = Field(..., ge=1, le=315_360_000)
    require_created: bool = True
    require_nonce: bool = True
    require_content_digest_with_body: bool = True


class PolicyDraftRequest(BaseModel):
    """Draft parameters; every field is optional and defaults to the value
    of the active policy version the draft is based on."""

    required_components: Optional[List[str]] = None
    required_algorithms: Optional[List[str]] = None
    clock_skew_seconds: Optional[int] = Field(default=None, ge=0, le=86400)
    max_age_seconds: Optional[int] = Field(default=None, ge=1, le=315_360_000)
    require_created: Optional[bool] = None
    require_nonce: Optional[bool] = None
    require_content_digest_with_body: Optional[bool] = None
    # Version the admin believes is active when creating the draft.
    baseline_version: Optional[int] = Field(default=None, ge=1)


class PolicyActivateRequest(BaseModel):
    # Version the admin believes is active right now; activation is a no-op
    # when the requested version is already active.
    expected_active_version: Optional[int] = Field(default=None, ge=1)


class ShadowVerifyRequest(VerifyRequest):
    policy_version: int = Field(
        ..., ge=1, description="Immutable policy version to verify against"
    )


class RegisterKeyRequest(BaseModel):
    keyid: str = Field(..., min_length=1, max_length=256)
    public_key: str = Field(..., description="PEM SPKI, base64 DER SPKI, or 32-byte raw Ed25519 (base64)")


class RevokeReceiptRequest(BaseModel):
    """Idempotent receipt-revocation command.

    ``effective_at`` accepts unix seconds (integer) or an ISO-8601 timestamp.
    ``expected_revision`` is the optimistic-concurrency token: it must equal
    the receipt's current revision (0 for a never-revoked receipt).
    ``command_id`` is an optional idempotency key; resubmitting the same
    command returns the original record instead of failing.
    """

    reason: str = Field(..., min_length=1, max_length=512)
    effective_at: Union[int, datetime] = Field(
        ..., description="When the revocation takes effect (unix seconds or ISO-8601)"
    )
    expected_revision: int = Field(..., ge=0)
    command_id: Optional[str] = Field(default=None, min_length=1, max_length=128)


class KeyInfo(BaseModel):
    keyid: str
    version: int
    key_kind: str
    fingerprint: str
    enabled: bool
    created_at: str
