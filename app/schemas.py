"""Pydantic models for the verification and admin APIs."""
from __future__ import annotations

from typing import Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator

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


class ReceiptRevokeRequest(BaseModel):
    """Idempotent admin command that revokes one acceptance receipt."""

    reason: str = Field(
        ...,
        min_length=1,
        max_length=1024,
        description="Human-readable revocation reason (single line, signed into the record)",
    )
    effective_at: int = Field(
        ...,
        ge=0,
        description="Unix seconds from which the revocation is effective; must not precede receipt issuance",
    )
    expected_revision: Optional[int] = Field(
        default=None,
        ge=0,
        description="Optimistic-concurrency guard: receipt revision the admin saw (0 before revocation)",
    )

    @field_validator("reason")
    @classmethod
    def _single_line(cls, value: str) -> str:
        reason = value.strip()
        if not reason or "\n" in reason or "\r" in reason:
            raise ValueError("reason must be a non-empty single-line string")
        return reason


class KeyInfo(BaseModel):
    keyid: str
    version: int
    key_kind: str
    fingerprint: str
    enabled: bool
    created_at: str
