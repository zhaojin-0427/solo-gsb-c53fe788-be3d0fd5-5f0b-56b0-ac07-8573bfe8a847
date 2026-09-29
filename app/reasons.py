"""Stable machine-readable reason codes returned by the API."""
from __future__ import annotations

# Request / envelope problems (HTTP 4xx).
BAD_REQUEST = "bad_request"
MALFORMED_SIGNATURE_INPUT = "malformed_signature_input"
MALFORMED_SIGNATURE = "malformed_signature"
LABEL_MISMATCH = "label_mismatch"
MULTIPLE_SIGNATURES = "multiple_signatures"
BODY_NOT_BASE64 = "body_not_base64"

# Policy / resolution problems.
UNKNOWN_KEY = "unknown_key"
KEY_DISABLED = "key_disabled"
ALGORITHM_UNSUPPORTED = "algorithm_unsupported"
ALGORITHM_NOT_ALLOWED = "algorithm_not_allowed"
REQUIRED_COMPONENT_MISSING = "required_component_missing"
CONTENT_DIGEST_REQUIRED = "content_digest_required"
CONTENT_DIGEST_MISSING = "content_digest_missing"
CONTENT_DIGEST_UNSUPPORTED = "content_digest_unsupported"
CONTENT_DIGEST_MISMATCH = "content_digest_mismatch"

# Component / base problems.
INVALID_COMPONENT = "invalid_component"
INVALID_COMPONENT_PARAMETER = "invalid_component_parameter"
UNKNOWN_COMPONENT = "unknown_component"
COMPONENT_VALUE_UNAVAILABLE = "component_value_unavailable"
DUPLICATE_COMPONENT = "duplicate_component"
RELATED_REQUEST_UNSUPPORTED = "related_request_unsupported"

# Signature parameter problems.
KEYID_REQUIRED = "keyid_required"
ALG_REQUIRED = "alg_required"
CREATED_REQUIRED = "created_required"
INVALID_SIGNATURE_PARAMETER = "invalid_signature_parameter"
CREATED_IN_FUTURE = "created_in_future"
MESSAGE_EXPIRED = "message_expired"
MESSAGE_AGE_EXCEEDED = "message_age_exceeded"

# Crypto / replay.
INVALID_PUBLIC_KEY = "invalid_public_key"
SIGNATURE_INVALID = "signature_invalid"
REPLAYED = "replayed"

# Policy versioning.
POLICY_VERSION_UNKNOWN = "policy_version_unknown"
POLICY_ACTIVATION_CONFLICT = "policy_activation_conflict"
POLICY_DRAFT_NOT_ACTIVATABLE = "policy_draft_not_activatable"

# Acceptance receipts.
RECEIPT_UNKNOWN = "receipt_unknown"
RECEIPT_ISSUANCE_FAILED = "receipt_issuance_failed"

# Internal.
INTERNAL_ERROR = "internal_error"

ALL_REASONS = frozenset(
    v
    for k, v in globals().items()
    if k.isupper() and isinstance(v, str)
)
