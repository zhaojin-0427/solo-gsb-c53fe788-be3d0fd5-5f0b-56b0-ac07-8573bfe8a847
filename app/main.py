"""FastAPI application: HTTP Message Signature Verification API."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from . import config, db, reasons
from .crypto import key_family, load_public_key, spki_fingerprint
from .policy_diff import diff_policies
from .schemas import (
    Policy,
    PolicyActivateRequest,
    PolicyDraftRequest,
    RegisterKeyRequest,
    ShadowVerifyRequest,
    VerifyRequest,
)
from .verifier import VerificationFailure, verify_request

logger = logging.getLogger("hss")
logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: "FastAPI"):
    db.connect()
    logger.info("database ready")
    try:
        yield
    finally:
        db.close()


app = FastAPI(
    title="HTTP Message Signature Verification API",
    description=(
        "Verifies HTTP message signatures submitted by clients according to "
        "[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421), with "
        "Content-Digest (RFC 9530), Ed25519 / RSA-PSS keys, freshness policy, "
        "atomic nonce replay protection, immutable policy versioning, "
        "read-only shadow verification and signed, offline-verifiable "
        "acceptance receipts."
    ),
    version="2.1.0",
    lifespan=lifespan,
)


# Failure reason -> HTTP status.
_FAILURE_STATUS = {
    reasons.REPLAYED: status.HTTP_409_CONFLICT,
    reasons.BAD_REQUEST: status.HTTP_400_BAD_REQUEST,
    reasons.BODY_NOT_BASE64: status.HTTP_400_BAD_REQUEST,
    reasons.MALFORMED_SIGNATURE_INPUT: status.HTTP_400_BAD_REQUEST,
    reasons.MALFORMED_SIGNATURE: status.HTTP_400_BAD_REQUEST,
    reasons.LABEL_MISMATCH: status.HTTP_400_BAD_REQUEST,
    reasons.MULTIPLE_SIGNATURES: status.HTTP_400_BAD_REQUEST,
    reasons.UNKNOWN_KEY: status.HTTP_404_NOT_FOUND,
    reasons.POLICY_VERSION_UNKNOWN: status.HTTP_404_NOT_FOUND,
    reasons.RECEIPT_UNKNOWN: status.HTTP_404_NOT_FOUND,
    reasons.RECEIPT_ISSUANCE_FAILED: status.HTTP_500_INTERNAL_SERVER_ERROR,
    reasons.POLICY_ACTIVATION_CONFLICT: status.HTTP_409_CONFLICT,
    reasons.POLICY_DRAFT_NOT_ACTIVATABLE: status.HTTP_409_CONFLICT,
}


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "active_policy_version": db.get_policy()["version"]}


@app.exception_handler(RequestValidationError)
async def _validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "status": "rejected",
            "reason": reasons.BAD_REQUEST,
            "detail": "request payload failed validation",
            "errors": exc.errors(),
        },
    )


def _validation_errors(exc: Exception):
    """Best-effort extraction of structured pydantic v2 validation errors."""
    get_errors = getattr(exc, "errors", None)
    if callable(get_errors):
        try:
            errors = get_errors()
            if isinstance(errors, list) and errors:
                return errors
        except Exception:  # pragma: no cover - defensive
            pass
    return [{"loc": [], "msg": str(exc), "type": "value_error"}]


def _parse_verify_envelope(payload: Dict[str, Any], model_cls):
    """Validate a /verify(-shadow) JSON envelope and normalise it.

    Validation failures are raised as ``RequestValidationError`` so the
    application-wide handler answers with the stable ``bad_request`` code.
    """
    try:
        model = model_cls.model_validate(payload)
    except Exception as exc:
        errors = _validation_errors(exc)
        raise RequestValidationError(errors if isinstance(errors, list) else [errors])

    normalized = {
        "method": model.method,
        "target_uri": model.target_uri,
        "headers": [_normalize_header(h) for h in model.headers],
        "body": model.body,
        "signature_input": payload.get("signature_input")
        or payload.get("Signature-Input"),
        "signature": payload.get("signature") or payload.get("Signature"),
    }
    return model, normalized


def _failure_response(
    failure: VerificationFailure,
    *,
    mode: str = "live",
    extra: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    http_status = _FAILURE_STATUS.get(failure.reason, status.HTTP_401_UNAUTHORIZED)
    content = {
        "status": "replayed" if failure.reason == reasons.REPLAYED else "rejected",
        "mode": mode,
        "reason": failure.reason,
        "detail": failure.detail,
    }
    content.update(failure.extras)
    if extra:
        content.update(extra)
    return JSONResponse(status_code=http_status, content=content)


def _accepted_content(result, *, mode: str, extra: Optional[Dict[str, Any]] = None):
    content = {
        "status": result.status if mode == "live" else "shadow_accepted",
        "mode": mode,
        "keyid": result.keyid,
        "key_version": result.key_version,
        "key_fingerprint": result.key_fingerprint,
        "label": result.label,
        "algorithm": result.algorithm,
        "created": result.created,
        "expires": result.expires,
        "nonce": result.nonce,
        "policy_version": result.policy_version,
        "components": result.components,
        "signature_base": result.signature_base,
        "signature_base_lines": result.signature_base_lines,
        # Live acceptances carry a signed, offline-verifiable receipt;
        # shadow runs never issue one (null).
        "receipt": result.receipt,
    }
    if extra:
        content.update(extra)
    return content


@app.post("/verify")
async def verify(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "error", "reason": reasons.BAD_REQUEST,
                    "detail": "request body must be valid JSON"},
        )

    _, normalized = _parse_verify_envelope(payload, VerifyRequest)

    try:
        result = verify_request(normalized)
    except VerificationFailure as failure:
        return _failure_response(failure)
    except db.ReceiptIssuanceError as exc:
        # Receipt signing/persistence failed: the whole transaction —
        # including the nonce claim — was rolled back, so no acceptance
        # state and no partial receipt exist.
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "mode": "live",
                "reason": reasons.RECEIPT_ISSUANCE_FAILED,
                "detail": str(exc),
            },
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=_accepted_content(result, mode="live"),
    )


@app.post("/verify-shadow")
async def verify_shadow(request: Request) -> JSONResponse:
    """Verify against an arbitrary immutable policy version, without effects.

    Runs the full RFC 9421 / Content-Digest / key / freshness pipeline in a
    read-only transaction: no nonce is consumed and no acceptance state is
    mutated.  The response carries the stable reason code on failure (same
    codes/status mapping as /verify) plus an itemised diff of the requested
    version versus the currently active version.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "error", "reason": reasons.BAD_REQUEST,
                    "detail": "request body must be valid JSON"},
        )

    model, normalized = _parse_verify_envelope(payload, ShadowVerifyRequest)
    requested_version = model.policy_version

    version_policy = db.get_policy_version(requested_version)
    if version_policy is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "status": "rejected",
                "mode": "shadow",
                "reason": reasons.POLICY_VERSION_UNKNOWN,
                "detail": f"policy version {requested_version} does not exist",
                "policy_version": requested_version,
            },
        )

    active_policy = db.get_policy()
    changes = diff_policies(version_policy, active_policy)
    diff_meta = {
        "active_policy_version": active_policy["version"],
        "diff_vs_active": changes,
        "diff_count": len(changes),
        "policy_status": version_policy["status"],
    }

    try:
        result = verify_request(normalized, policy=version_policy, shadow=True)
    except VerificationFailure as failure:
        # All failures carry the requested version (explicit extras win).
        failure.extras.setdefault("policy_version", requested_version)
        return _failure_response(failure, mode="shadow", extra=diff_meta)

    content = _accepted_content(result, mode="shadow", extra=diff_meta)
    # Advisory only: True when live verification already consumed this nonce.
    content["nonce_seen"] = result.nonce_seen
    return JSONResponse(status_code=status.HTTP_200_OK, content=content)


def _normalize_header(h: Any) -> Any:
    if isinstance(h, dict):
        return (h.get("name"), h.get("value", ""))
    return h


# ---------------------------------------------------------------------------
# Acceptance receipts (public, read-only)
# ---------------------------------------------------------------------------


@app.get("/receipts/keys")
def receipt_signing_keys() -> Dict[str, Any]:
    """Publish every receipt-signing public key version (active + retired).

    Offline verifiers fetch this once; retired keys stay listed so receipts
    issued before a rotation keep verifying.
    """
    return {"keys": db.list_receipt_signing_keys()}


@app.get("/receipts/{receipt_id}")
def read_receipt(receipt_id: str) -> Dict[str, Any]:
    """Fetch one persisted acceptance receipt by its unique id."""
    receipt = db.get_receipt(receipt_id)
    if receipt is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "reason": reasons.RECEIPT_UNKNOWN,
                "detail": f"receipt {receipt_id!r} does not exist",
            },
        )
    return receipt


# ---------------------------------------------------------------------------
# Admin API
# ---------------------------------------------------------------------------


def require_admin(x_admin_token: Optional[str] = Header(default=None)) -> None:
    if not config.ADMIN_TOKEN:
        return  # auth disabled
    if x_admin_token != config.ADMIN_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or invalid X-Admin-Token",
        )


@app.get("/admin/policy")
def read_policy(_: None = Depends(require_admin)) -> Dict[str, Any]:
    return db.get_policy()


@app.put("/admin/policy")
def replace_policy(
    policy: Policy, _: None = Depends(require_admin)
) -> Dict[str, Any]:
    return db.update_policy(policy.model_dump())


# --- Policy versioning -----------------------------------------------------


@app.get("/admin/policy/versions")
def list_versions(
    status: Optional[str] = None, _: None = Depends(require_admin)
) -> Dict[str, Any]:
    if status is not None and status not in ("draft", "active", "retired"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="status filter must be one of draft, active, retired",
        )
    return {
        "versions": db.list_policy_versions(status),
        "active_version": db.get_policy()["version"],
    }


@app.get("/admin/policy/versions/{version}")
def read_version(version: int, _: None = Depends(require_admin)) -> Dict[str, Any]:
    row = db.get_policy_version(version)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "reason": reasons.POLICY_VERSION_UNKNOWN,
                "detail": f"policy version {version} does not exist",
            },
        )
    return row


@app.post("/admin/policy/drafts", status_code=status.HTTP_201_CREATED)
def create_draft(
    req: PolicyDraftRequest, _: None = Depends(require_admin)
) -> Dict[str, Any]:
    data = req.model_dump(exclude_none=True)
    try:
        return db.create_policy_draft(data)
    except db.PolicyActivationConflict as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "reason": reasons.POLICY_ACTIVATION_CONFLICT,
                "detail": str(exc),
                "active_version": exc.active_version,
            },
        )


@app.post("/admin/policy/versions/{version}/activate")
def activate_version(
    version: int,
    req: Optional[PolicyActivateRequest] = None,
    _: None = Depends(require_admin),
) -> Dict[str, Any]:
    expected = req.expected_active_version if req is not None else None
    try:
        activated = db.activate_policy_version(version, expected)
    except db.PolicyVersionNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"reason": reasons.POLICY_VERSION_UNKNOWN, "detail": str(exc)},
        )
    except db.PolicyDraftNotActivatable as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "reason": reasons.POLICY_DRAFT_NOT_ACTIVATABLE,
                "detail": str(exc),
                "version": exc.version,
                "status": exc.status,
            },
        )
    except db.PolicyActivationConflict as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "reason": reasons.POLICY_ACTIVATION_CONFLICT,
                "detail": str(exc),
                "active_version": exc.active_version,
            },
        )
    return {
        "activated": activated,
        "active_version": activated["version"],
    }


# --- Key registry ----------------------------------------------------------


@app.post("/admin/keys", status_code=status.HTTP_201_CREATED)
def register_key(
    req: RegisterKeyRequest, _: None = Depends(require_admin)
) -> Dict[str, Any]:
    try:
        public_key = load_public_key(req.public_key)
    except Exception as exc:
        code = getattr(exc, "code", reasons.INVALID_PUBLIC_KEY)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"reason": code, "detail": str(exc)},
        )
    return db.register_key(
        keyid=req.keyid,
        public_key=req.public_key.strip(),
        key_kind=key_family(public_key),
        fingerprint=spki_fingerprint(public_key),
    )


@app.get("/admin/keys")
def list_keys(_: None = Depends(require_admin)) -> Dict[str, Any]:
    return {"keys": db.list_keys()}


@app.post("/admin/keys/{keyid}/disable")
def disable_key(keyid: str, _: None = Depends(require_admin)) -> Dict[str, str]:
    if not db.set_key_enabled(keyid, False):
        raise HTTPException(status_code=404, detail=f"no active key {keyid}")
    return {"keyid": keyid, "enabled": "false"}


@app.post("/admin/keys/{keyid}/enable")
def enable_key(keyid: str, _: None = Depends(require_admin)) -> Dict[str, str]:
    if not db.set_key_enabled(keyid, True):
        raise HTTPException(status_code=404, detail=f"no key {keyid} to enable")
    return {"keyid": keyid, "enabled": "true"}


# --- Receipt-signing key rotation -------------------------------------------


@app.post("/admin/receipt-keys/rotate", status_code=status.HTTP_201_CREATED)
def rotate_receipt_key(_: None = Depends(require_admin)) -> Dict[str, Any]:
    """Rotate the server receipt-signing key (atomic retire + activate).

    The retired public key remains published at ``GET /receipts/keys`` so
    receipts issued before the rotation stay verifiable offline.
    """
    return db.rotate_receipt_signing_key()
