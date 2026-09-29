"""End-to-end verification orchestration (RFC 9421 §3.2).

Two execution modes share exactly the same verification pipeline:

* **live** (``/verify``): on success the nonce is atomically claimed *and*
  an offline-verifiable acceptance receipt is signed and persisted, both in
  the same transaction — this is the formal acceptance decision and has
  replay protection;
* **shadow** (``/verify-shadow``): runs against any immutable policy version
  (draft, active or retired) in a *read-only* transaction.  It performs every
  check — RFC 9421 base/signature, Content-Digest, key resolution and
  freshness — but never writes ``used_nonces``, never issues a receipt and
  never changes formal acceptance state.  A nonce that live verification
  already consumed is reported advisedly as ``nonce_seen`` rather than
  failing as a replay.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import db, reasons
from .base import BuiltBase, HttpRequestMessage, build_signature_base
from .crypto import (
    CryptoError,
    key_family,
    load_public_key,
    verify_signature,
)
from .digest import verify_content_digest
from .sf9421 import (
    SignatureInputError,
    parse_signature_dictionary,
    require_innerlist,
    require_signature_item,
)


class VerificationFailure(Exception):
    def __init__(self, reason: str, detail: str, extras: Optional[Dict[str, Any]] = None):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.extras = extras or {}


@dataclass
class VerificationResult:
    status: str  # "accepted"
    keyid: str
    key_version: int
    algorithm: str
    label: str
    nonce: Optional[str]
    created: Optional[int]
    expires: Optional[int]
    components: Dict[str, str]
    signature_base: str
    signature_base_lines: List[str]
    key_fingerprint: str
    # Policy version the checks ran against.
    policy_version: int
    # Shadow mode only: advisory, never a failure cause.
    nonce_seen: Optional[bool] = None
    # Live mode only: the signed acceptance receipt (None for shadow runs).
    receipt: Optional[Dict[str, Any]] = None


def _param(params: Dict[str, Any], name: str, expected_types, reason: str, detail: str):
    if name not in params:
        raise VerificationFailure(reason, detail)
    value = params[name]
    if not isinstance(value, expected_types):
        raise VerificationFailure(
            reasons.INVALID_SIGNATURE_PARAMETER,
            f"signature parameter {name!r} has the wrong type "
            f"(got {type(value).__name__})",
        )
    return value


def _to_unix(value: Any, name: str) -> int:
    """RFC 9421 created/expires are integers; @-date datetimes are tolerated."""
    if isinstance(value, bool):  # bool is a subclass of int
        raise VerificationFailure(
            reasons.INVALID_SIGNATURE_PARAMETER,
            f"signature parameter {name!r} must be an integer unix timestamp",
        )
    if isinstance(value, int):
        return value
    if isinstance(value, datetime):
        return int(value.timestamp())
    raise VerificationFailure(
        reasons.INVALID_SIGNATURE_PARAMETER,
        f"signature parameter {name!r} must be an integer unix timestamp",
    )


def verify_request(
    payload: Dict[str, Any],
    now: Optional[datetime] = None,
    *,
    policy: Optional[Dict[str, Any]] = None,
    shadow: bool = False,
) -> VerificationResult:
    """Verify one request; return details or raise ``VerificationFailure``.

    ``policy`` selects the immutable policy snapshot to enforce (defaults to
    the currently active policy).  ``shadow=True`` makes the run read-only:
    nonces are never claimed and a previously consumed nonce is surfaced via
    ``nonce_seen`` instead of raising ``replayed``.
    """
    now = now or datetime.now(timezone.utc)
    now_ts = int(now.timestamp())

    # ----- 1. parse Signature-Input / Signature ---------------------------
    raw_input = payload.get("signature_input")
    raw_signature = payload.get("signature")
    if not isinstance(raw_input, str) or not raw_input.strip():
        raise VerificationFailure(
            reasons.MALFORMED_SIGNATURE_INPUT,
            "signature_input must be a non-empty Signature-Input field value",
        )
    if not isinstance(raw_signature, str) or not raw_signature.strip():
        raise VerificationFailure(
            reasons.MALFORMED_SIGNATURE,
            "signature must be a non-empty Signature field value",
        )

    try:
        inputs = parse_signature_dictionary(raw_input)
    except SignatureInputError as exc:
        raise VerificationFailure(
            reasons.MALFORMED_SIGNATURE_INPUT, f"cannot parse Signature-Input: {exc}"
        )

    try:
        signatures = parse_signature_dictionary(raw_signature)
    except SignatureInputError as exc:
        raise VerificationFailure(
            reasons.MALFORMED_SIGNATURE, f"cannot parse Signature: {exc}"
        )

    if not inputs:
        raise VerificationFailure(
            reasons.MALFORMED_SIGNATURE_INPUT, "Signature-Input lists no signatures"
        )
    if len(inputs) > 1:
        raise VerificationFailure(
            reasons.MULTIPLE_SIGNATURES,
            f"exactly one signature label expected, got {sorted(inputs)}",
        )

    label = next(iter(inputs))
    if label not in signatures:
        raise VerificationFailure(
            reasons.LABEL_MISMATCH,
            f"signature label {label!r} present in Signature-Input but not in Signature",
        )

    covered = require_innerlist(inputs[label], label)
    signature_item = require_signature_item(signatures[label], label)
    signature_bytes = signature_item.value

    sig_params = dict(covered.params)

    # ----- 2. mandatory signature parameters ------------------------------
    keyid = sig_params.get("keyid")
    if not isinstance(keyid, str) or keyid == "":
        raise VerificationFailure(
            reasons.KEYID_REQUIRED,
            "the 'keyid' signature parameter is required and must be a non-empty string",
        )
    alg = sig_params.get("alg")
    if alg is not None and not isinstance(alg, str):
        raise VerificationFailure(
            reasons.ALG_REQUIRED,
            "the 'alg' signature parameter must be a string when present",
        )

    created_raw = sig_params.get("created")
    expires_raw = sig_params.get("expires")
    created = _to_unix(created_raw, "created") if created_raw is not None else None
    expires = _to_unix(expires_raw, "expires") if expires_raw is not None else None

    nonce = sig_params.get("nonce")
    if nonce is not None and not isinstance(nonce, str):
        raise VerificationFailure(
            reasons.INVALID_SIGNATURE_PARAMETER,
            "the 'nonce' signature parameter must be a string",
        )

    # ----- 3. load policy --------------------------------------------------
    if policy is None:
        policy = db.get_policy()
    policy_version = int(policy["version"])

    # ----- 4. build the message -------------------------------------------
    headers = []
    for h in payload.get("headers", []):
        if isinstance(h, dict):
            name = h.get("name")
            value = h.get("value", "")
        elif isinstance(h, (list, tuple)) and len(h) == 2:
            name, value = h
        else:
            raise VerificationFailure(
                reasons.BAD_REQUEST,
                "each header must be an object {'name','value'} or [name, value]",
            )
        if not isinstance(name, str) or not name:
            raise VerificationFailure(
                reasons.BAD_REQUEST, "header name must be a non-empty string"
            )
        if not isinstance(value, str):
            raise VerificationFailure(
                reasons.BAD_REQUEST, f"header {name!r} value must be a string"
            )
        headers.append((name, value))

    body = b""
    raw_body = payload.get("body")
    if raw_body is not None:
        if not isinstance(raw_body, str):
            raise VerificationFailure(
                reasons.BODY_NOT_BASE64, "body must be a base64 string or null"
            )
        import base64

        try:
            body = base64.b64decode(raw_body, validate=True)
        except Exception as exc:
            raise VerificationFailure(
                reasons.BODY_NOT_BASE64, f"body is not valid base64: {exc}"
            )

    method = payload.get("method")
    target_uri = payload.get("target_uri")
    if not isinstance(method, str) or not method:
        raise VerificationFailure(reasons.BAD_REQUEST, "method is required")
    if not isinstance(target_uri, str) or not target_uri:
        raise VerificationFailure(reasons.BAD_REQUEST, "target_uri is required")

    from urllib.parse import urlsplit

    parts = urlsplit(target_uri)
    if not parts.scheme or not parts.netloc:
        raise VerificationFailure(
            reasons.BAD_REQUEST,
            "target_uri must be an absolute URI with scheme and authority",
        )
    if parts.scheme.lower() not in ("http", "https"):
        raise VerificationFailure(
            reasons.BAD_REQUEST,
            f"target_uri scheme {parts.scheme!r} is not http/https",
        )

    message = HttpRequestMessage(
        method=method, target_uri=target_uri, headers=headers, body=body
    )

    # ----- 5. Content-Digest ----------------------------------------------
    header_index = {n.lower(): v for n, v in headers}
    if "content-digest" in header_index:
        try:
            verify_content_digest(header_index["content-digest"], body)
        except ValueError as exc:
            code = getattr(exc, "code", reasons.CONTENT_DIGEST_MISMATCH)
            mapping = {
                "malformed_content_digest": reasons.MALFORMED_SIGNATURE_INPUT,
                "content_digest_missing": reasons.CONTENT_DIGEST_MISSING,
                "content_digest_unsupported": reasons.CONTENT_DIGEST_UNSUPPORTED,
                "content_digest_mismatch": reasons.CONTENT_DIGEST_MISMATCH,
            }
            raise VerificationFailure(
                mapping.get(code, reasons.CONTENT_DIGEST_MISMATCH), str(exc)
            )
    else:
        if body and policy["require_content_digest_with_body"]:
            raise VerificationFailure(
                reasons.CONTENT_DIGEST_REQUIRED,
                "a content-digest header is required when the request has a body",
            )

    # ----- 6. rebuild the signature base ----------------------------------
    from .base import ComponentError

    try:
        built: BuiltBase = build_signature_base(message, covered)
    except ComponentError as exc:
        raise VerificationFailure(exc.reason, exc.detail)

    # ----- 7. policy: required components ---------------------------------
    def _component_name(identifier: str) -> str:
        # Base identifiers are quoted SF strings, e.g. '"@query-param";name="a"'.
        head = identifier.split(";", 1)[0]
        if len(head) >= 2 and head[0] == '"' and head[-1] == '"':
            head = head[1:-1]
        return head

    covered_names = {_component_name(i) for i in built.identifiers}
    for required in policy["required_components"]:
        if required not in covered_names:
            raise VerificationFailure(
                reasons.REQUIRED_COMPONENT_MISSING,
                f"policy requires component {required!r}, not covered by the signature",
            )

    # Policy may additionally force content-digest on any body.
    if body and policy["require_content_digest_with_body"]:
        if "content-digest" not in covered_names:
            raise VerificationFailure(
                reasons.REQUIRED_COMPONENT_MISSING,
                "policy requires 'content-digest' to be covered when a body is present",
            )

    # ----- 8. resolve key + infer/check algorithm -------------------------
    # When alg is absent (allowed by RFC 9421) it is derived from the
    # registered public key.
    #
    # Shadow runs use a read-only transaction: even a bug or a future code
    # path that attempted an INSERT could never persist.
    with db.transaction(read_only=shadow) as cur:
        key_row = db.get_active_key(keyid, cur=cur)
        if key_row is None:
            raise VerificationFailure(
                reasons.UNKNOWN_KEY, f"no active public key registered for keyid {keyid!r}"
            )
        if not key_row["enabled"]:
            raise VerificationFailure(
                reasons.KEY_DISABLED, f"keyid {keyid!r} is disabled"
            )

        try:
            public_key = load_public_key(key_row["public_key"])
        except CryptoError as exc:
            raise VerificationFailure(exc.code, exc.detail)

        actual_family = key_family(public_key)
        if alg is None:
            # RFC 9421's RSA-PSS examples standardise on SHA-512; use it
            # when the signer omits the alg parameter.
            alg = "ed25519" if actual_family == "ed25519" else "rsa-pss-sha512"
        elif alg not in ("ed25519", "rsa-pss-sha256", "rsa-pss-sha512"):
            raise VerificationFailure(
                reasons.ALGORITHM_UNSUPPORTED,
                f"algorithm {alg!r} is not supported (expected ed25519 or rsa-pss-*)",
            )

        if alg not in policy["required_algorithms"]:
            raise VerificationFailure(
                reasons.ALGORITHM_NOT_ALLOWED,
                f"algorithm {alg!r} is not allowed by policy version {policy_version} "
                f"(allowed: {policy['required_algorithms']})",
            )

        expected_family = "ed25519" if alg == "ed25519" else "rsa"
        if actual_family != expected_family:
            raise VerificationFailure(
                reasons.INVALID_PUBLIC_KEY,
                f"registered key for {keyid!r} is {actual_family} "
                f"but alg {alg!r} requires {expected_family}",
            )

        # ----- 9. freshness ---------------------------------------------------
        skew = int(policy["clock_skew_seconds"])
        max_age = int(policy["max_age_seconds"])

        if created is None:
            if policy["require_created"]:
                raise VerificationFailure(
                    reasons.CREATED_REQUIRED,
                    "the 'created' signature parameter is required by policy",
                )

        if expires is not None:
            if expires < now_ts - skew:
                raise VerificationFailure(
                    reasons.MESSAGE_EXPIRED,
                    f"expires={expires} is in the past (now {now_ts}, skew {skew}s)",
                )

        if created is not None:
            if created > now_ts + skew:
                raise VerificationFailure(
                    reasons.CREATED_IN_FUTURE,
                    f"created={created} is more than {skew}s in the future (now {now_ts})",
                )
            if now_ts - created > max_age:
                raise VerificationFailure(
                    reasons.MESSAGE_AGE_EXCEEDED,
                    f"message age {now_ts - created}s exceeds max_age {max_age}s",
                )

        if nonce is None and policy["require_nonce"]:
            raise VerificationFailure(
                reasons.INVALID_SIGNATURE_PARAMETER,
                "the 'nonce' signature parameter is required by policy",
            )

        # ----- 10. crypto verify ---------------------------------------------
        try:
            verify_signature(alg, public_key, signature_bytes, built.base.encode("utf-8"))
        except CryptoError as exc:
            raise VerificationFailure(exc.code, exc.detail)

        # ----- 11. nonce handling --------------------------------------------
        nonce_seen: Optional[bool] = None
        if nonce is not None:
            if shadow:
                # Read-only advisory: never claim, never fail as a replay.
                nonce_seen = db.nonce_seen(keyid, nonce, cur=cur)
            else:
                # Signature is valid — claim the nonce atomically in THIS
                # transaction.
                try:
                    db.claim_nonce(cur, keyid, nonce, label=label)
                except db.ReplayDetected:
                    raise VerificationFailure(
                        reasons.REPLAYED,
                        f"nonce {nonce!r} for keyid {keyid!r} has already been accepted",
                        extras={
                            "keyid": keyid,
                            "key_version": key_row["version"],
                            "key_fingerprint": key_row["fingerprint"],
                            "algorithm": alg,
                            "label": label,
                            "nonce": nonce,
                            "policy_version": policy_version,
                        },
                    )

        # ----- 12. acceptance receipt (live only) -----------------------------
        # Signed and persisted in THIS transaction: the receipt insert and
        # the nonce claim commit or roll back together.  Rejections, replays
        # and shadow runs never produce a receipt.
        receipt: Optional[Dict[str, Any]] = None
        if not shadow:
            receipt = db.issue_receipt(
                cur,
                envelope=payload,
                keyid=keyid,
                key_version=key_row["version"],
                policy_version=policy_version,
                algorithm=alg,
                label=label,
                nonce=nonce,
            )

    return VerificationResult(
        status="accepted",
        keyid=keyid,
        key_version=key_row["version"],
        algorithm=alg,
        label=label,
        nonce=nonce,
        created=created,
        expires=expires,
        components=built.component_values,
        signature_base=built.base,
        signature_base_lines=built.lines,
        key_fingerprint=key_row["fingerprint"],
        policy_version=policy_version,
        nonce_seen=nonce_seen,
        receipt=receipt,
    )
