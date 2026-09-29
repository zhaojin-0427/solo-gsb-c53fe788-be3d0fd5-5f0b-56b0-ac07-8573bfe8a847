#!/usr/bin/env python3
"""Standalone offline verifier for /verify acceptance receipts and revocations.

Runs fully offline — no server, no database.  Requires only the
``cryptography`` package (plus this repository's ``app.receipts`` /
``app.crypto`` modules, which have no other dependencies).

Receipt checks:

1. the canonical payload is well-formed (``receipt/v1``, strict field order);
2. the receipt's mirror fields (``receipt_id`` / ``key_id`` /
   ``input_digest`` / ``context``) match the signed payload;
3. the Ed25519 signature over the exact payload bytes, using the server
   public key published at ``GET /receipts/keys`` — retired keys included,
   so receipts survive server key rotation;
4. optionally (``--request``), that the receipt binds to a specific
   ``/verify`` request body: the deterministic input digest is recomputed
   locally and compared with the signed payload.

Revocation checks (``--revocation`` or ``--status``):

5. the revocation payload is well-formed (``receipt-revocation/v1``,
   strict field order) and its mirror fields match;
6. it is cryptographically signed by the same published server keys
   (including historical/retired keys);
7. it is bound to *this* receipt — ``receipt_id`` and
   ``receipt_payload_sha256`` must match the acceptance receipt, so a
   revocation can never be replayed onto a different receipt;
8. it cannot rewrite history: ``effective_at >= receipt issued_at`` and
   ``revoked_at >= effective_at``;
9. the point-in-time state (``--at``, default now) matches the signed
   proof (``valid`` before ``effective_at``, ``revoked`` at/after it), and
   an optional ``--expect-status`` assertion is honoured.

Usage:
    python tools/verify_receipt.py --receipt receipt.json --keys keys.json \
        [--request request.json] [--revocation revocation.json] \
        [--status status.json] [--at 1790301296] [--expect-status revoked] [-q]

``receipt.json`` may be the receipt object itself, a full ``/verify``
response, or a ``GET /receipts/{id}`` response.  ``keys.json`` is the
``GET /receipts/keys`` response (or its ``keys`` list).  A
``--status status.json`` may be the ``GET /receipts/{id}/status``
response, in which case the embedded receipt and revocation are used.
Exit code 0 means every check passed; 1 means any check failed.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Allow running from anywhere inside a repository checkout.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import receipts  # noqa: E402
from app.crypto import load_public_key, spki_fingerprint  # noqa: E402


class CheckFailed(Exception):
    """A receipt/revocation verification check failed."""


def _load_json(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _extract_receipt(doc):
    """Accept a bare receipt, a /verify response, or a GET /receipts/{id} body."""
    if isinstance(doc, dict) and "receipt" in doc and "payload" not in doc:
        doc = doc["receipt"]
    if not isinstance(doc, dict) or not doc.get("payload") or not doc.get("signature"):
        raise CheckFailed(
            "receipt JSON must contain at least 'payload' and 'signature'"
        )
    return doc


def _extract_revocation(doc):
    """Accept a bare revocation proof or an envelope carrying one."""
    if isinstance(doc, dict) and "revocation" in doc and "payload" not in doc:
        doc = doc["revocation"]
    if not isinstance(doc, dict) or not doc.get("payload") or not doc.get("signature"):
        raise CheckFailed(
            "revocation JSON must contain at least 'payload' and 'signature'"
        )
    return doc


def _extract_keys(doc):
    keys = doc.get("keys") if isinstance(doc, dict) else doc
    if not isinstance(keys, list):
        raise CheckFailed("keys JSON must be a list or an object with a 'keys' list")
    return keys


def _find_key(keys, key_id):
    return next((k for k in keys if k.get("key_id") == key_id), None)


def _verify_server_signature(keys, *, key_id, payload, signature_b64, kind):
    """Verify an Ed25519 signature made by any published (incl. retired) key."""
    entry = _find_key(keys, key_id)
    if entry is None:
        raise CheckFailed(f"no public key published for {kind} key_id {key_id!r}")
    public_key = load_public_key(entry["public_key"])
    fingerprint = spki_fingerprint(public_key)
    if entry.get("fingerprint") and entry["fingerprint"] != fingerprint:
        raise CheckFailed("published fingerprint does not match the public key")
    if not receipts.verify_payload_signature(public_key, payload, signature_b64):
        raise CheckFailed(f"Ed25519 signature over the {kind} payload is INVALID")
    return entry, fingerprint


def run_receipt_checks(receipt, keys, request_doc=None):
    """Run every receipt-only offline check; raise CheckFailed on problems."""
    notes = []
    payload = receipt["payload"]
    fields = receipts.parse_payload(payload)  # raises ReceiptFormatError

    # Mirror fields must agree with the signed payload.
    for json_key in ("receipt_id", "key_id", "input_digest"):
        if json_key in receipt and receipt[json_key] != fields[json_key]:
            raise CheckFailed(
                f"receipt.{json_key} does not match the signed payload"
            )
    context = receipt.get("context")
    if context is not None:
        for name in (
            "keyid",
            "key_version",
            "policy_version",
            "algorithm",
            "label",
            "nonce",
        ):
            if name in context and context[name] != fields[name]:
                raise CheckFailed(
                    f"receipt.context.{name} does not match the signed payload"
                )
    notes.append(
        f"payload ok ({receipts.PAYLOAD_VERSION}), receipt_id={fields['receipt_id']}"
    )

    entry, fingerprint = _verify_server_signature(
        keys,
        key_id=fields["key_id"],
        payload=payload,
        signature_b64=receipt["signature"],
        kind="receipt",
    )
    notes.append(
        f"key {fields['key_id']} (status {entry.get('status', '?')}), "
        f"fingerprint {fingerprint[:16]}…"
    )

    # Optional binding to the original /verify request body.
    if request_doc is not None:
        digest = receipts.input_digest(request_doc)
        if digest != fields["input_digest"]:
            raise CheckFailed(
                "the receipt does NOT bind to the given request "
                "(input digest mismatch)"
            )
        notes.append("input digest matches the given /verify request")

    return fields, notes


def run_revocation_checks(receipt_fields, receipt, revocation, keys):
    """Verify a revocation proof against a receipt; raise CheckFailed."""
    notes = []
    payload = revocation["payload"]
    rev = receipts.parse_revocation_payload(payload)  # strict order/version

    # Mirror fields must agree with the signed payload.
    for json_key in (
        "revocation_id",
        "key_id",
        "receipt_id",
        "sequence",
        "revision",
        "receipt_payload_sha256",
        "reason",
        "effective_at",
        "revoked_at",
    ):
        if json_key in revocation and revocation[json_key] != rev[json_key]:
            raise CheckFailed(
                f"revocation.{json_key} does not match the signed payload"
            )

    # Cross-receipt reuse protection: the proof must name THIS receipt and
    # commit to the exact receipt payload bytes it revokes.
    if rev["receipt_id"] != receipt_fields["receipt_id"]:
        raise CheckFailed(
            "revocation is for a DIFFERENT receipt_id "
            f"({rev['receipt_id']!r} vs {receipt_fields['receipt_id']!r}); "
            "cross-receipt reuse rejected"
        )
    actual_receipt_hash = receipts.payload_sha256(receipt["payload"])
    if rev["receipt_payload_sha256"] != actual_receipt_hash:
        raise CheckFailed(
            "revocation binds to a different receipt payload hash "
            f"({rev['receipt_payload_sha256'][:16]}… vs "
            f"{actual_receipt_hash[:16]}…); cross-receipt reuse or tampering rejected"
        )
    if rev["revision"] < 1 or rev["sequence"] < 1:
        raise CheckFailed("revocation sequence/revision must be positive")
    notes.append(
        f"revocation ok ({receipts.REVOCATION_PAYLOAD_VERSION}), "
        f"revocation_id={rev['revocation_id']}, seq={rev['sequence']}, "
        f"revision={rev['revision']}"
    )

    entry, _ = _verify_server_signature(
        keys,
        key_id=rev["key_id"],
        payload=payload,
        signature_b64=revocation["signature"],
        kind="revocation",
    )
    notes.append(
        f"revocation signature valid (key {rev['key_id']}, "
        f"status {entry.get('status', '?')})"
    )

    # No rewriting history: neither the effective time nor the server
    # record time can precede the receipt's own issuance.  A future-dated
    # ``effective_at`` is legitimate (the revocation simply does not apply
    # until that instant), so revoked_at < effective_at is allowed.
    if rev["effective_at"] < receipt_fields["issued_at"]:
        raise CheckFailed(
            f"time travel: revocation effective_at={rev['effective_at']} "
            f"precedes receipt issued_at={receipt_fields['issued_at']}"
        )
    if rev["revoked_at"] < receipt_fields["issued_at"]:
        raise CheckFailed(
            f"time travel: revoked_at={rev['revoked_at']} precedes receipt "
            f"issued_at={receipt_fields['issued_at']}"
        )
    notes.append(
        f"time order ok: issued {receipt_fields['issued_at']} <= "
        f"effective {rev['effective_at']}; revoked {rev['revoked_at']}"
    )
    return rev, notes


def point_in_time_state(rev_fields, at_ts):
    """Return the status implied by a signed proof at instant ``at_ts``."""
    return "revoked" if at_ts >= rev_fields["effective_at"] else "valid"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline verifier for /verify acceptance receipts and revocations"
    )
    parser.add_argument(
        "--receipt",
        required=False,
        help="receipt JSON file (bare receipt, /verify response, or GET /receipts/{id} body); "
             "optional when --status embeds the receipt",
    )
    parser.add_argument(
        "--keys",
        required=True,
        help="GET /receipts/keys response JSON (or its 'keys' list)",
    )
    parser.add_argument(
        "--request",
        help="optional original /verify request JSON to check the input binding",
    )
    parser.add_argument(
        "--revocation",
        help="optional signed revocation proof JSON (bare proof or an envelope)",
    )
    parser.add_argument(
        "--status",
        help="optional GET /receipts/{id}/status response (embedded receipt/proof used)",
    )
    parser.add_argument(
        "--at",
        type=int,
        default=None,
        help="point-in-time unix seconds for the status check (default: now)",
    )
    parser.add_argument(
        "--expect-status",
        choices=("valid", "revoked"),
        help="assert the point-in-time state (requires a revocation proof for 'revoked')",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress OK output")
    args = parser.parse_args(argv)

    notes = []
    try:
        if not args.receipt and not args.status:
            raise CheckFailed("provide --receipt and/or --status")
        receipt_doc = _load_json(args.receipt) if args.receipt else None
        keys = _extract_keys(_load_json(args.keys))
        request_doc = _load_json(args.request) if args.request else None

        status_doc = _load_json(args.status) if args.status else None
        revocation_doc = _load_json(args.revocation) if args.revocation else None

        # A --status document can supply the receipt and/or the revocation.
        if status_doc is not None:
            if not isinstance(status_doc, dict) or "status" not in status_doc:
                raise CheckFailed("--status JSON must be a status response with 'status'")
            embedded_receipt = status_doc.get("receipt")
            if embedded_receipt is not None:
                if receipt_doc is not None:
                    raise CheckFailed(
                        "provide either --receipt or a status document embedding one, not both"
                    )
                receipt_doc = embedded_receipt
            embedded_rev = status_doc.get("revocation")
            if embedded_rev is not None:
                if revocation_doc is not None:
                    raise CheckFailed(
                        "revocation given both via --revocation and the status document"
                    )
                revocation_doc = embedded_rev

        receipt = _extract_receipt(receipt_doc)
        receipt_fields, receipt_notes = run_receipt_checks(
            receipt, keys, request_doc
        )
        notes.extend(receipt_notes)

        state = "valid"
        status_at_value = None
        if revocation_doc is not None:
            revocation = _extract_revocation(revocation_doc)
            rev_fields, rev_notes = run_revocation_checks(
                receipt_fields, receipt, revocation, keys
            )
            notes.extend(rev_notes)

            # The point-in-time instant: explicit --at wins; otherwise the
            # status document's own ``at``; otherwise now.
            if args.at is not None:
                at_ts = args.at
            elif status_doc is not None and status_doc.get("at") is not None:
                at_ts = int(status_doc["at"])
                status_at_value = at_ts
            else:
                at_ts = int(time.time())
            state = point_in_time_state(rev_fields, at_ts)
            notes.append(f"status at {at_ts}: {state}")

            # If the status document asserts a point-in-time answer it must
            # agree with what the signed proofs actually establish.
            if status_doc is not None:
                claimed = status_doc.get("status")
                status_at = status_doc.get("at")
                if claimed not in ("valid", "revoked"):
                    raise CheckFailed(
                        f"status document claims unexpected status {claimed!r}"
                    )
                check_at = (
                    int(status_at) if status_at is not None else at_ts
                )
                recomputed = point_in_time_state(rev_fields, check_at)
                if claimed != recomputed:
                    raise CheckFailed(
                        f"status document claims {claimed!r} but the signed proof "
                        f"establishes {recomputed!r} at that instant (time reversal)"
                    )
                notes.append(f"status document consistent ({claimed})")
                if status_at_value is not None and args.expect_status is None:
                    state = claimed
        else:
            if args.expect_status == "revoked":
                raise CheckFailed(
                    "expected status 'revoked' but no revocation proof was provided"
                )
            if args.at is not None:
                notes.append(f"status at {args.at}: valid (no revocation proof)")

        if args.expect_status and args.expect_status != state:
            raise CheckFailed(
                f"expected status {args.expect_status!r} but established {state!r}"
            )
    except Exception as exc:  # any failure means the artifacts cannot be trusted
        print(f"RECEIPT INVALID: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        for note in notes:
            print(f"  ✓ {note}")
        print(
            f"OK: receipt {receipt.get('receipt_id', '?')} verified offline "
            f"(status: {state})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
