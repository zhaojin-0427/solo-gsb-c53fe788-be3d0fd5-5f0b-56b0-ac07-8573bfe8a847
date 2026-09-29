#!/usr/bin/env python3
"""Standalone offline verifier for /verify acceptance receipts and revocations.

Runs fully offline — no server, no database.  Requires only the
``cryptography`` package (plus this repository's ``app.receipts`` /
``app.revocations`` / ``app.crypto`` modules, which have no other
dependencies).

Receipt checks performed:

1. the canonical payload is well-formed (``receipt/v1``, strict field order);
2. the receipt's mirror fields (``receipt_id`` / ``key_id`` /
   ``input_digest`` / ``context``) match the signed payload;
3. the Ed25519 signature over the exact payload bytes, using the server
   public key published at ``GET /receipts/keys`` — retired keys included,
   so receipts survive server key rotation;
4. optionally (``--request``), that the receipt binds to a specific
   ``/verify`` request body: the deterministic input digest is recomputed
   locally and compared with the signed payload.

Revocation checks (``--revocation``):

5. the canonical ``revocation/v1`` payload is well-formed and its mirror
   fields match the signed payload;
6. the Ed25519 signature verifies against the published (possibly retired)
   server key named by the record's ``key_id``;
7. the revocation binds to *this* receipt — a proof issued for a different
   ``receipt_id`` (cross-receipt reuse) fails;
8. with ``--at``, the receipt already existed and the revocation was already
   effective at that moment — claiming a revocation before its
   ``effective_at`` (time rollback) fails.

Audit-chain checks (``--chain``):

9. the published chain (``GET /revocations``) is gapless (sequences 1..N),
   every record's signature verifies, and every record hash-links to its
   predecessor; a ``--revocation`` proof must appear in the chain unchanged.

Usage:
    python tools/verify_receipt.py --receipt receipt.json --keys keys.json \
        [--request request.json] [--revocation revocation.json] \
        [--at UNIX_OR_ISO8601] [--chain chain.json] [-q]

``receipt.json`` may be the receipt object itself, a full ``/verify``
response, or a ``GET /receipts/{id}`` response.  ``keys.json`` is the
``GET /receipts/keys`` response (or its ``keys`` list).  ``revocation.json``
may be the revocation object itself, a revoke-command response, or a
``GET /receipts/{id}/status`` response.  ``chain.json`` is the
``GET /revocations`` response (or its ``revocations`` list).  Exit code 0
means every check passed; 1 means any check failed.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running from anywhere inside a repository checkout.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import receipts, revocations  # noqa: E402
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
    """Accept a bare revocation, a revoke response, or a status response."""
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


def _extract_chain(doc):
    """Return (records, head); head is the envelope's published tip or None."""
    head = None
    if isinstance(doc, dict):
        chain = doc.get("revocations")
        if "head_seq" in doc or "head_payload_sha256" in doc:
            head = (doc.get("head_seq"), doc.get("head_payload_sha256"))
    else:
        chain = doc
    if not isinstance(chain, list):
        raise CheckFailed(
            "chain JSON must be a list or an object with a 'revocations' list"
        )
    return chain, head


def _parse_at(text: str) -> int:
    """Parse --at as unix seconds or ISO-8601; return unix seconds."""
    value = text.strip()
    try:
        return int(value)
    except ValueError:
        pass
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise CheckFailed(f"--at is neither unix seconds nor ISO-8601: {exc}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def _resolve_key(keys, key_id: str):
    """Resolve a published (possibly retired) key and check its fingerprint."""
    entry = next((k for k in keys if k.get("key_id") == key_id), None)
    if entry is None:
        raise CheckFailed(f"no public key published for key_id {key_id!r}")
    public_key = load_public_key(entry["public_key"])
    fingerprint = spki_fingerprint(public_key)
    if entry.get("fingerprint") and entry["fingerprint"] != fingerprint:
        raise CheckFailed("published fingerprint does not match the public key")
    return public_key, entry, fingerprint


def check_revocation(revocation, receipt_fields, keys, at=None):
    """Verify one signed revocation proof against a receipt; return notes."""
    notes = []
    payload = revocation["payload"]
    fields = revocations.parse_payload(payload)  # raises RevocationFormatError

    # Mirror fields must agree with the signed payload.
    mirrors = {
        "revocation_id": fields["revocation_id"],
        "revocation_seq": fields["revocation_seq"],
        "receipt_id": fields["receipt_id"],
        "receipt_revision": fields["receipt_revision"],
        "reason": fields["reason"],
        "key_id": fields["key_id"],
        "command_id": fields["command_id"],
        "effective_at_unix": fields["effective_at"],
        "revoked_at_unix": fields["revoked_at"],
        "prev_seq": fields["prev_seq"] or None,
        "prev_payload_sha256": fields["prev_payload_sha256"],
    }
    for json_key, expected in mirrors.items():
        if json_key in revocation and revocation[json_key] != expected:
            raise CheckFailed(
                f"revocation.{json_key} does not match the signed payload"
            )
    if (
        "payload_sha256" in revocation
        and revocation["payload_sha256"] != revocations.payload_sha256(payload)
    ):
        raise CheckFailed("revocation.payload_sha256 does not match the payload")
    notes.append(
        f"revocation payload ok ({revocations.PAYLOAD_VERSION}), "
        f"seq={fields['revocation_seq']}, "
        f"revocation_id={fields['revocation_id']}"
    )

    # Cross-receipt reuse must fail: the proof must name this receipt.
    if fields["receipt_id"] != receipt_fields["receipt_id"]:
        raise CheckFailed(
            "the revocation is for receipt "
            f"{fields['receipt_id']!r}, not {receipt_fields['receipt_id']!r} "
            "(cross-receipt reuse)"
        )

    # Ed25519 signature over the exact payload bytes (historical keys work).
    public_key, entry, fingerprint = _resolve_key(keys, fields["key_id"])
    if not receipts.verify_payload_signature(
        public_key, payload, revocation["signature"]
    ):
        raise CheckFailed("Ed25519 signature over the revocation payload is INVALID")
    notes.append(
        f"revocation signed by {fields['key_id']} "
        f"(status {entry.get('status', '?')}), fingerprint {fingerprint[:16]}…: valid"
    )

    # Point-in-time consistency: no time rollback, receipt must have existed.
    if at is not None:
        if at < receipt_fields["issued_at"]:
            raise CheckFailed(
                f"the receipt was not yet issued at --at "
                f"(issued_at {receipt_fields['issued_at']} > {at})"
            )
        if at < fields["effective_at"]:
            raise CheckFailed(
                f"the revocation was not yet effective at --at "
                f"(effective_at {fields['effective_at']} > {at}): time rollback"
            )
        notes.append(f"revocation already effective at {at}")
    return notes


def check_chain(chain, keys, must_include=None, head=None):
    """Verify the revocation audit chain end to end; return notes."""
    notes = []
    records = sorted(chain, key=lambda r: r.get("revocation_seq", 0))
    prev = None
    for index, record in enumerate(records, start=1):
        fields = revocations.parse_payload(record["payload"])
        if fields["revocation_seq"] != index:
            raise CheckFailed(
                f"audit chain is not gapless: expected seq {index}, "
                f"got {fields['revocation_seq']}"
            )
        expected_prev_hash = (
            revocations.payload_sha256(prev["payload"]) if prev is not None else None
        )
        if fields["prev_payload_sha256"] != expected_prev_hash:
            raise CheckFailed(
                f"audit chain link broken at seq {index}: "
                "prev_payload_sha256 does not match the previous record"
            )
        if record.get("payload_sha256") and record[
            "payload_sha256"
        ] != revocations.payload_sha256(record["payload"]):
            raise CheckFailed(
                f"record {index}: payload_sha256 does not match the payload"
            )
        public_key, _, _ = _resolve_key(keys, fields["key_id"])
        if not receipts.verify_payload_signature(
            public_key, record["payload"], record["signature"]
        ):
            raise CheckFailed(
                f"record {index}: Ed25519 signature over the payload is INVALID"
            )
        prev = record
    if records:
        notes.append(
            f"audit chain ok: {len(records)} record(s), gapless and hash-linked"
        )

    # When the chain came with the server's published head, the tip must
    # match it exactly — a truncated or extended chain is rejected.
    if head is not None:
        head_seq, head_hash = head
        tip_seq = records and revocations.parse_payload(records[-1]["payload"])[
            "revocation_seq"
        ] or 0
        tip_hash = (
            revocations.payload_sha256(records[-1]["payload"]) if records else None
        )
        if head_seq != tip_seq or head_hash != tip_hash:
            raise CheckFailed(
                "the chain tip does not match the published head "
                f"(head_seq={head_seq}, head_payload_sha256={head_hash}): "
                "truncated or extended chain"
            )
        notes.append("chain tip matches the published head")

    if must_include is not None:
        target = revocations.parse_payload(must_include["payload"])
        match = next(
            (
                r
                for r in records
                if revocations.parse_payload(r["payload"])["revocation_id"]
                == target["revocation_id"]
            ),
            None,
        )
        if match is None:
            raise CheckFailed(
                "the revocation proof is not part of the published audit chain"
            )
        if match["payload"] != must_include["payload"]:
            raise CheckFailed(
                "the revocation proof differs from the audit-chain record "
                "(tampered)"
            )
        notes.append("revocation proof is anchored in the audit chain")
    return notes


def run_checks(receipt, keys, request_doc=None, revocation=None, at=None, chain=None):
    """Run every offline check; raise CheckFailed on the first problem."""
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

    # Resolve the signing key and cross-check its fingerprint.
    public_key, entry, fingerprint = _resolve_key(keys, fields["key_id"])
    notes.append(
        f"key {fields['key_id']} (status {entry.get('status', '?')}), "
        f"fingerprint {fingerprint[:16]}…"
    )

    # Ed25519 signature over the exact payload bytes.
    if not receipts.verify_payload_signature(public_key, payload, receipt["signature"]):
        raise CheckFailed("Ed25519 signature over the receipt payload is INVALID")
    notes.append("Ed25519 signature valid")

    # Optional binding to the original /verify request body.
    if request_doc is not None:
        digest = receipts.input_digest(request_doc)
        if digest != fields["input_digest"]:
            raise CheckFailed(
                "the receipt does NOT bind to the given request "
                "(input digest mismatch)"
            )
        notes.append("input digest matches the given /verify request")

    # Optional revocation proof, bound to this receipt and to --at.
    if revocation is not None:
        notes += check_revocation(revocation, fields, keys, at=at)

    # Optional audit-chain verification (and anchoring of the proof).
    if chain is not None:
        records, head = chain
        notes += check_chain(records, keys, must_include=revocation, head=head)

    return notes


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline verifier for /verify acceptance receipts and revocations"
    )
    parser.add_argument(
        "--receipt",
        required=True,
        help="receipt JSON file (bare receipt, /verify response, or GET /receipts/{id} body)",
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
        help="optional revocation proof JSON (bare record, revoke response, or status response)",
    )
    parser.add_argument(
        "--at",
        help="optional point in time (unix seconds or ISO-8601): with --revocation, "
        "require the receipt to exist and the revocation to be effective then",
    )
    parser.add_argument(
        "--chain",
        help="optional GET /revocations response JSON to verify the audit chain",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress OK output")
    args = parser.parse_args(argv)

    try:
        receipt = _extract_receipt(_load_json(args.receipt))
        keys = _extract_keys(_load_json(args.keys))
        request_doc = _load_json(args.request) if args.request else None
        revocation = (
            _extract_revocation(_load_json(args.revocation))
            if args.revocation
            else None
        )
        chain = _extract_chain(_load_json(args.chain)) if args.chain else None
        at = _parse_at(args.at) if args.at else None
        notes = run_checks(
            receipt,
            keys,
            request_doc,
            revocation=revocation,
            at=at,
            chain=chain,
        )
    except Exception as exc:  # any failure means the receipt cannot be trusted
        print(f"RECEIPT INVALID: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        for note in notes:
            print(f"  ✓ {note}")
        print(f"OK: receipt {receipt.get('receipt_id', '?')} verified offline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
