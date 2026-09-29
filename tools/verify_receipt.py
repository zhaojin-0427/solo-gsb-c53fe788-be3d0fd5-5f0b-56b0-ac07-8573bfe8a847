#!/usr/bin/env python3
"""Standalone offline verifier for /verify acceptance receipts.

Runs fully offline — no server, no database.  Requires only the
``cryptography`` package (plus this repository's ``app.receipts`` /
``app.crypto`` modules, which have no other dependencies).

Checks performed:

1. the canonical payload is well-formed (``receipt/v1``, strict field order);
2. the receipt's mirror fields (``receipt_id`` / ``key_id`` /
   ``input_digest`` / ``context``) match the signed payload;
3. the Ed25519 signature over the exact payload bytes, using the server
   public key published at ``GET /receipts/keys`` — retired keys included,
   so receipts survive server key rotation;
4. optionally (``--request``), that the receipt binds to a specific
   ``/verify`` request body: the deterministic input digest is recomputed
   locally and compared with the signed payload.

Usage:
    python tools/verify_receipt.py --receipt receipt.json --keys keys.json \
        [--request request.json] [-q]

``receipt.json`` may be the receipt object itself, a full ``/verify``
response, or a ``GET /receipts/{id}`` response.  ``keys.json`` is the
``GET /receipts/keys`` response (or its ``keys`` list).  Exit code 0 means
the receipt is valid; 1 means any check failed.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running from anywhere inside a repository checkout.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import receipts  # noqa: E402
from app.crypto import load_public_key, spki_fingerprint  # noqa: E402


class CheckFailed(Exception):
    """A receipt verification check failed."""


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


def _extract_keys(doc):
    keys = doc.get("keys") if isinstance(doc, dict) else doc
    if not isinstance(keys, list):
        raise CheckFailed("keys JSON must be a list or an object with a 'keys' list")
    return keys


def run_checks(receipt, keys, request_doc=None):
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
    entry = next((k for k in keys if k.get("key_id") == fields["key_id"]), None)
    if entry is None:
        raise CheckFailed(
            f"no public key published for key_id {fields['key_id']!r}"
        )
    public_key = load_public_key(entry["public_key"])
    fingerprint = spki_fingerprint(public_key)
    if entry.get("fingerprint") and entry["fingerprint"] != fingerprint:
        raise CheckFailed("published fingerprint does not match the public key")
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

    return notes


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline verifier for /verify acceptance receipts"
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
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress OK output")
    args = parser.parse_args(argv)

    try:
        receipt = _extract_receipt(_load_json(args.receipt))
        keys = _extract_keys(_load_json(args.keys))
        request_doc = _load_json(args.request) if args.request else None
        notes = run_checks(receipt, keys, request_doc)
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
