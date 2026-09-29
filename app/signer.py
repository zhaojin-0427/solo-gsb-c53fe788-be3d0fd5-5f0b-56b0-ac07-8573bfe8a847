"""Client-side message signing (RFC 9421) — used by the demo and tests.

The signer builds the *same* signature base the verifier rebuilds, signs it
with an Ed25519 or RSA-PSS private key, and returns the Signature-Input /
Signature field values plus a ready-to-POST request payload.
"""
from __future__ import annotations

import base64
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from http_sfv import InnerList, Item

from .base import HttpRequestMessage, build_signature_base
from .crypto import sign
from .digest import compute_content_digest
from .sf9421 import parse_signature_dictionary


def make_signed_request(
    *,
    private_key,
    algorithm: str,
    keyid: str,
    method: str,
    target_uri: str,
    headers: Optional[List[Tuple[str, str]]] = None,
    body: bytes = b"",
    components: Optional[List[str]] = None,
    created: Optional[int] = None,
    expires: Optional[int] = None,
    nonce: Any = "GENERATE",
    label: str = "sig1",
    tag: Optional[str] = None,
    digest_algorithm: str = "sha-256",
) -> Dict[str, Any]:
    """Return a /verify payload with valid RFC 9421 signature fields."""
    headers = list(headers or [])
    created = int(time.time()) if created is None else created
    # nonce="GENERATE" -> random nonce; nonce=False/None omits the parameter.
    if nonce == "GENERATE":
        nonce = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("ascii")

    if components is None:
        components = ["@method", "@target-uri", "@authority", "content-digest"]

    header_names = {n.lower() for n, _ in headers}
    if body and "content-digest" in components and "content-digest" not in header_names:
        headers.append(("content-digest", compute_content_digest(body, digest_algorithm)))

    # Build the inner list from component specs, e.g. "@query-param";name="a".
    covered = InnerList()
    for spec in components:
        if ";" in spec:
            from http_sfv.item import Parameters

            name, _, param_text = spec.partition(";")
            item = Item(name)
            # Parse the parameters by piggy-backing on InnerList parsing.
            tmp = InnerList()
            tmp.parse(f'("x";{param_text})'.encode("ascii"))
            item.params = Parameters(tmp.data[0].params)
            covered.data.append(item)
        else:
            covered.data.append(Item(spec))

    covered.params["keyid"] = keyid
    covered.params["alg"] = algorithm
    covered.params["created"] = created
    if expires is not None:
        covered.params["expires"] = expires
    if nonce:
        covered.params["nonce"] = nonce
    if tag is not None:
        covered.params["tag"] = tag

    message = HttpRequestMessage(
        method=method, target_uri=target_uri, headers=headers, body=body
    )
    built = build_signature_base(message, covered)

    raw_signature = sign(algorithm, private_key, built.base.encode("utf-8"))
    sig_item = Item(raw_signature)

    # Quoted string labels need explicit quoting in the field serialisation.
    label_key = label if _is_bare_key(label) else str(Item(label))
    signature_input = f"{label_key}={str(covered)}"
    signature_field = f"{label_key}={str(sig_item)}"

    # Validate our own fields parse.
    parse_signature_dictionary(signature_input)

    return {
        "method": method,
        "target_uri": target_uri,
        "headers": [{"name": n, "value": v} for n, v in headers],
        "body": base64.b64encode(body).decode("ascii") if body else None,
        "signature_input": signature_input,
        "signature": signature_field,
        "_signature_base": built.base,
        "_label": label,
        "_nonce": nonce,
        "_created": created,
    }


def _is_bare_key(name: str) -> bool:
    if not name:
        return False
    start = set("abcdefghijklmnopqrstuvwxyz*")
    allowed = start | set("0123456789_-.")
    return name[0] in start and all(c in allowed for c in name)
