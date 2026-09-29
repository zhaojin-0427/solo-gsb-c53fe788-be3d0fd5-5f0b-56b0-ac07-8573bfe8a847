"""Structured Fields parsing helpers for RFC 9421 header fields.

The ``Signature-Input`` and ``Signature`` fields are Structured Fields
dictionaries (RFC 8941) whose dictionary keys *may* be quoted strings
(signature labels, see RFC 9421 §4.1).  The ``http-sfv`` library only
accepts bare SF keys, so the top-level dictionary grammar is re-implemented
here while delegating every member/parameter/value parser to ``http-sfv``.
"""
from __future__ import annotations

from typing import Dict, Tuple

from http_sfv import Item
from http_sfv.dictionary import Dictionary
from http_sfv.item import InnerList, Parameters
from http_sfv.list import parse_item_or_inner_list
from http_sfv.util import discard_http_ows, parse_key

# Character used to separate dictionary members.
_COMMA = ord(b",")


class SignatureInputError(ValueError):
    """Raised when a Signature-Input / Signature field is malformed."""


def _parse_label(data: bytes) -> Tuple[int, str]:
    """Parse one dictionary key: bare SF key or quoted string label."""
    if not data:
        raise SignatureInputError("empty dictionary key")
    if data[0] == ord(b'"'):
        item = Item()
        try:
            consumed = item.parse_content(data)
        except ValueError as exc:
            raise SignatureInputError(f"invalid signature label: {exc}") from exc
        if not isinstance(item.value, str):
            raise SignatureInputError("signature label must be a string")
        return consumed, item.value
    try:
        return parse_key(data)
    except ValueError as exc:
        raise SignatureInputError(f"invalid dictionary key: {exc}") from exc


def parse_signature_dictionary(data: bytes) -> Dict[str, object]:
    """Parse a Signature-Input or Signature field.

    Returns an ordered mapping ``label -> http-sfv object`` (``InnerList``
    for Signature-Input, ``Item`` for Signature).  Duplicate labels are
    rejected per the RFC 8941 dictionary rule.
    """
    if isinstance(data, str):
        data = data.encode("latin-1")

    result: Dict[str, object] = {}
    pos = discard_http_ows(data)
    length = len(data)
    if pos == length:
        raise SignatureInputError("field is empty")

    while True:
        consumed, label = _parse_label(data[pos:])
        pos += consumed
        if label in result:
            raise SignatureInputError(f"duplicate signature label {label!r}")
        if pos >= length or data[pos] != ord(b"="):
            raise SignatureInputError(f"expected '=' after label {label!r}")
        pos += 1
        try:
            consumed, member = parse_item_or_inner_list(data[pos:])
        except ValueError as exc:
            raise SignatureInputError(
                f"invalid value for label {label!r}: {exc}"
            ) from exc
        pos += consumed
        result[label] = member

        pos += discard_http_ows(data[pos:])
        if pos == length:
            return result
        if data[pos] != _COMMA:
            raise SignatureInputError("trailing data after dictionary member")
        pos += 1
        pos += discard_http_ows(data[pos:])
        if pos >= length:
            raise SignatureInputError("trailing comma at end of field")


def require_innerlist(member: object, label: str) -> InnerList:
    if not isinstance(member, InnerList):
        raise SignatureInputError(
            f"signature-input label {label!r} must be an inner list"
        )
    return member


def require_signature_item(member: object, label: str) -> Item:
    if not isinstance(member, Item) or not isinstance(member.value, bytes):
        raise SignatureInputError(
            f"signature label {label!r} must be a byte sequence item"
        )
    return member


def parse_sf_field(field_name: str, raw_value: str):
    """Parse a covered HTTP field value as an SF structure.

    Tries dictionary, then list, then item — matching the "known structured
    field" usage of RFC 9421.
    """
    data = raw_value.encode("latin-1")
    errors = []
    for structure in (Dictionary,):
        try:
            sf = structure()
            sf.parse(data)
            return ("dictionary", sf)
        except ValueError as exc:
            errors.append(str(exc))
    from http_sfv import List

    try:
        sf = List()
        sf.parse(data)
        return ("list", sf)
    except ValueError as exc:
        errors.append(str(exc))
    try:
        sf = Item()
        sf.parse(data)
        return ("item", sf)
    except ValueError as exc:
        errors.append(str(exc))
    raise ValueError(
        f"field {field_name!r} is not a valid structured field: {'; '.join(errors)}"
    )


def ser_identifier(name: str, params: Dict[str, object]) -> str:
    """Serialise a component identifier (with parameters)."""
    if _is_bare_key(name):
        out = name
    else:
        out = str(Item(name))
    if params:
        out += _ser_params(params)
    return out


def _ser_params(params: Dict[str, object]) -> str:
    p = Parameters()
    for key, value in params.items():
        p[key] = value
    return str(p)


def _is_bare_key(name: str) -> bool:
    if not name:
        return False
    allowed_start = set("abcdefghijklmnopqrstuvwxyz*")
    allowed = allowed_start | set("0123456789_-.")
    return name[0] in allowed_start and all(c in allowed for c in name)
