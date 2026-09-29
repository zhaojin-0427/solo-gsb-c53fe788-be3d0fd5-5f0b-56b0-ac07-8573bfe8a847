"""Rebuild the signature base for an HTTP message (RFC 9421 §2.5).

Input is a *verification request* as submitted by the client: HTTP method,
target URI, an ordered list of raw header fields and (optionally) a body.
Every component listed in the ``Signature-Input`` inner list is resolved to
its canonical value and one signature-base line is produced per component,
in order, followed by the ``@signature-params`` line.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlsplit

from http_sfv import InnerList, Item
from http_sfv.item import Parameters

from .sf9421 import parse_sf_field


def _ser_params(params: Dict[str, Any]) -> str:
    p = Parameters()
    for key, value in params.items():
        p[key] = value
    return str(p)

# HTTP fields whose syntax is a Structured Field (RFC 8941 / IANA
# "Structured Field Values for HTTP" registry).  Fields not listed are
# canonicalised as legacy HTTP fields unless the component has an explicit
# ";sf" parameter.  Note: Date, Content-Type and other RFC 9110 fields are
# *not* structured fields.
SF_DICTIONARY_FIELDS = frozenset(
    name.lower()
    for name in (
        "accept-signature",
        "cache-status",
        "cdn-loop",
        "content-digest",
        "cross-origin-resource-policy",
        "expect",
        "origin-agent-cluster",
        "signature",
        "signature-input",
        "proxy-status",
        "surrogate-control",
        "want-content-digest",
        "x-content-type-options",
    )
)
SF_LIST_FIELDS = frozenset(
    name.lower()
    for name in (
        "accept-ch",
        "accept-encoding",
        "accept-language",
        "accept-push-policy",
        "accept-ranges",
        "alt-svc",
        "cache-control",
        "cdn-cache-control",
        "clear-site-data",
        "forwarded",
        "if-match",
        "if-none-match",
        "link",
        "prefer",
        "preference-applied",
        "priority",
        "vary",
    )
)
SF_ITEM_FIELDS = frozenset(
    name.lower()
    for name in (
        "age",
        "content-length",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "service-worker",
        "service-worker-allowed",
    )
)

DERIVED_COMPONENTS = frozenset(
    (
        "@method",
        "@target-uri",
        "@authority",
        "@scheme",
        "@path",
        "@query",
        "@query-param",
        "@request-target",
        "@status",
    )
)


class ComponentError(Exception):
    """A signature component cannot be resolved / canonicalised.

    ``reason`` is a stable machine-readable code (see app/reasons.py).
    """

    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass
class HttpRequestMessage:
    method: str
    target_uri: str
    # Ordered list of (lower-name, raw-value).
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""


@dataclass
class BuiltBase:
    base: str
    lines: List[str]
    # component identifier -> canonical value actually covered
    component_values: Dict[str, str]
    identifiers: List[str]

    @property
    def components(self) -> Dict[str, str]:
        return self.component_values


def _headers_to_byte_lines(message: HttpRequestMessage) -> Dict[str, List[bytes]]:
    grouped: Dict[str, List[bytes]] = {}
    for name, value in message.headers:
        lname = name.lower()
        try:
            grouped.setdefault(lname, []).append(value.encode("latin-1"))
        except UnicodeEncodeError as exc:
            raise ComponentError(
                "component_value_unavailable",
                f"header field {lname!r} contains non-ISO-8859-1 bytes: {exc}",
            ) from exc
    return grouped


def _legacy_field_value(lines: List[bytes]) -> str:
    """RFC 9421 §2.1.4 — canonical legacy HTTP field value."""
    parts: List[str] = []
    for line in lines:
        # Strip leading/trailing OWS (SP / HTAB), replace remaining HTAB with SP.
        text = line.decode("latin-1").strip(" \t").replace("\t", " ")
        parts.append(text)
    return ", ".join(parts)


def _sf_field_value(field_name: str, lines: List[bytes]) -> str:
    raw = b", ".join(lines).decode("latin-1")
    try:
        _, structure = parse_sf_field(field_name, raw)
    except ValueError as exc:
        raise ComponentError(
            "component_value_unavailable",
            f"structured field {field_name!r} cannot be parsed: {exc}",
        ) from exc
    try:
        return str(structure)
    except ValueError as exc:
        raise ComponentError(
            "component_value_unavailable",
            f"structured field {field_name!r} cannot be serialised: {exc}",
        ) from exc


def _header_value(
    field_name: str, grouped: Dict[str, List[bytes]], force_sf: bool
) -> str:
    lines = grouped.get(field_name)
    if not lines:
        raise ComponentError(
            "component_value_unavailable",
            f"header field {field_name!r} is not present in the request",
        )
    if force_sf or field_name in (
        SF_DICTIONARY_FIELDS | SF_LIST_FIELDS | SF_ITEM_FIELDS
    ):
        return _sf_field_value(field_name, lines)
    return _legacy_field_value(lines)


def _derived_value(
    component: str,
    params: Dict[str, Any],
    message: HttpRequestMessage,
) -> str:
    parts = urlsplit(message.target_uri)

    if component == "@method":
        return message.method.upper()

    if component == "@target-uri":
        return message.target_uri

    if component == "@authority":
        if parts.hostname:
            port = parts.port
            default = (parts.scheme == "http" and port == 80) or (
                parts.scheme == "https" and port == 443
            )
            if port is not None and not default:
                return f"{parts.hostname}:{port}"
            return parts.hostname
        raise ComponentError(
            "component_value_unavailable",
            "@authority cannot be derived: target URI has no authority",
        )

    if component == "@scheme":
        if not parts.scheme:
            raise ComponentError(
                "component_value_unavailable",
                "@scheme cannot be derived: target URI has no scheme",
            )
        return parts.scheme.lower()

    if component == "@path":
        path = parts.path or "/"
        return path

    if component == "@query":
        if parts.query == "":
            raise ComponentError(
                "component_value_unavailable",
                "@query cannot be derived: target URI has no query component",
            )
        return str(Item(f"?{parts.query}"))

    if component == "@query-param":
        name = params.get("name")
        if not isinstance(name, str) or name == "":
            raise ComponentError(
                "invalid_component_parameter",
                "@query-param requires a non-empty string 'name' parameter",
            )
        values = parse_qs(
            parts.query,
            keep_blank_values=True,
            strict_parsing=False,
        ).get(name, [])
        if not values:
            raise ComponentError(
                "component_value_unavailable",
                f"@query-param {name!r} is not present in the target URI",
            )
        if len(values) == 1:
            return str(Item(values[0]))
        return str(InnerList([Item(v) for v in values]))

    if component == "@request-target":
        target = parts.path or "/"
        if parts.query:
            target = f"{target}?{parts.query}"
        return target

    if component == "@status":
        raise ComponentError(
            "component_value_unavailable",
            "@status is only defined for HTTP responses, not requests",
        )

    raise ComponentError(
        "unknown_component",
        f"derived component {component!r} is not supported",
    )


def _validate_component_params(
    component: str, params: Dict[str, Any]
) -> None:
    # "req" related-request binding (RFC 9421 §2.2.6) is not supported.
    if "req" in params:
        raise ComponentError(
            "related_request_unsupported",
            "the 'req' related-request parameter is not supported",
        )

    if component == "@query-param":
        if "name" not in params:
            raise ComponentError(
                "invalid_component_parameter",
                "@query-param requires a 'name' parameter",
            )
        if not isinstance(params["name"], str):
            raise ComponentError(
                "invalid_component_parameter",
                "@query-param 'name' parameter must be a string",
            )

    if component in DERIVED_COMPONENTS:
        allowed = {"name"} if component == "@query-param" else set()
        for key in params:
            if key not in allowed:
                raise ComponentError(
                    "invalid_component_parameter",
                    f"derived component {component!r} does not accept parameter {key!r}",
                )
    else:
        # HTTP field components.
        if component.startswith("@"):
            return
        for key in params:
            if key not in ("sf", "key", "bs"):
                raise ComponentError(
                    "invalid_component_parameter",
                    f"field component {component!r} has unsupported parameter {key!r}",
                )
        if "key" in params and not isinstance(params["key"], str):
            raise ComponentError(
                "invalid_component_parameter",
                f"field {component!r} 'key' parameter must be a string",
            )
        if "sf" in params and not isinstance(params["sf"], bool):
            raise ComponentError(
                "invalid_component_parameter",
                f"field {component!r} 'sf' parameter must be a boolean",
            )
        if "bs" in params and not isinstance(params["bs"], bool):
            raise ComponentError(
                "invalid_component_parameter",
                f"field {component!r} 'bs' parameter must be a boolean",
            )


def build_signature_base(
    message: HttpRequestMessage,
    covered: InnerList,
) -> BuiltBase:
    """Build the signature base from the covered-component inner list."""
    grouped = _headers_to_byte_lines(message)

    lines: List[str] = []
    component_values: Dict[str, str] = {}
    identifiers: List[str] = []

    for member in covered:
        if not isinstance(member, Item) or not isinstance(member.value, str):
            raise ComponentError(
                "invalid_component",
                "every covered component must be a string item",
            )
        component = member.value
        params = dict(member.params)
        _validate_component_params(component, params)

        # In the signature base every component identifier is serialised as
        # an SF string (RFC 9421 §2.5), including plain HTTP field names.
        identifier = str(Item(component))
        if params:
            identifier += _ser_params(params)
        if identifier in identifiers:
            raise ComponentError(
                "duplicate_component",
                f"component {identifier!r} is listed more than once",
            )
        identifiers.append(identifier)

        if component.startswith("@"):
            if component not in DERIVED_COMPONENTS:
                raise ComponentError(
                    "unknown_component",
                    f"derived component {component!r} is not supported",
                )
            value = _derived_value(component, params, message)
        elif component == "*":
            raise ComponentError(
                "invalid_component",
                "the '*' component requires 'name' parameters and is not "
                "supported on request verification",
            )
        else:
            force_sf = bool(params.get("sf"))
            value = _header_value(component, grouped, force_sf)
            # The "key" parameter selects one member of an SF dictionary.
            if "key" in params:
                value = _select_dictionary_member(
                    component, value, params["key"]
                )
            elif params.get("bs"):
                value = _select_byteseq(component, value)

        component_values[identifier] = value
        lines.append(f"{identifier}: {value}")

    signature_params = str(covered)
    lines.append(f'"@signature-params": {signature_params}')
    component_values["@signature-params"] = signature_params

    return BuiltBase(
        base="\n".join(lines),
        lines=lines,
        component_values=component_values,
        identifiers=identifiers,
    )


def _select_dictionary_member(
    field_name: str, serialised: str, key: str
) -> str:
    from http_sfv import Dictionary

    d = Dictionary()
    try:
        d.parse(serialised.encode("latin-1"))
    except ValueError as exc:
        raise ComponentError(
            "component_value_unavailable",
            f"field {field_name!r} is not a structured dictionary: {exc}",
        ) from exc
    if key not in d:
        raise ComponentError(
            "component_value_unavailable",
            f"field {field_name!r} has no dictionary member {key!r}",
        )
    try:
        return str(d[key])
    except ValueError as exc:
        raise ComponentError(
            "component_value_unavailable",
            f"field {field_name!r} member {key!r} cannot be serialised: {exc}",
        ) from exc


def _select_byteseq(field_name: str, serialised: str) -> str:
    """``;bs`` — return the byte sequence of a single-member SF dict field."""
    from http_sfv import Dictionary

    d = Dictionary()
    try:
        d.parse(serialised.encode("latin-1"))
    except ValueError as exc:
        raise ComponentError(
            "component_value_unavailable",
            f"field {field_name!r} is not a structured dictionary: {exc}",
        ) from exc
    if len(d) != 1:
        raise ComponentError(
            "invalid_component_parameter",
            f"field {field_name!r};bs requires exactly one digest member",
        )
    member = next(iter(d.values()))
    if not isinstance(member, Item) or not isinstance(member.value, bytes):
        raise ComponentError(
            "invalid_component_parameter",
            f"field {field_name!r};bs member is not a byte sequence",
        )
    return str(member)
