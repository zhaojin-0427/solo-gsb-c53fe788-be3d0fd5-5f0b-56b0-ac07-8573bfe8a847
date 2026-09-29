"""Signature-base tests, including RFC 9421 Appendix B test vectors."""
from __future__ import annotations

import pytest

from app.base import (
    ComponentError,
    HttpRequestMessage,
    build_signature_base,
)
from app.sf9421 import (
    SignatureInputError,
    parse_signature_dictionary,
)


def _base(signature_input: str, message: HttpRequestMessage):
    members = parse_signature_dictionary(signature_input)
    return build_signature_base(message, members[list(members)[0]])


def test_rfc9421_b21_minimal_base():
    si = (
        'sig1=("@method" "@authority" "@path");created=1618884475;'
        'keyid="test-key-rsa-pss";alg="rsa-pss-sha512";tag="header-example"'
    )
    msg = HttpRequestMessage(
        "POST",
        "http://example.com/foo?param=Value&Pet=dog",
        [
            ("host", "example.com"),
            ("date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("content-type", "application/json"),
            ("content-length", "18"),
        ],
    )
    expected = (
        '"@method": POST\n'
        '"@authority": example.com\n'
        '"@path": /foo\n'
        '"@signature-params": ("@method" "@authority" "@path");'
        'created=1618884475;keyid="test-key-rsa-pss";alg="rsa-pss-sha512";'
        'tag="header-example"'
    )
    assert _base(si, msg).base == expected


def test_rfc9421_b22_full_base_legacy_fields():
    si = (
        'sig-b21=("date" "@method" "@path" "@query" "@authority" '
        '"content-type" "content-length");alg="rsa-pss-sha512";'
        'created=1618884475;keyid="test-key-rsa-pss";tag="header-example"'
    )
    msg = HttpRequestMessage(
        "POST",
        "http://example.com/foo?param=Value&Pet=dog",
        [
            ("host", "example.com"),
            ("date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("content-type", "application/json"),
            ("content-length", "18"),
            ("x-custom", "Example 1"),
            ("x-custom", "Example 2"),
            ("x-empty", ""),
        ],
    )
    expected = (
        '"date": Tue, 20 Apr 2021 02:07:55 GMT\n'
        '"@method": POST\n'
        '"@path": /foo\n'
        '"@query": "?param=Value&Pet=dog"\n'
        '"@authority": example.com\n'
        '"content-type": application/json\n'
        '"content-length": 18\n'
        '"@signature-params": ("date" "@method" "@path" "@query" "@authority" '
        '"content-type" "content-length");alg="rsa-pss-sha512";'
        'created=1618884475;keyid="test-key-rsa-pss";tag="header-example"'
    )
    assert _base(si, msg).base == expected


def test_legacy_multivalue_header_is_joined():
    si = 's=("x-multi")'
    msg = HttpRequestMessage(
        "GET",
        "http://h/",
        [("X-Multi", "  one\t"), ("x-multi", "two ")],
    )
    result = _base(si, msg)
    assert result.components['"x-multi"'] == "one, two"


def test_sf_header_is_canonicalised():
    si = 's=("cache-control";sf "content-digest";sf)'
    msg = HttpRequestMessage(
        "GET",
        "http://h/",
        [
            ("Cache-Control", "max-age=60 ,  must-revalidate"),
            ("Content-Digest", "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"),
        ],
    )
    result = _base(si, msg)
    assert result.components['"cache-control";sf'] == "max-age=60, must-revalidate"
    assert (
        result.components['"content-digest";sf']
        == "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
    )


def test_query_param_single_and_multiple():
    si = 's=("@query-param";name="a" "@query-param";name="b")'
    msg = HttpRequestMessage("GET", "https://h/p?a=1&a=2&b=z", [])
    result = _base(si, msg)
    assert result.components['"@query-param";name="a"'] == '("1" "2")'
    assert result.components['"@query-param";name="b"'] == '"z"'


def test_all_derived_components():
    si = 's=("@target-uri" "@scheme" "@request-target" "@path")'
    msg = HttpRequestMessage("get", "HTTPS://h.example:443/a/b", [])
    result = _base(si, msg)
    c = result.components
    assert c['"@target-uri"'] == "HTTPS://h.example:443/a/b"
    assert c['"@scheme"'] == "https"
    assert c['"@request-target"'] == "/a/b"
    assert c['"@path"'] == "/a/b"


def test_authority_non_default_port():
    msg = HttpRequestMessage("GET", "https://h:8443/x", [])
    result = _base('s=("@authority")', msg)
    assert result.components['"@authority"'] == "h:8443"


def test_missing_header_is_error():
    with pytest.raises(ComponentError) as exc:
        _base('s=("x-absent")', HttpRequestMessage("GET", "http://h/", []))
    assert exc.value.reason == "component_value_unavailable"


@pytest.mark.parametrize(
    "si,reason",
    [
        ('s=("@query")', "component_value_unavailable"),
        ('s=("@query-param";name="z")', "component_value_unavailable"),
        ('s=("@method" "@method")', "duplicate_component"),
        ('s=("@nope")', "unknown_component"),
        ('s=("@status")', "component_value_unavailable"),
        ('s=("@method";req=1)', "related_request_unsupported"),
        ('s=("@query-param")', "invalid_component_parameter"),
        ('s=("x";sf="no")', "invalid_component_parameter"),
    ],
)
def test_component_errors(si, reason):
    msg = HttpRequestMessage("GET", "http://h/p", [])
    with pytest.raises(ComponentError) as exc:
        _base(si, msg)
    assert exc.value.reason == reason


def test_quoted_string_label_parses():
    members = parse_signature_dictionary(
        '"my label"=("@method");keyid="k";created=1'
    )
    assert list(members) == ["my label"]


def test_duplicate_label_rejected():
    with pytest.raises(SignatureInputError):
        parse_signature_dictionary('a=("@method"), a=("@path")')


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "@missing",
        'sig1=("@method") trailing',
        'sig1',
    ],
)
def test_malformed_dictionary(raw):
    with pytest.raises(SignatureInputError):
        parse_signature_dictionary(raw)
