"""RFC 9421 Appendix B official test vector verification."""
from __future__ import annotations

import base64

RFC_RSA_PSS_PUB = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----"""

# §3.2 signature (rsa-pss-sha512, no explicit alg parameter).
RFC_RSA_PSS_SIG = base64.b64decode(
    "HIbjHC5rS0BYaa9v4QfD4193TORw7u9edguPh0AW3dMq9WImrlFrCGUDih47vAxi4L2YRZ3XMJc1uOKk"
    "/J0ZmZ+wcta4nKIgBkKq0rM9hs3CQyxXGxHLMCy8uqK488o+9jrptQ+xFPHK7a9sRL1IXNaagCNN3ZxJ"
    "sYapFj+JXbmaI5rtAdSfSvzPuBCh+ARHBmWuNo1UzVVdHXrl8ePL4cccqlazIJdC4QEjrF+Sn4IxBQzT"
    "ZsL9y9TP5FsZYzHvDqbInkTNigBcE9cKOYNFCn4D/WM7F6TNuZO9EgtzepLWcjTymlHzK7aXq6Am6sfOr"
    "pIC49yXjj3ae6HRalVc/g=="
)


def test_rfc9421_rsa_pss_official_vector(client, admin_headers):
    # Register the RFC test public key.
    r = client.post(
        "/admin/keys",
        json={"keyid": "test-key-rsa-pss", "public_key": RFC_RSA_PSS_PUB},
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text

    # Relax policy: RFC example omits nonce and uses no explicit alg.
    policy = client.get("/admin/policy", headers=admin_headers).json()
    policy["required_components"] = [
        "@method",
        "@authority",
        "@path",
        "content-digest",
        "content-length",
        "content-type",
    ]
    policy["required_algorithms"] = ["ed25519", "rsa-pss-sha256", "rsa-pss-sha512"]
    policy["require_nonce"] = False
    # Vector was created in 2021; accept historical timestamps for the test.
    policy["max_age_seconds"] = 300_000_000
    policy["clock_skew_seconds"] = 30
    client.put("/admin/policy", json=policy, headers=admin_headers)

    # No alg parameter: the verifier defaults RSA keys to rsa-pss-sha512,
    # matching the RFC test vector's @signature-params exactly.
    signature_input = (
        'sig1=("@method" "@authority" "@path" "content-digest" '
        '"content-length" "content-type");created=1618884473;'
        'keyid="test-key-rsa-pss"'
    )
    payload = {
        "method": "POST",
        "target_uri": "http://example.com/foo?param=Value&Pet=dog",
        "headers": [
            {"name": "Host", "value": "example.com"},
            {"name": "Date", "value": "Tue, 20 Apr 2021 02:07:55 GMT"},
            {"name": "Content-Type", "value": "application/json"},
            {
                "name": "Content-Digest",
                "value": (
                    "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX"
                    "+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
                ),
            },
            {"name": "Content-Length", "value": "18"},
        ],
        "body": base64.b64encode(b'{"hello": "world"}').decode(),
        "signature_input": signature_input,
        "signature": "sig1=:" + base64.b64encode(RFC_RSA_PSS_SIG).decode() + ":",
    }
    r = client.post("/verify", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "accepted"
    assert data["algorithm"] == "rsa-pss-sha512"  # inferred from RSA key
    assert data["components"]['"@path"'] == "/foo"
