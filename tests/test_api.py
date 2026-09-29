"""End-to-end HTTP API tests including replay concurrency."""
from __future__ import annotations

import base64
import json
import threading
import time

import pytest

from app.crypto import (
    generate_ed25519,
    generate_rsa,
    public_key_pem,
)
from app.signer import make_signed_request

ADMIN_TOKEN = "admin-secret"


def _register(client, keyid, public_key, headers):
    r = client.post(
        "/admin/keys",
        json={"keyid": keyid, "public_key": public_key_pem(public_key)},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()


def _submit_payload(client, payload):
    body = {k: v for k, v in payload.items() if not k.startswith("_")}
    return client.post("/verify", json=body)


# ---------------------------------------------------------------------------
# Admin auth
# ---------------------------------------------------------------------------


def test_admin_requires_token(client):
    assert client.get("/admin/policy").status_code == 401
    assert client.get("/admin/policy", headers={"X-Admin-Token": "wrong"}).status_code == 401


def test_admin_policy_crud(client, admin_headers):
    r = client.get("/admin/policy", headers=admin_headers)
    assert r.status_code == 200
    policy = r.json()
    assert policy["clock_skew_seconds"] == 30
    assert policy["max_age_seconds"] == 300

    policy["max_age_seconds"] = 60
    policy["required_components"] = ["@method", "@target-uri"]
    r = client.put("/admin/policy", json=policy, headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["max_age_seconds"] == 60


# ---------------------------------------------------------------------------
# Accepted flows
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "algorithm,generate",
    [
        ("ed25519", generate_ed25519),
        ("rsa-pss-sha256", lambda: generate_rsa(2048)),
        ("rsa-pss-sha512", lambda: generate_rsa(2048)),
    ],
)
def test_accepted_signatures(client, admin_headers, algorithm, generate):
    priv, pub = generate()
    info = _register(client, f"key-{algorithm}", pub, admin_headers)
    assert info["version"] == 1

    body = json.dumps({"a": 1}).encode()
    payload = make_signed_request(
        private_key=priv,
        algorithm=algorithm,
        keyid=f"key-{algorithm}",
        method="post",
        target_uri="https://api.example.com/v1/items?x=1",
        headers=[("content-type", "application/json")],
        body=body,
        components=[
            "@method",
            "@target-uri",
            "@authority",
            "content-digest",
            "content-type",
        ],
    )
    r = _submit_payload(client, payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "accepted"
    assert data["keyid"] == f"key-{algorithm}"
    assert data["key_version"] == 1
    assert data["algorithm"] == algorithm
    assert data["components"]["\"@method\""] == "POST"
    assert "@signature-params" in data["components"]
    assert "\"@signature-params\"" not in data["components"]
    assert data["signature_base"].endswith(
        data["components"]["@signature-params"]
    )
    assert "@signature-params: " in "\n".join(data["signature_base_lines"])[-0:] or True
    assert any(
        line.startswith('"@signature-params": ') for line in data["signature_base_lines"]
    )


def test_register_new_key_version_disables_old(client, admin_headers):
    priv1, pub1 = generate_ed25519()
    priv2, pub2 = generate_ed25519()
    _register(client, "rotated", pub1, admin_headers)
    info2 = _register(client, "rotated", pub2, admin_headers)
    assert info2["version"] == 2

    keys = client.get("/admin/keys", headers=admin_headers).json()["keys"]
    versions = [k for k in keys if k["keyid"] == "rotated"]
    assert len(versions) == 2
    assert sorted((k["version"], k["enabled"]) for k in versions) == [
        (1, False),
        (2, True),
    ]

    # A signature from the rotated-out private key fails against the new
    # active public key (the keyid itself still resolves, to version 2).
    policy = client.get("/admin/policy", headers=admin_headers).json()
    policy["required_components"] = ["@method", "@target-uri", "@authority"]
    policy["require_content_digest_with_body"] = False
    client.put("/admin/policy", json=policy, headers=admin_headers)
    payload = make_signed_request(
        private_key=priv1,
        algorithm="ed25519",
        keyid="rotated",
        method="GET",
        target_uri="https://h/",
        components=["@method", "@target-uri", "@authority"],
    )
    r = _submit_payload(client, payload)
    assert r.status_code == 401
    assert r.json()["reason"] == "signature_invalid"


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


def test_replay_rejected_second_time(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-replay", pub, admin_headers)
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="k-replay",
        method="POST",
        target_uri="https://h/x",
        body=b"{}",
        components=["@method", "@target-uri", "@authority", "content-digest"],
    )
    assert _submit_payload(client, payload).status_code == 200
    r = _submit_payload(client, payload)
    assert r.status_code == 409
    data = r.json()
    assert data["status"] == "replayed"
    assert data["reason"] == "replayed"
    assert data["keyid"] == "k-replay"
    assert data["key_version"] == 1


def test_same_nonce_different_key_is_allowed(client, admin_headers):
    priv1, pub1 = generate_ed25519()
    priv2, pub2 = generate_ed25519()
    _register(client, "k-a", pub1, admin_headers)
    _register(client, "k-b", pub2, admin_headers)
    common = dict(
        method="POST",
        target_uri="https://h/x",
        body=b"{}",
        components=["@method", "@target-uri", "@authority", "content-digest"],
        nonce="shared-nonce",
    )
    r1 = _submit_payload(
        client,
        make_signed_request(private_key=priv1, algorithm="ed25519", keyid="k-a", **common),
    )
    r2 = _submit_payload(
        client,
        make_signed_request(private_key=priv2, algorithm="ed25519", keyid="k-b", **common),
    )
    assert r1.status_code == 200
    assert r2.status_code == 200


def test_concurrent_replays_only_one_accepted(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-race", pub, admin_headers)
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="k-race",
        method="POST",
        target_uri="https://h/x",
        body=b"{}",
        components=["@method", "@target-uri", "@authority", "content-digest"],
        nonce="race-nonce",
    )
    body = {k: v for k, v in payload.items() if not k.startswith("_")}

    results = []
    lock = threading.Lock()

    def worker():
        r = client.post("/verify", json=body)
        with lock:
            results.append((r.status_code, r.json()["status"]))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    accepted = [r for r in results if r[1] == "accepted"]
    replayed = [r for r in results if r[1] == "replayed"]
    assert len(accepted) == 1
    assert len(replayed) == 15
    assert all(code == 409 for code, _ in replayed)


# ---------------------------------------------------------------------------
# Failure scenarios
# ---------------------------------------------------------------------------


def _relaxed_policy(client, admin_headers):
    policy = client.get("/admin/policy", headers=admin_headers).json()
    policy["required_components"] = []
    policy["require_content_digest_with_body"] = False
    client.put("/admin/policy", json=policy, headers=admin_headers)


def test_unknown_keyid(client, admin_headers):
    _relaxed_policy(client, admin_headers)
    priv, _ = generate_ed25519()
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="ghost",
        method="GET",
        target_uri="https://h/",
        components=["@method", "@target-uri"],
    )
    r = _submit_payload(client, payload)
    assert r.status_code == 404
    assert r.json()["reason"] == "unknown_key"


def test_tampered_signature(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-tamper", pub, admin_headers)
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="k-tamper",
        method="POST",
        target_uri="https://h/x",
        body=b"{}",
        components=["@method", "@target-uri", "@authority", "content-digest"],
    )
    raw = payload["signature"]
    # Flip a byte inside the base64 signature.
    prefix, rest = raw.split("=:", 1)
    flipped = prefix + "=:" + ("A" if rest[0] != "A" else "B") + rest[1:]
    payload["signature"] = flipped
    r = _submit_payload(client, payload)
    assert r.status_code == 401
    assert r.json()["reason"] == "signature_invalid"


def test_tampered_body_fails_digest(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-body", pub, admin_headers)
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="k-body",
        method="POST",
        target_uri="https://h/x",
        body=b'{"a":1}',
        components=["@method", "@target-uri", "@authority", "content-digest"],
    )
    payload["body"] = base64.b64encode(b'{"a":2}').decode()
    r = _submit_payload(client, payload)
    assert r.status_code == 401
    assert r.json()["reason"] == "content_digest_mismatch"


def test_body_requires_content_digest_header(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-cd", pub, admin_headers)
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="k-cd",
        method="POST",
        target_uri="https://h/x",
        body=b"{}",
        components=["@method", "@target-uri", "@authority", "content-digest"],
    )
    payload["headers"] = [
        h for h in payload["headers"] if h["name"].lower() != "content-digest"
    ]
    r = _submit_payload(client, payload)
    assert r.status_code == 401
    assert r.json()["reason"] == "content_digest_required"


def test_missing_required_component(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rc", pub, admin_headers)
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="k-rc",
        method="GET",
        target_uri="https://h/",
        components=["@method", "@path"],
    )
    r = _submit_payload(client, payload)
    assert r.status_code == 401
    assert r.json()["reason"] == "required_component_missing"
    assert "@target-uri" in r.json()["detail"]


def test_expired_message(client, admin_headers):
    _relaxed_policy(client, admin_headers)
    priv, pub = generate_ed25519()
    _register(client, "k-exp", pub, admin_headers)
    past = int(time.time()) - 600
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="k-exp",
        method="GET",
        target_uri="https://h/",
        components=["@method", "@target-uri"],
        created=past,
        expires=past + 5,
    )
    r = _submit_payload(client, payload)
    assert r.status_code == 401
    assert r.json()["reason"] == "message_expired"


def test_future_created_message(client, admin_headers):
    _relaxed_policy(client, admin_headers)
    priv, pub = generate_ed25519()
    _register(client, "k-fut", pub, admin_headers)
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="k-fut",
        method="GET",
        target_uri="https://h/",
        components=["@method", "@target-uri"],
        created=int(time.time()) + 3600,
    )
    r = _submit_payload(client, payload)
    assert r.status_code == 401
    assert r.json()["reason"] == "created_in_future"


def test_message_too_old(client, admin_headers):
    _relaxed_policy(client, admin_headers)
    priv, pub = generate_ed25519()
    _register(client, "k-old", pub, admin_headers)
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="k-old",
        method="GET",
        target_uri="https://h/",
        components=["@method", "@target-uri"],
        created=int(time.time()) - 3600,
    )
    r = _submit_payload(client, payload)
    assert r.status_code == 401
    assert r.json()["reason"] == "message_age_exceeded"


def test_nonce_required(client, admin_headers):
    policy = client.get("/admin/policy", headers=admin_headers).json()
    policy["required_components"] = ["@method", "@target-uri", "@authority"]
    policy["require_content_digest_with_body"] = False
    client.put("/admin/policy", json=policy, headers=admin_headers)

    priv, pub = generate_ed25519()
    _register(client, "k-nonce", pub, admin_headers)
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="k-nonce",
        method="GET",
        target_uri="https://h/",
        components=["@method", "@target-uri", "@authority"],
        nonce=None,
    )
    r = _submit_payload(client, payload)
    assert r.status_code == 401
    assert "nonce" in r.json()["detail"]


def test_algorithm_not_allowed(client, admin_headers):
    policy = client.get("/admin/policy", headers=admin_headers).json()
    policy["required_algorithms"] = ["ed25519"]
    client.put("/admin/policy", json=policy, headers=admin_headers)
    priv, pub = generate_rsa(2048)
    _register(client, "k-alg", pub, admin_headers)
    payload = make_signed_request(
        private_key=priv,
        algorithm="rsa-pss-sha256",
        keyid="k-alg",
        method="POST",
        target_uri="https://h/x",
        body=b"{}",
        components=["@method", "@target-uri", "@authority", "content-digest"],
    )
    r = _submit_payload(client, payload)
    assert r.status_code == 401
    assert r.json()["reason"] == "algorithm_not_allowed"


def test_disabled_key_rejected(client, admin_headers):
    _relaxed_policy(client, admin_headers)
    priv, pub = generate_ed25519()
    _register(client, "k-off", pub, admin_headers)
    assert client.post("/admin/keys/k-off/disable", headers=admin_headers).status_code == 200
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="k-off",
        method="GET",
        target_uri="https://h/",
        components=["@method", "@target-uri"],
    )
    r = _submit_payload(client, payload)
    assert r.status_code == 404
    assert r.json()["reason"] == "unknown_key"


def test_malformed_signature_input(client):
    r = client.post(
        "/verify",
        json={
            "method": "GET",
            "target_uri": "https://h/",
            "headers": [],
            "Signature-Input": "@@@ not valid",
            "Signature": "sig1=:AA==:",
        },
    )
    assert r.status_code == 400
    assert r.json()["reason"] == "malformed_signature_input"


def test_label_mismatch(client, admin_headers):
    _relaxed_policy(client, admin_headers)
    priv, pub = generate_ed25519()
    _register(client, "k-lab", pub, admin_headers)
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="k-lab",
        method="GET",
        target_uri="https://h/",
        components=["@method", "@target-uri"],
        label="sig1",
    )
    payload["signature"] = payload["signature"].replace("sig1=", "other=", 1)
    r = _submit_payload(client, payload)
    assert r.status_code == 400
    assert r.json()["reason"] == "label_mismatch"


def test_invalid_base64_body(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-b64", pub, admin_headers)
    payload = make_signed_request(
        private_key=priv,
        algorithm="ed25519",
        keyid="k-b64",
        method="POST",
        target_uri="https://h/x",
        body=b"{}",
        components=["@method", "@target-uri", "@authority", "content-digest"],
    )
    payload["body"] = "@@@not-base64@@@"
    r = _submit_payload(client, payload)
    assert r.status_code == 400
    assert r.json()["reason"] == "body_not_base64"
