"""Acceptance receipt tests: issuance, persistence, rotation, offline checks."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from app import db, receipts
from app.crypto import generate_ed25519, load_public_key, public_key_pem
from app.signer import make_signed_request

TOOL = Path(__file__).resolve().parent.parent / "tools" / "verify_receipt.py"


def _register(client, keyid, public_key, headers):
    r = client.post(
        "/admin/keys",
        json={"keyid": keyid, "public_key": public_key_pem(public_key)},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.json()


def _signed(priv, *, keyid="k", nonce="nonce-1", **overrides):
    params = dict(
        private_key=priv,
        algorithm="ed25519",
        keyid=keyid,
        method="POST",
        target_uri="https://h/x",
        body=b'{"a":1}',
        components=["@method", "@target-uri", "@authority", "content-digest"],
        nonce=nonce,
    )
    params.update(overrides)
    return make_signed_request(**params)


def _submit(client, payload, path="/verify"):
    body = {k: v for k, v in payload.items() if not k.startswith("_")}
    return client.post(path, json=body)


def _request_body(payload):
    return {k: v for k, v in payload.items() if not k.startswith("_")}


def _receipt_count():
    with db.transaction(read_only=True) as cur:
        cur.execute("SELECT COUNT(*) FROM receipts")
        return cur.fetchone()[0]


def _verify_receipt_offline(receipt, keys_doc):
    """In-process equivalent of tools/verify_receipt.py."""
    fields = receipts.parse_payload(receipt["payload"])
    entry = next(k for k in keys_doc["keys"] if k["key_id"] == fields["key_id"])
    pub = load_public_key(entry["public_key"])
    assert receipts.verify_payload_signature(pub, receipt["payload"], receipt["signature"])
    return fields, entry


# ---------------------------------------------------------------------------
# Issuance on acceptance
# ---------------------------------------------------------------------------


def test_accepted_verify_issues_verifiable_receipt(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rcpt", pub, admin_headers)
    payload = _signed(priv, keyid="k-rcpt")

    r = _submit(client, payload)
    assert r.status_code == 200, r.text
    data = r.json()

    # All pre-existing response fields are preserved.
    for field in (
        "status",
        "mode",
        "keyid",
        "key_version",
        "key_fingerprint",
        "label",
        "algorithm",
        "created",
        "expires",
        "nonce",
        "policy_version",
        "components",
        "signature_base",
        "signature_base_lines",
    ):
        assert field in data, field
    assert data["status"] == "accepted"

    receipt = data["receipt"]
    assert receipt is not None
    fields = receipts.parse_payload(receipt["payload"])

    # The payload binds the acceptance context.
    assert fields["receipt_id"] == receipt["receipt_id"]
    assert fields["keyid"] == "k-rcpt"
    assert fields["key_version"] == data["key_version"] == 1
    assert fields["policy_version"] == data["policy_version"]
    assert fields["algorithm"] == "ed25519"
    assert fields["label"] == "sig1"
    assert fields["nonce"] == "nonce-1"
    assert fields["issued_at"] == receipt["issued_at_unix"]
    assert receipt["context"]["keyid"] == "k-rcpt"

    # The digest binds the exact verification input, recomputed locally.
    assert fields["input_digest"] == receipts.input_digest(_request_body(payload))
    assert receipt["input_digest"] == fields["input_digest"]

    # The signature verifies against the published server key.
    keys_doc = client.get("/receipts/keys").json()
    _verify_receipt_offline(receipt, keys_doc)
    assert _receipt_count() == 1


def test_receipt_query_by_id(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-get", pub, admin_headers)
    payload = _signed(priv, keyid="k-get")
    receipt = _submit(client, payload).json()["receipt"]

    r = client.get(f"/receipts/{receipt['receipt_id']}")
    assert r.status_code == 200
    fetched = r.json()
    assert fetched == receipt

    # The fetched receipt still verifies offline.
    keys_doc = client.get("/receipts/keys").json()
    _verify_receipt_offline(fetched, keys_doc)


def test_receipt_query_unknown_id(client):
    r = client.get("/receipts/does-not-exist")
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "receipt_unknown"


def test_receipt_endpoints_are_public(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-pub", pub, admin_headers)
    payload = _signed(priv, keyid="k-pub")
    receipt = _submit(client, payload).json()["receipt"]

    # No X-Admin-Token on either endpoint.
    keys = client.get("/receipts/keys")
    assert keys.status_code == 200
    assert client.get(f"/receipts/{receipt['receipt_id']}").status_code == 200
    for entry in keys.json()["keys"]:
        assert "private_key" not in entry


# ---------------------------------------------------------------------------
# No receipt on rejection / replay / shadow
# ---------------------------------------------------------------------------


def test_rejection_issues_no_receipt(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rej", pub, admin_headers)
    payload = _signed(priv, keyid="k-rej")
    payload["signature"] = payload["signature"].replace("=:", "=:A", 1)

    r = _submit(client, payload)
    assert r.status_code == 401
    assert r.json()["reason"] == "signature_invalid"
    assert _receipt_count() == 0


def test_replay_issues_no_second_receipt(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-replay", pub, admin_headers)
    payload = _signed(priv, keyid="k-replay")

    assert _submit(client, payload).status_code == 200
    r = _submit(client, payload)
    assert r.status_code == 409
    assert "receipt" not in r.json()
    assert _receipt_count() == 1


def test_shadow_issues_no_receipt(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-shadow", pub, admin_headers)
    payload = _signed(priv, keyid="k-shadow")
    active = client.get("/admin/policy", headers=admin_headers).json()

    r = client.post(
        "/verify-shadow",
        json={**_request_body(payload), "policy_version": active["version"]},
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "shadow_accepted"
    assert r.json()["receipt"] is None
    assert _receipt_count() == 0


def test_concurrent_duplicate_nonce_yields_single_receipt(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-race", pub, admin_headers)
    payload = _signed(priv, keyid="k-race", nonce="race-nonce")
    body = _request_body(payload)

    results = []
    lock = threading.Lock()

    def worker():
        r = client.post("/verify", json=body)
        with lock:
            results.append((r.status_code, r.json()))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    accepted = [d for code, d in results if d.get("status") == "accepted"]
    replayed = [d for code, d in results if d.get("status") == "replayed"]
    assert len(accepted) == 1
    assert len(replayed) == 15
    assert accepted[0]["receipt"] is not None
    # At most one receipt exists for the duplicated nonce.
    assert _receipt_count() == 1


# ---------------------------------------------------------------------------
# Atomicity: receipt failure rolls back the whole acceptance
# ---------------------------------------------------------------------------


def test_receipt_persistence_failure_rolls_back(client, admin_headers, monkeypatch):
    priv, pub = generate_ed25519()
    _register(client, "k-fail", pub, admin_headers)
    payload = _signed(priv, keyid="k-fail", nonce="rollback-nonce")
    body = _request_body(payload)

    original = db.insert_receipt
    state = {"fail": True}

    def flaky_insert(*args, **kwargs):
        if state["fail"]:
            raise RuntimeError("simulated receipt insert failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(db, "insert_receipt", flaky_insert)

    r = client.post("/verify", json=body)
    assert r.status_code == 500
    assert r.json()["reason"] == "receipt_issuance_failed"
    assert _receipt_count() == 0

    # The nonce claim was rolled back too: the same payload verifies now.
    state["fail"] = False
    r = client.post("/verify", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["receipt"] is not None
    assert _receipt_count() == 1


def test_receipt_signing_failure_rolls_back(client, admin_headers, monkeypatch):
    priv, pub = generate_ed25519()
    _register(client, "k-sfail", pub, admin_headers)
    payload = _signed(priv, keyid="k-sfail", nonce="sign-rollback-nonce")
    body = _request_body(payload)

    def broken_sign(*args, **kwargs):
        raise RuntimeError("simulated signing failure")

    monkeypatch.setattr(receipts, "sign_payload", broken_sign)

    r = client.post("/verify", json=body)
    assert r.status_code == 500
    assert r.json()["reason"] == "receipt_issuance_failed"
    assert _receipt_count() == 0
    # The nonce was not consumed by the failed attempt.
    assert not db.nonce_seen("k-sfail", "sign-rollback-nonce")


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------


def test_rotation_keeps_old_receipts_verifiable(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rot", pub, admin_headers)

    first = _submit(client, _signed(priv, keyid="k-rot", nonce="n-1")).json()["receipt"]
    assert first["key_id"] == "receipt-signing#1"

    r = client.post("/admin/receipt-keys/rotate", headers=admin_headers)
    assert r.status_code == 201, r.text
    new_key = r.json()
    assert new_key["version"] == 2
    assert new_key["status"] == "active"
    assert "private_key" not in new_key

    second = _submit(client, _signed(priv, keyid="k-rot", nonce="n-2")).json()["receipt"]
    assert second["key_id"] == "receipt-signing#2"

    keys_doc = client.get("/receipts/keys").json()["keys"]
    by_id = {k["key_id"]: k for k in keys_doc}
    assert by_id["receipt-signing#1"]["status"] == "retired"
    assert by_id["receipt-signing#1"]["retired_at"] is not None
    assert by_id["receipt-signing#2"]["status"] == "active"

    # Both the pre-rotation and post-rotation receipts verify offline.
    _verify_receipt_offline(first, {"keys": keys_doc})
    _verify_receipt_offline(second, {"keys": keys_doc})


def test_rotation_requires_admin_token(client):
    assert client.post("/admin/receipt-keys/rotate").status_code == 401


# ---------------------------------------------------------------------------
# Standalone offline verifier tool
# ---------------------------------------------------------------------------


def _run_tool(*args):
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
    )


def test_offline_verifier_tool(client, admin_headers, tmp_path):
    priv, pub = generate_ed25519()
    _register(client, "k-tool", pub, admin_headers)
    payload = _signed(priv, keyid="k-tool")
    body = _request_body(payload)
    response = _submit(client, payload).json()
    receipt = response["receipt"]

    receipt_file = tmp_path / "receipt.json"
    receipt_file.write_text(json.dumps(receipt))
    response_file = tmp_path / "response.json"
    response_file.write_text(json.dumps(response))
    keys_file = tmp_path / "keys.json"
    keys_file.write_text(json.dumps(client.get("/receipts/keys").json()))
    request_file = tmp_path / "request.json"
    request_file.write_text(json.dumps(body))

    # Bare receipt + keys.
    proc = _run_tool("--receipt", str(receipt_file), "--keys", str(keys_file))
    assert proc.returncode == 0, proc.stderr
    assert "verified offline" in proc.stdout

    # Full /verify response works too, and the request binding checks out.
    proc = _run_tool(
        "--receipt", str(response_file),
        "--keys", str(keys_file),
        "--request", str(request_file),
    )
    assert proc.returncode == 0, proc.stderr

    # A tampered signature fails.
    bad = dict(receipt, signature="A" + receipt["signature"][1:])
    bad_file = tmp_path / "bad.json"
    bad_file.write_text(json.dumps(bad))
    proc = _run_tool("--receipt", str(bad_file), "--keys", str(keys_file))
    assert proc.returncode == 1
    assert "INVALID" in proc.stderr

    # A receipt checked against the wrong request fails the binding check.
    other = _request_body(_signed(priv, keyid="k-tool", nonce="other-nonce"))
    other_file = tmp_path / "other.json"
    other_file.write_text(json.dumps(other))
    proc = _run_tool(
        "--receipt", str(receipt_file),
        "--keys", str(keys_file),
        "--request", str(other_file),
    )
    assert proc.returncode == 1
    assert "digest mismatch" in proc.stderr


def test_offline_verifier_tool_after_rotation(client, admin_headers, tmp_path):
    priv, pub = generate_ed25519()
    _register(client, "k-rottool", pub, admin_headers)
    old_receipt = _submit(client, _signed(priv, keyid="k-rottool", nonce="n-1")).json()[
        "receipt"
    ]
    client.post("/admin/receipt-keys/rotate", headers=admin_headers)

    receipt_file = tmp_path / "receipt.json"
    receipt_file.write_text(json.dumps(old_receipt))
    keys_file = tmp_path / "keys.json"
    keys_file.write_text(json.dumps(client.get("/receipts/keys").json()))

    # The retired key is still published, so the old receipt verifies.
    proc = _run_tool("--receipt", str(receipt_file), "--keys", str(keys_file))
    assert proc.returncode == 0, proc.stderr


# ---------------------------------------------------------------------------
# Canonical payload / digest unit behaviour
# ---------------------------------------------------------------------------


def test_payload_round_trip_and_strictness():
    payload = receipts.build_payload(
        receipt_id="r-1",
        key_id="receipt-signing#1",
        issued_at=1790101132,
        keyid="key-1",
        key_version=3,
        policy_version=2,
        algorithm="ed25519",
        label="sig1",
        nonce="abc",
        input_digest="sha256:AAAA",
    )
    fields = receipts.parse_payload(payload)
    assert fields["receipt_id"] == "r-1"
    assert fields["issued_at"] == 1790101132
    assert fields["key_version"] == 3
    assert fields["nonce"] == "abc"

    # Reordering or dropping a field is rejected.
    lines = payload.split("\n")
    swapped = "\n".join([lines[0], lines[2], lines[1], *lines[3:]])
    with pytest.raises(receipts.ReceiptFormatError):
        receipts.parse_payload(swapped)
    with pytest.raises(receipts.ReceiptFormatError):
        receipts.parse_payload("\n".join(lines[:-1]))
    with pytest.raises(receipts.ReceiptFormatError):
        receipts.parse_payload(payload.replace("receipt/v1", "receipt/v2", 1))


def test_input_digest_is_deterministic_and_order_sensitive():
    base = {
        "method": "POST",
        "target_uri": "https://h/x",
        "headers": [{"name": "a", "value": "1"}, ["b", "2"]],
        "body": "e30=",
        "Signature-Input": 'sig1=("@method");keyid="k"',
        "Signature": "sig1=:AA==:",
    }
    normalised = receipts.normalize_envelope(base)
    # Dict and pair header forms, and both signature field spellings,
    # canonicalise identically.
    assert receipts.input_digest(base) == receipts.input_digest(normalised)
    assert receipts.input_digest(base) == receipts.input_digest(
        {**normalised, "headers": [[n, v] for n, v in normalised["headers"]]}
    )
    # Header order matters (it is part of what was verified).
    reordered = {
        **base,
        "headers": [base["headers"][1], base["headers"][0]],
    }
    assert receipts.input_digest(reordered) != receipts.input_digest(base)
    assert receipts.input_digest(base).startswith("sha256:")
