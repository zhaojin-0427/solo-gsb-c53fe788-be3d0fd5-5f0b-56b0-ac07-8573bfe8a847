"""Policy versioning and shadow verification tests."""
from __future__ import annotations

import json
import threading
import time

from app import db
from app.crypto import generate_ed25519, generate_rsa, public_key_pem
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


def _signed(priv, *, keyid="k", algorithm="ed25519", nonce=None, **overrides):
    params = dict(
        private_key=priv,
        algorithm=algorithm,
        keyid=keyid,
        method="POST",
        target_uri="https://h/x",
        body=b'{"a":1}',
        components=["@method", "@target-uri", "@authority", "content-digest"],
    )
    if nonce is not None:
        params["nonce"] = nonce
    params.update(overrides)
    return make_signed_request(**params)


def _submit(client, payload, path="/verify-shadow", policy_version=None):
    body = {k: v for k, v in payload.items() if not k.startswith("_")}
    if policy_version is not None:
        body["policy_version"] = policy_version
    return client.post(path, json=body)


# ---------------------------------------------------------------------------
# Bootstrap: version 1 always exists and is active
# ---------------------------------------------------------------------------


def test_version_one_seeded_active(client, admin_headers):
    r = client.get("/admin/policy/versions", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["active_version"] == 1
    versions = data["versions"]
    assert len(versions) == 1
    v1 = versions[0]
    assert v1["version"] == 1
    assert v1["status"] == "active"
    assert v1["baseline_version"] is None

    r = client.get("/admin/policy/versions/1", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "active"

    r = client.get("/admin/policy", headers=admin_headers)
    assert r.json()["version"] == 1


def test_get_unknown_version_404(client, admin_headers):
    r = client.get("/admin/policy/versions/999", headers=admin_headers)
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "policy_version_unknown"


def test_versions_endpoint_requires_admin(client):
    assert client.get("/admin/policy/versions").status_code == 401


# ---------------------------------------------------------------------------
# Draft creation
# ---------------------------------------------------------------------------


def test_create_draft_clones_active_by_default(client, admin_headers):
    r = client.post("/admin/policy/drafts", json={}, headers=admin_headers)
    assert r.status_code == 201, r.text
    draft = r.json()
    assert draft["version"] == 2
    assert draft["status"] == "draft"
    assert draft["baseline_version"] == 1
    active = client.get("/admin/policy", headers=admin_headers).json()
    for field in (
        "required_components",
        "required_algorithms",
        "clock_skew_seconds",
        "max_age_seconds",
        "require_created",
        "require_nonce",
        "require_content_digest_with_body",
    ):
        assert draft[field] == active[field]

    # Creating a draft does not change the active policy.
    assert client.get("/admin/policy", headers=admin_headers).json()["version"] == 1
    listing = client.get(
        "/admin/policy/versions?status=draft", headers=admin_headers
    ).json()["versions"]
    assert [v["version"] for v in listing] == [2]


def test_create_draft_with_overrides(client, admin_headers):
    r = client.post(
        "/admin/policy/drafts",
        json={
            "required_components": ["@method", "@target-uri"],
            "required_algorithms": ["ed25519"],
            "clock_skew_seconds": 5,
            "max_age_seconds": 60,
            "require_created": False,
            "require_nonce": False,
            "require_content_digest_with_body": False,
        },
        headers=admin_headers,
    )
    assert r.status_code == 201, r.text
    draft = r.json()
    assert draft["required_components"] == ["@method", "@target-uri"]
    assert draft["required_algorithms"] == ["ed25519"]
    assert draft["clock_skew_seconds"] == 5
    assert draft["max_age_seconds"] == 60
    assert draft["require_created"] is False
    assert draft["require_nonce"] is False
    assert draft["require_content_digest_with_body"] is False


def test_drafts_are_immutable_rows(client, admin_headers):
    r = client.post("/admin/policy/drafts", json={"max_age_seconds": 60},
                    headers=admin_headers)
    assert r.status_code == 201

    # A PUT to the live policy creates a *new* version; the stored draft 2
    # remains byte-for-byte unchanged (no API can mutate it).
    policy = client.get("/admin/policy", headers=admin_headers).json()
    fields = (
        "required_components", "required_algorithms", "clock_skew_seconds",
        "max_age_seconds", "require_created", "require_nonce",
        "require_content_digest_with_body",
    )
    r = client.put("/admin/policy", json={k: policy[k] for k in fields},
                   headers=admin_headers)
    assert r.status_code == 200
    numbers = sorted(
        v["version"]
        for v in client.get("/admin/policy/versions", headers=admin_headers).json()["versions"]
    )
    assert numbers == [1, 2, 3]
    v2 = client.get("/admin/policy/versions/2", headers=admin_headers).json()
    assert v2["status"] == "draft"
    assert v2["max_age_seconds"] == 60


def test_create_draft_stale_baseline_conflict(client, admin_headers):
    # Activate something so the active version moves to 2.
    d = client.post("/admin/policy/drafts", json={"max_age_seconds": 90},
                    headers=admin_headers).json()
    client.post(f"/admin/policy/versions/{d['version']}/activate",
                json={}, headers=admin_headers)

    # A draft request pinned to the old baseline must fail 409.
    r = client.post(
        "/admin/policy/drafts",
        json={"baseline_version": 1, "max_age_seconds": 100},
        headers=admin_headers,
    )
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["reason"] == "policy_activation_conflict"
    assert detail["active_version"] == 2


# ---------------------------------------------------------------------------
# Activation
# ---------------------------------------------------------------------------


def test_activate_draft_atomic_transition(client, admin_headers):
    draft = client.post(
        "/admin/policy/drafts",
        json={"required_algorithms": ["ed25519"], "max_age_seconds": 42},
        headers=admin_headers,
    ).json()

    r = client.post(
        f"/admin/policy/versions/{draft['version']}/activate",
        json={},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["active_version"] == draft["version"]
    assert body["activated"]["status"] == "active"
    assert body["activated"]["activated_at"] is not None

    versions = {v["version"]: v for v in
                client.get("/admin/policy/versions", headers=admin_headers)
                .json()["versions"]}
    assert versions[1]["status"] == "retired"
    assert versions[2]["status"] == "active"

    # /verify and the singleton mirror now enforce the new policy.
    live = client.get("/admin/policy", headers=admin_headers).json()
    assert live["version"] == 2
    assert live["max_age_seconds"] == 42
    assert live["required_algorithms"] == ["ed25519"]


def test_activate_unknown_version_404(client, admin_headers):
    r = client.post("/admin/policy/versions/77/activate", json={},
                    headers=admin_headers)
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "policy_version_unknown"


def test_activate_non_draft_rejected(client, admin_headers):
    # Version 1 is active, not a draft.
    r = client.post("/admin/policy/versions/1/activate", json={},
                    headers=admin_headers)
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["reason"] == "policy_draft_not_activatable"
    assert detail["status"] == "active"


def test_activation_stale_expected_version_conflict(client, admin_headers):
    d1 = client.post(
        "/admin/policy/drafts", json={"max_age_seconds": 90}, headers=admin_headers
    ).json()
    d2 = client.post(
        "/admin/policy/drafts", json={"max_age_seconds": 120}, headers=admin_headers
    ).json()
    # Both drafts are based on version 1.
    assert d1["baseline_version"] == d2["baseline_version"] == 1

    assert client.post(
        f"/admin/policy/versions/{d1['version']}/activate",
        json={"expected_active_version": 1}, headers=admin_headers,
    ).status_code == 200

    # Activating d2 with the stale expectation fails atomically.
    r = client.post(
        f"/admin/policy/versions/{d2['version']}/activate",
        json={"expected_active_version": 1}, headers=admin_headers,
    )
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["reason"] == "policy_activation_conflict"
    assert detail["active_version"] == d1["version"]

    # Nothing changed: d1 still active, d2 still draft.
    versions = {v["version"]: v for v in
                client.get("/admin/policy/versions", headers=admin_headers)
                .json()["versions"]}
    assert versions[d1["version"]]["status"] == "active"
    assert versions[d2["version"]]["status"] == "draft"


def test_concurrent_activations_only_one_wins(client, admin_headers):
    # Two drafts based on the same active version; activate concurrently.
    da = client.post("/admin/policy/drafts", json={"max_age_seconds": 11},
                     headers=admin_headers).json()
    db_ = client.post("/admin/policy/drafts", json={"max_age_seconds": 22},
                      headers=admin_headers).json()
    outcomes = []

    def worker(version):
        r = client.post(
            f"/admin/policy/versions/{version}/activate",
            json={"expected_active_version": 1}, headers=admin_headers,
        )
        outcomes.append((version, r.status_code))

    threads = [
        threading.Thread(target=worker, args=(da["version"],)),
        threading.Thread(target=worker, args=(db_["version"],)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    oks = [o for o in outcomes if o[1] == 200]
    conflicts = [o for o in outcomes if o[1] == 409]
    assert len(oks) == 1
    assert len(conflicts) == 1
    assert client.get("/admin/policy", headers=admin_headers).json()["version"] == oks[0][0]


def test_put_policy_creates_new_active_version(client, admin_headers):
    policy = client.get("/admin/policy", headers=admin_headers).json()
    policy["max_age_seconds"] = 123
    r = client.put("/admin/policy", json={k: policy[k] for k in (
        "required_components", "required_algorithms", "clock_skew_seconds",
        "max_age_seconds", "require_created", "require_nonce",
        "require_content_digest_with_body")}, headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["version"] == 2
    versions = client.get("/admin/policy/versions", headers=admin_headers).json()
    assert versions["active_version"] == 2
    assert [v["status"] for v in versions["versions"] if v["version"] == 1] == ["retired"]


# ---------------------------------------------------------------------------
# Shadow verification
# ---------------------------------------------------------------------------


def test_shadow_accepts_against_active_version(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-shadow", pub, admin_headers)
    payload = _signed(priv, keyid="k-shadow")
    r = _submit(client, payload, policy_version=1)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "shadow_accepted"
    assert data["mode"] == "shadow"
    assert data["policy_version"] == 1
    assert data["active_policy_version"] == 1
    assert data["diff_count"] == 0
    assert data["diff_vs_active"] == []
    assert data["nonce_seen"] is False
    # Full verification artifacts are present.
    assert data["components"]["\"@method\""] == "POST"
    assert data["signature_base"].startswith('"@method": POST')


def test_shadow_does_not_consume_nonce(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-n", pub, admin_headers)
    payload = _signed(priv, keyid="k-n", nonce="fixed-nonce")

    # Shadow twice: both succeed, neither consumes the nonce.
    assert _submit(client, payload, policy_version=1).status_code == 200
    r = _submit(client, payload, policy_version=1)
    assert r.status_code == 200
    assert r.json()["nonce_seen"] is False

    # Formal /verify still accepts (nonce was free) and now consumes it.
    r = _submit(client, payload, path="/verify")
    assert r.status_code == 200
    assert r.json()["status"] == "accepted"

    # Shadow after the live acceptance reports the advisory, but still 200.
    r = _submit(client, payload, policy_version=1)
    assert r.status_code == 200
    assert r.json()["status"] == "shadow_accepted"
    assert r.json()["nonce_seen"] is True

    # Live replay is still rejected as before.
    r = _submit(client, payload, path="/verify")
    assert r.status_code == 409
    assert r.json()["reason"] == "replayed"


def test_shadow_enforces_stricter_draft(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-s", pub, admin_headers)
    # Draft: only Ed25519 allowed.
    draft = client.post(
        "/admin/policy/drafts",
        json={"required_algorithms": ["ed25519"]},
        headers=admin_headers,
    ).json()

    rsa_priv, rsa_pub = generate_rsa(2048)
    _register(client, "k-rsa", rsa_pub, admin_headers)
    payload = _signed(
        rsa_priv, keyid="k-rsa", algorithm="rsa-pss-sha256"
    )

    # Shadow against the draft -> rejected by the draft's allow-list.
    r = _submit(client, payload, policy_version=draft["version"])
    assert r.status_code == 401
    data = r.json()
    assert data["mode"] == "shadow"
    assert data["reason"] == "algorithm_not_allowed"
    assert data["policy_version"] == draft["version"]
    assert data["policy_status"] == "draft"
    fields = {c["field"]: c for c in data["diff_vs_active"]}
    assert fields["required_algorithms"]["removed"] == [
        "rsa-pss-sha256",
        "rsa-pss-sha512",
    ]
    assert fields["required_algorithms"]["added"] == []

    # Same message is formally accepted under the active version (no state
    # was changed by the shadow run).
    r = _submit(client, payload, path="/verify")
    assert r.status_code == 200


def test_shadow_enforces_relaxed_retired_version(client, admin_headers):
    # v1 requires content-digest; create + activate a relaxed v2, then
    # shadow a body-less-digest request against retired v1.
    relaxed = client.post(
        "/admin/policy/drafts",
        json={"required_components": ["@method", "@target-uri", "@authority"],
              "require_content_digest_with_body": False},
        headers=admin_headers,
    ).json()
    client.post(f"/admin/policy/versions/{relaxed['version']}/activate",
                json={}, headers=admin_headers)

    priv, pub = generate_ed25519()
    _register(client, "k-r", pub, admin_headers)
    # Signature covers no content-digest component and no digest header, but
    # the request carries a body.
    payload = _signed(
        priv,
        keyid="k-r",
        components=["@method", "@target-uri", "@authority"],
    )
    payload["headers"] = [
        h for h in payload["headers"] if h["name"].lower() != "content-digest"
    ]

    # Active (v2, relaxed) accepts formally.
    r = _submit(client, payload, path="/verify")
    assert r.status_code == 200, r.text

    # Shadow against retired v1 (strict) fails, and diff shows the addition.
    r = _submit(client, payload, policy_version=1)
    assert r.status_code == 401
    assert r.json()["reason"] == "content_digest_required"
    assert r.json()["active_policy_version"] == 2
    assert r.json()["policy_status"] == "retired"
    fields = {c["field"]: c for c in r.json()["diff_vs_active"]}
    assert "content-digest" in fields["required_components"]["added"]
    assert fields["require_content_digest_with_body"] == {
        "field": "require_content_digest_with_body",
        "kind": "scalar",
        "active": False,
        "candidate": True,
        "changed": True,
    }


def test_shadow_stable_reason_codes_full_pipeline(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-fresh", pub, admin_headers)

    # Freshness checks run under the shadow version: future created.
    payload = _signed(
        priv, keyid="k-fresh", created=int(time.time()) + 3600
    )
    r = _submit(client, payload, policy_version=1)
    assert r.status_code == 401
    assert r.json()["reason"] == "created_in_future"

    # Bad key resolution still happens in shadow mode.
    payload = _signed(priv, keyid="ghost")
    r = _submit(client, payload, policy_version=1)
    assert r.status_code == 404
    assert r.json()["reason"] == "unknown_key"

    # Tampered signature -> signature_invalid, with no nonce side effects.
    payload = _signed(priv, keyid="k-fresh", nonce="tamper-nonce")
    raw = payload["signature"]
    prefix, rest = raw.split("=:", 1)
    payload["signature"] = prefix + "=:" + ("A" if rest[0] != "A" else "B") + rest[1:]
    r = _submit(client, payload, policy_version=1)
    assert r.status_code == 401
    assert r.json()["reason"] == "signature_invalid"


def test_shadow_unknown_version_404(client, admin_headers):
    priv, _ = generate_ed25519()
    payload = _signed(priv)
    r = _submit(client, payload, policy_version=4242)
    assert r.status_code == 404
    data = r.json()
    assert data["reason"] == "policy_version_unknown"
    assert data["policy_version"] == 4242


def test_shadow_requires_policy_version(client, admin_headers):
    priv, _ = generate_ed25519()
    payload = _signed(priv)
    body = {k: v for k, v in payload.items() if not k.startswith("_")}
    r = client.post("/verify-shadow", json=body)
    assert r.status_code == 400
    assert r.json()["reason"] == "bad_request"


def test_shadow_diff_scalar_changes(client, admin_headers):
    draft = client.post(
        "/admin/policy/drafts",
        json={"clock_skew_seconds": 99, "max_age_seconds": 999,
              "require_nonce": False},
        headers=admin_headers,
    ).json()
    priv, pub = generate_ed25519()
    _register(client, "k-d", pub, admin_headers)
    payload = _signed(priv, keyid="k-d")
    r = _submit(client, payload, policy_version=draft["version"])
    assert r.status_code == 200
    fields = {c["field"]: c for c in r.json()["diff_vs_active"]}
    assert fields["clock_skew_seconds"]["active"] == 30
    assert fields["clock_skew_seconds"]["candidate"] == 99
    assert fields["max_age_seconds"]["active"] == 300
    assert fields["max_age_seconds"]["candidate"] == 999
    assert fields["require_nonce"]["candidate"] is False
    assert r.json()["diff_count"] == 3


# ---------------------------------------------------------------------------
# Persistence / determinism
# ---------------------------------------------------------------------------


def test_bootstrap_snapshots_preexisting_singleton_policy(client, admin_headers):
    """A database from the pre-versioning era (verify_policy row, no
    policy_versions rows) gets its live policy snapshotted as active v1."""
    # Simulate the old database: wipe version history, keep a custom singleton.
    with db.transaction() as cur:
        cur.execute("DELETE FROM policy_versions")
        cur.execute(
            """
            UPDATE verify_policy SET
                required_components = %s::jsonb,
                required_algorithms = %s::jsonb,
                clock_skew_seconds = 7, max_age_seconds = 77,
                require_created = FALSE, require_nonce = FALSE,
                require_content_digest_with_body = FALSE
            WHERE id = 1
            """,
            ('["@method"]', '["ed25519"]'),
        )

    # Re-run the bootstrap seeding, as an upgraded app would on startup.
    with db.transaction() as cur:
        db._seed_initial_policy(cur)

    versions = client.get("/admin/policy/versions", headers=admin_headers).json()
    assert versions["active_version"] == 1
    v1 = [v for v in versions["versions"] if v["version"] == 1][0]
    assert v1["status"] == "active"
    assert v1["required_components"] == ["@method"]
    assert v1["clock_skew_seconds"] == 7
    assert v1["require_nonce"] is False
    live = client.get("/admin/policy", headers=admin_headers).json()
    assert live["version"] == 1
    assert live["max_age_seconds"] == 77


def test_versions_and_shadow_survive_restart(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-persist", pub, admin_headers)
    draft = client.post(
        "/admin/policy/drafts",
        json={"max_age_seconds": 77, "required_algorithms": ["ed25519"]},
        headers=admin_headers,
    ).json()
    client.post(
        f"/admin/policy/versions/{draft['version']}/activate",
        json={}, headers=admin_headers,
    )
    payload = _signed(priv, keyid="k-persist")
    before = _submit(client, payload, policy_version=1).json()
    before_versions = client.get(
        "/admin/policy/versions", headers=admin_headers
    ).json()

    # Simulate an application restart: close the pool and reconnect.
    db.close()
    db.connect()

    after = _submit(client, payload, policy_version=1).json()
    after_versions = client.get(
        "/admin/policy/versions", headers=admin_headers
    ).json()

    # Version query results and shadow outcome/diff are identical.
    assert after_versions == before_versions
    for key in ("status", "reason", "policy_version", "active_policy_version",
                "diff_vs_active", "diff_count", "nonce_seen", "signature_base"):
        assert after.get(key) == before.get(key)
    # And the activated policy is still enforced after restart.
    assert client.get("/admin/policy", headers=admin_headers).json()["version"] == 2
