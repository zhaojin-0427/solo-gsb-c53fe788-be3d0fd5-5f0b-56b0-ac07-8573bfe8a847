"""Receipt revocation tests: commands, audit chain, point-in-time status."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from app import db, receipts, revocations
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


def _accept(client, priv, keyid, nonce):
    payload = _signed(priv, keyid=keyid, nonce=nonce)
    body = {k: v for k, v in payload.items() if not k.startswith("_")}
    r = client.post("/verify", json=body)
    assert r.status_code == 200, r.text
    return r.json()["receipt"], body


def _revoke(client, receipt_id, headers, **overrides):
    command = {
        "reason": "signer key compromised",
        "effective_at": int(time.time()) - 60,
        "expected_revision": 0,
        "command_id": None,
    }
    command.update(overrides)
    command = {k: v for k, v in command.items() if v is not None}
    return client.post(
        f"/admin/receipts/{receipt_id}/revoke", json=command, headers=headers
    )


def _revocation_count():
    with db.transaction(read_only=True) as cur:
        cur.execute("SELECT COUNT(*) FROM receipt_revocations")
        return cur.fetchone()[0]


def _receipt_revision(receipt_id):
    with db.transaction(read_only=True) as cur:
        cur.execute(
            "SELECT revision FROM receipts WHERE receipt_id = %s", (receipt_id,)
        )
        row = cur.fetchone()
        return row[0] if row else None


def _verify_revocation_offline(document, keys_doc):
    """In-process equivalent of the tool's revocation checks."""
    fields = revocations.parse_payload(document["payload"])
    entry = next(k for k in keys_doc["keys"] if k["key_id"] == fields["key_id"])
    pub = load_public_key(entry["public_key"])
    assert receipts.verify_payload_signature(
        pub, document["payload"], document["signature"]
    )
    return fields


# ---------------------------------------------------------------------------
# Revocation command
# ---------------------------------------------------------------------------


def test_revoke_receipt_happy_path(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rv1", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rv1", "rv-1")
    rid = receipt["receipt_id"]

    effective = int(time.time()) - 30
    r = _revoke(
        client,
        rid,
        admin_headers,
        reason="signer key compromised",
        effective_at=effective,
        command_id="cmd-1",
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "revoked"
    assert body["receipt_id"] == rid
    assert body["idempotent_replay"] is False

    doc = body["revocation"]
    fields = revocations.parse_payload(doc["payload"])
    assert fields["revocation_id"] == doc["revocation_id"]
    assert fields["revocation_seq"] == 1
    assert fields["receipt_id"] == rid
    assert fields["receipt_revision"] == 1
    assert fields["reason"] == "signer key compromised"
    assert fields["effective_at"] == effective == doc["effective_at_unix"]
    assert fields["command_id"] == "cmd-1"
    assert fields["prev_seq"] == 0
    assert fields["prev_payload_sha256"] is None
    assert doc["payload_sha256"] == revocations.payload_sha256(doc["payload"])

    # The receipt revision was bumped atomically with the record.
    assert _receipt_revision(rid) == 1
    assert _revocation_count() == 1

    # The record verifies offline against the published server key.
    keys_doc = client.get("/receipts/keys").json()
    _verify_revocation_offline(doc, keys_doc)

    # The original receipt query is unchanged by the revocation.
    assert client.get(f"/receipts/{rid}").json() == receipt

    # The record is also directly fetchable.
    fetched = client.get(f"/receipts/{rid}/revocation")
    assert fetched.status_code == 200
    assert fetched.json() == doc


def test_revoke_unknown_receipt_404(client, admin_headers):
    r = _revoke(client, "no-such-receipt", admin_headers)
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "receipt_unknown"
    assert _revocation_count() == 0


def test_revoke_requires_admin_token(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rvauth", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rvauth", "rv-auth")
    rid = receipt["receipt_id"]

    assert _revoke(client, rid, {}).status_code == 401
    assert (
        _revoke(client, rid, {"X-Admin-Token": "wrong"}).status_code == 401
    )
    assert _revocation_count() == 0
    assert _receipt_revision(rid) == 0


def test_revoke_rejects_invalid_command_body(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rvbad", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rvbad", "rv-bad")
    rid = receipt["receipt_id"]

    # Missing reason / expected_revision, negative revision, bad effective_at.
    for body in (
        {"effective_at": 1, "expected_revision": 0},
        {"reason": "x", "effective_at": 1},
        {"reason": "x", "effective_at": 1, "expected_revision": -1},
        {"reason": "", "effective_at": 1, "expected_revision": 0},
        {"reason": "x", "effective_at": "not-a-time", "expected_revision": 0},
    ):
        r = client.post(
            f"/admin/receipts/{rid}/revoke", json=body, headers=admin_headers
        )
        assert r.status_code == 400, (body, r.text)
        assert r.json()["reason"] == "bad_request"
    assert _revocation_count() == 0


def test_revoke_effective_at_accepts_iso8601(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rviso", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rviso", "rv-iso")
    rid = receipt["receipt_id"]

    r = _revoke(
        client,
        rid,
        admin_headers,
        effective_at="2026-09-29T08:00:00+02:00",  # 06:00 UTC
    )
    assert r.status_code == 201, r.text
    doc = r.json()["revocation"]
    # 2026-09-29T06:00:00Z in unix seconds:
    import calendar

    expected = calendar.timegm((2026, 9, 29, 6, 0, 0))
    assert doc["effective_at_unix"] == expected


# ---------------------------------------------------------------------------
# Idempotency and conflicts
# ---------------------------------------------------------------------------


def test_revoke_idempotent_replay_with_command_id(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-ridem", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-ridem", "rv-idem")
    rid = receipt["receipt_id"]

    command = dict(reason="compromised", effective_at=1700000000,
                   expected_revision=0, command_id="cmd-xyz")
    first = _revoke(client, rid, admin_headers, **command)
    assert first.status_code == 201

    replay = _revoke(client, rid, admin_headers, **command)
    assert replay.status_code == 200
    assert replay.json()["idempotent_replay"] is True
    assert replay.json()["revocation"] == first.json()["revocation"]
    assert _revocation_count() == 1
    assert _receipt_revision(rid) == 1


def test_revoke_idempotent_replay_without_command_id(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-ridem2", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-ridem2", "rv-idem2")
    rid = receipt["receipt_id"]

    command = dict(reason="compromised", effective_at=1700000000,
                   expected_revision=0)
    first = _revoke(client, rid, admin_headers, **command)
    assert first.status_code == 201
    replay = _revoke(client, rid, admin_headers, **command)
    assert replay.status_code == 200
    assert replay.json()["revocation"]["revocation_id"] == \
        first.json()["revocation"]["revocation_id"]
    assert _revocation_count() == 1


def test_revoke_conflicting_command_rejected(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rconf", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rconf", "rv-conf")
    rid = receipt["receipt_id"]

    first = _revoke(client, rid, admin_headers, reason="compromised",
                    effective_at=1700000000, command_id="cmd-a")
    assert first.status_code == 201

    # Different reason, different effective_at, different command id, and a
    # reused command id with different parameters are all conflicts.
    for overrides in (
        dict(reason="other reason", effective_at=1700000000, command_id="cmd-a"),
        dict(reason="compromised", effective_at=1700000001, command_id="cmd-a"),
        dict(reason="compromised", effective_at=1700000000, command_id="cmd-b"),
        dict(reason="compromised", effective_at=1700000000),
    ):
        r = _revoke(client, rid, admin_headers, **overrides)
        assert r.status_code == 409, (overrides, r.text)
        detail = r.json()["detail"]
        assert detail["reason"] == "revocation_conflict"
        # The conflict response carries the record that won.
        assert detail["revocation"]["revocation_id"] == \
            first.json()["revocation"]["revocation_id"]

    assert _revocation_count() == 1
    assert _receipt_revision(rid) == 1


def test_revoke_expected_revision_mismatch(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rrev", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rrev", "rv-rev")
    rid = receipt["receipt_id"]

    r = _revoke(client, rid, admin_headers, expected_revision=7)
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["reason"] == "revocation_revision_conflict"
    assert detail["current_revision"] == 0
    assert _revocation_count() == 0
    assert _receipt_revision(rid) == 0

    # The correct revision still works afterwards.
    assert _revoke(client, rid, admin_headers).status_code == 201


def test_concurrent_identical_commands_yield_single_record(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rconc", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rconc", "rv-conc")
    rid = receipt["receipt_id"]

    command = dict(reason="compromised", effective_at=1700000000,
                   expected_revision=0, command_id="cmd-race")
    results = []
    lock = threading.Lock()

    def worker():
        r = _revoke(client, rid, admin_headers, **command)
        with lock:
            results.append((r.status_code, r.json()))

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    created = [b for code, b in results if code == 201]
    replayed = [b for code, b in results if code == 200]
    assert len(created) == 1
    assert len(replayed) == 11
    ids = {b["revocation"]["revocation_id"] for b in created + replayed}
    assert len(ids) == 1
    assert _revocation_count() == 1
    assert _receipt_revision(rid) == 1


def test_concurrent_distinct_commands_exactly_one_wins(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rconc2", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rconc2", "rv-conc2")
    rid = receipt["receipt_id"]

    results = []
    lock = threading.Lock()

    def worker(i):
        r = _revoke(
            client, rid, admin_headers,
            reason=f"reason-{i}", effective_at=1700000000 + i,
            expected_revision=0, command_id=f"cmd-race-{i}",
        )
        with lock:
            results.append(r.status_code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(201) == 1
    assert results.count(409) == 9
    assert _revocation_count() == 1
    assert _receipt_revision(rid) == 1


# ---------------------------------------------------------------------------
# Audit chain
# ---------------------------------------------------------------------------


def test_audit_chain_links_records_in_order(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rchain", pub, admin_headers)
    docs = []
    for i in range(3):
        receipt, _ = _accept(client, priv, "k-rchain", f"rv-chain-{i}")
        r = _revoke(client, receipt["receipt_id"], admin_headers,
                    reason=f"reason {i}", effective_at=1700000000 + i)
        assert r.status_code == 201, r.text
        docs.append(r.json()["revocation"])

    assert [d["revocation_seq"] for d in docs] == [1, 2, 3]
    assert docs[0]["prev_seq"] is None
    assert docs[0]["prev_payload_sha256"] is None
    for prev, cur in zip(docs, docs[1:]):
        assert cur["prev_seq"] == prev["revocation_seq"]
        assert cur["prev_payload_sha256"] == prev["payload_sha256"]

    # The public chain endpoint agrees, head included.
    chain = client.get("/revocations").json()
    assert chain["head_seq"] == 3
    assert chain["head_payload_sha256"] == docs[-1]["payload_sha256"]
    assert [d["revocation_id"] for d in chain["revocations"]] == \
        [d["revocation_id"] for d in docs]

    # Every record verifies offline against the published keys.
    keys_doc = client.get("/receipts/keys").json()
    for doc in chain["revocations"]:
        _verify_revocation_offline(doc, keys_doc)


def test_concurrent_revocations_keep_chain_gapless(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rconc3", pub, admin_headers)
    receipts_out = []
    for i in range(8):
        receipt, _ = _accept(client, priv, "k-rconc3", f"rv-gap-{i}")
        receipts_out.append(receipt["receipt_id"])

    barrier = threading.Barrier(8)
    errors = []

    def worker(rid, i):
        try:
            barrier.wait(timeout=10)
            r = _revoke(client, rid, admin_headers,
                        reason=f"r{i}", effective_at=1700000000,
                        expected_revision=0, command_id=f"gap-{i}")
            assert r.status_code == 201, r.text
        except Exception as exc:  # pragma: no cover - failure diagnostics
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(rid, i))
        for i, rid in enumerate(receipts_out)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    chain = client.get("/revocations").json()["revocations"]
    assert len(chain) == 8
    seqs = [d["revocation_seq"] for d in chain]
    assert seqs == list(range(1, 9))  # gapless, totally ordered
    prev = None
    for doc in chain:
        expected = prev["payload_sha256"] if prev else None
        assert doc["prev_payload_sha256"] == expected
        prev = doc


def test_revocation_records_are_immutable(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rimmut", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rimmut", "rv-immut")
    assert _revoke(client, receipt["receipt_id"], admin_headers).status_code == 201

    with pytest.raises(Exception):
        with db.transaction() as cur:
            cur.execute(
                "UPDATE receipt_revocations SET reason = 'tampered'"
            )
    with pytest.raises(Exception):
        with db.transaction() as cur:
            cur.execute("DELETE FROM receipt_revocations")
    # Nothing changed.
    assert _revocation_count() == 1


def test_revocation_issuance_failure_rolls_back(client, admin_headers, monkeypatch):
    priv, pub = generate_ed25519()
    _register(client, "k-rfail", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rfail", "rv-fail")
    rid = receipt["receipt_id"]

    def broken_sign(*args, **kwargs):
        raise RuntimeError("simulated signing failure")

    monkeypatch.setattr(receipts, "sign_payload", broken_sign)
    r = _revoke(client, rid, admin_headers)
    assert r.status_code == 500
    assert r.json()["reason"] == "revocation_issuance_failed"

    # Nothing persisted: no record, revision untouched, retry succeeds.
    assert _revocation_count() == 0
    assert _receipt_revision(rid) == 0
    monkeypatch.undo()
    assert _revoke(client, rid, admin_headers).status_code == 201
    assert _receipt_revision(rid) == 1


# ---------------------------------------------------------------------------
# Point-in-time status
# ---------------------------------------------------------------------------


def test_status_transitions_and_point_in_time(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rstat", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rstat", "rv-stat")
    rid = receipt["receipt_id"]

    # Valid before any revocation; the receipt's own issuance time is known.
    now = int(time.time())
    r = client.get(f"/receipts/{rid}/status")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "valid"
    assert body["revision"] == 0
    assert body["revocation"] is None
    issued_at = body["issued_at_unix"]
    assert issued_at <= now

    # Unknown for a receipt id that does not exist (HTTP 200, tristate).
    r = client.get("/receipts/no-such-receipt/status")
    assert r.status_code == 200
    assert r.json()["status"] == "unknown"

    # Unknown before the receipt existed.
    r = client.get(f"/receipts/{rid}/status", params={"at": issued_at - 10})
    assert r.json()["status"] == "unknown"

    # Revoke with effect one hour in the future.
    effective = now + 3600
    r = _revoke(client, rid, admin_headers, reason="scheduled",
                effective_at=effective)
    assert r.status_code == 201

    # Now (before the effective time) the receipt still reads valid...
    r = client.get(f"/receipts/{rid}/status")
    body = r.json()
    assert body["status"] == "valid"
    assert body["revision"] == 1  # current revision already bumped
    assert body["revocation"] is None

    # ...but at/after effective_at it reads revoked, with the signed proof.
    r = client.get(f"/receipts/{rid}/status", params={"at": effective})
    body = r.json()
    assert body["status"] == "revoked"
    proof = body["revocation"]
    assert proof["receipt_id"] == rid
    keys_doc = client.get("/receipts/keys").json()
    _verify_revocation_offline(proof, keys_doc)

    # ISO-8601 timestamps work for `at` too.
    r = client.get(
        f"/receipts/{rid}/status",
        params={"at": "2999-01-01T00:00:00Z"},
    )
    assert r.json()["status"] == "revoked"
    r = client.get(
        f"/receipts/{rid}/status",
        params={"at": "2000-01-01T00:00:00+00:00"},
    )
    assert r.json()["status"] == "unknown"


def test_status_rejects_malformed_at(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rbadat", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rbadat", "rv-badat")
    r = client.get(
        f"/receipts/{receipt['receipt_id']}/status", params={"at": "tomorrow"}
    )
    assert r.status_code == 400
    assert r.json()["detail"]["reason"] == "bad_request"


def test_get_revocation_404_when_not_revoked(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-r404", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-r404", "rv-404")
    rid = receipt["receipt_id"]

    r = client.get(f"/receipts/{rid}/revocation")
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "revocation_unknown"
    r = client.get("/receipts/no-such/revocation")
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "receipt_unknown"


def test_revocation_endpoints_are_public(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rpub", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rpub", "rv-pub")
    rid = receipt["receipt_id"]
    assert _revoke(client, rid, admin_headers).status_code == 201

    # No X-Admin-Token on any of these.
    assert client.get(f"/receipts/{rid}/status").status_code == 200
    assert client.get(f"/receipts/{rid}/revocation").status_code == 200
    chain = client.get("/revocations")
    assert chain.status_code == 200
    for doc in chain.json()["revocations"]:
        assert "private_key" not in doc


# ---------------------------------------------------------------------------
# Consistency across restart; existing behaviour preserved
# ---------------------------------------------------------------------------


def test_pre_revocation_database_upgrades_smoothly(client, admin_headers):
    """A database from the pre-revocation era (receipts without a revision
    column, no receipt_revocations table) is upgraded by the idempotent
    schema bootstrap, and revocation works on it immediately."""
    priv, pub = generate_ed25519()
    _register(client, "k-rupg", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rupg", "rv-upg")
    rid = receipt["receipt_id"]

    # Simulate the old schema.
    with db.transaction() as cur:
        cur.execute("DROP TABLE receipt_revocations")
        cur.execute("ALTER TABLE receipts DROP COLUMN revision")

    # Re-run the schema bootstrap, as an upgraded app would on startup.
    with db.transaction() as cur:
        cur.execute(db.SCHEMA)

    # The pre-existing receipt survived with revision 0 and can be revoked.
    assert _receipt_revision(rid) == 0
    assert client.get(f"/receipts/{rid}").json() == receipt
    r = _revoke(client, rid, admin_headers)
    assert r.status_code == 201, r.text
    assert r.json()["revocation"]["revocation_seq"] == 1
    assert client.get(f"/receipts/{rid}/status").json()["status"] == "revoked"


def test_revocation_and_status_survive_restart(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rpersist", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rpersist", "rv-persist")
    rid = receipt["receipt_id"]
    assert _revoke(client, rid, admin_headers, command_id="cmd-p").status_code == 201

    # Pin `at` so both sides of the restart ask the identical question.
    at = str(int(time.time()) + 3600)
    before_status = client.get(f"/receipts/{rid}/status", params={"at": at}).json()
    before_chain = client.get("/revocations").json()
    before_revocation = client.get(f"/receipts/{rid}/revocation").json()

    # Simulate an application restart: close the pool and reconnect.
    db.close()
    db.connect()

    assert client.get(f"/receipts/{rid}/status", params={"at": at}).json() == before_status
    assert client.get("/revocations").json() == before_chain
    assert client.get(f"/receipts/{rid}/revocation").json() == before_revocation

    # The idempotent replay still returns the original record after restart.
    r = _revoke(client, rid, admin_headers, reason="signer key compromised",
                effective_at=int(time.time()) - 60, expected_revision=0,
                command_id="cmd-p")
    assert r.status_code == 200
    assert r.json()["revocation"]["revocation_id"] == \
        before_revocation["revocation_id"]


def test_verify_replay_and_receipt_query_unaffected_by_revocation(
    client, admin_headers
):
    priv, pub = generate_ed25519()
    _register(client, "k-rkeep", pub, admin_headers)
    payload = _signed(priv, keyid="k-rkeep", nonce="rv-keep")
    body = {k: v for k, v in payload.items() if not k.startswith("_")}

    first = client.post("/verify", json=body)
    assert first.status_code == 200
    receipt = first.json()["receipt"]
    rid = receipt["receipt_id"]

    assert _revoke(client, rid, admin_headers).status_code == 201

    # Replay protection is unchanged: the same payload is still a replay.
    replay = client.post("/verify", json=body)
    assert replay.status_code == 409
    assert replay.json()["reason"] == "replayed"

    # Shadow verification still works and issues nothing.
    active = client.get("/admin/policy", headers=admin_headers).json()
    shadow = client.post(
        "/verify-shadow", json={**body, "policy_version": active["version"]}
    )
    assert shadow.status_code == 200
    assert shadow.json()["nonce_seen"] is True
    assert shadow.json()["receipt"] is None

    # The original receipt query returns the exact same document.
    assert client.get(f"/receipts/{rid}").json() == receipt


def test_revocation_signed_by_retired_key_still_verifies(client, admin_headers):
    priv, pub = generate_ed25519()
    _register(client, "k-rrot", pub, admin_headers)
    receipt, _ = _accept(client, priv, "k-rrot", "rv-rot")
    rid = receipt["receipt_id"]

    r = _revoke(client, rid, admin_headers)
    doc = r.json()["revocation"]
    assert doc["key_id"] == "receipt-signing#1"

    # Rotate the server signing key; the old revocation must still verify.
    assert client.post(
        "/admin/receipt-keys/rotate", headers=admin_headers
    ).status_code == 201
    keys_doc = client.get("/receipts/keys").json()
    _verify_revocation_offline(doc, keys_doc)

    # New revocations use the new key version.
    receipt2, _ = _accept(client, priv, "k-rrot", "rv-rot-2")
    r2 = _revoke(client, receipt2["receipt_id"], admin_headers)
    assert r2.json()["revocation"]["key_id"] == "receipt-signing#2"
    _verify_revocation_offline(r2.json()["revocation"], keys_doc)


# ---------------------------------------------------------------------------
# Canonical revocation payload unit behaviour
# ---------------------------------------------------------------------------


def test_revocation_payload_round_trip_and_strictness():
    payload = revocations.build_payload(
        revocation_id="rev-1",
        revocation_seq=2,
        receipt_id="rcpt-1",
        receipt_revision=1,
        reason="compromised",
        effective_at=1790101132,
        revoked_at=1790101200,
        key_id="receipt-signing#1",
        command_id="cmd-1",
        prev_seq=1,
        prev_payload_sha256="ab" * 32,
    )
    fields = revocations.parse_payload(payload)
    assert fields["revocation_id"] == "rev-1"
    assert fields["revocation_seq"] == 2
    assert fields["prev_seq"] == 1
    assert fields["command_id"] == "cmd-1"

    # Reordering, dropping a field, a wrong version, or a broken chain link
    # are all rejected.
    lines = payload.split("\n")
    swapped = "\n".join([lines[0], lines[2], lines[1], *lines[3:]])
    with pytest.raises(revocations.RevocationFormatError):
        revocations.parse_payload(swapped)
    with pytest.raises(revocations.RevocationFormatError):
        revocations.parse_payload("\n".join(lines[:-1]))
    with pytest.raises(revocations.RevocationFormatError):
        revocations.parse_payload(payload.replace("revocation/v1", "revocation/v2", 1))
    with pytest.raises(revocations.RevocationFormatError):
        revocations.parse_payload(
            payload.replace("prev_seq: 1", "prev_seq: 0", 1)
        )

    # Genesis record: prev fields are both empty.
    genesis = revocations.build_payload(
        revocation_id="rev-0",
        revocation_seq=1,
        receipt_id="rcpt-0",
        receipt_revision=1,
        reason="r",
        effective_at=1,
        revoked_at=1,
        key_id="receipt-signing#1",
        command_id=None,
        prev_seq=0,
        prev_payload_sha256=None,
    )
    fields = revocations.parse_payload(genesis)
    assert fields["prev_seq"] == 0
    assert fields["prev_payload_sha256"] is None
    assert fields["command_id"] is None


# ---------------------------------------------------------------------------
# Standalone offline verifier tool: receipts + revocations + chain
# ---------------------------------------------------------------------------


def _run_tool(*args):
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
    )


def test_offline_tool_verifies_revocation_and_chain(client, admin_headers, tmp_path):
    priv, pub = generate_ed25519()
    _register(client, "k-rtool", pub, admin_headers)

    # Two receipts, both revoked, so the chain has two linked records.  The
    # effective time is slightly in the future so that `--at` values exist on
    # both sides of it while staying after the receipts' issuance.
    receipt_a, _ = _accept(client, priv, "k-rtool", "rv-tool-a")
    receipt_b, _ = _accept(client, priv, "k-rtool", "rv-tool-b")
    effective = int(time.time()) + 60
    rev_a = _revoke(client, receipt_a["receipt_id"], admin_headers,
                    reason="compromised", effective_at=effective).json()
    rev_b = _revoke(client, receipt_b["receipt_id"], admin_headers,
                    reason="superseded", effective_at=effective).json()

    keys_file = tmp_path / "keys.json"
    keys_file.write_text(json.dumps(client.get("/receipts/keys").json()))
    chain_file = tmp_path / "chain.json"
    chain_file.write_text(json.dumps(client.get("/revocations").json()))
    receipt_file = tmp_path / "receipt.json"
    receipt_file.write_text(json.dumps(receipt_a))
    revocation_file = tmp_path / "revocation.json"
    revocation_file.write_text(json.dumps(rev_a["revocation"]))
    # A full status response is accepted as the revocation document too
    # (queried at a moment when the revocation is already effective).
    status_file = tmp_path / "status.json"
    status_file.write_text(
        json.dumps(
            client.get(
                f"/receipts/{receipt_a['receipt_id']}/status",
                params={"at": effective + 5},
            ).json()
        )
    )

    # Receipt + revocation + chain, with --at after the effective time.
    proc = _run_tool(
        "--receipt", str(receipt_file),
        "--keys", str(keys_file),
        "--revocation", str(revocation_file),
        "--chain", str(chain_file),
        "--at", str(effective + 5),
    )
    assert proc.returncode == 0, proc.stderr
    assert "verified offline" in proc.stdout

    # The status-response form works as well.
    proc = _run_tool(
        "--receipt", str(receipt_file),
        "--keys", str(keys_file),
        "--revocation", str(status_file),
    )
    assert proc.returncode == 0, proc.stderr

    # Tampered revocation payload -> signature failure.
    tampered = dict(rev_a["revocation"])
    tampered["payload"] = tampered["payload"].replace(
        "compromised", "compromissee", 1
    )
    tampered_file = tmp_path / "tampered.json"
    tampered_file.write_text(json.dumps(tampered))
    proc = _run_tool(
        "--receipt", str(receipt_file),
        "--keys", str(keys_file),
        "--revocation", str(tampered_file),
    )
    assert proc.returncode == 1
    assert "INVALID" in proc.stderr

    # Cross-receipt reuse: receipt B's proof must not validate receipt A.
    other_rev_file = tmp_path / "other_rev.json"
    other_rev_file.write_text(json.dumps(rev_b["revocation"]))
    proc = _run_tool(
        "--receipt", str(receipt_file),
        "--keys", str(keys_file),
        "--revocation", str(other_rev_file),
    )
    assert proc.returncode == 1
    assert "cross-receipt" in proc.stderr

    # Time rollback: --at before effective_at must fail.
    proc = _run_tool(
        "--receipt", str(receipt_file),
        "--keys", str(keys_file),
        "--revocation", str(revocation_file),
        "--at", str(effective - 5),
    )
    assert proc.returncode == 1
    assert "time rollback" in proc.stderr

    # A broken chain (record dropped) must fail.
    broken_chain = client.get("/revocations").json()
    broken_chain["revocations"] = broken_chain["revocations"][:1]
    broken_file = tmp_path / "broken_chain.json"
    broken_file.write_text(json.dumps(broken_chain))
    proc = _run_tool(
        "--receipt", str(receipt_file),
        "--keys", str(keys_file),
        "--revocation", str(revocation_file),
        "--chain", str(broken_file),
    )
    assert proc.returncode == 1

    # A tampered chain link must fail.
    tampered_chain = client.get("/revocations").json()
    tampered_chain["revocations"][1]["payload"] = tampered_chain["revocations"][1][
        "payload"
    ].replace("superseded", "superseded!", 1)
    tampered_chain_file = tmp_path / "tampered_chain.json"
    tampered_chain_file.write_text(json.dumps(tampered_chain))
    proc = _run_tool(
        "--receipt", str(receipt_file),
        "--keys", str(keys_file),
        "--chain", str(tampered_chain_file),
    )
    assert proc.returncode == 1
