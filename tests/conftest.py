"""Pytest fixtures: bring up an embedded PostgreSQL and an isolated schema."""
from __future__ import annotations

import os
import tempfile

# ---------------------------------------------------------------------------
# Point the application at an embedded postgres BEFORE importing app modules.
# ---------------------------------------------------------------------------
if "DATABASE_URL" not in os.environ:
    import pgserver

    _PGDATA = tempfile.mkdtemp(prefix="hss-pg-")
    _server = pgserver.get_server(_PGDATA)
    _uri = _server.get_uri()  # postgresql://postgres:@/postgres?host=<dir>
    _host = _uri.split("host=")[-1]
    try:
        _server.psql("CREATE ROLE hss LOGIN PASSWORD 'hss' SUPERUSER;")
    except Exception:
        pass
    try:
        _server.psql("CREATE DATABASE hss OWNER hss;")
    except Exception:
        pass
    os.environ["DATABASE_URL"] = f"postgresql://hss:hss@/hss?host={_host}"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import db  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _database():
    db.connect()
    yield
    db.close()


@pytest.fixture(autouse=True)
def _clean_tables():
    with db.transaction() as cur:
        cur.execute(
            "TRUNCATE used_nonces, signer_keys, verify_policy, policy_versions, "
            "receipts, receipt_keys, receipt_revocations, audit_events "
            "RESTART IDENTITY"
        )
        db._seed_initial_policy(cur)
        db.ensure_receipt_signing_key(cur)
    yield


@pytest.fixture
def client():
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin_headers():
    return {"X-Admin-Token": os.environ.get("ADMIN_TOKEN", "admin-secret")}
