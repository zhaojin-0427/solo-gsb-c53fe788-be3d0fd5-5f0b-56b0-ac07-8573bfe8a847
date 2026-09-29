"""PostgreSQL access: schema, key registry, policy, replay protection, receipts."""
from __future__ import annotations

import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, Optional, Tuple

import psycopg2
from psycopg2 import pool as pg_pool
from psycopg2.errors import UniqueViolation
from psycopg2.extras import Json

from . import config, receipts, revocations
from .crypto import (
    generate_ed25519,
    load_private_key,
    private_key_pem,
    public_key_pem,
    spki_fingerprint,
)


class ReplayDetected(Exception):
    """Raised when a (keyid, nonce) pair has already been accepted."""


class ReceiptIssuanceError(Exception):
    """Raised when receipt signing/persistence fails.

    The caller's transaction — including the nonce claim — must roll back
    as a whole, so no acceptance state and no partial receipt survive.
    """


class PolicyVersionNotFound(Exception):
    """Raised when a requested policy version does not exist."""

    def __init__(self, version: int):
        super().__init__(f"policy version {version} does not exist")
        self.version = version


class PolicyActivationConflict(Exception):
    """Raised when an atomic activation loses an optimistic-concurrency race."""

    def __init__(self, message: str, *, active_version: int):
        super().__init__(message)
        self.active_version = active_version


class PolicyDraftNotActivatable(Exception):
    """Raised when activation targets a version that is not a draft."""

    def __init__(self, version: int, status: str):
        super().__init__(
            f"policy version {version} is {status!r}, only drafts can be activated"
        )
        self.version = version
        self.status = status


class ReceiptUnknown(Exception):
    """Raised when a revocation targets a receipt id that does not exist."""

    def __init__(self, receipt_id: str):
        super().__init__(f"receipt {receipt_id!r} does not exist")
        self.receipt_id = receipt_id


class RevocationConflict(Exception):
    """Raised when the receipt is already revoked by a *different* command."""

    def __init__(self, message: str, *, revocation: Dict[str, Any]):
        super().__init__(message)
        self.revocation = revocation


class RevocationRevisionConflict(Exception):
    """Raised when ``expected_revision`` does not match the receipt revision."""

    def __init__(self, message: str, *, current_revision: int):
        super().__init__(message)
        self.current_revision = current_revision


class RevocationIssuanceError(Exception):
    """Raised when revocation signing/persistence fails.

    The caller's transaction — including the receipt revision bump — rolls
    back as a whole, so no partial revocation state survives and the command
    can be retried safely.
    """


_pool: Optional[pg_pool.ThreadedConnectionPool] = None
_pool_lock = threading.Lock()

# The policy fields shared by every policy snapshot.
POLICY_FIELDS = (
    "required_components",
    "required_algorithms",
    "clock_skew_seconds",
    "max_age_seconds",
    "require_created",
    "require_nonce",
    "require_content_digest_with_body",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS signer_keys (
    id          BIGSERIAL PRIMARY KEY,
    keyid       TEXT NOT NULL,
    version     INTEGER NOT NULL,
    public_key  TEXT NOT NULL,
    key_kind    TEXT NOT NULL CHECK (key_kind IN ('ed25519', 'rsa')),
    fingerprint TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (keyid, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS signer_keys_active_uidx
    ON signer_keys (keyid) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS signer_keys_keyid_idx
    ON signer_keys (keyid, version DESC);

CREATE TABLE IF NOT EXISTS verify_policy (
    id                      INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    required_components     JSONB NOT NULL,
    required_algorithms     JSONB NOT NULL,
    clock_skew_seconds      INTEGER NOT NULL,
    max_age_seconds         INTEGER NOT NULL,
    require_created         BOOLEAN NOT NULL,
    require_nonce           BOOLEAN NOT NULL,
    require_content_digest_with_body BOOLEAN NOT NULL,
    active_version          INTEGER NOT NULL DEFAULT 1,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Idempotent upgrade for databases created before policy versioning.
ALTER TABLE verify_policy
    ADD COLUMN IF NOT EXISTS active_version INTEGER NOT NULL DEFAULT 1;

-- Immutable, versioned verification-policy snapshots.
CREATE TABLE IF NOT EXISTS policy_versions (
    id                      BIGSERIAL PRIMARY KEY,
    version                 INTEGER NOT NULL UNIQUE,
    status                  TEXT NOT NULL CHECK (status IN ('draft', 'active', 'retired')),
    baseline_version        INTEGER,
    required_components     JSONB NOT NULL,
    required_algorithms     JSONB NOT NULL,
    clock_skew_seconds      INTEGER NOT NULL,
    max_age_seconds         INTEGER NOT NULL,
    require_created         BOOLEAN NOT NULL,
    require_nonce           BOOLEAN NOT NULL,
    require_content_digest_with_body BOOLEAN NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at            TIMESTAMPTZ
);
-- At most one active policy version, enforced by the database itself.
CREATE UNIQUE INDEX IF NOT EXISTS policy_versions_active_uidx
    ON policy_versions ((status)) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS policy_versions_status_idx
    ON policy_versions (status, version DESC);

CREATE TABLE IF NOT EXISTS used_nonces (
    id          BIGSERIAL PRIMARY KEY,
    keyid       TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (keyid, nonce)
);
CREATE INDEX IF NOT EXISTS used_nonces_seen_idx ON used_nonces (seen_at);

-- Server-side Ed25519 receipt-signing keys (versioned; private keys never
-- leave the database and are never exposed by any API).
CREATE TABLE IF NOT EXISTS receipt_keys (
    id          BIGSERIAL PRIMARY KEY,
    keyid       TEXT NOT NULL,
    version     INTEGER NOT NULL,
    public_key  TEXT NOT NULL,
    private_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at  TIMESTAMPTZ,
    UNIQUE (keyid, version)
);
-- At most one active receipt-signing key, enforced by the database itself.
CREATE UNIQUE INDEX IF NOT EXISTS receipt_keys_active_uidx
    ON receipt_keys (keyid) WHERE enabled = TRUE;

-- Acceptance receipts: the signed canonical payload is the source of truth;
-- the remaining columns are lookup conveniences.
CREATE TABLE IF NOT EXISTS receipts (
    id           BIGSERIAL PRIMARY KEY,
    receipt_id   TEXT NOT NULL UNIQUE,
    key_id       TEXT NOT NULL,
    payload      TEXT NOT NULL,
    signature    TEXT NOT NULL,
    input_digest TEXT NOT NULL,
    signer_keyid TEXT NOT NULL,
    nonce        TEXT,
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS receipts_issued_idx ON receipts (issued_at);
CREATE INDEX IF NOT EXISTS receipts_signer_nonce_idx
    ON receipts (signer_keyid, nonce);
-- Idempotent upgrade for databases created before receipt revocation:
-- a per-receipt optimistic-concurrency revision (0 = issued, 1 = revoked).
ALTER TABLE receipts
    ADD COLUMN IF NOT EXISTS revision INTEGER NOT NULL DEFAULT 0;

-- Immutable, sequenced revocation records forming a hash-chained audit log.
-- Each record links to its predecessor via prev_payload_sha256; the chain is
-- allocated under an advisory lock so concurrent revocations stay gapless.
CREATE TABLE IF NOT EXISTS receipt_revocations (
    id                  BIGSERIAL PRIMARY KEY,
    revocation_id       TEXT NOT NULL UNIQUE,
    revocation_seq      BIGINT NOT NULL UNIQUE,
    receipt_id          TEXT NOT NULL UNIQUE REFERENCES receipts (receipt_id),
    command_id          TEXT,
    expected_revision   INTEGER NOT NULL,
    receipt_revision    INTEGER NOT NULL,
    reason              TEXT NOT NULL,
    effective_at        TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    key_id              TEXT NOT NULL,
    prev_payload_sha256 TEXT,
    payload             TEXT NOT NULL,
    payload_sha256      TEXT NOT NULL,
    signature           TEXT NOT NULL
);
-- At most one revocation per idempotency key, enforced by the database.
CREATE UNIQUE INDEX IF NOT EXISTS receipt_revocations_command_uidx
    ON receipt_revocations (command_id) WHERE command_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS receipt_revocations_seq_idx
    ON receipt_revocations (revocation_seq);

-- Revocation records are immutable: the database itself rejects changes.
CREATE OR REPLACE FUNCTION reject_revocation_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'receipt_revocations rows are immutable';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS receipt_revocations_immutable ON receipt_revocations;
CREATE TRIGGER receipt_revocations_immutable
    BEFORE UPDATE OR DELETE ON receipt_revocations
    FOR EACH ROW EXECUTE FUNCTION reject_revocation_mutation();
"""

DEFAULT_POLICY: Dict[str, Any] = {
    "required_components": list(config.DEFAULT_REQUIRED_COMPONENTS),
    "required_algorithms": list(config.DEFAULT_REQUIRED_ALGORITHMS),
    "clock_skew_seconds": config.DEFAULT_CLOCK_SKEW_SECONDS,
    "max_age_seconds": config.DEFAULT_MAX_AGE_SECONDS,
    "require_created": True,
    "require_nonce": True,
    "require_content_digest_with_body": True,
}


def connect() -> None:
    global _pool
    with _pool_lock:
        if _pool is not None:
            return
        last_exc = None
        for attempt in range(config.DB_CONNECT_RETRIES):
            try:
                _pool = pg_pool.ThreadedConnectionPool(
                    minconn=1, maxconn=20, dsn=config.DATABASE_URL
                )
                break
            except psycopg2.Error as exc:
                last_exc = exc
                time.sleep(config.DB_CONNECT_DELAY)
        else:  # pragma: no cover - startup path only
            raise RuntimeError(
                f"could not connect to database after {config.DB_CONNECT_RETRIES} attempts: {last_exc}"
            )

        conn = _pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(SCHEMA)
                _seed_initial_policy(cur)
                ensure_receipt_signing_key(cur)
            conn.commit()
        finally:
            _pool.putconn(conn)


def close() -> None:
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.closeall()
            _pool = None


@contextmanager
def transaction(read_only: bool = False) -> Iterator[Any]:
    """Yield a DB cursor inside a transaction; commit on success.

    ``read_only`` transactions may not mutate anything and always roll back,
    which is how shadow verification is guaranteed to leave no trace.
    """
    if _pool is None:
        connect()
    assert _pool is not None
    conn = _pool.getconn()
    try:
        if read_only:
            conn.set_session(readonly=True)
        with conn.cursor() as cur:
            yield cur
        if read_only:
            conn.rollback()
        else:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        if read_only:
            # Reset the connection before returning it to the pool.
            conn.set_session(readonly=False)
        _pool.putconn(conn)


# ---------------------------------------------------------------------------
# Signer keys
# ---------------------------------------------------------------------------


def register_key(
    keyid: str,
    public_key: str,
    key_kind: str,
    fingerprint: str,
) -> Dict[str, Any]:
    """Insert a new enabled version of ``keyid`` atomically.

    A unique partial index ensures there is at most one enabled version per
    keyid; re-registering first disables the previously enabled row and
    bumps the version, all in one transaction.
    """
    with transaction() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (keyid,))
        cur.execute(
            "UPDATE signer_keys SET enabled = FALSE WHERE keyid = %s AND enabled = TRUE",
            (keyid,),
        )
        cur.execute(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM signer_keys WHERE keyid = %s",
            (keyid,),
        )
        version = cur.fetchone()[0]
        cur.execute(
            """
            INSERT INTO signer_keys (keyid, version, public_key, key_kind, fingerprint, enabled)
            VALUES (%s, %s, %s, %s, %s, TRUE)
            RETURNING id, created_at
            """,
            (keyid, version, public_key, key_kind, fingerprint),
        )
        row = cur.fetchone()
        return {
            "keyid": keyid,
            "version": version,
            "key_kind": key_kind,
            "fingerprint": fingerprint,
            "enabled": True,
            "id": row[0],
            "created_at": row[1].isoformat(),
        }


def get_active_key(keyid: str, cur=None) -> Optional[Dict[str, Any]]:
    def _fetch(c):
        c.execute(
            """
            SELECT keyid, version, public_key, key_kind, fingerprint, enabled, created_at
            FROM signer_keys
            WHERE keyid = %s AND enabled = TRUE
            """,
            (keyid,),
        )
        row = c.fetchone()
        if row is None:
            return None
        return {
            "keyid": row[0],
            "version": row[1],
            "public_key": row[2],
            "key_kind": row[3],
            "fingerprint": row[4],
            "enabled": row[5],
            "created_at": row[6].isoformat(),
        }

    if cur is not None:
        return _fetch(cur)
    with transaction() as c:
        return _fetch(c)


def list_keys() -> list:
    with transaction() as cur:
        cur.execute(
            """
            SELECT keyid, version, key_kind, fingerprint, enabled, created_at
            FROM signer_keys
            ORDER BY keyid, version DESC
            """
        )
        return [
            {
                "keyid": r[0],
                "version": r[1],
                "key_kind": r[2],
                "fingerprint": r[3],
                "enabled": r[4],
                "created_at": r[5].isoformat(),
            }
            for r in cur.fetchall()
        ]


def set_key_enabled(keyid: str, enabled: bool) -> bool:
    with transaction() as cur:
        cur.execute(
            "UPDATE signer_keys SET enabled = %s WHERE keyid = %s AND enabled = TRUE",
            (enabled, keyid),
        )
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Policy
#
# The authoritative policy history lives in ``policy_versions`` (immutable
# snapshots).  ``verify_policy`` is a singleton mirror of the active version
# used by /verify; every activation updates both in one transaction.  Nothing
# is cached in process memory, so any app process — including after a restart
# — observes exactly the same policy.
# ---------------------------------------------------------------------------


def _seed_initial_policy(cur) -> None:
    """Create active policy version 1 and the singleton mirror on first boot.

    Safe to call repeatedly (e.g. from test fixtures): existing rows win.
    When an older database already has a ``verify_policy`` singleton but no
    version history, the live policy is snapshotted as active version 1.
    """
    cur.execute("SELECT to_regclass('policy_versions') IS NOT NULL")
    versions_table_exists = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM policy_versions") if versions_table_exists else None
    if versions_table_exists and cur.fetchone()[0] > 0:
        return

    cur.execute("SELECT COUNT(*) FROM verify_policy")
    has_live_policy = cur.fetchone()[0] > 0
    if has_live_policy:
        source = """
            SELECT required_components, required_algorithms,
                   clock_skew_seconds, max_age_seconds,
                   require_created, require_nonce,
                   require_content_digest_with_body
            FROM verify_policy WHERE id = 1
        """
    else:
        source = """
            SELECT %(required_components)s, %(required_algorithms)s,
                   %(clock_skew_seconds)s, %(max_age_seconds)s,
                   %(require_created)s, %(require_nonce)s,
                   %(require_content_digest_with_body)s
        """

    cur.execute(
        f"""
        INSERT INTO policy_versions (
            version, status, baseline_version,
            required_components, required_algorithms,
            clock_skew_seconds, max_age_seconds,
            require_created, require_nonce,
            require_content_digest_with_body,
            activated_at
        )
        SELECT 1, 'active', NULL,
               src.required_components::jsonb,
               src.required_algorithms::jsonb,
               src.clock_skew_seconds, src.max_age_seconds,
               src.require_created, src.require_nonce,
               src.require_content_digest_with_body, now()
        FROM ({source}) AS src(
            required_components, required_algorithms, clock_skew_seconds,
            max_age_seconds, require_created, require_nonce,
            require_content_digest_with_body
        )
        """,
        {
            **DEFAULT_POLICY,
            "required_components": Json(DEFAULT_POLICY["required_components"]),
            "required_algorithms": Json(DEFAULT_POLICY["required_algorithms"]),
        },
    )
    if not has_live_policy:
        cur.execute(
            """
            INSERT INTO verify_policy (
                id, required_components, required_algorithms,
                clock_skew_seconds, max_age_seconds,
                require_created, require_nonce,
                require_content_digest_with_body, active_version
            )
            SELECT 1,
                   %(required_components)s,
                   %(required_algorithms)s,
                   %(clock_skew_seconds)s,
                   %(max_age_seconds)s,
                   %(require_created)s,
                   %(require_nonce)s,
                   %(require_content_digest_with_body)s,
                   1
            """,
            {
                **DEFAULT_POLICY,
                "required_components": Json(DEFAULT_POLICY["required_components"]),
                "required_algorithms": Json(DEFAULT_POLICY["required_algorithms"]),
            },
        )
    else:
        # Existing singleton: just record which version it mirrors.
        cur.execute("UPDATE verify_policy SET active_version = 1 WHERE id = 1")


def _version_row_to_dict(r) -> Dict[str, Any]:
    # Column order matches _VERSION_SELECT.
    return {
        "version": r[0],
        "status": r[1],
        "required_components": r[2],
        "required_algorithms": r[3],
        "clock_skew_seconds": r[4],
        "max_age_seconds": r[5],
        "require_created": r[6],
        "require_nonce": r[7],
        "require_content_digest_with_body": r[8],
        "created_at": r[9].isoformat() if r[9] else None,
        "baseline_version": r[10],
        "activated_at": r[11].isoformat() if r[11] else None,
    }


_VERSION_SELECT = """
    SELECT version, status,
           required_components, required_algorithms, clock_skew_seconds,
           max_age_seconds, require_created, require_nonce,
           require_content_digest_with_body,
           created_at, baseline_version, activated_at
    FROM policy_versions
"""


def get_policy(cur=None) -> Dict[str, Any]:
    """Return the currently active policy (what /verify enforces)."""

    def _fetch(c):
        c.execute(
            """
            SELECT pv.required_components, pv.required_algorithms,
                   pv.clock_skew_seconds, pv.max_age_seconds,
                   pv.require_created, pv.require_nonce,
                   pv.require_content_digest_with_body,
                   pv.version, pv.activated_at
            FROM policy_versions pv
            WHERE pv.status = 'active'
            """
        )
        r = c.fetchone()
        if r is None:  # pragma: no cover - bootstrap always seeds a row
            raise RuntimeError("no active policy version")
        return {
            "required_components": r[0],
            "required_algorithms": r[1],
            "clock_skew_seconds": r[2],
            "max_age_seconds": r[3],
            "require_created": r[4],
            "require_nonce": r[5],
            "require_content_digest_with_body": r[6],
            "version": r[7],
            "activated_at": r[8].isoformat() if r[8] else None,
        }

    if cur is not None:
        return _fetch(cur)
    with transaction(read_only=True) as c:
        return _fetch(c)


def get_policy_version(version: int, cur=None) -> Optional[Dict[str, Any]]:
    """Return one immutable policy version snapshot (draft/active/retired)."""

    def _fetch(c):
        c.execute(_VERSION_SELECT + " WHERE version = %s", (version,))
        r = c.fetchone()
        return _version_row_to_dict(r) if r is not None else None

    if cur is not None:
        return _fetch(cur)
    with transaction(read_only=True) as c:
        return _fetch(c)


def list_policy_versions(status_filter: Optional[str] = None) -> list:
    with transaction(read_only=True) as cur:
        if status_filter:
            cur.execute(
                _VERSION_SELECT + " WHERE status = %s ORDER BY version DESC",
                (status_filter,),
            )
        else:
            cur.execute(_VERSION_SELECT + " ORDER BY version DESC")
        return [_version_row_to_dict(r) for r in cur.fetchall()]


def create_policy_draft(overrides: Dict[str, Any]) -> Dict[str, Any]:
    """Create an immutable draft from the current active policy.

    ``baseline_version`` (when supplied) must equal the active version;
    otherwise a concurrent activation happened first and the caller must
    rebase.
    """
    overrides = dict(overrides)
    baseline_version = overrides.pop("baseline_version", None)
    with transaction() as cur:
        # Serialise draft/activation writers so version allocation and the
        # baseline check cannot interleave.
        cur.execute("SELECT pg_advisory_xact_lock(hashtextextended('policy_versions', 0))")
        active = get_policy(cur=cur)
        current_version = active["version"]
        if baseline_version is not None and baseline_version != current_version:
            raise PolicyActivationConflict(
                f"baseline version {baseline_version} is no longer active "
                f"(current active version is {current_version}); rebase the draft",
                active_version=current_version,
            )

        values = {name: active[name] for name in POLICY_FIELDS}
        for name in POLICY_FIELDS:
            if overrides.get(name) is not None:
                values[name] = overrides[name]

        cur.execute("SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions")
        new_version = cur.fetchone()[0]
        cur.execute(
            """
            INSERT INTO policy_versions (
                version, status, baseline_version,
                required_components, required_algorithms,
                clock_skew_seconds, max_age_seconds,
                require_created, require_nonce,
                require_content_digest_with_body
            ) VALUES (
                %s, %s, %s,
                %s, %s,
                %s, %s,
                %s, %s,
                %s
            )
            """,
            (
                new_version,
                "draft",
                current_version,
                Json(values["required_components"]),
                Json(values["required_algorithms"]),
                values["clock_skew_seconds"],
                values["max_age_seconds"],
                values["require_created"],
                values["require_nonce"],
                values["require_content_digest_with_body"],
            ),
        )
        cur.execute(_VERSION_SELECT + " WHERE version = %s", (new_version,))
        return _version_row_to_dict(cur.fetchone())


def activate_policy_version(
    version: int, expected_active_version: Optional[int] = None
) -> Dict[str, Any]:
    """Atomically activate a draft version.

    Steps, all in one transaction under an advisory lock:

    1. the target must exist and be a ``draft``;
    2. the active version must equal the caller's expected baseline
       (``expected_active_version`` defaults to the draft's baseline);
    3. the old active row becomes ``retired``, the draft becomes ``active``;
    4. the singleton ``verify_policy`` mirror is refreshed from it.

    A stale baseline raises ``PolicyActivationConflict`` (HTTP 409) and
    changes nothing.
    """
    with transaction() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(hashtextextended('policy_versions', 0))")
        cur.execute(_VERSION_SELECT + " WHERE version = %s", (version,))
        row = cur.fetchone()
        if row is None:
            raise PolicyVersionNotFound(version)
        target = _version_row_to_dict(row)
        if target["status"] != "draft":
            raise PolicyDraftNotActivatable(version, target["status"])

        active = get_policy(cur=cur)
        current_version = active["version"]
        expected = (
            expected_active_version
            if expected_active_version is not None
            else target["baseline_version"]
        )
        if expected is not None and expected != current_version:
            raise PolicyActivationConflict(
                f"cannot activate version {version}: active version is "
                f"{current_version} but the change was based on version {expected}",
                active_version=current_version,
            )

        cur.execute(
            """
            UPDATE policy_versions SET status = 'retired'
            WHERE status = 'active'
            """,
        )
        cur.execute(
            """
            UPDATE policy_versions
            SET status = 'active', activated_at = now()
            WHERE version = %s
            """,
            (version,),
        )
        cur.execute(
            """
            UPDATE verify_policy SET
                required_components = %(required_components)s,
                required_algorithms = %(required_algorithms)s,
                clock_skew_seconds = %(clock_skew_seconds)s,
                max_age_seconds = %(max_age_seconds)s,
                require_created = %(require_created)s,
                require_nonce = %(require_nonce)s,
                require_content_digest_with_body = %(require_content_digest_with_body)s,
                active_version = %(version)s,
                updated_at = now()
            WHERE id = 1
            """,
            {
                "required_components": Json(target["required_components"]),
                "required_algorithms": Json(target["required_algorithms"]),
                "clock_skew_seconds": target["clock_skew_seconds"],
                "max_age_seconds": target["max_age_seconds"],
                "require_created": target["require_created"],
                "require_nonce": target["require_nonce"],
                "require_content_digest_with_body": target[
                    "require_content_digest_with_body"
                ],
                "version": version,
            },
        )
        cur.execute(_VERSION_SELECT + " WHERE version = %s", (version,))
        return _version_row_to_dict(cur.fetchone())


def update_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Replace the live policy (legacy PUT /admin/policy behaviour).

    To keep /verify and the version history consistent, this performs the
    same atomic transition as draft activation: a new immutable active
    version snapshot is created, the previous one is retired, and the
    singleton mirror is refreshed — all in one transaction.
    """
    with transaction() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(hashtextextended('policy_versions', 0))")
        cur.execute(
            "SELECT version FROM policy_versions WHERE status = 'active'"
        )
        baseline_row = cur.fetchone()
        baseline_version = baseline_row[0] if baseline_row else None
        cur.execute("SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions")
        new_version = cur.fetchone()[0]
        cur.execute(
            """
            UPDATE policy_versions SET status = 'retired'
            WHERE status = 'active'
            """,
        )
        cur.execute(
            """
            INSERT INTO policy_versions (
                version, status, baseline_version,
                required_components, required_algorithms,
                clock_skew_seconds, max_age_seconds,
                require_created, require_nonce,
                require_content_digest_with_body, activated_at
            ) VALUES (%s, 'active', %s, %s, %s, %s, %s, %s, %s, %s, now())
            """,
            (
                new_version,
                baseline_version,
                Json(policy["required_components"]),
                Json(policy["required_algorithms"]),
                policy["clock_skew_seconds"],
                policy["max_age_seconds"],
                policy["require_created"],
                policy["require_nonce"],
                policy["require_content_digest_with_body"],
            ),
        )
        cur.execute(
            """
            UPDATE verify_policy SET
                required_components = %s,
                required_algorithms = %s,
                clock_skew_seconds = %s,
                max_age_seconds = %s,
                require_created = %s,
                require_nonce = %s,
                require_content_digest_with_body = %s,
                active_version = %s,
                updated_at = now()
            WHERE id = 1
            """,
            (
                Json(policy["required_components"]),
                Json(policy["required_algorithms"]),
                policy["clock_skew_seconds"],
                policy["max_age_seconds"],
                policy["require_created"],
                policy["require_nonce"],
                policy["require_content_digest_with_body"],
                new_version,
            ),
        )
        cur.execute(_VERSION_SELECT + " WHERE version = %s", (new_version,))
        return _version_row_to_dict(cur.fetchone())


def nonce_seen(keyid: str, nonce: str, cur=None) -> bool:
    """Read-only check whether (keyid, nonce) was already accepted."""

    def _fetch(c):
        c.execute(
            "SELECT 1 FROM used_nonces WHERE keyid = %s AND nonce = %s",
            (keyid, nonce),
        )
        return c.fetchone() is not None

    if cur is not None:
        return _fetch(cur)
    with transaction(read_only=True) as c:
        return _fetch(c)


# ---------------------------------------------------------------------------
# Replay protection — MUST run in the same transaction/connection as the
# caller so the UNIQUE(keyid, nonce) insert is atomic under concurrency.
# ---------------------------------------------------------------------------


def claim_nonce(cur, keyid: str, nonce: str, label: str = "") -> None:
    """Atomically claim (keyid, nonce).

    Raises ``ReplayDetected`` when the pair already exists.  Must be called
    inside the caller's transaction (``cur``).
    """
    try:
        cur.execute(
            "INSERT INTO used_nonces (keyid, nonce, label) VALUES (%s, %s, %s)",
            (keyid, nonce, label),
        )
    except UniqueViolation as exc:
        raise ReplayDetected(keyid, nonce) from exc


# ---------------------------------------------------------------------------
# Receipt-signing keys (server-side Ed25519; private keys never leave the DB)
# ---------------------------------------------------------------------------

_RECEIPT_KEY_SELECT = """
    SELECT keyid, version, public_key, private_key, fingerprint,
           enabled, created_at, retired_at
    FROM receipt_keys
"""


def _receipt_key_row_to_dict(r, *, include_private: bool = False) -> Dict[str, Any]:
    # Column order matches _RECEIPT_KEY_SELECT.
    info = {
        "key_id": f"{r[0]}#{r[1]}",
        "keyid": r[0],
        "version": r[1],
        "public_key": r[2],
        "fingerprint": r[4],
        "status": "active" if r[5] else "retired",
        "created_at": r[6].isoformat() if r[6] else None,
        "retired_at": r[7].isoformat() if r[7] else None,
    }
    if include_private:
        info["private_key"] = r[3]
    return info


def _active_receipt_key(cur) -> Optional[Dict[str, Any]]:
    cur.execute(
        _RECEIPT_KEY_SELECT + " WHERE keyid = %s AND enabled = TRUE",
        (receipts.RECEIPT_KEYID,),
    )
    row = cur.fetchone()
    return _receipt_key_row_to_dict(row, include_private=True) if row else None


def _insert_receipt_key(cur, version: int) -> None:
    priv, pub = generate_ed25519()
    cur.execute(
        """
        INSERT INTO receipt_keys (keyid, version, public_key, private_key, fingerprint, enabled)
        VALUES (%s, %s, %s, %s, %s, TRUE)
        """,
        (
            receipts.RECEIPT_KEYID,
            version,
            public_key_pem(pub),
            private_key_pem(priv),
            spki_fingerprint(pub),
        ),
    )


def ensure_receipt_signing_key(cur) -> Dict[str, Any]:
    """Return the active receipt-signing key, generating version 1 if absent.

    Must be called inside the caller's transaction.  An advisory lock makes
    the check-then-insert race-free; the partial unique index is the
    database-enforced backstop.
    """
    row = _active_receipt_key(cur)
    if row is not None:
        return row
    cur.execute("SELECT pg_advisory_xact_lock(hashtextextended('receipt_signing_key', 0))")
    row = _active_receipt_key(cur)  # re-check under the lock
    if row is not None:
        return row
    _insert_receipt_key(cur, 1)
    return _active_receipt_key(cur)


def rotate_receipt_signing_key() -> Dict[str, Any]:
    """Atomically retire the active receipt key and activate a fresh version.

    Old public keys stay published (status ``retired``) so historical
    receipts remain verifiable offline after rotation.
    """
    with transaction() as cur:
        cur.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended('receipt_signing_key', 0))"
        )
        ensure_receipt_signing_key(cur)
        cur.execute(
            "UPDATE receipt_keys SET enabled = FALSE, retired_at = now() "
            "WHERE keyid = %s AND enabled = TRUE",
            (receipts.RECEIPT_KEYID,),
        )
        cur.execute(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM receipt_keys WHERE keyid = %s",
            (receipts.RECEIPT_KEYID,),
        )
        version = cur.fetchone()[0]
        _insert_receipt_key(cur, version)
        row = _active_receipt_key(cur)
        return {k: v for k, v in row.items() if k != "private_key"}


def list_receipt_signing_keys() -> list:
    """Public view of every receipt-signing key version (never private keys)."""
    with transaction(read_only=True) as cur:
        cur.execute(
            _RECEIPT_KEY_SELECT + " WHERE keyid = %s ORDER BY version DESC",
            (receipts.RECEIPT_KEYID,),
        )
        return [_receipt_key_row_to_dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Acceptance receipts — issued in the SAME transaction as the nonce claim so
# both commit or roll back together.
# ---------------------------------------------------------------------------


def insert_receipt(
    cur,
    *,
    receipt_id: str,
    key_id: str,
    payload: str,
    signature: str,
    input_digest: str,
    signer_keyid: str,
    nonce: Optional[str],
    issued_at: datetime,
) -> None:
    """Insert one receipt row (must run in the caller's transaction)."""
    cur.execute(
        """
        INSERT INTO receipts (
            receipt_id, key_id, payload, signature, input_digest,
            signer_keyid, nonce, issued_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            receipt_id,
            key_id,
            payload,
            signature,
            input_digest,
            signer_keyid,
            nonce,
            issued_at,
        ),
    )


def issue_receipt(
    cur,
    *,
    envelope: Dict[str, Any],
    keyid: str,
    key_version: int,
    policy_version: int,
    algorithm: str,
    label: str,
    nonce: Optional[str],
) -> Dict[str, Any]:
    """Build, sign and persist an acceptance receipt in *this* transaction.

    Any failure raises ``ReceiptIssuanceError``; the caller's transaction —
    including the nonce claim — then rolls back as a whole.
    """
    try:
        key = ensure_receipt_signing_key(cur)
        private_key = load_private_key(key["private_key"])
        digest = receipts.input_digest(envelope)
        receipt_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        payload = receipts.build_payload(
            receipt_id=receipt_id,
            key_id=key["key_id"],
            issued_at=int(now.timestamp()),
            keyid=keyid,
            key_version=key_version,
            policy_version=policy_version,
            algorithm=algorithm,
            label=label,
            nonce=nonce,
            input_digest=digest,
        )
        signature = receipts.sign_payload(private_key, payload)
        insert_receipt(
            cur,
            receipt_id=receipt_id,
            key_id=key["key_id"],
            payload=payload,
            signature=signature,
            input_digest=digest,
            signer_keyid=keyid,
            nonce=nonce,
            issued_at=now,
        )
    except ReceiptIssuanceError:
        raise
    except Exception as exc:
        raise ReceiptIssuanceError(
            f"could not issue acceptance receipt: {exc}"
        ) from exc
    return receipts.receipt_document(
        payload=payload, signature=signature, issued_at=now.isoformat()
    )


def get_receipt(receipt_id: str) -> Optional[Dict[str, Any]]:
    """Fetch one persisted receipt by its unique id (read-only).

    The response document is rebuilt from the stored canonical payload, so
    every convenience field mirrors exactly what was signed.
    """
    with transaction(read_only=True) as cur:
        cur.execute(
            "SELECT payload, signature, issued_at FROM receipts WHERE receipt_id = %s",
            (receipt_id,),
        )
        row = cur.fetchone()
    if row is None:
        return None
    return receipts.receipt_document(
        payload=row[0], signature=row[1], issued_at=row[2].isoformat()
    )


# ---------------------------------------------------------------------------
# Receipt revocation — the command, the receipt revision bump and the audit
# chain append commit in ONE transaction, so concurrent commands and restarts
# observe exactly one consistent outcome.
# ---------------------------------------------------------------------------

_REVOCATION_SELECT = """
    SELECT payload, signature, effective_at, revoked_at,
           command_id, expected_revision, reason
    FROM receipt_revocations
"""


def _revocation_doc_from_row(r) -> Dict[str, Any]:
    # Column order matches _REVOCATION_SELECT.
    return revocations.revocation_document(
        payload=r[0],
        signature=r[1],
        effective_at=r[2].isoformat(),
        revoked_at=r[3].isoformat(),
    )


def _get_revocation_row(cur, receipt_id: str):
    cur.execute(
        _REVOCATION_SELECT + " WHERE receipt_id = %s",
        (receipt_id,),
    )
    return cur.fetchone()


def _command_matches(
    row,
    *,
    reason: str,
    effective_at: datetime,
    expected_revision: int,
    command_id: Optional[str],
) -> bool:
    """True when the stored revocation came from an identical command.

    With an idempotency key (``command_id``) on either side, both must carry
    the same key; the command parameters must always match as well.
    """
    stored_command_id = row[4]
    if command_id is not None or stored_command_id is not None:
        if command_id is None or stored_command_id != command_id:
            return False
    stored_effective_at = int(row[2].timestamp())
    return (
        row[6] == reason
        and stored_effective_at == int(effective_at.timestamp())
        and row[5] == expected_revision
    )


def revoke_receipt(
    *,
    receipt_id: str,
    reason: str,
    effective_at: datetime,
    expected_revision: int,
    command_id: Optional[str] = None,
) -> Tuple[Dict[str, Any], bool]:
    """Idempotently revoke one receipt; return ``(document, created)``.

    One transaction, in order:

    1. lock the receipt row (``FOR UPDATE``) — unknown ids are rejected;
    2. if a revocation already exists, an identical command is an idempotent
       replay (``created=False``) and a different one a conflict;
    3. ``expected_revision`` must equal the receipt's current revision
       (optimistic concurrency);
    4. under a global advisory lock, allocate the next gapless audit-chain
       sequence and read the chain head;
    5. bump the receipt revision with an atomic compare-and-swap, build the
       canonical ``revocation/v1`` payload, sign it with the active
       receipt-signing key and insert the immutable record.

    Everything commits or rolls back together, so a crash or a conflict
    leaves no partial state and the command can be retried safely.
    """
    effective_at = effective_at.astimezone(timezone.utc)
    with transaction() as cur:
        cur.execute(
            "SELECT revision FROM receipts WHERE receipt_id = %s FOR UPDATE",
            (receipt_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise ReceiptUnknown(receipt_id)
        current_revision = row[0]

        existing = _get_revocation_row(cur, receipt_id)
        if existing is not None:
            document = _revocation_doc_from_row(existing)
            if _command_matches(
                existing,
                reason=reason,
                effective_at=effective_at,
                expected_revision=expected_revision,
                command_id=command_id,
            ):
                return document, False
            raise RevocationConflict(
                f"receipt {receipt_id!r} is already revoked by a different "
                f"command (revocation {document['revocation_id']!r})",
                revocation=document,
            )

        if expected_revision != current_revision:
            raise RevocationRevisionConflict(
                f"expected_revision {expected_revision} does not match the "
                f"receipt's current revision {current_revision}",
                current_revision=current_revision,
            )

        # Serialise all revocations so chain allocation is race-free; the
        # UNIQUE(revocation_seq) constraint is the database-enforced backstop.
        cur.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended('receipt_revocations', 0))"
        )
        cur.execute(
            "SELECT revocation_seq, payload_sha256 FROM receipt_revocations "
            "ORDER BY revocation_seq DESC LIMIT 1"
        )
        head = cur.fetchone()
        prev_seq = head[0] if head else 0
        prev_hash = head[1] if head else None
        seq = prev_seq + 1

        # Atomic compare-and-swap of the receipt revision (the FOR UPDATE row
        # lock is already held, so this cannot lose a race).
        cur.execute(
            "UPDATE receipts SET revision = revision + 1 "
            "WHERE receipt_id = %s AND revision = %s",
            (receipt_id, expected_revision),
        )
        if cur.rowcount != 1:  # pragma: no cover - defensive
            raise RevocationRevisionConflict(
                "receipt revision changed underneath the command",
                current_revision=current_revision,
            )

        try:
            key = ensure_receipt_signing_key(cur)
            private_key = load_private_key(key["private_key"])
            now = datetime.now(timezone.utc)
            new_revision = expected_revision + 1
            revocation_id = str(uuid.uuid4())
            payload = revocations.build_payload(
                revocation_id=revocation_id,
                revocation_seq=seq,
                receipt_id=receipt_id,
                receipt_revision=new_revision,
                reason=reason,
                effective_at=int(effective_at.timestamp()),
                revoked_at=int(now.timestamp()),
                key_id=key["key_id"],
                command_id=command_id,
                prev_seq=prev_seq,
                prev_payload_sha256=prev_hash,
            )
            signature = receipts.sign_payload(private_key, payload)
            cur.execute(
                """
                INSERT INTO receipt_revocations (
                    revocation_id, revocation_seq, receipt_id, command_id,
                    expected_revision, receipt_revision, reason,
                    effective_at, revoked_at, key_id, prev_payload_sha256,
                    payload, payload_sha256, signature
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    revocation_id,
                    seq,
                    receipt_id,
                    command_id,
                    expected_revision,
                    new_revision,
                    reason,
                    effective_at,
                    now,
                    key["key_id"],
                    prev_hash,
                    payload,
                    revocations.payload_sha256(payload),
                    signature,
                ),
            )
        except RevocationIssuanceError:
            raise
        except Exception as exc:
            raise RevocationIssuanceError(
                f"could not issue revocation record: {exc}"
            ) from exc

        document = revocations.revocation_document(
            payload=payload,
            signature=signature,
            effective_at=effective_at.isoformat(),
            revoked_at=now.isoformat(),
        )
        return document, True


def get_revocation_for_receipt(receipt_id: str) -> Optional[Dict[str, Any]]:
    """Fetch the revocation record of one receipt (read-only)."""
    with transaction(read_only=True) as cur:
        row = _get_revocation_row(cur, receipt_id)
    return _revocation_doc_from_row(row) if row is not None else None


def list_revocations() -> list:
    """Return the whole revocation audit chain, ordered by sequence."""
    with transaction(read_only=True) as cur:
        cur.execute(_REVOCATION_SELECT + " ORDER BY revocation_seq ASC")
        return [_revocation_doc_from_row(r) for r in cur.fetchall()]


def receipt_status_at(receipt_id: str, at: datetime) -> Dict[str, Any]:
    """Point-in-time receipt status: ``valid`` / ``revoked`` / ``unknown``.

    ``unknown`` means no such receipt exists, or the receipt had not yet been
    issued at ``at``.  ``revoked`` applies from the revocation's
    ``effective_at`` onwards; before that moment the receipt reads ``valid``.
    The answer derives only from persisted state, so it is identical across
    processes and restarts.
    """
    at = at.astimezone(timezone.utc)
    at_ts = int(at.timestamp())
    answer: Dict[str, Any] = {
        "receipt_id": receipt_id,
        "at": at.isoformat(),
        "at_unix": at_ts,
    }
    with transaction(read_only=True) as cur:
        cur.execute(
            "SELECT issued_at, revision FROM receipts WHERE receipt_id = %s",
            (receipt_id,),
        )
        row = cur.fetchone()
        if row is None or at_ts < int(row[0].timestamp()):
            answer["status"] = "unknown"
            return answer

        issued_at, revision = row
        answer.update(
            {
                "issued_at": issued_at.isoformat(),
                "issued_at_unix": int(issued_at.timestamp()),
                "revision": revision,
            }
        )
        revocation_row = _get_revocation_row(cur, receipt_id)
        if revocation_row is not None and at_ts >= int(
            revocation_row[2].timestamp()
        ):
            answer["status"] = "revoked"
            answer["revocation"] = _revocation_doc_from_row(revocation_row)
        else:
            answer["status"] = "valid"
            answer["revocation"] = None
        return answer
