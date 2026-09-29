"""PostgreSQL access: schema, key registry, policy, replay protection, receipts."""
from __future__ import annotations

import hashlib
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, Optional

import psycopg2
from psycopg2 import pool as pg_pool
from psycopg2.errors import UniqueViolation
from psycopg2.extras import Json

from . import config, receipts
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


class ReceiptNotFound(Exception):
    """Raised when an admin command targets an unknown receipt id."""


class ReceiptAlreadyRevoked(Exception):
    """Raised when a non-idempotent revocation targets an already-revoked receipt."""

    def __init__(self, receipt_id: str, revocation_id: str, revision: int):
        super().__init__(f"receipt {receipt_id!r} is already revoked at revision {revision}")
        self.receipt_id = receipt_id
        self.revocation_id = revocation_id
        self.revision = revision


class RevocationRevisionConflict(Exception):
    """Raised when expected_revision does not match the current revision."""

    def __init__(self, receipt_id: str, expected: int, current: int):
        super().__init__(
            f"receipt {receipt_id!r} expected revision {expected} "
            f"but current revision is {current}"
        )
        self.receipt_id = receipt_id
        self.expected = expected
        self.current = current


class RevocationEffectiveBeforeIssuance(Exception):
    """Raised when effective_at precedes the receipt's issuance time.

    Such a command would rewrite history (time travel) and is rejected.
    """

    def __init__(self, receipt_id: str, effective_at: int, issued_at: int):
        super().__init__(
            f"revocation effective_at={effective_at} is before the receipt "
            f"was issued at {issued_at}"
        )
        self.receipt_id = receipt_id
        self.effective_at = effective_at
        self.issued_at = issued_at


class RevocationError(Exception):
    """Raised when revocation signing/persistence fails (whole tx rolls back)."""


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

-- Immutable, server-signed receipt revocation records.  Rows are append-only:
-- a unique index allows at most one revocation per receipt; the global
-- audit ``sequence`` is gapless and the signed payload binds to the exact
-- receipt (id + receipt payload hash), so a revocation cannot be replayed
-- onto another receipt or silently altered.
CREATE TABLE IF NOT EXISTS receipt_revocations (
    id                      BIGSERIAL PRIMARY KEY,
    revocation_id           TEXT NOT NULL UNIQUE,
    receipt_id              TEXT NOT NULL UNIQUE REFERENCES receipts(receipt_id),
    sequence                BIGINT NOT NULL UNIQUE,
    revision                INTEGER NOT NULL,
    key_id                  TEXT NOT NULL,
    payload                 TEXT NOT NULL,
    signature               TEXT NOT NULL,
    receipt_payload_sha256  TEXT NOT NULL,
    reason                  TEXT NOT NULL,
    effective_at            TIMESTAMPTZ NOT NULL,
    revoked_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Tamper-evident, gapless audit chain.  Every state-changing admin event
-- (currently: receipt revocation) is appended in the SAME transaction as
-- the change it records; each row commits the hash of its predecessor, so
-- any deleted or altered row is detectable by recomputing the chain.
CREATE TABLE IF NOT EXISTS audit_events (
    seq          BIGSERIAL PRIMARY KEY,
    event_type   TEXT NOT NULL,
    event_id     TEXT NOT NULL,
    receipt_id   TEXT,
    canonical    TEXT NOT NULL,
    entry_sha256 TEXT NOT NULL,
    prev_sha256  TEXT NOT NULL,
    receipt_payload_sha256     TEXT,
    revocation_payload_sha256  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Idempotent upgrade for databases created before the hash columns existed.
ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS receipt_payload_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS revocation_payload_sha256 TEXT;
"""

#: Genesis predecessor hash for the first audit chain entry.
AUDIT_GENESIS_PREV = "0" * 64

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
# Tamper-evident audit chain
#
# Append-only, gapless, hash-chained.  Each entry's canonical text embeds
# the predecessor hash; the chain and the state changes it describes commit
# in the SAME transaction, so a revocation without its audit entry (or vice
# versa) can never survive a commit.  Nothing ever UPDATEs or DELETEs here.
# ---------------------------------------------------------------------------

AUDIT_CANONICAL_VERSION = "audit-entry/v1"


def audit_canonical(
    *,
    seq: int,
    event_type: str,
    event_id: str,
    receipt_id: Optional[str],
    prev_sha256: str,
    receipt_payload_sha256: Optional[str] = None,
    revocation_payload_sha256: Optional[str] = None,
) -> str:
    """Deterministic canonical text of one audit chain entry."""
    lines = [
        AUDIT_CANONICAL_VERSION,
        f"seq: {int(seq)}",
        f"event_type: {event_type}",
        f"event_id: {event_id}",
        f"receipt_id: {receipt_id or ''}",
        f"prev_sha256: {prev_sha256}",
    ]
    if revocation_payload_sha256 is not None:
        lines.append(f"revocation_payload_sha256: {revocation_payload_sha256}")
    if receipt_payload_sha256 is not None:
        lines.append(f"receipt_payload_sha256: {receipt_payload_sha256}")
    return "\n".join(lines)


def _append_audit_event(
    cur,
    *,
    event_type: str,
    event_id: str,
    receipt_id: Optional[str],
    receipt_payload_sha256: Optional[str] = None,
    revocation_payload_sha256: Optional[str] = None,
) -> int:
    """Append one hash-chained audit entry inside the caller's transaction.

    A global advisory lock serialises writers; sequence numbers are derived
    from the previous row (not a SEQUENCE object), so the committed chain
    is gapless.  Returns the assigned sequence number.
    """
    cur.execute("SELECT pg_advisory_xact_lock(hashtextextended('audit_chain', 0))")
    cur.execute("SELECT seq, entry_sha256 FROM audit_events ORDER BY seq DESC LIMIT 1")
    last = cur.fetchone()
    seq = (last[0] + 1) if last else 1
    prev_sha256 = last[1] if last else AUDIT_GENESIS_PREV
    canonical = audit_canonical(
        seq=seq,
        event_type=event_type,
        event_id=event_id,
        receipt_id=receipt_id,
        prev_sha256=prev_sha256,
        receipt_payload_sha256=receipt_payload_sha256,
        revocation_payload_sha256=revocation_payload_sha256,
    )
    entry_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    cur.execute(
        """
        INSERT INTO audit_events (
            seq, event_type, event_id, receipt_id,
            canonical, entry_sha256, prev_sha256,
            receipt_payload_sha256, revocation_payload_sha256
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            seq,
            event_type,
            event_id,
            receipt_id,
            canonical,
            entry_sha256,
            prev_sha256,
            receipt_payload_sha256,
            revocation_payload_sha256,
        ),
    )
    return seq


def list_audit_events(event_type: Optional[str] = None) -> list:
    """List audit chain entries in sequence order (admin only)."""
    with transaction(read_only=True) as cur:
        if event_type:
            cur.execute(
                "SELECT seq, event_type, event_id, receipt_id, entry_sha256, "
                "prev_sha256, created_at FROM audit_events "
                "WHERE event_type = %s ORDER BY seq",
                (event_type,),
            )
        else:
            cur.execute(
                "SELECT seq, event_type, event_id, receipt_id, entry_sha256, "
                "prev_sha256, created_at FROM audit_events ORDER BY seq"
            )
        return [
            {
                "seq": r[0],
                "event_type": r[1],
                "event_id": r[2],
                "receipt_id": r[3],
                "entry_sha256": r[4],
                "prev_sha256": r[5],
                "created_at": r[6].isoformat() if r[6] else None,
            }
            for r in cur.fetchall()
        ]


def verify_audit_chain(cur=None) -> Dict[str, Any]:
    """Recompute the whole audit chain and report the first broken link.

    Reads only.  ``first_bad_seq`` is null when every link is intact.
    """

    def _check(c):
        c.execute(
            "SELECT seq, event_type, event_id, receipt_id, canonical, "
            "entry_sha256, prev_sha256, receipt_payload_sha256, "
            "revocation_payload_sha256 FROM audit_events ORDER BY seq"
        )
        rows = c.fetchall()
        prev = AUDIT_GENESIS_PREV
        expected_seq = 1
        first_bad = None
        for r in rows:
            (
                seq,
                event_type,
                event_id,
                receipt_id,
                canonical,
                entry,
                stored_prev,
                receipt_hash,
                revocation_hash,
            ) = r
            # Rebuild the canonical text from the plain columns: tampering
            # with event_id/receipt_id/hashes (or canonical itself) is caught.
            rebuilt = audit_canonical(
                seq=seq,
                event_type=event_type,
                event_id=event_id,
                receipt_id=receipt_id,
                prev_sha256=stored_prev,
                receipt_payload_sha256=receipt_hash,
                revocation_payload_sha256=revocation_hash,
            )
            recomputed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            intact = (
                first_bad is None
                and seq == expected_seq
                and stored_prev == prev
                and rebuilt == canonical
                and entry == recomputed_hash
            )
            if not intact and first_bad is None:
                first_bad = seq
            prev = entry
            expected_seq += 1
        return {
            "ok": first_bad is None,
            "entries": len(rows),
            "first_bad_seq": first_bad,
        }

    if cur is not None:
        return _check(cur)
    with transaction(read_only=True) as c:
        return _check(c)


# ---------------------------------------------------------------------------
# Receipt revocation — idempotent, optimistic-revision checked, immutable.
#
# ``POST /admin/receipts/{receipt_id}/revoke`` runs entirely in one
# transaction:
#
#   1. a global advisory lock serialises audit-chain appends;
#   2. the target receipt row is locked (``SELECT ... FOR UPDATE``);
#   3. unknown receipts are rejected (404 receipt_unknown);
#   4. an existing revocation makes the command either an idempotent replay
#      (same reason + effective_at -> 200, identical proof) or a conflict
#      (different command -> 409 receipt_already_revoked);
#   5. ``expected_revision`` (optimistic concurrency) must match: a fresh
#      receipt is at revision 0;
#   6. ``effective_at`` must not precede receipt issuance (no rewriting
#      history / time travel);
#   7. the immutable, sequenced, server-signed revocation record and the
#      audit-chain entry are inserted together and commit atomically.
# ---------------------------------------------------------------------------


_REVOCATION_SELECT = """
    SELECT revocation_id, key_id, payload, signature, receipt_payload_sha256,
           reason, effective_at, revoked_at, sequence, revision
    FROM receipt_revocations
"""


def _revocation_row_to_doc(r) -> Dict[str, Any]:
    # Column order matches _REVOCATION_SELECT.
    return receipts.revocation_document(payload=r[2], signature=r[3])


def _get_revocation(cur, receipt_id: str):
    cur.execute(_REVOCATION_SELECT + " WHERE receipt_id = %s", (receipt_id,))
    return cur.fetchone()


def revoke_receipt(
    *,
    receipt_id: str,
    reason: str,
    effective_at: int,
    expected_revision: Optional[int] = None,
) -> Dict[str, Any]:
    """Idempotently revoke an acceptance receipt (single atomic transaction).

    Returns ``{"revocation": <signed proof document>, "idempotent": bool}``.
    Raises ``ReceiptNotFound``, ``ReceiptAlreadyRevoked``,
    ``RevocationRevisionConflict``, ``RevocationEffectiveBeforeIssuance``
    or ``RevocationError``.
    """
    with transaction() as cur:
        # Serialise chain writers, then lock exactly this receipt row.
        cur.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended('audit_chain', 0))"
        )
        cur.execute(
            "SELECT payload, signature, issued_at FROM receipts "
            "WHERE receipt_id = %s FOR UPDATE",
            (receipt_id,),
        )
        receipt_row = cur.fetchone()
        if receipt_row is None:
            raise ReceiptNotFound(receipt_id)
        receipt_payload, receipt_signature, issued_dt = receipt_row
        issued_ts = int(issued_dt.timestamp())

        existing = _get_revocation(cur, receipt_id)
        if existing is not None:
            doc = _revocation_row_to_doc(existing)
            same_command = (
                existing[5] == reason
                and int(existing[6].timestamp()) == int(effective_at)
            )
            if same_command:
                # Idempotent replay: return the exact same immutable proof.
                return {"revocation": doc, "idempotent": True}
            raise ReceiptAlreadyRevoked(receipt_id, existing[0], existing[9])

        # Fresh receipt: current revision is 0.
        if expected_revision is not None and expected_revision != 0:
            raise RevocationRevisionConflict(receipt_id, expected_revision, 0)

        if int(effective_at) < issued_ts:
            raise RevocationEffectiveBeforeIssuance(
                receipt_id, int(effective_at), issued_ts
            )

        try:
            key = ensure_receipt_signing_key(cur)
            private_key = load_private_key(key["private_key"])
            receipt_hash = receipts.payload_sha256(receipt_payload)
            revocation_id = str(uuid.uuid4())
            revoked_dt = datetime.now(timezone.utc)
            revoked_ts = int(revoked_dt.timestamp())
            effective_dt = datetime.fromtimestamp(int(effective_at), tz=timezone.utc)

            # Reserve the global audit sequence under the advisory lock:
            # the sequence is part of the signed revocation payload, and
            # the audit entry appended below must get the same number.
            cur.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM audit_events"
            )
            sequence = cur.fetchone()[0]
            payload = receipts.build_revocation_payload(
                revocation_id=revocation_id,
                key_id=key["key_id"],
                receipt_id=receipt_id,
                sequence=sequence,
                revision=1,
                receipt_payload_sha256=receipt_hash,
                reason=reason,
                effective_at=int(effective_at),
                revoked_at=revoked_ts,
            )
            signature = receipts.sign_payload(private_key, payload)
            revocation_hash = receipts.payload_sha256(payload)

            audit_seq = _append_audit_event(
                cur,
                event_type="receipt_revoked",
                event_id=revocation_id,
                receipt_id=receipt_id,
                receipt_payload_sha256=receipt_hash,
                revocation_payload_sha256=revocation_hash,
            )
            if audit_seq != sequence:  # pragma: no cover - lock makes this impossible
                raise RevocationError("audit sequence allocation was inconsistent")

            cur.execute(
                """
                INSERT INTO receipt_revocations (
                    revocation_id, receipt_id, sequence, revision, key_id,
                    payload, signature, receipt_payload_sha256,
                    reason, effective_at, revoked_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    revocation_id,
                    receipt_id,
                    sequence,
                    1,
                    key["key_id"],
                    payload,
                    signature,
                    receipt_hash,
                    reason,
                    effective_dt,
                    revoked_dt,
                ),
            )
        except (RevocationError, receipts.ReceiptFormatError):
            raise
        except Exception as exc:
            raise RevocationError(f"could not persist revocation: {exc}") from exc

        return {"revocation": receipts.revocation_document(
            payload=payload, signature=signature
        ), "idempotent": False}


def get_receipt_status(receipt_id: str, at_ts: int) -> Optional[Dict[str, Any]]:
    """Point-in-time receipt state: ``valid``, ``revoked`` or ``None`` (unknown).

    A receipt counts as revoked at ``at_ts`` only when a persisted
    revocation is effective at or before that instant; a revocation with a
    later ``effective_at`` leaves the receipt valid at the queried time.
    """
    with transaction(read_only=True) as cur:
        cur.execute(
            "SELECT payload, signature, issued_at FROM receipts WHERE receipt_id = %s",
            (receipt_id,),
        )
        receipt_row = cur.fetchone()
        if receipt_row is None:
            return None
        receipt = receipts.receipt_document(
            payload=receipt_row[0],
            signature=receipt_row[1],
            issued_at=receipt_row[2].isoformat(),
        )
        rev_row = _get_revocation(cur, receipt_id)
        revocation = None
        status = "valid"
        if rev_row is not None:
            effective_ts = int(rev_row[6].timestamp())
            if at_ts >= effective_ts:
                status = "revoked"
            revocation = _revocation_row_to_doc(rev_row)
        return {
            "receipt_id": receipt_id,
            "status": status,
            "at": at_ts,
            "issued_at_unix": receipt["issued_at_unix"],
            "receipt": receipt,
            "revocation": revocation,
        }
