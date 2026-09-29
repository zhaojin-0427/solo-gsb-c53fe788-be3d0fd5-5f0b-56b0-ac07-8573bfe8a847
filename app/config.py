"""Runtime configuration loaded from environment variables."""
from __future__ import annotations

import os


def _dsn() -> str:
    return os.environ.get(
        "DATABASE_URL",
        "postgresql://hss:hss@localhost:5432/hss",
    )


DATABASE_URL: str = _dsn()
DB_CONNECT_RETRIES: int = int(os.environ.get("DB_CONNECT_RETRIES", "30"))
DB_CONNECT_DELAY: float = float(os.environ.get("DB_CONNECT_DELAY", "1.0"))

# Shared secret for the /admin endpoints. Empty string disables authentication.
ADMIN_TOKEN: str = os.environ.get("ADMIN_TOKEN", "admin-secret")

# Algorithms this verifier understands.
SUPPORTED_ALGORITHMS = (
    "ed25519",
    "rsa-pss-sha256",
    "rsa-pss-sha512",
)

DEFAULT_REQUIRED_COMPONENTS = [
    "@method",
    "@target-uri",
    "@authority",
    "content-digest",
]
DEFAULT_REQUIRED_ALGORITHMS = list(SUPPORTED_ALGORITHMS)
DEFAULT_CLOCK_SKEW_SECONDS = 30
DEFAULT_MAX_AGE_SECONDS = 300
