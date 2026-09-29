"""Itemised diffs between immutable policy versions.

Used by shadow verification to show exactly how the requested policy version
deviates from the version currently enforced by ``/verify``.  Output is
deterministic: given the same two stored versions it is byte-for-byte
identical, including across restarts.
"""
from __future__ import annotations

from typing import Any, Dict, List

# Scalar policy switches / numeric limits.
SCALAR_FIELDS = (
    "clock_skew_seconds",
    "max_age_seconds",
    "require_created",
    "require_nonce",
    "require_content_digest_with_body",
)
# Ordered-list policy fields, compared add/remove (order preserved).
LIST_FIELDS = (
    "required_components",
    "required_algorithms",
)


def _list_diff(field: str, active: List[str], candidate: List[str]) -> Dict[str, Any]:
    added = [v for v in candidate if v not in active]
    removed = [v for v in active if v not in candidate]
    return {
        "field": field,
        "kind": "set",
        "active": list(active),
        "candidate": list(candidate),
        "added": added,
        "removed": removed,
        "changed": bool(added or removed),
    }


def diff_policies(
    candidate: Dict[str, Any], active: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Return one entry per field that differs between two policy snapshots."""
    changes: List[Dict[str, Any]] = []

    for field in LIST_FIELDS:
        changes.append(_list_diff(field, active.get(field, []), candidate.get(field, [])))

    for field in SCALAR_FIELDS:
        old = active.get(field)
        new = candidate.get(field)
        changes.append(
            {
                "field": field,
                "kind": "scalar",
                "active": old,
                "candidate": new,
                "changed": old != new,
            }
        )

    return [c for c in changes if c["changed"]]
