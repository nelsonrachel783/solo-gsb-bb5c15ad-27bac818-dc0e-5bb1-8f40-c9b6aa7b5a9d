"""Read-only verification of stored audit records.

Re-runs the bidi parser over the record's stored raw text and diffs the
freshly computed result against the persisted ``result`` document field
by field. Differences are reported as RFC 6901 JSON Pointer paths (array
elements addressed by their index), sorted lexicographically by pointer.
Each entry carries both values plus ``stored_present`` /
``recomputed_present`` flags so a missing key is distinguishable from an
explicit ``null``. Nothing here mutates the stored record.
"""

from __future__ import annotations

from typing import Any

from .bidi import parse_bidi

# Sentinel for "key/element absent on this side" -- distinct from a real
# JSON null, which is a perfectly ordinary value.
_MISSING: Any = object()


def _escape_pointer_token(token: str) -> str:
    """RFC 6901 escaping for a single reference token."""
    return token.replace("~", "~0").replace("/", "~1")


def _scalar_equal(a: Any, b: Any) -> bool:
    # bool is a subclass of int: keep True/False distinct from 1/0.
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return a == b


def _record(diffs: list[dict], path: str, stored: Any, recomputed: Any) -> None:
    diffs.append({
        "path": path,
        "stored": None if stored is _MISSING else stored,
        "recomputed": None if recomputed is _MISSING else recomputed,
        "stored_present": stored is not _MISSING,
        "recomputed_present": recomputed is not _MISSING,
    })


def _diff(stored: Any, recomputed: Any, path: str, diffs: list[dict]) -> None:
    if stored is _MISSING or recomputed is _MISSING:
        _record(diffs, path, stored, recomputed)
        return
    if isinstance(stored, dict) and isinstance(recomputed, dict):
        for key in sorted(set(stored) | set(recomputed)):
            _diff(
                stored.get(key, _MISSING),
                recomputed.get(key, _MISSING),
                f"{path}/{_escape_pointer_token(str(key))}",
                diffs,
            )
        return
    if isinstance(stored, list) and isinstance(recomputed, list):
        # Walk to the longer length: extra elements surface as a diff at
        # their own index with the absent side flagged not-present.
        for index in range(max(len(stored), len(recomputed))):
            s = stored[index] if index < len(stored) else _MISSING
            r = recomputed[index] if index < len(recomputed) else _MISSING
            _diff(s, r, f"{path}/{index}", diffs)
        return
    # Scalars (and scalar/container mismatches) compare by value.
    if not _scalar_equal(stored, recomputed):
        _record(diffs, path, stored, recomputed)


def verify_audit_record(record: dict) -> dict:
    """Recompute the audit from its stored text and diff against ``result``.

    The record is only read; the verification never writes back.
    """
    stored_result = record["result"]
    recomputed_result = parse_bidi(record["raw_text"]).to_dict()

    diffs: list[dict] = []
    _diff(stored_result, recomputed_result, "", diffs)
    diffs.sort(key=lambda entry: entry["path"])

    return {
        "id": record["id"],
        "consistent": not diffs,
        "diff_count": len(diffs),
        "diffs": diffs,
    }
