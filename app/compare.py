"""Regression comparison between two stored audit records.

Controls are paired by **abbreviation and order of appearance**: the n-th
occurrence of, e.g., ``RLO`` in the *before* record is paired with the n-th
``RLO`` in the *after* record. Extra occurrences on either side are reported
as added / removed. Paired occurrences are compared for position (logical
index / line / column) and pairing scope (``scope_end`` / ``paired_with`` /
orphan status).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Optional

_RISK_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Summary columns persisted for every audit record (see database._row_to_summary).
_SUMMARY_KEYS = (
    "id",
    "created_at",
    "filename",
    "text_length",
    "risk_level",
    "max_depth",
    "error_count",
    "control_count",
)


def _compact_control(control: dict[str, Any], occurrence: int) -> dict[str, Any]:
    """Project one parsed control down to the fields used in comparisons."""
    return {
        "occurrence": occurrence,
        "codepoint": control["codepoint"],
        "abbreviation": control["abbreviation"],
        "name": control["name"],
        "kind": control["kind"],
        "logical_index": control["logical_index"],
        "position": control["position"],
        "depth_after": control["depth_after"],
        "scope_end": control["scope_end"],
        "paired_with": control["paired_with"],
        "is_orphan": control["is_orphan"],
        "risk": control["risk"],
    }


def _group_controls(result: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Group compact controls by abbreviation, in order of appearance."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in result.get("controls", []):
        groups[control["abbreviation"]].append(
            _compact_control(control, len(groups[control["abbreviation"]]) + 1)
        )
    return groups


def _position_change(
    before: dict[str, Any], after: dict[str, Any]
) -> Optional[dict[str, Any]]:
    if before["logical_index"] == after["logical_index"]:
        return None
    return {
        "abbreviation": before["abbreviation"],
        "occurrence": before["occurrence"],
        "logical_index": {
            "before": before["logical_index"],
            "after": after["logical_index"],
            "delta": after["logical_index"] - before["logical_index"],
        },
        "position": {"before": before["position"], "after": after["position"]},
        "before": before,
        "after": after,
    }


def _scope_length(control: dict[str, Any]) -> Optional[int]:
    """Length of the affected span; None when no scope was assigned."""
    if control["scope_end"] is None:
        return None
    return control["scope_end"] - control["logical_index"]


def _pairing_change(
    before: dict[str, Any], after: dict[str, Any]
) -> Optional[dict[str, Any]]:
    # A pair shifted wholesale keeps the same pairing: detect only a changed
    # partner, changed orphan status or a changed span length (paired range).
    before_length = _scope_length(before)
    after_length = _scope_length(after)
    if (
        before["paired_with"] == after["paired_with"]
        and before["is_orphan"] == after["is_orphan"]
        and before_length == after_length
    ):
        return None
    return {
        "abbreviation": before["abbreviation"],
        "occurrence": before["occurrence"],
        "scope_end": {"before": before["scope_end"], "after": after["scope_end"]},
        "scope_length": {"before": before_length, "after": after_length},
        "paired_with": {
            "before": before["paired_with"],
            "after": after["paired_with"],
        },
        "is_orphan": {"before": before["is_orphan"], "after": after["is_orphan"]},
        "before": before,
        "after": after,
    }


def _risk_diff(before_level: str, after_level: str) -> dict[str, Any]:
    before_rank = _RISK_ORDER[before_level]
    after_rank = _RISK_ORDER[after_level]
    if after_rank > before_rank:
        direction = "escalated"
    elif after_rank < before_rank:
        direction = "de-escalated"
    else:
        direction = "unchanged"
    return {
        "before": before_level,
        "after": after_level,
        "changed": before_level != after_level,
        "direction": direction,
        "order_delta": after_rank - before_rank,
    }


def _summary(record: dict[str, Any]) -> dict[str, Any]:
    return {key: record[key] for key in _SUMMARY_KEYS}


def compare_audits(
    before_record: dict[str, Any], after_record: dict[str, Any]
) -> dict[str, Any]:
    """Compare two stored audit records and return a regression report."""
    before_result = before_record["result"]
    after_result = after_record["result"]

    before_groups = _group_controls(before_result)
    after_groups = _group_controls(after_result)

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    position_changed: list[dict[str, Any]] = []
    pairing_changed: list[dict[str, Any]] = []

    for abbr in sorted(set(before_groups) | set(after_groups)):
        before_seq = before_groups.get(abbr, [])
        after_seq = after_groups.get(abbr, [])
        paired = min(len(before_seq), len(after_seq))

        for index in range(paired):
            before_ctrl = before_seq[index]
            after_ctrl = after_seq[index]
            move = _position_change(before_ctrl, after_ctrl)
            if move is not None:
                position_changed.append(move)
            scope = _pairing_change(before_ctrl, after_ctrl)
            if scope is not None:
                pairing_changed.append(scope)

        for control in after_seq[paired:]:
            added.append({"abbreviation": abbr, "occurrence": control["occurrence"],
                          "control": control})
        for control in before_seq[paired:]:
            removed.append({"abbreviation": abbr, "occurrence": control["occurrence"],
                            "control": control})

    # New / vanished controls read best in document order, not grouped by name.
    added.sort(key=lambda item: item["control"]["logical_index"])
    removed.sort(key=lambda item: item["control"]["logical_index"])
    position_changed.sort(key=lambda item: item["before"]["logical_index"])
    pairing_changed.sort(key=lambda item: item["before"]["logical_index"])

    risk = _risk_diff(before_result["risk_level"], after_result["risk_level"])
    error_count = {
        "before": before_result["error_count"],
        "after": after_result["error_count"],
        "changed": before_result["error_count"] != after_result["error_count"],
        "delta": after_result["error_count"] - before_result["error_count"],
    }

    changed = bool(
        risk["changed"]
        or error_count["changed"]
        or added
        or removed
        or position_changed
        or pairing_changed
    )

    return {
        "before_id": before_record["id"],
        "after_id": after_record["id"],
        "changed": changed,
        "risk": risk,
        "error_count": error_count,
        "control_changes": {
            "added": added,
            "removed": removed,
            "position_changed": position_changed,
            "pairing_changed": pairing_changed,
        },
        "summary": {
            "before": _summary(before_record),
            "after": _summary(after_record),
        },
    }
