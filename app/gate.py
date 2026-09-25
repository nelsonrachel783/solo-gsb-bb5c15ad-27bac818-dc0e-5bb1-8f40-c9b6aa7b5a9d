"""Path-based risk gate for a batch of stored audit records.

Given a default maximum tolerated risk and an ordered list of path rules,
each record is matched against the file name stored on it.  Rule templates
are split on ``/`` into segments.  Within a segment, ``*`` matches any run
of characters but never crosses ``/`` (so ``*.py`` matches one segment);
a standalone ``**`` segment matches zero or more whole segments.  Segments
without ``*`` are literal (fixed) matches.

When several rules match a path the most specific one wins: first by the
number of literal (fixed) segments, then by the total number of template
segments, then by request order.  Records without a file name, or whose file
name matches no rule, fall back to the default threshold.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional, Sequence

RISK_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Wildcard segment token for "zero or more segments".
MATCH_MANY = "**"


@lru_cache(maxsize=1024)
def _segment_regex(segment: str) -> "re.Pattern[str]":
    """Compile one template segment to an anchored regex.

    ``*`` matches any run of characters *within* the segment; everything
    else is literal.  A segment never spans ``/`` because templates and
    paths are matched segment by segment.
    """
    parts = [re.escape(piece) for piece in segment.split("*")]
    return re.compile(".*".join(parts) + r"\Z")


@dataclass(frozen=True)
class GateRule:
    """One ordered path rule from the gate request."""

    index: int
    template: str
    max_risk: str
    segments: tuple[str, ...]
    fixed_segments: int

    @classmethod
    def make(cls, index: int, template: str, max_risk: str) -> "GateRule":
        segments = tuple(template.split("/"))
        fixed = sum(1 for segment in segments if "*" not in segment)
        return cls(index, template, max_risk, segments, fixed)


def _segments_match(template_segment: str, path_segment: str) -> bool:
    """Match a single path segment against one template segment.

    ``**`` also matches one segment here -- the zero-or-more-segments
    behaviour is handled by the segment-level dynamic program in
    :func:`_template_matches`.
    """
    if template_segment == MATCH_MANY:
        return True
    return _segment_regex(template_segment).match(path_segment) is not None


def _template_matches(
    template: Sequence[str], segments: Sequence[str]
) -> bool:
    """Match template segments against path segments.

    ``*`` matches within a single segment, ``**`` matches zero or more
    segments.  Dynamic program over template/path segment positions so
    consecutive ``**`` tokens and ``**`` in the middle of a template work
    correctly.
    """
    matched = [[False] * (len(segments) + 1) for _ in range(len(template) + 1)]
    matched[0][0] = True
    for ti, token in enumerate(template, start=1):
        # A segment position of 0: only "**" can consume zero segments.
        matched[ti][0] = matched[ti - 1][0] and token == MATCH_MANY
        for pi, segment in enumerate(segments, start=1):
            if token == MATCH_MANY:
                # Consume zero segments (same template token, prior segment
                # position) or one more segment (prior template token).
                matched[ti][pi] = matched[ti][pi - 1] or matched[ti - 1][pi]
            else:
                matched[ti][pi] = (
                    matched[ti - 1][pi - 1] and _segments_match(token, segment)
                )
    return matched[len(template)][len(segments)]


def select_rule(filename: str, rules: Sequence[GateRule]) -> Optional[GateRule]:
    """Select the most specific matching rule for a file name.

    Tie-breaks, in order: more literal segments, more total template
    segments, earlier request order.  ``None`` when nothing matches.
    """
    segments = tuple(filename.split("/"))
    best: Optional[GateRule] = None
    for rule in rules:
        if not _template_matches(rule.segments, segments):
            continue
        if best is None or (
            rule.fixed_segments,
            len(rule.segments),
            # earlier order must win, so compare negatively against the best
            -rule.index,
        ) > (best.fixed_segments, len(best.segments), -best.index):
            best = rule
    return best


def evaluate_record(
    record: dict,
    default_max_risk: str,
    rules: Sequence[GateRule],
) -> dict:
    """Apply the gate to one stored audit record (read-only)."""
    filename = record.get("filename")
    actual = record["risk_level"]
    matched_rule: Optional[GateRule] = None
    used_default = True

    if isinstance(filename, str) and filename.strip():
        matched_rule = select_rule(filename, rules)

    if matched_rule is not None:
        threshold = matched_rule.max_risk
        used_default = False
    else:
        threshold = default_max_risk

    passed = RISK_ORDER[actual] <= RISK_ORDER[threshold]

    return {
        "id": record["id"],
        "filename": filename,
        "actual_risk": actual,
        "threshold": threshold,
        "matched_rule": None
        if matched_rule is None
        else {
            "index": matched_rule.index,
            "template": matched_rule.template,
            "max_risk": matched_rule.max_risk,
        },
        "used_default": used_default,
        "passed": passed,
    }
