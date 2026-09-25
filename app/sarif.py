"""SARIF 2.1.0 export for stored bidi audit records.

Each stored audit (``raw_text`` + persisted parse ``result``) is converted into
a SARIF 2.1.0 document suitable for code-scanning platforms (GitHub code
scanning, Azure DevOps SARIF importer, ...):

* every control-character **error** (unclosed opener, orphan PDF/PDI, nesting
  depth overflow) becomes one ``result`` anchored on that single control;
* every **dangerous span** (RLO/LRO override scope, unclosed scope) becomes one
  ``result`` anchored on the full span;
* the per-finding ``risk`` maps to SARIF ``level``
  (critical/high -> error, medium -> warning, low/info -> note);
* regions use 1-based **UTF-16 code-unit** columns, recomputed from the stored
  original text line by line (as required by the SARIF specification);
* records created by the unified-diff auditor are relocated to the audited
  **new file's** real line numbers via ``meta.added_lines``: the rebuilt
  ``raw_text`` concatenates added lines that may be far apart in the new file,
  so rebuilt line numbers are never used directly; a span crossing unaudited
  lines between non-consecutive additions is emitted as one result with one
  physical location per contiguous run of audited added lines only;
* ``partialFingerprints`` is a stable SHA-256 over rule id, codepoint and
  codepoint range -- it does not depend on the database row id, so re-auditing
  the same content maps to the same fingerprint;
* rules and results are emitted in a fixed sorted order.
"""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_right
from typing import Any, Optional
from urllib.parse import quote

from .bidi import escape_preview

SARIF_VERSION = "2.1.0"
SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/"
    "sarif-schema-2.1.0.json"
)
TOOL_NAME = "bidi-audit"
TOOL_VERSION = "1.0.0"
FINGERPRINT_KEY = "bidi-audit/v1/sha256"

# risk -> SARIF result level (note | warning | error)
_SARIF_LEVEL = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}

# risk -> GitHub code-scanning security severity (used in rule properties)
_SECURITY_SEVERITY = {
    "info": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# Human-readable noun used in rule descriptions.
_NOUN = {
    "LRE": "left-to-right embedding",
    "RLE": "right-to-left embedding",
    "LRO": "left-to-right override",
    "RLO": "right-to-left override",
    "LRI": "left-to-right isolate",
    "RLI": "right-to-left isolate",
    "FSI": "first-strong isolate",
}

_TROJAN_NOTE = (
    "Bidirectional control characters can reorder the visual rendering of "
    "source code while leaving its logical order unchanged (Trojan Source / "
    "CVE-2021-42574)."
)


# ---------------------------------------------------------------------------
# Text indexing: logical (code-point) offset -> line + UTF-16 column
# ---------------------------------------------------------------------------

class _TextIndex:
    """Map Python str indices (code points) to 1-based line/UTF-16 columns."""

    def __init__(self, text: str) -> None:
        self._text = text
        # Offset of the first code point of every line (line 1 starts at 0).
        self._line_starts = [0]
        # UTF-16 length of the whole text up to (but excluding) code point i:
        # utf16_prefix[i] == sum of UTF-16 widths of text[:i].
        self._utf16_prefix = [0]
        for i, ch in enumerate(text):
            self._utf16_prefix.append(
                self._utf16_prefix[-1] + _utf16_width(ch)
            )
            if ch == "\n":
                self._line_starts.append(i + 1)

    def _line_col(self, index: int) -> tuple[int, int]:
        line = bisect_right(self._line_starts, index)
        line_start = self._line_starts[line - 1]
        column = self._utf16_prefix[index] - self._utf16_prefix[line_start] + 1
        return line, column

    def region(self, start: int, end: int) -> dict[str, int]:
        """SARIF region for the half-open code-point range ``[start, end)``.

        Columns are 1-based UTF-16 code units; ``endColumn`` points just past
        the last covered character (exclusive), per SARIF §3.30.4.
        """
        start_line, start_column = self._line_col(start)
        # End position: just past the last covered code point.
        last = max(start, end - 1)
        end_line, last_column = self._line_col(last)
        end_column = last_column + _utf16_width(self._text[last])
        return {
            "startLine": start_line,
            "startColumn": start_column,
            "endLine": end_line,
            "endColumn": end_column,
        }


def _utf16_width(ch: str) -> int:
    """UTF-16 code units occupied by one code point (1 BMP, 2 astral)."""
    return 2 if ord(ch) > 0xFFFF else 1


# ---------------------------------------------------------------------------
# Locators: parser offsets -> SARIF physical locations
# ---------------------------------------------------------------------------

class _PlainLocator:
    """Locate offsets in ``raw_text`` taken verbatim as the artifact."""

    def __init__(self, text: str, artifact_uri: str) -> None:
        self._index = _TextIndex(text)
        self._artifact_uri = artifact_uri

    def control_locations(self, start: int, end: int) -> list[dict[str, Any]]:
        return [self._physical(self._index.region(start, end))]

    def span_locations(self, start: int, end: int) -> list[dict[str, Any]]:
        return [self._physical(self._index.region(start, end))]

    def _physical(self, region: dict[str, int]) -> dict[str, Any]:
        return {"physicalLocation": {
            "artifactLocation": {"uri": self._artifact_uri},
            "region": region,
        }}


class _DiffLocator:
    """Locate parser offsets in a unified-diff record's *new file*.

    The parser ran on ``raw_text``, which is the concatenation of the diff's
    added lines; the mapping from each rebuilt-text byte range to the real
    new-file line number comes from ``meta.added_lines``.  Added lines that
    are not consecutive in the new file sit in different hunks, with context,
    removed and untouched lines between them: those gaps are **not audited**
    and must never be covered by a result region.
    """

    def __init__(self, text: str, artifact_uri: str, added_lines: list[dict]):
        self._text = text
        self._artifact_uri = artifact_uri
        self._entries = self._build_entries(text, added_lines)

    @staticmethod
    def _build_entries(text: str, added_lines: list[dict]) -> list[dict]:
        """Attach a half-open rebuilt-text range to every added-line entry.

        Prefer the explicit ``rebuilt_start``/``rebuilt_end`` persisted with
        the record; reconstruct the ranges for older records that only stored
        ``no_newline``.  The reconstruction walks ``raw_text`` line by line;
        a ``no_newline`` entry not at the end of the additions is a structure
        git never emits (a missing newline splits a hunk at end of file), so
        its exact boundary is unrecoverable and it maps to an empty range.
        """
        entries: list[dict] = []
        offset = 0
        for k, meta_entry in enumerate(added_lines):
            start = meta_entry.get("rebuilt_start")
            end = meta_entry.get("rebuilt_end")
            if start is not None and end is not None:
                entries.append({
                    "new_line": meta_entry["new_line"],
                    "start": start,
                    "end": end,
                })
                continue
            no_newline = meta_entry.get("no_newline", False)
            if no_newline and k + 1 < len(added_lines):
                line_start = offset
                line_end = offset
            elif offset >= len(text):
                line_start = line_end = len(text)
            else:
                line_start = offset
                nl = text.find("\n", offset)
                if nl == -1:
                    line_end = len(text)
                else:
                    line_end = nl + 1
            entries.append({
                "new_line": meta_entry["new_line"],
                "start": line_start,
                "end": line_end,
            })
            offset = line_end
        return entries

    def _entry_at(self, offset: int) -> int:
        """Index of the entry whose rebuilt range covers ``offset``.

        An offset on the synthetic ``\\n`` of an entry belongs to that entry.
        An offset past every range (e.g. the exclusive end at ``len(text)``)
        clamps to the last entry.
        """
        for k, entry in enumerate(self._entries):
            if entry["start"] <= offset < entry["end"]:
                return k
        return len(self._entries) - 1

    def _utf16_column(self, entry: dict, offset: int) -> int:
        """1-based UTF-16 column of ``offset`` within one added line."""
        column = 1
        line_start = entry["start"]
        for i in range(line_start, offset):
            column += _utf16_width(self._text[i])
        return column

    def _line_end_column(self, entry: dict) -> int:
        """Exclusive UTF-16 column just past the line's content (its ``\\n``
        edge), so the region ends on the audited line without covering the
        following, possibly unaudited, new-file line."""
        content_end = entry["end"]
        if (
            entry["end"] > entry["start"]
            and self._text[entry["end"] - 1] == "\n"
        ):
            content_end -= 1
        column = 1
        for i in range(entry["start"], content_end):
            column += _utf16_width(self._text[i])
        return column

    def _region(self, first: dict, last: dict) -> dict[str, int]:
        if first["k"] == last["k"]:
            start_line = first["new_line"]
            start_column = self._utf16_column(first["entry"], first["offset"])
            end_line = last["new_line"]
            end_column = self._end_column(last["entry"], last["offset"])
            return {
                "startLine": start_line,
                "startColumn": start_column,
                "endLine": end_line,
                "endColumn": end_column,
            }
        return {
            "startLine": first["new_line"],
            "startColumn": self._utf16_column(
                first["entry"], first["offset"]
            ),
            "endLine": last["new_line"],
            "endColumn": self._line_end_column(last["entry"]),
        }

    def _end_column(self, entry: dict, offset: int) -> int:
        """Exclusive UTF-16 column just past the code point at ``offset``.

        When ``offset`` is the entry's synthetic ``\\n`` separator, clamp to
        the end of the line content: the next new-file line may be an
        unaudited gap line and must never be covered.
        """
        if (
            offset < len(self._text)
            and self._text[offset] != "\n"
        ):
            return self._utf16_column(entry, offset) + _utf16_width(
                self._text[offset]
            )
        return self._line_end_column(entry)

    def _physical(self, region: dict[str, int]) -> dict[str, Any]:
        return {"physicalLocation": {
            "artifactLocation": {"uri": self._artifact_uri},
            "region": region,
        }}

    def control_locations(self, start: int, end: int) -> list[dict[str, Any]]:
        k = self._entry_at(start)
        entry = self._entries[k]
        region = self._region(
            {"entry": entry, "new_line": entry["new_line"],
             "offset": start, "k": k},
            {"entry": entry, "new_line": entry["new_line"],
             "offset": end - 1, "k": k},
        )
        return [self._physical(region)]

    def span_locations(self, start: int, end: int) -> list[dict[str, Any]]:
        """Split ``[start, end)`` into one location per contiguous run.

        Entries with consecutive new-file line numbers belong to one region;
        a jump in line numbers means unaudited lines in between, which start
        a new region.  A region covering only part of its first entry begins
        at ``start``; a region covering only part of its last entry ends at
        ``end``; whole-entry runs include the synthetic line terminator.
        """
        half_open_end = end
        # The exclusive end points "just past" the last covered code point.
        last_offset = max(start, end - 1)
        first_k = self._entry_at(start)
        last_k = self._entry_at(last_offset)

        # Group the covered entry indices into runs of consecutive new-file
        # line numbers.
        groups: list[list[int]] = []
        current = [first_k]
        prev_line = self._entries[first_k]["new_line"]
        for k in range(first_k + 1, last_k + 1):
            new_line = self._entries[k]["new_line"]
            if new_line != prev_line + 1:
                groups.append(current)
                current = []
            current.append(k)
            prev_line = new_line
        groups.append(current)

        locations: list[dict[str, Any]] = []
        for group in groups:
            g_first_k = group[0]
            g_last_k = group[-1]
            first_entry = self._entries[g_first_k]
            last_entry = self._entries[g_last_k]
            first_offset = max(start, first_entry["start"])
            # Last covered code point within this group.
            group_cover_end = min(half_open_end, last_entry["end"])
            last_covered = max(first_offset, group_cover_end - 1)
            region = self._region(
                {"entry": first_entry,
                 "new_line": first_entry["new_line"],
                 "offset": first_offset, "k": g_first_k},
                {"entry": last_entry,
                 "new_line": last_entry["new_line"],
                 "offset": last_covered, "k": g_last_k},
            )
            locations.append(self._physical(region))
        return locations


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------

def _fingerprint(rule_id: str, codepoint: str, start: int, end: int) -> dict[str, str]:
    basis = f"{rule_id}|{codepoint}|{start}|{end}".encode("utf-8")
    digest = hashlib.sha256(basis).hexdigest()
    return {FINGERPRINT_KEY: digest}


# ---------------------------------------------------------------------------
# Rule catalogue
# ---------------------------------------------------------------------------

def _rule(
    rule_id: str,
    name: str,
    risk: str,
    short: str,
    full: str,
    tags: list[str],
) -> dict[str, Any]:
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": short},
        "fullDescription": {"text": full},
        "defaultConfiguration": {"level": _SARIF_LEVEL[risk]},
        "properties": {
            "tags": tags,
            "security-severity": _SECURITY_SEVERITY[risk],
        },
    }


def _unclosed_control_rule(abbr: str, codepoint: str) -> tuple[str, dict[str, Any]]:
    noun = _NOUN.get(abbr, "bidi scope")
    risk = "critical" if abbr in ("RLO", "LRO") else "medium"
    rule_id = f"bidi/unclosed-{abbr}"
    rule = _rule(
        rule_id,
        f"Unclosed{abbr}",
        risk,
        f"Unclosed {abbr} ({noun}, {codepoint}) scope",
        (
            f"The {noun} opened by {abbr} ({codepoint}) is never terminated by "
            "its matching closer, so its directional effect extends to the end "
            "of the text. " + _TROJAN_NOTE
        ),
        ["security", "unicode", "bidi", "unclosed"],
    )
    return rule_id, rule


def _implicit_control_rule(abbr: str, codepoint: str) -> tuple[str, dict[str, Any]]:
    noun = _NOUN.get(abbr, "bidi scope")
    rule_id = f"bidi/unclosed-{abbr}"
    rule = _rule(
        rule_id,
        f"Unclosed{abbr}",
        "medium",
        f"Implicitly terminated {abbr} ({noun}, {codepoint}) scope",
        (
            f"The {noun} opened by {abbr} ({codepoint}) is never closed by its "
            "own PDF and is implicitly terminated by a PDI. " + _TROJAN_NOTE
        ),
        ["security", "unicode", "bidi", "unclosed"],
    )
    return rule_id, rule


def _orphan_closer_rule(abbr: str, codepoint: str) -> tuple[str, dict[str, Any]]:
    if abbr == "PDF":
        short = "PDF without a matching embedding opener"
        full = (
            "A POP DIRECTIONAL FORMATTING character (PDF, U+202C) has no "
            "matching LRE/RLE/LRO/RLO opener to terminate."
        )
        name = "OrphanPDF"
    else:  # PDI
        short = "PDI without a matching isolate initiator"
        full = (
            "A POP DIRECTIONAL ISOLATE character (PDI, U+2069) has no matching "
            "LRI/RLI/FSI isolate initiator to terminate."
        )
        name = "OrphanPDI"
    rule_id = f"bidi/orphan-{abbr}"
    rule = _rule(
        rule_id, name, "medium", short, full,
        ["security", "unicode", "bidi", "orphan-closer"],
    )
    return rule_id, rule


def _depth_rule() -> tuple[str, dict[str, Any]]:
    rule_id = "bidi/nesting-depth-limit"
    rule = _rule(
        rule_id,
        "BidiNestingDepthLimitExceeded",
        "critical",
        "Bidirectional nesting depth limit exceeded",
        (
            "The explicit bidirectional embedding/isolate nesting depth limit "
            "(UAX #9, rule BD13) was exceeded; the offending control character "
            "is ignored by conformant parsers, which usually signals a "
            "malformed or malicious payload."
        ),
        ["security", "unicode", "bidi", "depth-limit"],
    )
    return rule_id, rule


def _span_rule(opener: str, codepoint: str) -> tuple[str, dict[str, Any]]:
    """One rule per opener; covers both balanced and unclosed dangerous spans.

    Default level: override openers (RLO/LRO) are ``error``; unclosed
    embedding/isolate scopes are ``warning``. Each result still carries its
    own effective ``level`` mapped from its ``risk``.
    """
    is_override = opener in ("RLO", "LRO")
    risk = "high" if is_override else "medium"
    rule_id = f"bidi/span-{opener}"
    rule = _rule(
        rule_id,
        f"Dangerous{opener}Span",
        risk,
        f"Dangerous {opener} bidirectional scope ({codepoint})",
        (
            f"The {_NOUN.get(opener, 'bidirectional scope')} opened by "
            f"{opener} ({codepoint}) forces visual reordering of its "
            "contents; if never closed the effect extends to the end of the "
            "text, which can hide malicious characters behind benign-looking "
            "code. " + _TROJAN_NOTE
        ),
        ["security", "unicode", "bidi", "dangerous-span"]
        + (["override"] if is_override else ["unclosed"]),
    )
    return rule_id, rule


# ---------------------------------------------------------------------------
# Finding extraction
# ---------------------------------------------------------------------------

# Every parser error starts with "ABBR at logical index N (...)"; map each
# error back to its control via that index so error ordering is irrelevant.
_ERROR_INDEX_RE = re.compile(r"at logical index (\d+)")


def _errors_by_index(errors: list[str]) -> dict[int, str]:
    by_index: dict[int, str] = {}
    for message in errors:
        match = _ERROR_INDEX_RE.search(message)
        if match:
            by_index[int(match.group(1))] = message
    return by_index


def _classify_control_error(control: dict[str, Any], error: str) -> str:
    """Return one of: depth, orphan_closer, implicit, unclosed."""
    if "depth limit" in error:
        return "depth"
    if control["scope_end"] is None:
        # Lone PDF / PDI: never had a scope opened for it.
        return "orphan_closer"
    if control.get("paired_with") == "U+2069(implicit)":
        return "implicit"
    return "unclosed"


def _result_sort_key(result: dict[str, Any]) -> tuple:
    region = result["locations"][0]["physicalLocation"]["region"]
    return (
        region["startLine"],
        region["startColumn"],
        result["ruleId"],
        region["endLine"],
        region["endColumn"],
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def build_sarif(record: dict[str, Any]) -> dict[str, Any]:
    """Convert a stored audit record (as returned by ``get_audit``) to SARIF."""
    audit_id = record["id"]
    text = record["raw_text"]
    result = record["result"]

    filename = record.get("filename")
    uri = filename if filename else f"audit-{audit_id}"
    artifact_uri = quote(uri.replace("\\", "/"), safe="/:")

    # Unified-diff records audit only the added lines, concatenated in
    # new-file order; relocate findings to the real new-file line numbers
    # instead of treating the rebuilt text as a contiguous document.
    meta = record.get("meta") or {}
    if meta.get("source") == "unified_diff":
        locator: Any = _DiffLocator(
            text, artifact_uri, meta.get("added_lines", [])
        )
    else:
        locator = _PlainLocator(text, artifact_uri)

    # abbreviation -> codepoint, from the stored controls (first occurrence).
    codepoint_by_abbr: dict[str, str] = {}
    for control in result.get("controls", []):
        codepoint_by_abbr.setdefault(control["abbreviation"], control["codepoint"])

    # Parser errors and controls are joined via the logical index embedded in
    # every error message (errors are not emitted in document order).
    errors_by_index = _errors_by_index(result.get("errors", []))
    rules: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []

    # ---- control-character errors ----------------------------------------
    for control in result.get("controls", []):
        if not control.get("is_orphan"):
            continue
        error = errors_by_index.get(control["logical_index"])
        if error is None:
            # Defensive: every is_orphan control has a parser error today.
            idx0 = control["logical_index"]
            error = (
                f"{control['abbreviation']} ({control['codepoint']}) at logical "
                f"index {idx0} (line {control['position']['line']}, "
                f"col {control['position']['column']})"
            )
        kind = _classify_control_error(control, error)
        abbr = control["abbreviation"]
        codepoint = control["codepoint"]

        if kind == "depth":
            rule_id, rule = _depth_rule()
        elif kind == "orphan_closer":
            rule_id, rule = _orphan_closer_rule(abbr, codepoint)
        elif kind == "implicit":
            rule_id, rule = _implicit_control_rule(abbr, codepoint)
        else:
            rule_id, rule = _unclosed_control_rule(abbr, codepoint)
        rules.setdefault(rule_id, rule)

        idx = control["logical_index"]
        locations = locator.control_locations(idx, idx + 1)
        locations[0]["physicalLocation"]["region"]["snippet"] = {
            "text": escape_preview(text[idx])
        }
        findings.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[control["risk"]],
            "message": {"text": error},
            "locations": locations,
            "partialFingerprints": _fingerprint(rule_id, codepoint, idx, idx + 1),
            "properties": {
                "codepoint": codepoint,
                "abbreviation": abbr,
                "logical_index": idx,
                "escaped": escape_preview(text[idx]),
            },
        })

    # ---- dangerous spans ---------------------------------------------------
    for span in result.get("dangerous_spans", []):
        start = span["start"]
        end = span["end"]
        opener = span["opener"]
        codepoint = codepoint_by_abbr.get(opener, opener)
        rule_id, rule = _span_rule(opener, codepoint)
        rules.setdefault(rule_id, rule)

        raw = text[start:end]
        escaped = span.get("escaped_preview") or escape_preview(raw)
        locations = locator.span_locations(start, end)
        # Attach the logical-order preview to the first (primary) location.
        locations[0]["physicalLocation"]["region"]["snippet"] = {
            "text": escaped
        }
        findings.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[span["risk"]],
            "message": {"text": span["reason"]},
            "locations": locations,
            "partialFingerprints": _fingerprint(rule_id, codepoint, start, end),
            "properties": {
                "opener": opener,
                "codepoint": codepoint,
                "logical_index": {"start": start, "end": end},
                "escaped_preview": escaped,
            },
        })

    findings.sort(key=_result_sort_key)

    return {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "semanticVersion": TOOL_VERSION,
                    "rules": [rules[key] for key in sorted(rules)],
                }
            },
            "invocations": [{"executionSuccessful": True}],
            "results": findings,
        }],
    }
