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
* ``partialFingerprints`` is a stable SHA-256 over rule id, codepoint and
  codepoint range -- it does not depend on the database row id, so re-auditing
  the same content maps to the same fingerprint;
* rules and results are emitted in a fixed sorted order.
"""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_right
from typing import Any
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
    index = _TextIndex(text)

    filename = record.get("filename")
    uri = filename if filename else f"audit-{audit_id}"
    artifact_uri = quote(uri.replace("\\", "/"), safe="/:")

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
        region = index.region(idx, idx + 1)
        region["snippet"] = {"text": escape_preview(text[idx])}
        findings.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[control["risk"]],
            "message": {"text": error},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": region,
                }
            }],
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
        region = index.region(start, end)
        region["snippet"] = {"text": escaped}
        findings.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[span["risk"]],
            "message": {"text": span["reason"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": region,
                }
            }],
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
