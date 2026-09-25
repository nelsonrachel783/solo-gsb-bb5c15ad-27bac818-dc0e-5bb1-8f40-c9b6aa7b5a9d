"""Unicode bidirectional control-character parser.

Implements the pairing/nesting rules of UAX #9 (Unicode Bidirectional
Algorithm) for the *explicit embedding/override* controls (LRE/RLE/LRO/RLO/PDF)
and tracks the *isolates* (LRI/RLI/FSI/PDI), plus reports all other bidi
controls (RLM/LRM/ALM).

Nothing here mutates the supplied text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Character catalogue
# ---------------------------------------------------------------------------

class BidiKind(str, Enum):
    MARK = "mark"                    # LRM/RLM/ALM : zero-width, no pairing
    EMBEDDING = "embedding"          # LRE/RLE : push + PDF pops
    OVERRIDE = "override"            # LRO/RLO : push + PDF pops
    ISOLATE_INITIATOR = "isolate_initiator"  # LRI/RLI/FSI : push + PDI pops
    ISOLATE_TERMINATOR = "isolate_terminator"  # PDI
    POP_DIRECTIONAL = "pop_directional"        # PDF
    SEPARATOR = "separator"          # first-strong applies to following run
    INVISIBLE = "invisible"          # other formatting/zero-width chars


# codepoint -> (abbreviation, name, kind, opening?, visualised glyph?)
_BIDI_TABLE: dict[int, tuple[str, str, BidiKind, bool, str]] = {
    0x200E: ("LRM", "LEFT-TO-RIGHT MARK", BidiKind.MARK, False, ""),
    0x200F: ("RLM", "RIGHT-TO-LEFT MARK", BidiKind.MARK, False, ""),
    0x061C: ("ALM", "ARABIC LETTER MARK", BidiKind.MARK, False, ""),

    0x202A: ("LRE", "LEFT-TO-RIGHT EMBEDDING", BidiKind.EMBEDDING, True, ""),
    0x202B: ("RLE", "RIGHT-TO-LEFT EMBEDDING", BidiKind.EMBEDDING, True, ""),
    0x202D: ("LRO", "LEFT-TO-RIGHT OVERRIDE", BidiKind.EMBEDDING, True, ""),
    0x202E: ("RLO", "RIGHT-TO-LEFT OVERRIDE", BidiKind.OVERRIDE, True, ""),
    0x202C: ("PDF", "POP DIRECTIONAL FORMATTING", BidiKind.POP_DIRECTIONAL, False, ""),

    0x2066: ("LRI", "LEFT-TO-RIGHT ISOLATE", BidiKind.ISOLATE_INITIATOR, True, ""),
    0x2067: ("RLI", "RIGHT-TO-LEFT ISOLATE", BidiKind.ISOLATE_INITIATOR, True, ""),
    0x2068: ("FSI", "FIRST STRONG ISOLATE", BidiKind.ISOLATE_INITIATOR, True, ""),
    0x2069: ("PDI", "POP DIRECTIONAL ISOLATE", BidiKind.ISOLATE_TERMINATOR, False, ""),

    # UBA separators (no nesting, but widely abused; reported as info)
    0x2061: ("FSA", "FUNCTION APPLICATION", BidiKind.SEPARATOR, False, ""),
    0x2062: ("ITS", "INVISIBLE TIMES", BidiKind.SEPARATOR, False, ""),
    0x2063: ("ISS", "INVISIBLE SEPARATOR", BidiKind.SEPARATOR, False, ""),
    0x2064: ("IPF", "INVISIBLE PLUS", BidiKind.SEPARATOR, False, ""),
}

# Deprecated in UAX #9 but still honoured for pairing depth by parsers.
EMBEDDING_OPENERS = {0x202A, 0x202B, 0x202D, 0x202E}
ISOLATE_OPENERS = {0x2066, 0x2067, 0x2068}

#: Codepoints of every character the parser treats as a bidi control.
BIDI_CONTROL_CODEPOINTS = frozenset(_BIDI_TABLE)


def control_abbreviation(codepoint: int) -> Optional[str]:
    """Abbreviation (``"RLO"`` ...) of the bidi control at ``codepoint``,
    or ``None`` when the character is not a known bidi control."""
    info = _BIDI_TABLE.get(codepoint)
    return info[0] if info is not None else None

# Limit from BD13 (61) plus the isolate level; exceeding it is an error.
MAX_DEPTH = 125


class RiskLevel(str, Enum):
    INFO = "info"          # harmless marks (LRM/RLM/ALM), separators
    LOW = "low"            # balanced embedding / isolate
    MEDIUM = "medium"      # RLE/LRE or unclosed isolate, lone PDF
    HIGH = "high"          # RLO / LRO present anywhere
    CRITICAL = "critical"  # unclosed override OR depth overflow


@dataclass
class ControlHit:
    codepoint: str          # "U+202E"
    abbreviation: str       # "RLO"
    name: str
    kind: BidiKind
    logical_index: int      # Python str index (code point offset)
    line: int
    column: int             # 1-based code point column on the line
    depth_after: int        # explicit nesting depth right after this char
    scope_end: Optional[int] = None   # logical index of matching closer
    paired_with: Optional[str] = None # codepoint of the matching closer/opener
    is_orphan: bool = False           # opener with no closer / closer with no opener
    risk: RiskLevel = RiskLevel.INFO

    def to_dict(self) -> dict:
        return {
            "codepoint": self.codepoint,
            "abbreviation": self.abbreviation,
            "name": self.name,
            "kind": self.kind.value,
            "logical_index": self.logical_index,
            "position": {"line": self.line, "column": self.column},
            "depth_after": self.depth_after,
            "scope_end": self.scope_end,
            "paired_with": self.paired_with,
            "is_orphan": self.is_orphan,
            "risk": self.risk.value,
        }


@dataclass
class DangerousSpan:
    start: int
    end: int                # exclusive, logical indices
    reason: str             # e.g. "unclosed RLO override"
    opener: str
    risk: RiskLevel
    raw: str = ""           # original substring (order untouched)
    escaped_preview: str = ""  # readable, escaped representation

    def to_dict(self) -> dict:
        return {
            "start": self.start,
            "end": self.end,
            "reason": self.reason,
            "opener": self.opener,
            "risk": self.risk.value,
            "raw": self.raw,
            "escaped_preview": self.escaped_preview,
        }


@dataclass
class ParseResult:
    text: str
    controls: list[ControlHit] = field(default_factory=list)
    spans: list[DangerousSpan] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    max_depth: int = 0
    risk: RiskLevel = RiskLevel.INFO
    stats: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        order = {
            RiskLevel.INFO: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4,
        }
        return {
            "length": len(self.text),
            "max_depth": self.max_depth,
            "risk_level": self.risk.value,
            "error_count": len(self.errors),
            "errors": self.errors,
            "controls": [c.to_dict() for c in self.controls],
            "dangerous_spans": [s.to_dict() for s in self.spans],
            "stats": self.stats,
        }


# ---------------------------------------------------------------------------
# Escaping -- keep the *logical* (reading) order, render every bidi control
# and other invisible format character visibly.
# ---------------------------------------------------------------------------

def _escape_char(ch: str) -> str:
    cp = ord(ch)
    if cp in _BIDI_TABLE:
        return f"⟨{_BIDI_TABLE[cp][0]}⟩"
    # other invisible / formatting characters worth exposing
    if ch in ("\t",):
        return "\\t"
    if ch in ("\r",):
        return "\\r"
    if ch in ("\n",):
        return "\\n"
    if 0x200B <= cp <= 0x200F or 0x2028 <= cp <= 0x202F or 0x2060 <= cp <= 0x2069 \
            or cp in (0xFEFF, 0x00AD, 0x034F, 0x061C, 0x180E) \
            or 0xE0000 <= cp <= 0xE007F:
        return f"⟨U+{cp:04X}⟩"
    # other non-printable controls
    if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
        return f"⟨U+{cp:04X}⟩"
    return ch


def escape_preview(segment: str) -> str:
    """Return *segment* in logical order with bidi/invisible chars rendered
    as readable placeholders such as ``⟨RLO⟩`` / ``⟨U+200B⟩``."""
    return "".join(_escape_char(ch) for ch in segment)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _line_col(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    last_nl = text.rfind("\n", 0, index)
    column = index - last_nl  # 1-based (index just after newline -> col 1)
    return line, column


def parse_bidi(text: str) -> ParseResult:
    result = ParseResult(text=text)

    # Unified stack: ("emb", hit_idx) waits for PDF; ("iso", hit_idx) waits
    # for PDI. A PDF searches past open isolates to find its embedding (X9).
    stack: list[tuple[str, int]] = []

    _RISK_ORDER = {
        RiskLevel.INFO: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4,
    }

    overall = RiskLevel.INFO
    def raise_risk(level: RiskLevel):
        nonlocal overall
        if _RISK_ORDER[level] > _RISK_ORDER[overall]:
            overall = level

    counts: dict[str, int] = {}

    for i, ch in enumerate(text):
        cp = ord(ch)
        info = _BIDI_TABLE.get(cp)
        if info is None:
            continue
        abbr, name, kind, _is_opener, _glyph = info
        counts[abbr] = counts.get(abbr, 0) + 1
        line, column = _line_col(text, i)

        hit = ControlHit(
            codepoint=f"U+{cp:04X}",
            abbreviation=abbr,
            name=name,
            kind=kind,
            logical_index=i,
            line=line,
            column=column,
            depth_after=len(stack),
        )

        if kind in (BidiKind.EMBEDDING, BidiKind.OVERRIDE):
            # X2..X5: push
            if len(stack) >= MAX_DEPTH:
                hit.is_orphan = True
                hit.risk = RiskLevel.CRITICAL
                result.errors.append(
                    f"{abbr} at logical index {i} (line {line}, col {column}) "
                    f"ignored: explicit nesting depth limit ({MAX_DEPTH}) exceeded"
                )
                raise_risk(RiskLevel.CRITICAL)
            else:
                stack.append(("emb", len(result.controls)))
                hit.depth_after = len(stack)
                if kind is BidiKind.OVERRIDE:
                    hit.risk = RiskLevel.HIGH
                    raise_risk(RiskLevel.HIGH)
                else:
                    hit.risk = RiskLevel.LOW
                    raise_risk(RiskLevel.LOW)

        elif kind is BidiKind.ISOLATE_INITIATOR:
            # X5a..X5c
            if len(stack) >= MAX_DEPTH:
                hit.is_orphan = True
                hit.risk = RiskLevel.CRITICAL
                result.errors.append(
                    f"{abbr} at logical index {i} (line {line}, col {column}) "
                    f"ignored: explicit nesting depth limit ({MAX_DEPTH}) exceeded"
                )
                raise_risk(RiskLevel.CRITICAL)
            else:
                stack.append(("iso", len(result.controls)))
                hit.depth_after = len(stack)
                hit.risk = RiskLevel.LOW if abbr != "RLI" else RiskLevel.MEDIUM
                if abbr == "RLI":
                    raise_risk(RiskLevel.MEDIUM)
                else:
                    raise_risk(RiskLevel.LOW)

        elif kind is BidiKind.POP_DIRECTIONAL:
            # X7: PDF terminates the nearest embedding, ignoring unterminated
            # isolate initiators above it.
            hit.depth_after = len(stack)
            target_local: Optional[int] = None
            for frame_i in range(len(stack) - 1, -1, -1):
                if stack[frame_i][0] == "emb":
                    target_local = frame_i
                    break
                if stack[frame_i][0] == "iso":
                    continue
            if target_local is None:
                hit.is_orphan = True
                hit.risk = RiskLevel.MEDIUM
                result.errors.append(
                    f"PDF at logical index {i} (line {line}, col {column}) has no "
                    f"matching embedding opener (LRE/RLE/LRO/RLO)"
                )
                raise_risk(RiskLevel.MEDIUM)
            else:
                # Any isolates above the embedding are left for their PDIs;
                # in strict UAX#9 those isolates are automatically ended.
                _frame_kind, opener_hit_idx = stack.pop(target_local)
                opener = result.controls[opener_hit_idx]
                opener.scope_end = i
                opener.paired_with = "U+202C"
                hit.paired_with = opener.codepoint
                hit.depth_after = len(stack)
                if opener.kind is BidiKind.OVERRIDE:
                    hit.risk = RiskLevel.HIGH

        elif kind is BidiKind.ISOLATE_TERMINATOR:
            # X6a: PDI pops the nearest isolate initiator. If none, ignored.
            hit.depth_after = len(stack)
            target_local = None
            for frame_i in range(len(stack) - 1, -1, -1):
                if stack[frame_i][0] == "iso":
                    target_local = frame_i
                    break
            if target_local is None:
                hit.is_orphan = True
                hit.risk = RiskLevel.MEDIUM
                result.errors.append(
                    f"PDI at logical index {i} (line {line}, col {column}) has no "
                    f"matching isolate initiator (LRI/RLI/FSI)"
                )
                raise_risk(RiskLevel.MEDIUM)
            else:
                # Embeddings nested inside the isolate are force-closed (X9).
                force_closed = []
                while len(stack) - 1 > target_local:
                    fk, fhi = stack.pop()
                    if fk == "emb":
                        force_closed.append(fhi)
                _frame_kind, opener_hit_idx = stack.pop()
                for fhi in force_closed:
                    op = result.controls[fhi]
                    op.is_orphan = True
                    op.scope_end = i
                    op.paired_with = "U+2069(implicit)"
                    result.errors.append(
                        f"{op.abbreviation} at logical index {op.logical_index} "
                        f"(line {op.line}, col {op.column}) was never closed by PDF; "
                        f"implicitly terminated by PDI at index {i}"
                    )
                    if op.kind is BidiKind.OVERRIDE:
                        op.risk = RiskLevel.CRITICAL
                        raise_risk(RiskLevel.CRITICAL)
                    else:
                        if op.risk is RiskLevel.LOW:
                            op.risk = RiskLevel.MEDIUM
                        raise_risk(RiskLevel.MEDIUM)
                opener = result.controls[opener_hit_idx]
                opener.scope_end = i
                opener.paired_with = "U+2069"
                hit.paired_with = opener.codepoint
                hit.depth_after = len(stack)
                if opener.abbreviation == "RLI":
                    hit.risk = RiskLevel.MEDIUM

        elif kind is BidiKind.MARK:
            hit.risk = RiskLevel.INFO
        else:  # separators / other invisible formatting
            hit.risk = RiskLevel.INFO

        result.controls.append(hit)
        result.max_depth = max(result.max_depth, len(stack))

    # End of text: whatever remains on the stack is unclosed.
    for frame_kind, hit_idx in stack:
        opener = result.controls[hit_idx]
        opener.is_orphan = True
        opener.scope_end = len(text)
        line, column = _line_col(text, opener.logical_index)
        if frame_kind == "iso":
            result.errors.append(
                f"{opener.abbreviation} at logical index {opener.logical_index} "
                f"(line {line}, col {column}) is never closed by PDI"
            )
            opener.risk = RiskLevel.MEDIUM
            raise_risk(RiskLevel.MEDIUM)
        else:
            result.errors.append(
                f"{opener.abbreviation} at logical index {opener.logical_index} "
                f"(line {line}, col {column}) is never closed by PDF"
            )
            if opener.kind is BidiKind.OVERRIDE:
                opener.risk = RiskLevel.CRITICAL
                raise_risk(RiskLevel.CRITICAL)
            else:
                opener.risk = RiskLevel.MEDIUM
                raise_risk(RiskLevel.MEDIUM)

    # Build dangerous spans: every override scope + every unclosed opener.
    for hit in result.controls:
        dangerous = False
        reason = ""
        if hit.kind is BidiKind.OVERRIDE and hit.scope_end is not None:
            dangerous = True
            if hit.is_orphan:
                reason = f"unclosed {hit.abbreviation} override (reordering extends to end of text)"
            else:
                reason = f"{hit.abbreviation} override forces visual reordering of enclosed characters"
        elif hit.is_orphan and hit.scope_end is not None and hit.paired_with is None:
            dangerous = True
            reason = f"unclosed {hit.abbreviation} scope"

        if dangerous:
            start = hit.logical_index
            end = min(hit.scope_end, len(text))
            raw = text[start:end]
            result.spans.append(DangerousSpan(
                start=start,
                end=end,
                reason=reason,
                opener=hit.abbreviation,
                risk=hit.risk,
                raw=raw,
                escaped_preview=escape_preview(raw),
            ))

    result.risk = overall
    result.stats = {
        "total_control_chars": len(result.controls),
        "by_abbreviation": counts,
        "unclosed_openers": sum(1 for c in result.controls
                                if c.is_orphan and c.kind in
                                (BidiKind.EMBEDDING, BidiKind.OVERRIDE,
                                 BidiKind.ISOLATE_INITIATOR)),
        "orphan_closers": sum(1 for c in result.controls
                              if c.is_orphan and c.kind in
                              (BidiKind.POP_DIRECTIONAL,
                               BidiKind.ISOLATE_TERMINATOR)),
        "dangerous_span_count": len(result.spans),
    }
    return result
