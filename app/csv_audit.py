"""CSV cell formula-disguise auditing.

Parses raw CSV text -- comma-separated fields, double-quoted enclosures
with ``""`` escapes and CRLF/LF record breaks -- and flags every cell
whose first character, after skipping a prefix of spaces, tabs and
Unicode bidi control characters, is one of the spreadsheet formula
triggers (``=``, ``+``, ``-``, ``@``): the classic CSV / formula
injection shape, optionally disguised so a naive
``cell.startswith("=")`` check misses it.

Every finding reports the 1-based record/field numbers, the formula
character's codepoint offset and 1-based line/column in the original
document, the skipped prefix (each character classified) and the
cell's bidi risk level computed by the existing parser.  Newlines
inside quotes, escaped quotes and empty cells all take part in normal
record/field accounting, so they never shift record numbers or
positions.  Nothing is persisted and the document is never modified.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Optional

from .bidi import BIDI_CONTROL_CODEPOINTS, control_abbreviation, parse_bidi

# Characters that make a spreadsheet evaluate the cell as a formula.
FORMULA_CHARS = "=+-@"

# Skipped before the formula check: spaces, tabs and every bidi control.
_WHITESPACE = frozenset(" \t")


class CsvParseError(ValueError):
    """The CSV text is structurally invalid.

    ``error`` is ``unclosed_quote`` or ``illegal_quote``; ``offset`` is
    the 0-based codepoint offset in the original document where the
    problem was detected (the opening quote for an unclosed field).
    """

    def __init__(self, error: str, offset: int, message: str):
        super().__init__(f"offset {offset}: {message}")
        self.error = error
        self.offset = offset
        self.message = message


# ---------------------------------------------------------------------------
# Parsed model
# ---------------------------------------------------------------------------

@dataclass
class CsvCell:
    value: str                 # decoded field content ("" -> ")
    start: int                 # offset of the field's first character
    record: int                # 1-based record number
    field: int                 # 1-based field number within the record
    quoted: bool
    # Original document offset of the source unit each decoded character
    # came from (an escaped "" pair maps to its first quote).
    char_offsets: list[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _CsvParser:
    def __init__(self, text: str):
        self.text = text
        self.n = len(text)

    def parse(self) -> list[list[CsvCell]]:
        text, n = self.text, self.n
        records: list[list[CsvCell]] = []
        i = 0
        while i < n:
            record: list[CsvCell] = []
            record_no = len(records) + 1
            while True:
                cell, i = self._parse_field(i, record_no, len(record) + 1)
                record.append(cell)
                if i < n and text[i] == ",":
                    i += 1
                    continue
                break
            # Record break: CRLF consumed as a unit, or a lone LF.  A
            # lone CR is ordinary field content, so line numbers always
            # advance by the '\n' the separator contains.
            if text.startswith("\r\n", i):
                i += 2
            elif i < n and text[i] == "\n":
                i += 1
            records.append(record)
        return records

    def _parse_field(
        self, i: int, record_no: int, field_no: int
    ) -> tuple[CsvCell, int]:
        text, n = self.text, self.n
        start = i
        if i < n and text[i] == '"':
            return self._parse_quoted_field(i, record_no, field_no)
        chars: list[str] = []
        offsets: list[int] = []
        while i < n:
            ch = text[i]
            if ch == "," or ch == "\n":
                break
            if ch == "\r" and i + 1 < n and text[i + 1] == "\n":
                break
            if ch == '"':
                raise CsvParseError(
                    "illegal_quote",
                    i,
                    "quote character inside an unquoted field; a quote "
                    "pair may only enclose the whole field",
                )
            chars.append(ch)
            offsets.append(i)
            i += 1
        cell = CsvCell(
            value="".join(chars), start=start, record=record_no,
            field=field_no, quoted=False, char_offsets=offsets,
        )
        return cell, i

    def _parse_quoted_field(
        self, i: int, record_no: int, field_no: int
    ) -> tuple[CsvCell, int]:
        text, n = self.text, self.n
        start = i
        i += 1  # opening quote
        chars: list[str] = []
        offsets: list[int] = []
        while True:
            if i >= n:
                raise CsvParseError(
                    "unclosed_quote",
                    start,
                    "quoted field starting here is never closed",
                )
            ch = text[i]
            if ch == '"':
                if i + 1 < n and text[i + 1] == '"':
                    chars.append('"')
                    offsets.append(i)  # the pair maps to its first quote
                    i += 2
                    continue
                i += 1  # closing quote
                break
            chars.append(ch)
            offsets.append(i)
            i += 1
        # Only a delimiter may follow the closing quote.
        if i < n and text[i] not in (",", "\n") and not (
            text[i] == "\r" and i + 1 < n and text[i + 1] == "\n"
        ):
            raise CsvParseError(
                "illegal_quote",
                i,
                f"unexpected character {text[i]!r} after the closing "
                "quote; expected ',', a newline or the end of the "
                "document",
            )
        cell = CsvCell(
            value="".join(chars), start=start, record=record_no,
            field=field_no, quoted=True, char_offsets=offsets,
        )
        return cell, i


# ---------------------------------------------------------------------------
# Document line/column mapping
# ---------------------------------------------------------------------------

class _LineIndex:
    """Precomputed line-start offsets for O(log n) line/column lookups."""

    def __init__(self, text: str):
        self._starts = [0] + [
            i + 1 for i, ch in enumerate(text) if ch == "\n"
        ]

    def line_col(self, offset: int) -> tuple[int, int]:
        line = bisect.bisect_right(self._starts, offset)
        column = offset - self._starts[line - 1] + 1
        return line, column


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

@dataclass
class CsvFormulaFinding:
    record: int             # 1-based record number
    field: int              # 1-based field number within the record
    formula_char: str       # one of "=", "+", "-", "@"
    formula_offset: int     # codepoint offset of the formula character
    position: dict          # {"line", "column"} of the formula character
    prefix: str             # skipped prefix, verbatim
    prefix_controls: list[dict]  # per-character classification of the prefix
    risk_level: str         # bidi risk level of the decoded cell

    def to_dict(self) -> dict:
        return {
            "record": self.record,
            "field": self.field,
            "formula_char": self.formula_char,
            "formula_offset": self.formula_offset,
            "position": self.position,
            "prefix": self.prefix,
            "prefix_controls": self.prefix_controls,
            "risk_level": self.risk_level,
        }


@dataclass
class CsvAuditReport:
    record_count: int
    field_count: int
    findings: list[CsvFormulaFinding] = field(default_factory=list)


def _is_skipped(ch: str) -> bool:
    return ch in _WHITESPACE or ord(ch) in BIDI_CONTROL_CODEPOINTS


def _prefix_kind(ch: str) -> str:
    if ch == " ":
        return "space"
    if ch == "\t":
        return "tab"
    return control_abbreviation(ord(ch)) or "bidi"


def _inspect_cell(
    cell: CsvCell, lines: _LineIndex
) -> Optional[CsvFormulaFinding]:
    value = cell.value
    k = 0
    while k < len(value) and _is_skipped(value[k]):
        k += 1
    if k >= len(value) or value[k] not in FORMULA_CHARS:
        return None
    prefix = value[:k]
    prefix_controls = []
    for j, ch in enumerate(prefix):
        offset = cell.char_offsets[j]
        line, column = lines.line_col(offset)
        prefix_controls.append({
            "char": ch,
            "codepoint": f"U+{ord(ch):04X}",
            "kind": _prefix_kind(ch),
            "offset": offset,
            "position": {"line": line, "column": column},
        })
    formula_offset = cell.char_offsets[k]
    line, column = lines.line_col(formula_offset)
    return CsvFormulaFinding(
        record=cell.record,
        field=cell.field,
        formula_char=value[k],
        formula_offset=formula_offset,
        position={"line": line, "column": column},
        prefix=prefix,
        prefix_controls=prefix_controls,
        risk_level=parse_bidi(value).risk.value,
    )


def audit_csv_document(document: str) -> CsvAuditReport:
    """Parse ``document`` as CSV and flag formula-prefixed cells.

    Raises :class:`CsvParseError` on unclosed or illegal quotes before
    anything is reported.  Nothing is persisted here.
    """
    records = _CsvParser(document).parse()
    lines = _LineIndex(document)
    findings: list[CsvFormulaFinding] = []
    field_count = 0
    for record in records:
        field_count += len(record)
        for cell in record:
            finding = _inspect_cell(cell, lines)
            if finding is not None:
                findings.append(finding)
    return CsvAuditReport(
        record_count=len(records),
        field_count=field_count,
        findings=findings,
    )
