"""Python identifier extraction with Unicode NFKC collision reporting.

Python source code is lexed with the standard library ``tokenize`` module,
which implements the lexical rules of the reference interpreter (PEP 3131
identifiers included).  Identifiers (``NAME`` tokens) are collected while
comments, strings, numbers, operators and all structural tokens are
skipped; hard keywords are skipped as well, comparing the **NFKC-normalised**
spelling so that confusables such as ``Ｔｒｕｅ`` (full-width letters) are
treated as the keyword ``True`` rather than as identifiers.

Each surviving identifier spelling is Unicode NFKC normalised.  A collision
is reported only when one normalised form is spelled in at least two
different raw ways; a spelling repeated verbatim, or a spelling that differs
only in case, is *not* a collision.  Every occurrence keeps its codepoint
offset and 1-based line/column in the original source; collisions and the
occurrences inside them are ordered by source position, so the output is
stable.

Any lexical failure (an unlexable character, an unterminated string or
statement, inconsistent indentation ...) raises
:class:`IdentifierLexError` carrying the original-source position before
any report is produced, so a rejected source never produces an audit
result.  A string opened by a single/double quote that is never closed
on its line is reported as ``unterminated_statement`` positioned where
the string scan stopped (the line break or end of source), not as an
unexpected character at the quote.

A collision *fix preview* (:func:`preview_collision_fix`) reuses this same
scan to locate one collision group by its NFKC normalised name and rewrites
only the group's non-canonical spellings to the normalised form.  Because
the scan covers identifier tokens alone, string literals, comments and all
other characters are left byte-for-byte untouched; span replacement never
touches a line ending, and a leading BOM survives as well.  The edited
source is rescanned so the caller sees the collisions that would remain.
Nothing is persisted at this layer.

A *mixed-script* scan (:func:`scan_mixed_scripts`) reuses the same lexical
pass to flag identifiers whose letters mix the Latin, Greek and Cyrillic
scripts -- the classic homoglyph disguise, e.g. a Cyrillic ``а`` (U+0430)
inside an otherwise Latin name.  Only characters whose Unicode data name
starts with ``LATIN``, ``GREEK`` or ``CYRILLIC`` carry a script; combining
marks, digits, the underscore and lookalikes named otherwise (full-width,
mathematical letters) are script-neutral.  Every identifier whose letters
span two or more scripts is reported once per occurrence, listing each
script-carrying character with its codepoint offset and line/column.
"""

from __future__ import annotations

import io
import keyword
import tokenize
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

# A leading BOM is legal at the very start of a UTF-8 source file; the
# tokenizer (which works on decoded text) treats one elsewhere as an error.
_BOM = "﻿"

# Characters that open a string literal.  The 3.11 tokenizer emits a lone
# quote as an ERRORTOKEN when the string it opens is never closed on its
# line, so such a token marks an unterminated statement rather than an
# unlexable character.
_QUOTES = "'\""


class IdentifierLexError(ValueError):
    """Lexical scanning of the Python source failed.

    ``line`` is 1-based and ``column`` is 1-based; ``offset`` is the
    0-based codepoint offset in the original source.  All three point at
    the offending character (or, for an unterminated construct, at the
    position where the scanner gave up).
    """

    def __init__(
        self,
        message: str,
        *,
        offset: int,
        line: int,
        column: int,
        error: str = "invalid_python_source",
    ):
        super().__init__(f"line {line}, column {column}: {message}")
        self.message = message
        self.offset = offset
        self.line = line
        self.column = column
        self.error = error


class CollisionGroupNotFoundError(ValueError):
    """No collision group with the requested NFKC normalised name exists.

    A name only matches a *collision* group: it must be the normalised
    form of at least two distinct raw identifier spellings in the source.
    A name carried by a single spelling (or by no identifier at all) is
    not a fixable collision.
    """

    def __init__(self, normalised: str):
        super().__init__(
            f"no NFKC collision group with normalised name {normalised!r}"
        )
        self.normalised = normalised


@dataclass
class Occurrence:
    """One in-source appearance of an identifier spelling."""

    offset: int           # codepoint offset of the first character (0-based)
    end_offset: int       # codepoint offset just past the last character
    line: int             # 1-based source line
    column: int           # 1-based source column (codepoints)


@dataclass
class IdentifierToken:
    """One non-keyword identifier occurrence, in source order."""

    spelling: str
    occurrence: Occurrence


@dataclass
class SpellingOccurrences:
    spelling: str
    occurrence_count: int
    occurrences: list[Occurrence] = field(default_factory=list)


@dataclass
class Collision:
    """One normalised form shared by two or more distinct raw spellings."""

    normalised: str
    spelling_count: int
    occurrence_count: int
    spellings: list[SpellingOccurrences] = field(default_factory=list)


@dataclass
class NormalizationReport:
    identifier_count: int          # total non-keyword identifier occurrences
    distinct_spelling_count: int   # distinct raw spellings
    collision_count: int
    collisions: list[Collision] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "identifier_count": self.identifier_count,
            "distinct_spelling_count": self.distinct_spelling_count,
            "collision_count": self.collision_count,
            "collisions": [
                {
                    "normalised": c.normalised,
                    "spelling_count": c.spelling_count,
                    "occurrence_count": c.occurrence_count,
                    "spellings": [
                        {
                            "spelling": s.spelling,
                            "occurrence_count": s.occurrence_count,
                            "occurrences": [
                                {
                                    "offset": o.offset,
                                    "end_offset": o.end_offset,
                                    "line": o.line,
                                    "column": o.column,
                                }
                                for o in s.occurrences
                            ],
                        }
                        for s in c.spellings
                    ],
                }
                for c in self.collisions
            ],
        }


@dataclass
class IdentifierEdit:
    """One spelling replacement produced by a collision fix preview."""

    offset: int        # codepoint offset of the first character (0-based)
    end_offset: int    # codepoint offset just past the last character
    original: str      # raw spelling as found in the source
    replacement: str   # canonical (NFKC normalised) spelling


@dataclass
class CollisionFixPreview:
    """The non-persisted result of a collision-group fix preview."""

    target_normalised: str
    edits: list[IdentifierEdit]
    fixed_source: str
    report_before: NormalizationReport
    report_after: NormalizationReport

    def to_dict(self) -> dict:
        return {
            "target_normalised": self.target_normalised,
            "edit_count": len(self.edits),
            "edits": [
                {
                    "offset": e.offset,
                    "end_offset": e.end_offset,
                    "original": e.original,
                    "replacement": e.replacement,
                }
                for e in self.edits
            ],
            "fixed_source": self.fixed_source,
            "report": self.report_after.to_dict(),
        }


def _line_start_offsets(text: str) -> list[int]:
    """Codepoint offset at which each 1-based line starts (index 0 unused)."""
    starts = [0, 0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _is_identifier_continuation(ch: str) -> bool:
    """True when *ch* may extend a Python identifier (PEP 3131 XID_Continue).

    The reference tokenizer's rule is exactly "the character may appear
    somewhere inside an identifier", which ``str.isidentifier`` reports
    for a one-character suffix test.  This covers characters the 3.11
    ``tokenize`` regular expression (``\\w+``) misses, notably standalone
    combining marks such as U+0301 COMBINING ACUTE ACCENT, which the
    interpreter itself accepts in identifiers.
    """
    return ("a" + ch).isidentifier()


def _extract_identifiers(source: str) -> list[IdentifierToken]:
    """Lex *source* and return its non-keyword identifiers in source order.

    Raises :class:`IdentifierLexError` on any lexical failure.
    """
    # Strip a single leading BOM; remember it so reported offsets stay
    # relative to the original (unstripped) source.
    bom_offset = 0
    if source.startswith(_BOM):
        source = source[len(_BOM):]
        bom_offset = len(_BOM)

    line_starts = _line_start_offsets(source)

    def stripped_offset(tok_line: int, col: int) -> int:
        """Codepoint offset of a tokenize (line, 0-based column) position,
        measured in the BOM-stripped source."""
        if tok_line >= len(line_starts):
            return len(source)
        return line_starts[tok_line] + col

    def raw_offset(tok_line: int, col: int) -> int:
        """Codepoint offset in the original (unstripped) source."""
        return stripped_offset(tok_line, col) + bom_offset

    def raw_column(tok_line: int, col: int) -> int:
        """1-based column in the original source."""
        return col + 1 + (1 if tok_line == 1 and bom_offset else 0)

    tokens: list[IdentifierToken] = []
    # End offset (stripped-source coordinates) of the most recently
    # extracted identifier; used to recognise continuation marks split off
    # from a name by the tokenizer's ``\w+`` matching.
    last_name_end = -1

    def record_name(tok: "tokenize.TokenInfo") -> None:
        nonlocal last_name_end
        start_line, start_col = tok.start
        stripped_start = stripped_offset(start_line, start_col)
        # The 3.11 tokenizer names identifiers with ``\w+`` and emits each
        # non-``\w`` continuation character (e.g. a combining mark in a
        # decomposed identifier such as ``e`` + U+0301) as a separate
        # ERRORTOKEN even though the interpreter accepts it.  Extend the
        # name over every following PEP 3131 continuation character.
        end = stripped_start + len(tok.string)
        while end < len(source) and _is_identifier_continuation(source[end]):
            end += 1
        last_name_end = end
        spelling = source[stripped_start:end]
        # Hard keywords are compared after NFKC normalisation so
        # full-width/confusable keyword spellings are skipped exactly as
        # the interpreter normalises identifiers.
        if keyword.iskeyword(unicodedata.normalize("NFKC", spelling)):
            return
        tokens.append(
            IdentifierToken(
                spelling=spelling,
                occurrence=Occurrence(
                    offset=stripped_start + bom_offset,
                    end_offset=end + bom_offset,
                    line=start_line,
                    column=raw_column(start_line, start_col),
                ),
            )
        )

    def unexpected_character(tok: "tokenize.TokenInfo") -> None:
        start_line, start_col = tok.start
        ch = tok.string[0]
        raise IdentifierLexError(
            f"unexpected character {ch!r} (U+{ord(ch):04X}) "
            "while tokenizing Python source",
            offset=raw_offset(start_line, start_col),
            line=start_line,
            column=raw_column(start_line, start_col),
            error="unexpected_character",
        )

    def unterminated_string(tok: "tokenize.TokenInfo") -> None:
        start_line, start_col = tok.start
        ch = tok.string[0]
        # A lone quote ERRORTOKEN is the opening quote of a string the
        # tokenizer could not close: single/double-quoted strings cannot
        # cross a line break, so the string scan stops at the next line
        # break, or at end of source when the line itself is unterminated.
        # Report that stop position (on the quote's own line), not the
        # quote itself.
        stop = stripped_offset(start_line, start_col)
        while stop < len(source) and source[stop] not in "\r\n":
            stop += 1
        stop_col = stop - line_starts[start_line]
        raise IdentifierLexError(
            f"unterminated string literal: opening quote {ch!r} at "
            f"line {start_line}, column {start_col + 1} is never closed",
            offset=stop + bom_offset,
            line=start_line,
            column=raw_column(start_line, stop_col),
            error="unterminated_statement",
        )

    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.NAME:
                record_name(tok)
            elif tok.type == tokenize.ERRORTOKEN and tok.string:
                stripped_pos = stripped_offset(*tok.start)
                # record_name extends the name through every following
                # continuation character; the 3.11 tokenizer emits those
                # extra marks (e.g. combining accents) as one ERRORTOKEN
                # each.  A continuation-mark ERRORTOKEN starting within
                # the just-extended span is the name's split-off tail and
                # was already accounted for by record_name.
                if (
                    not tok.string.isspace()
                    and _is_identifier_continuation(tok.string[0])
                    and stripped_pos < last_name_end
                ):
                    continue
                if not tok.string.isspace():
                    # A lone quote is the opening quote of a string that
                    # is never closed on its line: an unterminated
                    # statement, not an unlexable character.
                    if tok.string[0] in _QUOTES:
                        unterminated_string(tok)
                    # Whitespace ERRORTOKENs are benign noise; anything
                    # else is an unlexable character (a stray combining
                    # mark not attached to a name included).
                    unexpected_character(tok)
    except tokenize.TokenError as exc:
        # args is (message, (1-based line, 0-based column))
        message = exc.args[0] if exc.args else "unexpected end of input"
        position = exc.args[1] if len(exc.args) > 1 else (1, 0)
        tok_line, tok_col = position
        kind = (
            "unterminated_string"
            if "multi-line string" in message
            else "unterminated_statement"
        )
        raise IdentifierLexError(
            message,
            offset=raw_offset(tok_line, tok_col),
            line=tok_line,
            column=raw_column(tok_line, tok_col),
            error=kind,
        )
    except IndentationError as exc:
        # exc.lineno is 1-based, exc.offset is 1-based (stripped-source
        # coordinates).
        lineno = exc.lineno or 1
        column = exc.offset or 1
        if lineno < len(line_starts):
            offset = line_starts[lineno] + column - 1 + bom_offset
        else:
            offset = len(source) + bom_offset
        if lineno == 1 and bom_offset:
            column += 1
        raise IdentifierLexError(
            exc.msg or "inconsistent indentation",
            offset=offset,
            line=lineno,
            column=column,
            error="indentation_error",
        )

    return tokens


def scan_identifiers(source: str) -> NormalizationReport:
    """Extract identifiers and build the NFKC collision report.

    Raises :class:`IdentifierLexError` on any lexical failure.
    """
    tokens = _extract_identifiers(source)

    # normalised form -> raw spelling -> occurrences (insertion order is
    # source order for both levels)
    grouped: "OrderedDict[str, OrderedDict[str, list[Occurrence]]]" = OrderedDict()
    first_seen: dict[str, int] = {}
    for token in tokens:
        normalised = unicodedata.normalize("NFKC", token.spelling)
        by_spelling = grouped.setdefault(normalised, OrderedDict())
        by_spelling.setdefault(token.spelling, []).append(token.occurrence)
        if normalised not in first_seen:
            first_seen[normalised] = token.occurrence.offset

    collisions: list[Collision] = []
    for normalised, by_spelling in grouped.items():
        if len(by_spelling) < 2:
            continue
        spellings = [
            SpellingOccurrences(
                spelling=spelling,
                occurrence_count=len(occurrences),
                occurrences=occurrences,
            )
            for spelling, occurrences in by_spelling.items()
        ]
        collisions.append(
            Collision(
                normalised=normalised,
                spelling_count=len(spellings),
                occurrence_count=sum(s.occurrence_count for s in spellings),
                spellings=spellings,
            )
        )

    # Source order: first occurrence of the normalised form, with spellings
    # and their occurrences already in source order from token scanning.
    collisions.sort(key=lambda c: first_seen[c.normalised])

    return NormalizationReport(
        identifier_count=len(tokens),
        distinct_spelling_count=sum(len(m) for m in grouped.values()),
        collision_count=len(collisions),
        collisions=collisions,
    )


# Script classes recognised for homoglyph detection, keyed by the prefix of
# the character's Unicode data name.  No listed prefix is a prefix of
# another, so the first match wins unambiguously.
_SCRIPT_PREFIXES = (
    ("LATIN", "latin"),
    ("GREEK", "greek"),
    ("CYRILLIC", "cyrillic"),
)


def _name_script(ch: str) -> Optional[str]:
    """Script class carried by *ch*, or ``None`` when it is script-neutral.

    Only characters whose Unicode data name starts with ``LATIN``, ``GREEK``
    or ``CYRILLIC`` carry a script.  Everything else that may appear inside
    an identifier -- combining marks, digits, the underscore, and lookalike
    letters named otherwise (``FULLWIDTH LATIN ...``, ``MATHEMATICAL ...``)
    -- is script-neutral and never counts towards a mix.
    """
    name = unicodedata.name(ch, "")
    for prefix, script in _SCRIPT_PREFIXES:
        if name.startswith(prefix):
            return script
    return None


@dataclass
class MixedScriptChar:
    """One script-carrying character of a mixed-script identifier."""

    char: str
    codepoint: str     # "U+0440" style
    script: str        # "latin" | "greek" | "cyrillic"
    offset: int        # codepoint offset in the original source (0-based)
    line: int          # 1-based source line
    column: int        # 1-based source column (codepoints)


@dataclass
class MixedScriptFinding:
    """One occurrence of an identifier mixing two or more scripts."""

    spelling: str
    scripts: list[str]   # distinct scripts, in first-appearance order
    offset: int          # codepoint offset of the identifier (0-based)
    end_offset: int      # codepoint offset just past the identifier
    line: int            # 1-based source line
    column: int          # 1-based source column (codepoints)
    characters: list[MixedScriptChar] = field(default_factory=list)


@dataclass
class MixedScriptReport:
    identifier_count: int   # total non-keyword identifier occurrences
    finding_count: int
    findings: list[MixedScriptFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "identifier_count": self.identifier_count,
            "finding_count": self.finding_count,
            "findings": [
                {
                    "spelling": f.spelling,
                    "scripts": f.scripts,
                    "offset": f.offset,
                    "end_offset": f.end_offset,
                    "line": f.line,
                    "column": f.column,
                    "characters": [
                        {
                            "char": c.char,
                            "codepoint": c.codepoint,
                            "script": c.script,
                            "offset": c.offset,
                            "line": c.line,
                            "column": c.column,
                        }
                        for c in f.characters
                    ],
                }
                for f in self.findings
            ],
        }


def scan_mixed_scripts(source: str) -> MixedScriptReport:
    """Extract identifiers and report those mixing Latin/Greek/Cyrillic.

    Every occurrence of an identifier whose letters span two or more of the
    recognised scripts is reported separately, in source order; a repeated
    name therefore appears once per occurrence.  Raises
    :class:`IdentifierLexError` on any lexical failure.
    """
    tokens = _extract_identifiers(source)
    findings: list[MixedScriptFinding] = []
    for token in tokens:
        occurrence = token.occurrence
        characters: list[MixedScriptChar] = []
        scripts: list[str] = []
        # Identifiers never span lines, so each character's column is the
        # identifier's column plus its codepoint index within the spelling.
        for index, ch in enumerate(token.spelling):
            script = _name_script(ch)
            if script is None:
                continue
            if script not in scripts:
                scripts.append(script)
            characters.append(
                MixedScriptChar(
                    char=ch,
                    codepoint=f"U+{ord(ch):04X}",
                    script=script,
                    offset=occurrence.offset + index,
                    line=occurrence.line,
                    column=occurrence.column + index,
                )
            )
        if len(scripts) < 2:
            continue
        findings.append(
            MixedScriptFinding(
                spelling=token.spelling,
                scripts=scripts,
                offset=occurrence.offset,
                end_offset=occurrence.end_offset,
                line=occurrence.line,
                column=occurrence.column,
                characters=characters,
            )
        )
    return MixedScriptReport(
        identifier_count=len(tokens),
        finding_count=len(findings),
        findings=findings,
    )


def preview_collision_fix(source: str, target_name: str) -> CollisionFixPreview:
    """Preview fixing one NFKC collision group without persisting anything.

    The source is scanned with :func:`scan_identifiers`; ``target_name`` is
    NFKC normalised first, so either a raw or a normalised spelling can be
    supplied.  It must resolve to a collision group (one normalised form
    shared by at least two distinct raw spellings), otherwise
    :class:`CollisionGroupNotFoundError` is raised; a lexical failure
    propagates as :class:`IdentifierLexError`.

    Within the group every occurrence of a *non-canonical* spelling (a raw
    spelling different from its NFKC normalised form) is rewritten to that
    form; occurrences already spelled canonically need no edit.  Only those
    identifier spans change -- comments, strings, keywords and every other
    character are copied verbatim, and since edits are in-span the BOM and
    all line endings are preserved.  The edited source is rescanned and the
    resulting report is returned alongside the edit list (ordered by source
    position) and the fixed source.
    """
    report_before = scan_identifiers(source)
    target = unicodedata.normalize("NFKC", target_name)

    group: Optional[Collision] = None
    for collision in report_before.collisions:
        if collision.normalised == target:
            group = collision
            break
    if group is None:
        raise CollisionGroupNotFoundError(target)

    edits: list[IdentifierEdit] = []
    for spelling_group in group.spellings:
        if spelling_group.spelling == target:
            # Already canonical: leave every occurrence untouched.
            continue
        for occurrence in spelling_group.occurrences:
            edits.append(
                IdentifierEdit(
                    offset=occurrence.offset,
                    end_offset=occurrence.end_offset,
                    original=spelling_group.spelling,
                    replacement=target,
                )
            )
    edits.sort(key=lambda edit: edit.offset)

    # Apply edits from the end backwards so earlier codepoint offsets stay
    # valid while the string changes length.
    fixed = source
    for edit in reversed(edits):
        fixed = fixed[:edit.offset] + edit.replacement + fixed[edit.end_offset:]

    report_after = scan_identifiers(fixed)
    return CollisionFixPreview(
        target_normalised=target,
        edits=edits,
        fixed_source=fixed,
        report_before=report_before,
        report_after=report_after,
    )
