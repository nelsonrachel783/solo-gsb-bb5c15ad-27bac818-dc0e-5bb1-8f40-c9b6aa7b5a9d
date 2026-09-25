"""JSON document string-value auditing.

A strict, position-tracking JSON parser (RFC 8259) walks a raw JSON
document and feeds every string *value* -- object values and array
elements, never object keys -- to the bidi parser.  Every decoded string
keeps a mapping from each decoded character back to the raw document
offset it was read from, so ``\\uXXXX`` escapes and UTF-16 surrogate
pairs map every finding to the exact line/column of the original
document, while ordinary escapes (``\\n``, ``\\\\`` ...) and object keys
are never mistaken for hits.

Duplicate object keys (compared after escape decoding) and any grammar
violation raise :class:`JsonParseError` *before* anything is audited or
persisted, so a rejected document never produces partial records.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import Iterator, Optional

from .bidi import parse_bidi

# Nesting deeper than this is rejected: legitimate documents stay far
# below it and the recursive parser keeps a safe margin below Python's
# own recursion limit.
MAX_NESTING_DEPTH = 256

_LOGICAL_INDEX_RE = re.compile(r"at logical index (\d+)")

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_SIMPLE_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}
_WHITESPACE = " \t\n\r"


class JsonParseError(ValueError):
    """The document is not valid JSON (or exceeds the nesting limit).

    ``offset`` is the 0-based code-point offset in the original document
    where the problem was detected.
    """

    def __init__(self, offset: int, message: str):
        super().__init__(f"offset {offset}: {message}")
        self.offset = offset
        self.message = message


class DuplicateKeyError(JsonParseError):
    """An object contains the same (decoded) key twice.

    ``pointer`` is the RFC 6901 JSON Pointer of the object holding the
    duplicate; ``key`` is the duplicated (decoded) key.
    """

    def __init__(self, offset: int, key: str, pointer: str):
        super().__init__(
            offset,
            f"duplicate object key {key!r} in object "
            f"{pointer or '<root>'}",
        )
        self.key = key
        self.pointer = pointer


# ---------------------------------------------------------------------------
# Parsed model
# ---------------------------------------------------------------------------

@dataclass
class JsonString:
    value: str                # decoded string content
    start: int                # offset of the opening quote in the document
    end: int                  # offset just past the closing quote
    # Raw document offset of the source unit each decoded character came
    # from (the character itself, or the backslash of its escape; a
    # surrogate pair maps to the first backslash).  One extra trailing
    # entry holds the closing-quote offset, i.e. the content end.
    char_offsets: list[int] = field(default_factory=list)


@dataclass
class JsonArray:
    items: list = field(default_factory=list)


@dataclass
class JsonObject:
    items: list = field(default_factory=list)  # list[tuple[JsonString, value]]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _JsonParser:
    def __init__(self, text: str):
        self.text = text
        self.n = len(text)
        self.i = 0

    # -- helpers ------------------------------------------------------
    def _error(self, offset: int, message: str) -> None:
        raise JsonParseError(offset, message)

    def _peek(self) -> str:
        return self.text[self.i] if self.i < self.n else ""

    def _skip_ws(self) -> None:
        text, n = self.text, self.n
        i = self.i
        while i < n and text[i] in _WHITESPACE:
            i += 1
        self.i = i

    # -- entry point --------------------------------------------------
    def parse(self):
        self._skip_ws()
        if self.i >= self.n:
            self._error(self.i, "empty document: expected a JSON value")
        value = self._parse_value(0, [])
        self._skip_ws()
        if self.i != self.n:
            self._error(
                self.i, "unexpected trailing data after the JSON value"
            )
        return value

    # -- values -------------------------------------------------------
    def _parse_value(self, depth: int, path: list[str]):
        if depth > MAX_NESTING_DEPTH:
            self._error(
                self.i,
                f"nesting depth exceeds the limit of {MAX_NESTING_DEPTH}",
            )
        ch = self._peek()
        if ch == "{":
            return self._parse_object(depth, path)
        if ch == "[":
            return self._parse_array(depth, path)
        if ch == '"':
            return self._parse_string()
        if ch == "t":
            return self._parse_literal("true")
        if ch == "f":
            return self._parse_literal("false")
        if ch == "n":
            return self._parse_literal("null")
        if ch == "-" or "0" <= ch <= "9":
            return self._parse_number()
        if ch == "":
            self._error(
                self.i, "unexpected end of document: expected a JSON value"
            )
        self._error(
            self.i, f"unexpected character {ch!r}: expected a JSON value"
        )

    def _parse_literal(self, word: str) -> None:
        if self.text.startswith(word, self.i):
            self.i += len(word)
            return None
        self._error(self.i, f"invalid literal (expected {word!r})")

    def _parse_number(self) -> None:
        text, n = self.text, self.n
        start = self.i
        i = start
        if i < n and text[i] == "-":
            i += 1
        # integer part: "0" or [1-9] digits
        if i >= n:
            self._error(start, "invalid number: expected a digit")
        if text[i] == "0":
            i += 1
        elif "1" <= text[i] <= "9":
            while i < n and "0" <= text[i] <= "9":
                i += 1
        else:
            self._error(i, "invalid number: expected a digit")
        # fraction
        if i < n and text[i] == ".":
            i += 1
            if i >= n or not ("0" <= text[i] <= "9"):
                self._error(
                    i, "invalid number: expected a digit after '.'"
                )
            while i < n and "0" <= text[i] <= "9":
                i += 1
        # exponent
        if i < n and text[i] in "eE":
            i += 1
            if i < n and text[i] in "+-":
                i += 1
            if i >= n or not ("0" <= text[i] <= "9"):
                self._error(
                    i, "invalid number: expected a digit in the exponent"
                )
            while i < n and "0" <= text[i] <= "9":
                i += 1
        self.i = i
        return None

    # -- strings ------------------------------------------------------
    def _parse_string(self) -> JsonString:
        text, n = self.text, self.n
        start = self.i
        self.i += 1  # opening quote
        chars: list[str] = []
        offsets: list[int] = []
        while True:
            i = self.i
            if i >= n:
                self._error(start, "unterminated string literal")
            ch = text[i]
            if ch == '"':
                offsets.append(i)  # content end == closing-quote offset
                self.i = i + 1
                return JsonString("".join(chars), start, i + 1, offsets)
            if ch == "\\":
                decoded, new_i = self._parse_escape(i)
                chars.append(decoded)
                offsets.append(i)  # the backslash starts the source unit
                self.i = new_i
                continue
            cp = ord(ch)
            if cp < 0x20:
                self._error(
                    i, "unescaped control character in string literal"
                )
            if 0xD800 <= cp <= 0xDFFF:
                self._error(
                    i, "lone UTF-16 surrogate in string literal"
                )
            chars.append(ch)
            offsets.append(i)
            self.i = i + 1

    def _parse_escape(self, backslash: int) -> tuple[str, int]:
        """Decode the escape starting at ``backslash``; return the decoded
        character and the offset just past the escape sequence."""
        i = backslash + 1
        if i >= self.n:
            self._error(backslash, "unterminated escape sequence")
        e = self.text[i]
        simple = _SIMPLE_ESCAPES.get(e)
        if simple is not None:
            return simple, i + 1
        if e != "u":
            self._error(i, f"invalid escape sequence '\\{e}'")
        hi = self._parse_hex4(i + 1, backslash)
        after = i + 5  # just past the 4 hex digits
        if 0xD800 <= hi <= 0xDBFF:
            # A high surrogate is only valid as half of a pair: a
            # low-surrogate escape must follow immediately.
            if self.text.startswith("\\u", after):
                lo = self._parse_hex4(after + 2, after)
                if 0xDC00 <= lo <= 0xDFFF:
                    cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                    return chr(cp), after + 6
                self._error(
                    after,
                    "invalid UTF-16 surrogate pair: expected a low "
                    "surrogate (\\uDC00-\\uDFFF)",
                )
            self._error(
                after,
                "unpaired UTF-16 high surrogate: expected a following "
                "\\uDC00-\\uDFFF escape",
            )
        if 0xDC00 <= hi <= 0xDFFF:
            self._error(i, "unpaired UTF-16 low surrogate")
        return chr(hi), after

    def _parse_hex4(self, at: int, escape_offset: int) -> int:
        digits = self.text[at:at + 4]
        if len(digits) < 4 or any(c not in _HEX_DIGITS for c in digits):
            self._error(
                escape_offset,
                "invalid \\u escape: expected 4 hexadecimal digits",
            )
        return int(digits, 16)

    # -- containers ---------------------------------------------------
    def _parse_object(self, depth: int, path: list[str]) -> JsonObject:
        self.i += 1  # '{'
        obj = JsonObject()
        seen: set[str] = set()
        self._skip_ws()
        if self._peek() == "}":
            self.i += 1
            return obj
        while True:
            self._skip_ws()
            if self._peek() != '"':
                self._error(
                    self.i,
                    "expected an object key string"
                    if self.i < self.n
                    else "unterminated object: expected a key string",
                )
            key = self._parse_string()
            if key.value in seen:
                pointer = "".join(
                    "/" + escape_pointer_token(p) for p in path
                )
                raise DuplicateKeyError(key.start, key.value, pointer)
            seen.add(key.value)
            self._skip_ws()
            if self._peek() != ":":
                self._error(self.i, "expected ':' after the object key")
            self.i += 1
            self._skip_ws()
            value = self._parse_value(depth + 1, path + [key.value])
            obj.items.append((key, value))
            self._skip_ws()
            ch = self._peek()
            if ch == ",":
                self.i += 1
                continue
            if ch == "}":
                self.i += 1
                return obj
            self._error(
                self.i,
                "expected ',' or '}' in object"
                if ch
                else "unterminated object: expected ',' or '}'",
            )

    def _parse_array(self, depth: int, path: list[str]) -> JsonArray:
        self.i += 1  # '['
        arr = JsonArray()
        self._skip_ws()
        if self._peek() == "]":
            self.i += 1
            return arr
        index = 0
        while True:
            self._skip_ws()
            value = self._parse_value(depth + 1, path + [str(index)])
            arr.items.append(value)
            index += 1
            self._skip_ws()
            ch = self._peek()
            if ch == ",":
                self.i += 1
                continue
            if ch == "]":
                self.i += 1
                return arr
            self._error(
                self.i,
                "expected ',' or ']' in array"
                if ch
                else "unterminated array: expected ',' or ']'",
            )


# ---------------------------------------------------------------------------
# JSON Pointer walk
# ---------------------------------------------------------------------------

def escape_pointer_token(token: str) -> str:
    """RFC 6901 escaping for a single reference token."""
    return token.replace("~", "~0").replace("/", "~1")


def _iter_string_values(
    value, path: list[str]
) -> Iterator[tuple[str, JsonString]]:
    """Yield ``(pointer, JsonString)`` for every string *value* in the
    document tree (object keys are never yielded).  The root string, if
    any, yields the empty pointer ``""``."""
    if isinstance(value, JsonString):
        pointer = "".join("/" + escape_pointer_token(p) for p in path)
        yield pointer, value
    elif isinstance(value, JsonArray):
        for index, item in enumerate(value.items):
            yield from _iter_string_values(item, path + [str(index)])
    elif isinstance(value, JsonObject):
        for key, item in value.items:
            yield from _iter_string_values(item, path + [key.value])


# ---------------------------------------------------------------------------
# Document line/column mapping
# ---------------------------------------------------------------------------

class _LineIndex:
    """Precomputed line-start offsets for O(log n) line/column lookups."""

    def __init__(self, text: str):
        self._starts = [0] + [
            m.end() for m in re.finditer("\n", text)
        ]

    def line_col(self, offset: int) -> tuple[int, int]:
        line = bisect.bisect_right(self._starts, offset)
        column = offset - self._starts[line - 1] + 1
        return line, column


def line_col(document: str, offset: int) -> tuple[int, int]:
    """1-based (line, column) of ``offset`` in ``document`` (code points)."""
    line = document.count("\n", 0, offset) + 1
    last_nl = document.rfind("\n", 0, offset)
    return line, offset - last_nl


def _build_locations(
    pointer: str,
    js: JsonString,
    result: dict,
    lines: _LineIndex,
) -> dict:
    """Map every finding of one decoded string value back to the original
    document (offset + 1-based line/column), keeping the parse result's
    own logical indices untouched."""

    def locate(logical_index: int) -> tuple[int, dict]:
        offset = js.char_offsets[logical_index]
        line, column = lines.line_col(offset)
        return offset, {"line": line, "column": column}

    controls: list[dict] = []
    for i, control in enumerate(result["controls"]):
        offset, position = locate(control["logical_index"])
        controls.append({
            "result_index": i,
            "logical_index": control["logical_index"],
            "pointer": pointer,
            "offset": offset,
            "position": position,
        })

    errors: list[dict] = []
    for i, message in enumerate(result["errors"]):
        # Every parser error message carries the flagged character's
        # logical index; map that index back into the document.
        match = _LOGICAL_INDEX_RE.search(message)
        entry: dict = {
            "result_index": i,
            "logical_index": (
                int(match.group(1)) if match else None
            ),
            "pointer": pointer,
            "offset": None,
            "position": None,
        }
        if match is not None:
            offset, position = locate(int(match.group(1)))
            entry["offset"] = offset
            entry["position"] = position
        errors.append(entry)

    spans: list[dict] = []
    for i, span in enumerate(result["dangerous_spans"]):
        start_offset, start_pos = locate(span["start"])
        # span end is exclusive; char_offsets has a trailing entry for
        # the content end (the closing quote), so end == len(value) maps
        # to the offset just past the last content character.
        end_offset, end_pos = locate(span["end"])
        spans.append({
            "result_index": i,
            "start_logical_index": span["start"],
            "end_logical_index": span["end"],
            "pointer": pointer,
            "offsets": {"start": start_offset, "end": end_offset},
            "position": {"start": start_pos, "end": end_pos},
        })

    return {"controls": controls, "errors": errors,
            "dangerous_spans": spans}


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

@dataclass
class ValueAudit:
    pointer: str        # RFC 6901 JSON Pointer of the string value
    span: dict          # {"start", "end"}: raw offsets of the string token
    text: str           # decoded string value (what gets audited/stored)
    result: dict
    locations: dict
    meta: dict


def audit_json_document(document: str) -> list[ValueAudit]:
    """Parse ``document`` as strict JSON and audit every string value.

    The whole document is parsed and validated first; a
    :class:`JsonParseError` (or :class:`DuplicateKeyError`) is raised
    before any value is audited, so callers never persist partial
    results.  Nothing is stored here.
    """
    tree = _JsonParser(document).parse()
    lines = _LineIndex(document)
    audits: list[ValueAudit] = []
    for pointer, js in _iter_string_values(tree, []):
        result = parse_bidi(js.value).to_dict()
        locations = _build_locations(pointer, js, result, lines)
        span = {"start": js.start, "end": js.end}
        meta = {
            "source": "json_document",
            "version": 1,
            "pointer": pointer,
            "span": span,
            "locations": locations,
        }
        audits.append(ValueAudit(
            pointer=pointer,
            span=span,
            text=js.value,
            result=result,
            locations=locations,
            meta=meta,
        ))
    return audits
