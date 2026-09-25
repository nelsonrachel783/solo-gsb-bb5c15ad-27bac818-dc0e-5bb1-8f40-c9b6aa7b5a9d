"""Unified-diff parsing and per-file bidi auditing.

The parser understands multi-file, multi-hunk unified diffs as produced by
``git diff`` / ``diff -u`` (including file preamble headers, rename/mode
headers and binary patches).  Only **added lines** (hunk body lines that
start with ``+``) are audited: file headers, removed lines (``-``),
context lines (a leading space) and the ``\\ No newline at end of file``
marker are parsed for structure but never analysed.

For every file containing added lines the added text is rebuilt in
new-file order and fed to :func:`app.bidi.parse_bidi`.  Every parser
finding (control character, error, dangerous span) is then mapped back to
the new file's line/column and to the diff line it came from, while the
original parse result keeps its logical-index view untouched.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Optional

from .bidi import parse_bidi

NO_NEWLINE_MARKER = "\\ No newline at end of file"

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:[ \t].*)?$")
_POS_RE = re.compile(r"\(line (\d+), col (\d+)\)")
_LOGICAL_INDEX_RE = re.compile(r"at logical index (\d+)")

# Preamble / extended header lines accepted outside hunks.
_HEADER_PREFIXES = (
    "diff --git ",
    "index ",
    "old mode ",
    "new mode ",
    "new file mode ",
    "deleted file mode ",
    "new file symlink ",
    "deleted file symlink ",
    "similarity index ",
    "dissimilarity index ",
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
    "Binary files ",
    "From ",
)

_RISK_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class DiffParseError(ValueError):
    """The diff text is structurally invalid.

    ``line_no`` is the 1-based number of the first diff line where the
    problem becomes visible.
    """

    def __init__(self, line_no: int, message: str):
        super().__init__(f"line {line_no}: {message}")
        self.line_no = line_no
        self.message = message


# ---------------------------------------------------------------------------
# Parsed diff model
# ---------------------------------------------------------------------------

@dataclass
class AddedLine:
    text: str          # content after the leading '+' (newline stripped)
    new_line: int      # 1-based line number in the new file (hunk header driven)
    diff_line: int     # 1-based line number in the diff text
    no_newline: bool = False  # followed by the "\ No newline..." marker


@dataclass
class _Hunk:
    header_line: int
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    old_used: int = 0
    new_used: int = 0
    added: list[AddedLine] = field(default_factory=list)


@dataclass
class FilePatch:
    old_path: Optional[str]
    new_path: Optional[str]
    header_line: int          # diff line of the section start / '---' header
    plus_line: Optional[int]  # diff line of the '+++' header
    hunks: list[_Hunk] = field(default_factory=list)
    binary: bool = False
    # Section introduced by a "diff --git" / "Binary files" preamble:
    # it is a valid file even without headers or hunks (empty or binary
    # files print neither).
    from_preamble: bool = False


# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------

def _unquote_path(value: str) -> str:
    """Decode a git-quoted path (``"src/a b.txt"`` with C escapes)."""
    if len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
        return value
    body = value[1:-1]
    out: list[str] = []
    i = 0
    simple = {
        "a": "\a", "b": "\b", "f": "\f", "n": "\n",
        "r": "\r", "t": "\t", "v": "\v", '"': '"', "\\": "\\",
    }
    while i < len(body):
        ch = body[i]
        if ch != "\\" or i + 1 >= len(body):
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt in simple:
            out.append(simple[nxt])
            i += 2
        elif nxt.isdigit():
            digits = body[i + 1:i + 4]
            octal = ""
            for d in digits:
                if d in "01234567" and len(octal) < 3:
                    octal += d
                else:
                    break
            out.append(chr(int(octal, 8)))
            i += 1 + len(octal)
        else:
            out.append(nxt)
            i += 2
    return "".join(out)


def _header_path(line: str) -> Optional[str]:
    """Extract the path half from a ``--- `` / ``+++ `` header line."""
    rest = line[4:]
    if "\t" in rest:  # timestamp follows the path, tab separated
        rest = rest.split("\t", 1)[0]
    rest = rest.rstrip()
    path = _unquote_path(rest)
    if path == "/dev/null":
        return None
    return path


def _strip_git_prefixes(
    old: Optional[str], new: Optional[str]
) -> tuple[Optional[str], Optional[str]]:
    """Strip the git ``a/`` / ``b/`` prefixes, but only for a recognisable
    git pair so plain ``diff -u`` output keeps paths verbatim."""
    if old is not None and new is not None:
        if old.startswith("a/") and new.startswith("b/"):
            return old[2:], new[2:]
    elif old is None and new is not None and new.startswith("b/"):
        return None, new[2:]
    elif new is None and old is not None and old.startswith("a/"):
        return old[2:], None
    return old, new


def _git_diff_paths(line: str) -> tuple[str, str]:
    """Parse the two paths of a ``diff --git a/x b/x`` header (handles
    git's C-style quoted paths) and strip the git ``a/``/``b/`` prefixes."""
    tokens = shlex.split(line[len("diff --git "):])
    if len(tokens) >= 2:
        old, new = tokens[0], tokens[1]
    else:
        # Unquoted paths never contain spaces for a valid git header; a
        # single token can only mean a rename-style self pair.
        token = tokens[0] if tokens else ""
        old = new = token
    stripped_old, stripped_new = _strip_git_prefixes(old, new)
    return stripped_old if stripped_old is not None else old, (
        stripped_new if stripped_new is not None else new
    )


def _binary_files_paths(line: str) -> tuple[Optional[str], Optional[str]]:
    """Parse ``Binary files <old> and <new> differ`` (the plain diff form),
    mapping git's ``/dev/null`` side to ``None`` and stripping git prefixes."""
    body = line[len("Binary files "):]
    body = body[: -len(" differ")] if body.endswith(" differ") else body
    sep = " and "
    if sep not in body:
        return None, None
    old_raw, new_raw = body.split(sep, 1)
    old = None if old_raw == "/dev/null" else _unquote_path(old_raw)
    new = None if new_raw == "/dev/null" else _unquote_path(new_raw)
    return _strip_git_prefixes(old, new)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_OUT = "out"
_PREAMBLE = "preamble"
_HEADERS = "headers"
_HUNK = "hunk"
_BINARY = "binary"


class _DiffParser:
    def __init__(self, text: str):
        lines = text.split("\n")
        # A trailing newline terminates the last line; the empty element it
        # produces is not itself a diff line.
        if text.endswith("\n") and lines and lines[-1] == "":
            lines.pop()
        self._lines = lines
        self.files: list[FilePatch] = []

    def parse(self) -> list[FilePatch]:
        state = _OUT
        current: Optional[FilePatch] = None
        hunk: Optional[_Hunk] = None
        new_cursor = 0          # next new-file line number inside the hunk
        prev_body_kind: Optional[str] = None  # '+', '-' or ' '
        prev_added: Optional[AddedLine] = None

        def check_hunk_closed(h: _Hunk) -> None:
            # Over-consumption is already reported at the first offending
            # body line; here only a truncated hunk (fewer lines than the
            # header declared) remains, attributed to the header itself.
            if h.old_used != h.old_count or h.new_used != h.new_count:
                raise DiffParseError(
                    h.header_line,
                    f"hunk header declares {h.old_count} old and {h.new_count} "
                    f"new line(s) but the body contains {h.old_used} old and "
                    f"{h.new_used} new line(s)",
                )

        def close_hunk() -> None:
            nonlocal hunk, prev_body_kind, prev_added
            if hunk is not None:
                check_hunk_closed(hunk)
                hunk = None
                prev_body_kind = None
                prev_added = None

        def close_file() -> None:
            nonlocal current
            close_hunk()
            if current is not None:
                if current.from_preamble:
                    # Preambular sections may be empty new files or binary
                    # files that print no headers/hunks at all: valid.
                    self.files.append(current)
                    current = None
                    return
                if current.new_path is None and not current.binary \
                        and not current.hunks:
                    # A bare '---' line without a following '+++' (or a
                    # deletion patch missing its hunks) is truncated/garbage.
                    raise DiffParseError(
                        current.header_line,
                        "'---' header is not followed by a '+++' header and hunks",
                    )
                if current.new_path is not None and not current.binary \
                        and not current.hunks:
                    raise DiffParseError(
                        current.plus_line or current.header_line,
                        "file header is not followed by any hunk",
                    )
                self.files.append(current)
                current = None

        def start_hunk(lineno: int, header: str) -> None:
            nonlocal state, hunk, new_cursor, prev_body_kind
            m = _HUNK_RE.match(header)
            if m is None:
                raise DiffParseError(
                    lineno, f"malformed hunk header: {header[:60]!r}"
                )
            old_start, old_count, new_start, new_count = m.groups()
            hunk = _Hunk(
                header_line=lineno,
                old_start=int(old_start),
                old_count=int(old_count or 1),
                new_start=int(new_start),
                new_count=int(new_count or 1),
            )
            assert current is not None
            current.hunks.append(hunk)
            # The cursor holds the line number assigned to the next kept
            # (' ' or '+') line; it is incremented after that line is used.
            new_cursor = hunk.new_start
            prev_body_kind = None
            prev_added = None
            state = _HUNK

        for lineno, raw in enumerate(self._lines, start=1):
            line = raw[:-1] if raw.endswith("\r") else raw

            # ----------------------------------------------------------- OUT
            if state == _OUT:
                if line == "" or line.startswith(("index ", "From ")):
                    continue
                if line.startswith("diff --git "):
                    old, new = _git_diff_paths(line)
                    current = FilePatch(
                        old_path=old, new_path=new, header_line=lineno,
                        plus_line=None, from_preamble=True,
                    )
                    state = _PREAMBLE
                    continue
                if line.startswith("Binary files "):
                    old, new = _binary_files_paths(line)
                    old, new = _strip_git_prefixes(old, new)
                    current = FilePatch(
                        old_path=old, new_path=new, header_line=lineno,
                        plus_line=None, binary=True, from_preamble=True,
                    )
                    self.files.append(current)
                    current = None
                    continue
                if line.startswith("--- "):
                    current = FilePatch(
                        old_path=_header_path(line),
                        new_path=None,
                        header_line=lineno,
                        plus_line=None,
                    )
                    state = _HEADERS
                    continue
                if line.startswith("+++ "):
                    raise DiffParseError(
                        lineno, "'+++' header without a preceding '---' header"
                    )
                if line.startswith("@@"):
                    raise DiffParseError(
                        lineno, "hunk header outside of a file section"
                    )
                raise DiffParseError(
                    lineno, f"unrecognised diff line outside hunk: {line[:40]!r}"
                )

            # ---------------------------------------------------- PREAMBLE
            if state == _PREAMBLE:
                assert current is not None
                if line == "":
                    continue
                if line.startswith("diff --git "):
                    # Empty/unchanged previous section ends; start the next.
                    close_file()
                    old, new = _git_diff_paths(line)
                    current = FilePatch(
                        old_path=old, new_path=new, header_line=lineno,
                        plus_line=None, from_preamble=True,
                    )
                    state = _PREAMBLE
                    continue
                if line == "GIT binary patch":
                    current.binary = True
                    state = _BINARY
                    continue
                if line.startswith("Binary files "):
                    old, new = _binary_files_paths(line)
                    current.binary = True
                    current.old_path, current.new_path = old, new
                    continue
                if line.startswith("--- "):
                    current.old_path = _header_path(line)
                    state = _HEADERS
                    continue
                if line.startswith("+++ "):
                    raise DiffParseError(
                        lineno, "'+++' header without a preceding '---' header"
                    )
                if line.startswith("@@"):
                    raise DiffParseError(
                        lineno,
                        "hunk header without '---'/'+++' file headers",
                    )
                if line.startswith(_HEADER_PREFIXES):
                    continue
                raise DiffParseError(
                    lineno, f"unrecognised diff header line: {line[:40]!r}"
                )

            # ------------------------------------------------------- HEADERS
            if state == _HEADERS:
                assert current is not None
                if line == "":
                    continue
                if line.startswith("diff --git "):
                    # A next-file preamble ends the current (binary) patch.
                    close_file()
                    old, new = _git_diff_paths(line)
                    current = FilePatch(
                        old_path=old, new_path=new, header_line=lineno,
                        plus_line=None, from_preamble=True,
                    )
                    state = _PREAMBLE
                    continue
                if line == "GIT binary patch":
                    current.binary = True
                    state = _BINARY
                    continue
                if line.startswith("Binary files "):
                    old, new = _binary_files_paths(line)
                    current.binary = True
                    current.old_path, current.new_path = old, new
                    continue
                if line.startswith("+++ "):
                    current.new_path = _header_path(line)
                    current.plus_line = lineno
                    old, new = _strip_git_prefixes(
                        current.old_path, current.new_path
                    )
                    current.old_path, current.new_path = old, new
                    continue
                if line.startswith("--- "):
                    raise DiffParseError(
                        lineno,
                        "unexpected '---' header: previous file header has no "
                        "'+++' header",
                    )
                if line.startswith("@@"):
                    if current.new_path is None and current.old_path is None:
                        raise DiffParseError(
                            lineno, "hunk without any file header path"
                        )
                    start_hunk(lineno, line)
                    continue
                if line.startswith(("From ",)):
                    close_file()
                    state = _OUT
                    continue
                if line.startswith(_HEADER_PREFIXES):
                    continue
                raise DiffParseError(
                    lineno, f"unrecognised diff header line: {line[:40]!r}"
                )

            # -------------------------------------------------------- BINARY
            if state == _BINARY:
                # Base85 body lines run until an empty separator or the next
                # file section; their content is irrelevant (no text added).
                if line == "":
                    state = _PREAMBLE if current is not None else _OUT
                    continue
                if line.startswith("diff --git "):
                    close_file()
                    old, new = _git_diff_paths(line)
                    current = FilePatch(
                        old_path=old, new_path=new, header_line=lineno,
                        plus_line=None, from_preamble=True,
                    )
                    state = _PREAMBLE
                    continue
                if line.startswith("--- "):
                    close_file()
                    current = FilePatch(
                        old_path=_header_path(line),
                        new_path=None,
                        header_line=lineno,
                        plus_line=None,
                    )
                    state = _HEADERS
                    continue
                if line.startswith(_HEADER_PREFIXES):
                    continue
                continue

            # ---------------------------------------------------------- HUNK
            assert state == _HUNK and hunk is not None and current is not None
            kind = line[:1]
            if kind in ("+", "-", " "):
                if kind == "+":
                    if hunk.new_used + 1 > hunk.new_count:
                        raise DiffParseError(
                            lineno,
                            f"hunk body exceeds the {hunk.new_count} new "
                            f"line(s) declared by its header",
                        )
                    added = AddedLine(
                        text=line[1:],
                        new_line=new_cursor,
                        diff_line=lineno,
                    )
                    hunk.added.append(added)
                    prev_added = added
                    hunk.new_used += 1
                elif kind == "-":
                    if hunk.old_used + 1 > hunk.old_count:
                        raise DiffParseError(
                            lineno,
                            f"hunk body exceeds the {hunk.old_count} old "
                            f"line(s) declared by its header",
                        )
                    hunk.old_used += 1
                else:
                    if (
                        hunk.old_used + 1 > hunk.old_count
                        or hunk.new_used + 1 > hunk.new_count
                    ):
                        raise DiffParseError(
                            lineno,
                            "hunk context line exceeds the line count "
                            "declared by its header",
                        )
                    hunk.old_used += 1
                    hunk.new_used += 1
                    prev_added = None
                if kind != "-":
                    new_cursor += 1
                prev_body_kind = kind
                continue

            if line.startswith("@@"):
                # Another hunk of the same file: finish this one first.
                close_hunk()
                start_hunk(lineno, line)
                continue

            if line.startswith("diff --git "):
                # Next file section ends the current one.
                close_file()
                old, new = _git_diff_paths(line)
                current = FilePatch(
                    old_path=old, new_path=new, header_line=lineno,
                    plus_line=None, from_preamble=True,
                )
                state = _PREAMBLE
                continue

            if line.startswith(_HEADER_PREFIXES) or line.startswith(
                "--- "
            ) or line.startswith("+++ "):
                # Current hunk/file ends; reprocess this line from OUT state.
                close_file()
                state = _OUT
                if line.startswith("--- "):
                    current = FilePatch(
                        old_path=_header_path(line),
                        new_path=None,
                        header_line=lineno,
                        plus_line=None,
                    )
                    state = _HEADERS
                elif line.startswith("+++ "):
                    raise DiffParseError(
                        lineno, "'+++' header without a preceding '---' header"
                    )
                continue

            if line.startswith("\\"):
                if line != NO_NEWLINE_MARKER:
                    raise DiffParseError(
                        lineno,
                        f"invalid no-newline marker (expected "
                        f"{NO_NEWLINE_MARKER!r})",
                    )
                if prev_body_kind is None:
                    raise DiffParseError(
                        lineno,
                        "no-newline marker is not attached to a preceding "
                        "added, removed or context line",
                    )
                if prev_body_kind == "+" and prev_added is not None:
                    prev_added.no_newline = True
                prev_body_kind = None
                prev_added = None
                continue

            raise DiffParseError(
                lineno,
                "hunk body line must start with ' ', '+' or '-' "
                f"(got {line[:40]!r})",
            )

        # End of input: whatever remains open must be complete.
        close_file()

        if not self.files:
            raise DiffParseError(1, "no unified diff file sections found")
        return self.files


def parse_unified_diff(text: str) -> list[FilePatch]:
    """Parse unified ``text`` into per-file patches.

    Raises :class:`DiffParseError` on the first structural problem; the
    line count of every hunk header is checked against its body.
    """
    return _DiffParser(text).parse()


# ---------------------------------------------------------------------------
# Audit + mapping
# ---------------------------------------------------------------------------

@dataclass
class FileAudit:
    new_path: str
    old_path: Optional[str]
    text: str
    entries: list[AddedLine]
    result: dict
    locations: dict
    meta: dict


def _rebuild_added_text(
    entries: list[AddedLine],
) -> tuple[str, list[int]]:
    """Concatenate added lines in new-file order and return the text plus
    each entry's starting logical offset."""
    parts: list[str] = []
    starts: list[int] = []
    offset = 0
    for entry in entries:
        starts.append(offset)
        parts.append(entry.text)
        offset += len(entry.text)
        if not entry.no_newline:
            parts.append("\n")
            offset += 1
    return "".join(parts), starts


def _map_offset(
    index: int,
    entries: list[AddedLine],
    starts: list[int],
) -> tuple[int, int, int, int]:
    """Map a logical index in the rebuilt text to (new line, new column,
    diff line, diff column).  Indices on the synthetic ``\\n`` separator
    map to the end of the preceding added line."""
    for k, entry in enumerate(entries):
        start = starts[k]
        length = len(entry.text)
        if start <= index <= start + length:
            column = index - start + 1
            return (
                entry.new_line,
                column,
                entry.diff_line,
                column + 1,  # the '+' prefix shifts diff columns by one
            )
    # Defensive fallback: clamp to the end of the last added line.
    entry = entries[-1]
    column = len(entry.text) + 1
    return entry.new_line, column, entry.diff_line, column + 1


def _position(line: int, column: int) -> dict:
    return {"line": line, "column": column}


def _build_locations(
    path: str,
    entries: list[AddedLine],
    starts: list[int],
    text: str,
    result: dict,
) -> dict:
    controls: list[dict] = []
    for i, control in enumerate(result["controls"]):
        # Rebuilt lines correspond 1:1 to added entries.
        entry = entries[control["position"]["line"] - 1]
        column = control["position"]["column"]
        controls.append({
            "result_index": i,
            "logical_index": control["logical_index"],
            "path": path,
            "position": _position(entry.new_line, column),
            "diff_position": _position(entry.diff_line, column + 1),
        })

    errors: list[dict] = []
    for i, message in enumerate(result["errors"]):
        # The first "(line N, col M)" is the flagged character's own
        # position; implicit-termination messages add a second one for the
        # PDI that closed the scope, which is not what we map to.
        match = _POS_RE.search(message)
        if match is None:
            continue
        pline, pcolumn = (int(g) for g in match.groups())
        entry = entries[pline - 1]
        index_match = _LOGICAL_INDEX_RE.search(message)
        errors.append({
            "result_index": i,
            "logical_index": (
                int(index_match.group(1)) if index_match else None
            ),
            "path": path,
            "position": _position(entry.new_line, pcolumn),
            "diff_position": _position(entry.diff_line, pcolumn + 1),
        })

    spans: list[dict] = []
    for i, span in enumerate(result["dangerous_spans"]):
        sl, sc, sdl, sdc = _map_offset(span["start"], entries, starts)
        el, ec, edl, edc = _map_offset(span["end"], entries, starts)
        spans.append({
            "result_index": i,
            "start_logical_index": span["start"],
            "end_logical_index": span["end"],
            "path": path,
            "position": {
                "start": _position(sl, sc),
                "end": _position(el, ec),
            },
            "diff_position": {
                "start": _position(sdl, sdc),
                "end": _position(edl, edc),
            },
        })

    return {"controls": controls, "errors": errors, "dangerous_spans": spans}


def audit_diff(diff_text: str) -> list[FileAudit]:
    """Fully parse and validate a unified diff, then audit every file that
    contains added lines.  Nothing is persisted here."""
    patches = parse_unified_diff(diff_text)
    audits: list[FileAudit] = []
    for patch in patches:
        entries: list[AddedLine] = [
            added for hunk in patch.hunks for added in hunk.added
        ]
        if not entries or patch.new_path is None:
            continue
        text, starts = _rebuild_added_text(entries)
        result = parse_bidi(text).to_dict()
        locations = _build_locations(
            patch.new_path, entries, starts, text, result
        )
        meta = {
            "source": "unified_diff",
            "version": 1,
            "new_path": patch.new_path,
            "old_path": patch.old_path,
            "added_lines": [
                {
                    "new_line": e.new_line,
                    "diff_line": e.diff_line,
                    "no_newline": e.no_newline,
                }
                for e in entries
            ],
            "locations": locations,
        }
        audits.append(FileAudit(
            new_path=patch.new_path,
            old_path=patch.old_path,
            text=text,
            entries=entries,
            result=result,
            locations=locations,
            meta=meta,
        ))
    return audits


def highest_risk(levels: list[str]) -> str:
    return max(levels, key=lambda level: _RISK_ORDER[level], default="info")
