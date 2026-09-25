"""URL query-key ambiguity auditing.

Takes a raw URL and audits the keys of its query component for
ambiguity.  The query runs from the first ``?`` to the first ``#`` or
the end of the URL (a ``?`` that only appears inside the fragment
starts no query).  Parameters are split on the *undecoded* ``&``
character and each segment's key ends at its first undecoded ``=``, so
every key keeps its exact start/end codepoint offsets in the original
URL and a value may itself contain ``=``; zero-length segments
(``&&``, leading/trailing ``&``) carry no key and are skipped.

Each key is then decoded **once** -- percent triplets are decoded as
UTF-8 bytes and ``+`` counts as a space, so ``%2520`` yields ``%20``
rather than a space and a literal ``%2B`` is a plus sign, not a space
-- and Unicode NFKC normalised.  Two or more parameter keys that
collapse to the same normalised form are reported as a collision group
(the classic HTTP parameter pollution / confusable-key shape, e.g.
``a`` next to ``%61``, ``a+b`` next to ``a%20b``, or a full-width
``X`` next to ASCII ``X``); exact duplicate keys collide as well.
Parameter *values* are never decoded and never take part in the
comparison.

A key that cannot be decoded -- a ``%`` not followed by two
hexadecimal digits, or percent-decoded bytes that are not valid UTF-8
-- raises :class:`QueryKeyDecodeError` carrying the 0-based codepoint
offset in the original URL before anything is reported, so a rejected
URL never produces a partial report.  Nothing is persisted here.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Optional

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class QueryKeyDecodeError(ValueError):
    """A parameter key cannot be percent/UTF-8 decoded.

    ``error`` is ``invalid_percent_encoding`` or ``invalid_utf8``;
    ``offset`` is the 0-based codepoint offset in the original URL of
    the offending ``%`` (for UTF-8 failures, of the ``%`` that produced
    the first undecodable byte); ``parameter_index`` is the 0-based
    index of the parameter the key belongs to.
    """

    def __init__(
        self, error: str, offset: int, parameter_index: int, message: str
    ):
        super().__init__(f"offset {offset}: {message}")
        self.error = error
        self.offset = offset
        self.parameter_index = parameter_index
        self.message = message


# ---------------------------------------------------------------------------
# Parsed model
# ---------------------------------------------------------------------------

@dataclass
class QueryParameter:
    index: int               # 0-based among the kept parameters
    raw_key: str             # key exactly as it appears in the URL
    decoded_key: str         # after one percent/UTF-8 decode pass
    normalised_key: str      # NFKC of the decoded key
    key_start: int           # codepoint offset of the key's first char
    key_end: int             # codepoint offset just past the key

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "raw": self.raw_key,
            "decoded": self.decoded_key,
            "start": self.key_start,
            "end": self.key_end,
        }


@dataclass
class QueryKeyCollision:
    normalised: str
    occurrences: list[QueryParameter]

    def to_dict(self) -> dict:
        return {
            "normalised": self.normalised,
            "occurrence_count": len(self.occurrences),
            "occurrences": [p.to_dict() for p in self.occurrences],
        }


@dataclass
class UrlQueryKeyReport:
    query_start: Optional[int]   # offset just past '?'; None when no query
    query_end: Optional[int]     # offset of '#' or of the URL's end
    parameter_count: int
    distinct_key_count: int      # distinct NFKC-normalised keys
    parameters: list[QueryParameter] = field(default_factory=list)
    collisions: list[QueryKeyCollision] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Key decoding
# ---------------------------------------------------------------------------

def _decode_key(raw_key: str, key_start: int, index: int) -> str:
    """Decode *raw_key* once: ``+`` -> space, ``%XX`` -> byte, UTF-8.

    Raises :class:`QueryKeyDecodeError` positioned in the original URL.
    """
    data = bytearray()
    origins: list[int] = []  # URL offset that produced each byte
    i, n = 0, len(raw_key)
    while i < n:
        ch = raw_key[i]
        if ch == "%":
            if (
                i + 2 >= n
                or raw_key[i + 1] not in _HEX_DIGITS
                or raw_key[i + 2] not in _HEX_DIGITS
            ):
                raise QueryKeyDecodeError(
                    "invalid_percent_encoding",
                    key_start + i,
                    index,
                    f"'%' in the key of parameter {index} is not followed "
                    "by two hexadecimal digits",
                )
            data.append(int(raw_key[i + 1 : i + 3], 16))
            origins.append(key_start + i)
            i += 3
        elif ch == "+":
            data.append(0x20)
            origins.append(key_start + i)
            i += 1
        else:
            encoded = ch.encode("utf-8")
            data.extend(encoded)
            origins.extend([key_start + i] * len(encoded))
            i += 1
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QueryKeyDecodeError(
            "invalid_utf8",
            origins[exc.start],
            index,
            f"the percent-decoded key of parameter {index} is not valid "
            f"UTF-8 ({exc.reason})",
        ) from None


# ---------------------------------------------------------------------------
# Query splitting
# ---------------------------------------------------------------------------

def _query_span(url: str) -> Optional[tuple[int, int]]:
    """Offsets of the raw query component: just past the first ``?`` up
    to the first ``#`` or the end of the URL.  A ``?`` that only appears
    inside the fragment (after ``#``) starts no query."""
    q = url.find("?")
    if q == -1:
        return None
    hash_pos = url.find("#")
    if hash_pos != -1 and hash_pos < q:
        return None
    return q + 1, hash_pos if hash_pos != -1 else len(url)


def _split_parameters(url: str, start: int, end: int) -> list[QueryParameter]:
    """Split the query on undecoded ``&`` and ``=`` and decode each key.

    Zero-length segments carry no key and are skipped; the first ``=``
    of a segment ends the key, so a value may itself contain ``=``
    (values are never inspected).
    """
    parameters: list[QueryParameter] = []
    pos = start
    while pos <= end:
        amp = url.find("&", pos, end)
        seg_end = amp if amp != -1 else end
        if seg_end > pos:
            eq = url.find("=", pos, seg_end)
            key_end = eq if eq != -1 else seg_end
            index = len(parameters)
            raw_key = url[pos:key_end]
            decoded = _decode_key(raw_key, pos, index)
            parameters.append(
                QueryParameter(
                    index=index,
                    raw_key=raw_key,
                    decoded_key=decoded,
                    normalised_key=unicodedata.normalize("NFKC", decoded),
                    key_start=pos,
                    key_end=key_end,
                )
            )
        if amp == -1:
            break
        pos = amp + 1
    return parameters


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def audit_url_query_keys(url: str) -> UrlQueryKeyReport:
    """Audit the query keys of *url* for normalisation collisions.

    Raises :class:`QueryKeyDecodeError` before reporting anything when
    a key cannot be decoded.  Nothing is persisted here.
    """
    span = _query_span(url)
    if span is None:
        return UrlQueryKeyReport(
            query_start=None,
            query_end=None,
            parameter_count=0,
            distinct_key_count=0,
        )
    parameters = _split_parameters(url, span[0], span[1])
    groups: dict[str, list[QueryParameter]] = {}
    for parameter in parameters:
        groups.setdefault(parameter.normalised_key, []).append(parameter)
    # Insertion order is the source order of each group's first
    # occurrence, so the collision list is stable.
    collisions = [
        QueryKeyCollision(normalised=key, occurrences=members)
        for key, members in groups.items()
        if len(members) >= 2
    ]
    return UrlQueryKeyReport(
        query_start=span[0],
        query_end=span[1],
        parameter_count=len(parameters),
        distinct_key_count=len(groups),
        parameters=parameters,
        collisions=collisions,
    )
