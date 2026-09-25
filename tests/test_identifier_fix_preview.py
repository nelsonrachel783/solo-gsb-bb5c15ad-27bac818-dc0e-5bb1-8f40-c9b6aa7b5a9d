"""Tests for the NFKC collision fix preview (POST identifiers/fix-preview).

Covers: reuse of the lexical scan to locate one collision group by its
NFKC normalised name, replacement of only non-canonical spellings (the
canonical spelling is never rewritten), edits ordered by source position
with original-source codepoint spans, round-trip reconstruction of the
fixed source, length-changing replacements (astral/decomposed codepoints),
preservation of strings/comments/BOM/CRLF and every other character,
rescanning the fixed source (target group gone, other groups remain),
target-name NFKC normalisation, 422 for missing groups and lexical
failures, and the API contract (200, not persisted, no DB writes).

Non-ASCII characters are written as \\uXXXX escapes so the file's exact
codepoint composition is independent of editor normalisation.
"""

import pytest

from app.identifiers import (
    CollisionGroupNotFoundError,
    IdentifierLexError,
    preview_collision_fix,
    scan_identifiers,
)

ACUTE = "é"          # precomposed e-acute
E_COMBINING = "e" + chr(0x0301)  # 'e' + combining acute U+0301
FW_X = "Ｘ"          # fullwidth Latin capital X
MATH_X = "𝐗"         # mathematical bold capital X (astral plane)
FW_A = "ａ"          # fullwidth Latin small a
MATH_A = "𝐚"         # mathematical bold small a
FI_LIGATURE = "ﬁ"    # U+FB01 LATIN SMALL LIGATURE FI
BOM = "﻿"


def _apply_edits(source: str, edits: list[dict]) -> str:
    """Rebuild the fixed source from the reported spans, right to left."""
    fixed = source
    for edit in sorted(edits, key=lambda e: e["offset"], reverse=True):
        fixed = (
            fixed[: edit["offset"]]
            + edit["replacement"]
            + fixed[edit["end_offset"] :]
        )
    return fixed


# ------------------------------------------------------- unit: the preview --

def test_preview_replaces_only_noncanonical_spelling():
    # ACUTE (U+00E9) is itself the NFKC canonical spelling; the decomposed
    # 'e' + U+0301 is the non-canonical one and must be the sole edit.
    src = f"{ACUTE} = 1\nx = {E_COMBINING}\n"
    preview = preview_collision_fix(src, ACUTE)
    assert preview.target_normalised == ACUTE
    assert len(preview.edits) == 1
    edit = preview.edits[0]
    assert edit.original == E_COMBINING
    assert edit.replacement == ACUTE
    assert src[edit.offset : edit.end_offset] == E_COMBINING
    assert preview.fixed_source == f"{ACUTE} = 1\nx = {ACUTE}\n"
    assert preview.report_after.collision_count == 0
    assert preview.report_before.collision_count == 1


def test_preview_with_canonical_spelling_present_keeps_it():
    src = f"{FI_LIGATURE} = 1\nfi = {FI_LIGATURE} + {FI_LIGATURE}\n"
    preview = preview_collision_fix(src, "fi")
    assert preview.target_normalised == "fi"
    # three ligature occurrences, zero edits for the canonical ASCII 'fi'
    assert len(preview.edits) == 3
    assert all(e.original == FI_LIGATURE for e in preview.edits)
    assert all(e.replacement == "fi" for e in preview.edits)
    edited_spans = [(e.offset, e.end_offset) for e in preview.edits]
    assert edited_spans == [(0, 1), (11, 12), (15, 16)]
    assert preview.fixed_source == "fi = 1\nfi = fi + fi\n"
    # the literal 'fi' on line 2 (offsets 6..8) is outside every edit
    assert all(not (start <= 6 < end) for start, end in edited_spans)
    assert preview.report_after.collision_count == 0
    assert preview.report_after.identifier_count == 4


def test_preview_without_canonical_spelling_rewrites_all():
    # Two non-canonical spellings, neither equals the normalised form:
    # every occurrence is rewritten.
    src = f"{FW_X} = 1\n{MATH_X} = 2\n{FW_X} + {MATH_X}\n"
    preview = preview_collision_fix(src, "X")
    assert len(preview.edits) == 4
    assert [e.original for e in preview.edits] == [
        FW_X, MATH_X, FW_X, MATH_X
    ]
    assert all(e.replacement == "X" for e in preview.edits)
    assert preview.fixed_source == "X = 1\nX = 2\nX + X\n"
    assert preview.report_after.collision_count == 0
    # identifier occurrences are only renamed, never added or removed
    assert preview.report_after.identifier_count == 4
    assert preview.report_before.identifier_count == 4


def test_edits_are_sorted_and_roundtrip_to_fixed_source():
    src = f"{FW_X} = {FI_LIGATURE}\n{MATH_X} = fi\n{E_COMBINING} = 1\n"
    preview = preview_collision_fix(src, "X")
    offsets = [e.offset for e in preview.edits]
    assert offsets == sorted(offsets)
    # every edit covers its exact original span ...
    for edit in preview.edits:
        assert src[edit.offset : edit.end_offset] == edit.original
        assert edit.original != edit.replacement
    # ... and applying the reported spans to the original yields exactly the
    # fixed source the endpoint would return
    assert (
        _apply_edits(src, preview.to_dict()["edits"]) == preview.fixed_source
    )
    # edits never overlap: canonical spans are disjoint identifier tokens
    for earlier, later in zip(preview.edits, preview.edits[1:]):
        assert earlier.end_offset <= later.offset


def test_unchanged_segments_are_copied_verbatim():
    src = f"a = {FW_X} + 1\nb = {MATH_X} * 2\n"
    preview = preview_collision_fix(src, "X")
    fixed = preview.fixed_source
    # interleave original segments with replacements and expect equality
    rebuilt = ""
    cursor = 0
    for edit in preview.edits:
        rebuilt += src[cursor:edit.offset]
        rebuilt += edit.replacement
        cursor = edit.end_offset
    rebuilt += src[cursor:]
    assert rebuilt == fixed
    # literals surrounding the identifiers survive
    assert "a = " in fixed and " + 1\n" in fixed
    assert "b = " in fixed and " * 2\n" in fixed


def test_fixed_source_preserves_bom_crlf_strings_and_comments():
    src = (
        f"{BOM}# {FW_X} lives in a comment\r\n"
        f"s = '{MATH_X} inside a string'\r\n"
        f"{FW_X} = 1\r\n"
        f"{MATH_X} = 2\r\n"
    )
    preview = preview_collision_fix(src, "X")
    fixed = preview.fixed_source
    # only the two real identifiers (lines 3-4) are edited
    assert len(preview.edits) == 2
    # BOM and every CRLF survive untouched
    assert fixed.startswith(BOM)
    assert fixed.count("\r\n") == src.count("\r\n") == 4
    assert "\n" not in fixed.replace("\r\n", "")
    # comment and string contents are never identifier spans
    assert fixed.startswith(f"{BOM}# {FW_X} lives in a comment\r\n")
    assert f"s = '{MATH_X} inside a string'\r\n" in fixed
    # the two fixed identifiers, and no others, are ASCII 'X'
    assert fixed.count("X") == 2
    assert FW_X not in fixed.split("\r\n", 2)[2]
    assert preview.report_after.collision_count == 0


def test_report_after_matches_independent_rescan():
    src = f"{FI_LIGATURE} = 1\nfi = 2\n"
    preview = preview_collision_fix(src, "fi")
    rescanned = scan_identifiers(preview.fixed_source).to_dict()
    assert preview.report_after.to_dict() == rescanned
    assert preview.report_before.to_dict() == scan_identifiers(src).to_dict()


def test_fixing_one_group_leaves_other_groups_in_place():
    src = (
        f"{ACUTE} = 1\n"
        f"{E_COMBINING} = 2\n"
        f"{FW_X} = 3\n"
        f"{MATH_X} = 4\n"
    )
    preview = preview_collision_fix(src, ACUTE)
    assert len(preview.edits) == 1
    assert preview.edits[0].offset == len(f"{ACUTE} = 1\n")
    after = preview.report_after
    assert after.collision_count == 1
    assert after.collisions[0].normalised == "X"
    # the X lines are carried over unchanged
    assert preview.fixed_source.endswith(f"{FW_X} = 3\n{MATH_X} = 4\n")


def test_target_name_is_itself_nfkc_normalised():
    src = f"{FW_X} = 1\n{MATH_X} = 2\n"
    # a raw non-canonical spelling is accepted as the group selector
    preview = preview_collision_fix(src, FW_X)
    assert preview.target_normalised == "X"
    assert len(preview.edits) == 2
    assert preview.report_after.collision_count == 0


def test_length_changing_replacement_keeps_later_offsets_original():
    # the ligature is one codepoint that expands to two; edits later in
    # the source must still use original-source offsets
    src = f"{FI_LIGATURE} = 1\nfi = {FI_LIGATURE}\n"
    preview = preview_collision_fix(src, "fi")
    first, second = preview.edits
    assert (first.offset, first.end_offset) == (0, 1)
    # second occurrence: "ﬁ = 1\nfi = " is 11 codepoints
    assert (second.offset, second.end_offset) == (11, 12)
    assert src[second.offset : second.end_offset] == FI_LIGATURE
    assert preview.fixed_source == "fi = 1\nfi = fi\n"
    assert len(preview.fixed_source) == len(src) + 2


def test_decomposed_spelling_replacement_rescans_clean():
    src = f"def f({E_COMBINING}):\n    return {E_COMBINING}\n{ACUTE} = 3\n"
    preview = preview_collision_fix(src, ACUTE)
    assert [e.original for e in preview.edits] == [
        E_COMBINING, E_COMBINING
    ]
    fixed = preview.fixed_source
    assert fixed == f"def f({ACUTE}):\n    return {ACUTE}\n{ACUTE} = 3\n"
    # replacement length contracts (2 codepoints -> 1); offsets are
    # original-source coordinates and the rescan has no collisions
    assert preview.report_after.collision_count == 0
    assert scan_identifiers(fixed).collision_count == 0


def test_preview_no_collision_group_for_single_spelling():
    with pytest.raises(CollisionGroupNotFoundError) as exc:
        preview_collision_fix("foo = 1\nfoo = 2\n", "foo")
    assert exc.value.normalised == "foo"


def test_preview_unknown_group_name_not_found():
    src = f"{FI_LIGATURE} = 1\nfi = 2\n"
    with pytest.raises(CollisionGroupNotFoundError) as exc:
        preview_collision_fix(src, "xyz")
    assert exc.value.normalised == "xyz"


def test_preview_raw_selector_without_group_reports_normalised_name():
    # the ligature normalises to 'fi', which is not a group here
    with pytest.raises(CollisionGroupNotFoundError) as exc:
        preview_collision_fix("foo = 1\n", FI_LIGATURE)
    assert exc.value.normalised == "fi"


def test_preview_case_difference_is_not_a_group():
    # NFKC preserves case, so 'X' and 'x' never form a group
    with pytest.raises(CollisionGroupNotFoundError):
        preview_collision_fix("X = 1\nx = 2\n", "X")


def test_preview_lex_failure_raises_scanner_error():
    with pytest.raises(IdentifierLexError) as exc:
        preview_collision_fix("x = 1 $\n", "x")
    assert exc.value.error == "unexpected_character"
    assert (exc.value.line, exc.value.column) == (1, 7)


@pytest.mark.parametrize("quote", ["'", '"'])
def test_preview_unterminated_quote_raises_unterminated_statement(quote):
    # the preview reuses the normalization scan: a source ending in an
    # unterminated quote is not an unexpected character at the quote but
    # an unterminated statement positioned where the string scan stopped
    with pytest.raises(IdentifierLexError) as exc:
        preview_collision_fix(f"x = {quote}", "x")
    assert exc.value.error == "unterminated_statement"
    assert (exc.value.offset, exc.value.line, exc.value.column) == (5, 1, 6)


# --------------------------------------------------------------- API: POST -

def test_post_fix_preview_200_shape(client):
    src = f"{FI_LIGATURE} = 1\nfi = {FI_LIGATURE}\n"
    resp = client.post(
        "/api/v1/identifiers/normalization/fix-preview",
        json={"source": src, "normalised_name": "fi"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stored"] is False
    assert body["target_normalised"] == "fi"
    assert body["source_length"] == len(src)
    assert body["edit_count"] == 2
    edit = body["edits"][0]
    assert set(edit) == {"offset", "end_offset", "original", "replacement"}
    assert edit["offset"] == 0 and edit["end_offset"] == 1
    assert edit["original"] == FI_LIGATURE and edit["replacement"] == "fi"
    assert body["fixed_source"] == "fi = 1\nfi = fi\n"
    assert body["fixed_source_length"] == len(body["fixed_source"])
    assert body["report"]["collision_count"] == 0


def test_post_fix_preview_accepts_raw_spelling_as_name(client):
    src = f"{FW_X} = 1\n{MATH_X} = 2\n"
    resp = client.post(
        "/api/v1/identifiers/normalization/fix-preview",
        json={"source": src, "normalised_name": MATH_X},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["target_normalised"] == "X"
    assert body["fixed_source"] == "X = 1\nX = 2\n"


def test_post_fix_preview_group_not_found_422(client):
    resp = client.post(
        "/api/v1/identifiers/normalization/fix-preview",
        json={"source": "foo = 1\nfoo = 2\n", "normalised_name": "foo"},
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "collision_group_not_found"
    assert detail["normalised"] == "foo"
    assert "message" in detail


def test_post_fix_preview_lex_error_422_with_position(client):
    resp = client.post(
        "/api/v1/identifiers/normalization/fix-preview",
        json={"source": "x = 1 $\n", "normalised_name": "x"},
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "unexpected_character"
    assert detail["offset"] == 6
    assert detail["line"] == 1 and detail["column"] == 7


def test_post_fix_preview_unterminated_string_422(client):
    resp = client.post(
        "/api/v1/identifiers/normalization/fix-preview",
        json={"source": "s = '''never ends\n", "normalised_name": "s"},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "unterminated_string"


@pytest.mark.parametrize("quote", ["'", '"'])
def test_post_fix_preview_unterminated_quote_422(client, quote):
    resp = client.post(
        "/api/v1/identifiers/normalization/fix-preview",
        json={"source": f"x = {quote}", "normalised_name": "x"},
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "unterminated_statement"
    assert detail["offset"] == 5
    assert detail["line"] == 1 and detail["column"] == 6
    assert "message" in detail


def test_post_fix_preview_unterminated_quote_writes_nothing(client):
    client.post(
        "/api/v1/identifiers/normalization/fix-preview",
        json={"source": "x = '", "normalised_name": "x"},
    )
    stored = client.post(
        "/api/v1/identifiers/normalization", json={"source": "y = 1\n"}
    )
    assert stored.status_code == 201
    assert stored.json()["id"] == 1
    assert client.get("/api/v1/audits").json()["total"] == 0


@pytest.mark.parametrize(
    "payload",
    [
        {"normalised_name": "x"},                       # missing source
        {"source": "x = 1\n"},                          # missing name
        {"source": "x = 1\n", "normalised_name": ""},   # empty name
        {},                                             # both missing
    ],
)
def test_post_fix_preview_missing_fields_422(client, payload):
    resp = client.post(
        "/api/v1/identifiers/normalization/fix-preview", json=payload
    )
    assert resp.status_code == 422


def test_post_fix_preview_writes_nothing(client):
    # neither a successful preview nor a 422 may allocate a report id
    client.post(
        "/api/v1/identifiers/normalization/fix-preview",
        json={
            "source": f"{FI_LIGATURE} = 1\nfi = 2\n",
            "normalised_name": "fi",
        },
    )
    client.post(
        "/api/v1/identifiers/normalization/fix-preview",
        json={"source": "x = 1 $\n", "normalised_name": "x"},
    )
    client.post(
        "/api/v1/identifiers/normalization/fix-preview",
        json={"source": "foo = 1\n", "normalised_name": "foo"},
    )
    stored = client.post(
        "/api/v1/identifiers/normalization", json={"source": "y = 1\n"}
    )
    assert stored.status_code == 201
    assert stored.json()["id"] == 1
    # previews must not touch the audits table either
    assert client.get("/api/v1/audits").json()["total"] == 0


def test_fix_preview_route_is_distinct_from_report_read(client):
    # POST fix-preview must not be swallowed by GET .../{report_id}
    assert client.post(
        "/api/v1/identifiers/normalization/fix-preview",
        json={"source": "foo = 1\n", "normalised_name": "foo"},
    ).status_code == 422


def test_root_lists_fix_preview(client):
    endpoints = client.get("/").json()["endpoints"]
    assert (
        "POST /api/v1/identifiers/normalization/fix-preview" in endpoints
    )
