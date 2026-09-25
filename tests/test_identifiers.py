"""Tests for identifier NFKC normalization (POST/GET identifiers).

Covers: identifier extraction per Python lexical rules (comments, strings
and hard keywords skipped, including NFKC-confusable full-width keyword
spellings), NFKC collision detection (only distinct raw spellings collide;
pure repetition and case differences do not), source-stable occurrence
ordering with codepoint offsets/line/column, multi-line offsets, BOM
handling, lexical failures returning 422 with original-source position and
writing nothing, persistence and read-by-id, and 404/missing-field
branches.

Non-ASCII characters are written as \\uXXXX escapes so the file's exact
codepoint composition is independent of editor normalisation.
"""

import pytest

from app.identifiers import IdentifierLexError, scan_identifiers

ACUTE = "é"          # precomposed e-acute
E_COMBINING = "e" + chr(0x0301)  # 'e' + combining acute U+0301
FW_X = "Ｘ"          # fullwidth Latin capital X
MATH_X = "𝐗"         # mathematical bold capital X (astral plane)
FW_A = "ａ"          # fullwidth Latin small a
FW_B = "ｂ"          # fullwidth Latin small b
MATH_A = "𝐚"         # mathematical bold small a
MATH_B = "𝐛"         # mathematical bold small b
FI_LIGATURE = "ﬁ"    # U+FB01 LATIN SMALL LIGATURE FI
FW_TRUE = "Ｔｒｕｅ"  # fullwidth spelling that NFKC-normalises to keyword True
BOM = "﻿"


# ----------------------------------------------------------- unit: scan ---

def test_basic_nfkc_collision():
    # Precomposed U+00E9 vs 'e' + U+0301 are distinct raw spellings with
    # one NFKC normalised form.
    assert ACUTE != E_COMBINING
    src = f"{ACUTE} = 1\nx = {E_COMBINING}\n"
    report = scan_identifiers(src).to_dict()
    assert report["identifier_count"] == 3
    assert report["collision_count"] == 1
    collision = report["collisions"][0]
    assert collision["normalised"] == ACUTE
    assert collision["spelling_count"] == 2
    spellings = {s["spelling"] for s in collision["spellings"]}
    assert spellings == {ACUTE, E_COMBINING}


def test_occurrences_cover_their_source_and_order_is_stable():
    src = f"{ACUTE} = 1\ndef f({E_COMBINING}):\n    return {ACUTE}\n"
    report = scan_identifiers(src).to_dict()
    collision = report["collisions"][0]
    # spellings appear in first-seen order
    assert [s["spelling"] for s in collision["spellings"]] == [
        ACUTE, E_COMBINING
    ]
    # every occurrence covers its exact source span
    for s in collision["spellings"]:
        for o in s["occurrences"]:
            assert src[o["offset"]:o["end_offset"]] == s["spelling"]
        # each spelling's own occurrence list is in source order
        offsets = [o["offset"] for o in s["occurrences"]]
        assert offsets == sorted(offsets)
    # decomposed spelling lives on line 2 at column 7 (after "def f(")
    second = collision["spellings"][1]["occurrences"][0]
    assert second["line"] == 2
    assert second["column"] == 7
    # the line-1 occurrence starts at column 1
    assert collision["spellings"][0]["occurrences"][0]["column"] == 1
    # one spelling occurs twice, the other once; source order inside the
    # first spelling's list is line 1 then line 3
    first_offsets = [
        o["offset"] for o in collision["spellings"][0]["occurrences"]
    ]
    assert first_offsets == [0, 28]
    assert [s["occurrence_count"] for s in collision["spellings"]] == [2, 1]
    assert collision["occurrence_count"] == 3


def test_collisions_sorted_by_first_source_position():
    src = f"{MATH_A} {MATH_B} {FW_A} {FW_B}\n"
    report = scan_identifiers(src).to_dict()
    assert [c["normalised"] for c in report["collisions"]] == ["a", "b"]


def test_pure_repetition_is_not_collision():
    report = scan_identifiers("foo = 1\nfoo = foo + 1\n").to_dict()
    assert report["collision_count"] == 0
    assert report["identifier_count"] == 3
    assert report["distinct_spelling_count"] == 1


def test_case_difference_is_not_collision():
    # NFKC is case preserving: 'X' and 'x' stay distinct.
    report = scan_identifiers("X = 1\nx = 2\nxx = X\n").to_dict()
    assert report["collision_count"] == 0
    assert report["distinct_spelling_count"] == 3


def test_keywords_are_skipped_including_confusable_spellings():
    # Full-width letters NFKC-normalise to the hard keyword 'True'.
    report = scan_identifiers(f"{FW_TRUE} = 1\ntrueish = 2\n").to_dict()
    assert report["identifier_count"] == 1
    assert report["distinct_spelling_count"] == 1
    assert report["collision_count"] == 0
    all_names = [
        s["spelling"]
        for c in report["collisions"]
        for s in c["spellings"]
    ]
    assert FW_TRUE not in all_names


def test_regular_keywords_and_soft_keywords():
    report = scan_identifiers("def f(g):\n    return g\n").to_dict()
    # 'def' and 'return' are hard keywords; only f and g survive
    assert report["identifier_count"] == 3  # f, g, g
    assert report["distinct_spelling_count"] == 2
    # match/case are soft keywords and remain ordinary identifiers
    soft = scan_identifiers("match = 1\ncase = 2\n").to_dict()
    assert soft["identifier_count"] == 2
    assert soft["distinct_spelling_count"] == 2


def test_comments_and_strings_are_skipped():
    src = (
        f"# {ACUTE} comment {FW_X}\n"
        f"s = '{ACUTE} and {FW_X} inside'\n"
        f"t = f'{ACUTE} {{{MATH_X}}}'\n"
        f'doc = """{ACUTE} {FW_X}"""\n'
        f"{ACUTE} = 1\n"
    )
    report = scan_identifiers(src).to_dict()
    # s, t, doc and the final bare identifier; nothing inside comments
    # or string literals contributes
    assert report["identifier_count"] == 4
    assert report["collision_count"] == 0
    names = {
        s["spelling"]
        for c in report["collisions"]
        for s in c["spellings"]
    }
    assert FW_X not in names and MATH_X not in names


def test_fi_ligature_collides_with_ascii_spelling():
    # U+FB01 LATIN SMALL LIGATURE FI NFKC-normalises to 'fi'.
    report = scan_identifiers(f"{FI_LIGATURE} = 1\nfi = 2\n").to_dict()
    assert report["collision_count"] == 1
    collision = report["collisions"][0]
    assert collision["normalised"] == "fi"
    assert {s["spelling"] for s in collision["spellings"]} == {
        FI_LIGATURE, "fi"
    }


def test_astral_identifiers_use_codepoint_offsets():
    # Mathematical bold X is a single codepoint on the astral plane.
    src = f"{MATH_X} = 1\n{FW_X} = 2\n"
    report = scan_identifiers(src).to_dict()
    collision = report["collisions"][0]
    first = collision["spellings"][0]["occurrences"][0]
    assert first["end_offset"] - first["offset"] == 1
    assert src[first["offset"]:first["end_offset"]] == MATH_X
    second = collision["spellings"][1]["occurrences"][0]
    assert src[second["offset"]:second["end_offset"]] == FW_X
    assert first["line"] == 1 and second["line"] == 2


def test_multiline_offsets():
    # "a = 1\n\n" is 6 codepoints; line 3 begins at offset 6.
    src = f"a = 1\n\n{FW_X} = 2\n{MATH_X} = 3\n"
    report = scan_identifiers(src).to_dict()
    collision = report["collisions"][0]
    first = collision["spellings"][0]["occurrences"][0]
    second = collision["spellings"][1]["occurrences"][0]
    assert src[first["offset"]:first["end_offset"]] == FW_X
    assert src[second["offset"]:second["end_offset"]] == MATH_X
    assert (first["line"], first["offset"]) == (3, 7)
    assert (second["line"], second["offset"]) == (4, 13)


def test_bom_is_accepted_and_offsets_include_it():
    src = f"{BOM}{FW_X} = 1\n{MATH_X} = 2\n"
    report = scan_identifiers(src).to_dict()
    assert report["collision_count"] == 1
    occurrence = report["collisions"][0]["spellings"][0]["occurrences"][0]
    # offset/column account for the leading BOM
    assert occurrence["offset"] == 1
    assert occurrence["column"] == 2
    assert src[occurrence["offset"]:occurrence["end_offset"]] == FW_X


def test_crlf_columns_match_codepoints():
    src = f"x = 1\r\n{FW_X} = 2\r\n{MATH_X} = 3\r\n"
    report = scan_identifiers(src).to_dict()
    assert report["collision_count"] == 1
    for collision in report["collisions"]:
        for spelling in collision["spellings"]:
            for o in spelling["occurrences"]:
                assert src[o["offset"]:o["end_offset"]] == \
                    spelling["spelling"]


def test_empty_and_comment_only_source():
    assert scan_identifiers("").to_dict()["identifier_count"] == 0
    report = scan_identifiers("# just a comment\n").to_dict()
    assert report["identifier_count"] == 0
    assert report["collision_count"] == 0


# ------------------------------------------------------- unit: lex errors --

@pytest.mark.parametrize(
    "source,error",
    [
        ("x = 1 $\n", "unexpected_character"),
        ("x\x00y = 1\n", "unexpected_character"),
        ("x = '''unterminated\n", "unterminated_string"),
        ("x = '", "unterminated_statement"),
        ('x = "', "unterminated_statement"),
        ('x = "abc\n', "unterminated_statement"),
        ("x = 1\\\n", "unterminated_statement"),
        ("x = (\n", "unterminated_statement"),
        ("def f():\n  x=1\n y=2\n", "indentation_error"),
    ],
)
def test_lexical_failure_raises_with_position(source, error):
    with pytest.raises(IdentifierLexError) as exc:
        scan_identifiers(source)
    assert exc.value.error == error
    assert exc.value.line >= 1
    assert exc.value.column >= 1
    assert 0 <= exc.value.offset <= len(source)


def test_unexpected_character_position():
    src = "x = 1 $\n"
    with pytest.raises(IdentifierLexError) as exc:
        scan_identifiers(src)
    assert exc.value.error == "unexpected_character"
    assert (exc.value.line, exc.value.column) == (1, 7)
    assert exc.value.offset == 6
    assert "U+0024" in exc.value.message


@pytest.mark.parametrize("quote", ["'", '"'])
def test_unterminated_quote_at_eof_position(quote):
    # The 3.11 tokenizer reports the opening quote as an ERRORTOKEN; the
    # failure must be positioned where the string scan stopped (end of
    # source here), not at the quote.
    src = f"x = {quote}"
    with pytest.raises(IdentifierLexError) as exc:
        scan_identifiers(src)
    assert exc.value.error == "unterminated_statement"
    assert (exc.value.offset, exc.value.line, exc.value.column) == (5, 1, 6)


def test_unterminated_quote_position_is_line_end_not_quote():
    # The string scan stops at the line break: 'x = "abc' is 8 codepoints,
    # so the stop position is the newline at offset 8 (line 1, column 9).
    with pytest.raises(IdentifierLexError) as exc:
        scan_identifiers('x = "abc\n')
    assert exc.value.error == "unterminated_statement"
    assert (exc.value.offset, exc.value.line, exc.value.column) == (8, 1, 9)


def test_unterminated_quote_position_on_later_line_with_bom():
    src = f"{BOM}a = 1\nb = '"
    with pytest.raises(IdentifierLexError) as exc:
        scan_identifiers(src)
    assert exc.value.error == "unterminated_statement"
    # end of source: BOM + "a = 1\nb = '" is 12 codepoints
    assert (exc.value.offset, exc.value.line, exc.value.column) == (12, 2, 6)


def test_indentation_error_position():
    with pytest.raises(IdentifierLexError) as exc:
        scan_identifiers("def f():\n  x=1\n y=2\n")
    assert exc.value.error == "indentation_error"
    assert exc.value.line == 3
    assert exc.value.column == 1


# --------------------------------------------------------------- API: POST -

def test_post_collision_stored_and_shape(client):
    src = f"{FI_LIGATURE} = 1\nfi = 2\n"
    resp = client.post(
        "/api/v1/identifiers/normalization",
        json={"source": src, "filename": "m.py"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["stored"] is True
    assert body["filename"] == "m.py"
    assert body["source_length"] == len(src)
    report = body["report"]
    assert report["collision_count"] == 1
    collision = report["collisions"][0]
    assert collision["normalised"] == "fi"
    flat = [
        o["offset"]
        for s in collision["spellings"]
        for o in s["occurrences"]
    ]
    assert flat == sorted(flat)
    assert isinstance(body["id"], int)


def test_post_no_collisions_still_persists_and_is_readable(client):
    resp = client.post(
        "/api/v1/identifiers/normalization", json={"source": "foo = 1\n"}
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["report"]["collision_count"] == 0
    got = client.get(
        f"/api/v1/identifiers/normalization/{body['id']}"
    )
    assert got.status_code == 200
    assert got.json()["report"]["collision_count"] == 0


def test_post_filename_optional(client):
    resp = client.post(
        "/api/v1/identifiers/normalization", json={"source": "x = 1\n"}
    )
    assert resp.status_code == 201
    assert resp.json()["filename"] is None


def test_post_lex_failure_422_with_position_and_no_audit(client):
    resp = client.post(
        "/api/v1/identifiers/normalization", json={"source": "x = 1 $\n"}
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "unexpected_character"
    assert detail["line"] == 1 and detail["column"] == 7
    assert detail["offset"] == 6
    assert "message" in detail

    # a later successful request still gets id 1: the failure wrote nothing
    ok = client.post(
        "/api/v1/identifiers/normalization", json={"source": "y = 1\n"}
    )
    assert ok.status_code == 201
    assert ok.json()["id"] == 1


def test_post_unterminated_string_422(client):
    resp = client.post(
        "/api/v1/identifiers/normalization",
        json={"source": "s = '''never ends\n"},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "unterminated_string"


def test_post_unterminated_quote_422_with_stop_position_and_no_audit(client):
    resp = client.post(
        "/api/v1/identifiers/normalization", json={"source": "x = '"}
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "unterminated_statement"
    assert detail["offset"] == 5
    assert detail["line"] == 1 and detail["column"] == 6
    assert "message" in detail

    # the lexical failure wrote nothing: a later success still gets id 1
    ok = client.post(
        "/api/v1/identifiers/normalization", json={"source": "y = 1\n"}
    )
    assert ok.status_code == 201
    assert ok.json()["id"] == 1


def test_post_indentation_error_422(client):
    resp = client.post(
        "/api/v1/identifiers/normalization",
        json={"source": "def f():\n  x=1\n y=2\n"},
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "indentation_error"
    assert detail["line"] == 3


def test_post_missing_source_field_422(client):
    resp = client.post(
        "/api/v1/identifiers/normalization", json={"filename": "m.py"}
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------- API: GET -

def test_get_report_returns_full_record(client):
    src = f"def f():\n    return {FW_X} + {MATH_X}\n"
    created = client.post(
        "/api/v1/identifiers/normalization",
        json={"source": src, "filename": "x.py"},
    ).json()
    resp = client.get(
        f"/api/v1/identifiers/normalization/{created['id']}"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == created["id"]
    assert body["filename"] == "x.py"
    assert body["raw_source"] == src
    assert body["source_length"] == len(src)
    # f, fullwidth X, mathematical bold X
    assert body["identifier_count"] == 3
    assert body["distinct_spelling_count"] == 3
    assert body["collision_count"] == 1
    assert body["report"]["collisions"][0]["normalised"] == "X"
    assert "created_at" in body


def test_get_missing_report_404(client):
    resp = client.get("/api/v1/identifiers/normalization/424242")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "identifier normalization report not found"}


def test_identifier_records_are_independent_of_audits(client):
    # an identifiers POST must not create an audits row and vice versa
    client.post(
        "/api/v1/identifiers/normalization", json={"source": "x = 1\n"}
    )
    assert client.get("/api/v1/audits").json()["total"] == 0
    client.post("/api/v1/audits", json={"text": "plain"})
    second = client.post(
        "/api/v1/identifiers/normalization", json={"source": "y = 2\n"}
    ).json()
    # independent id sequence continuing from 1 in a fresh database
    assert second["id"] == 2


def test_root_lists_new_endpoint(client):
    body = client.get("/").json()
    assert "POST /api/v1/identifiers/normalization" in body["endpoints"]
    assert "GET  /api/v1/identifiers/normalization/{id}" in body["endpoints"]
