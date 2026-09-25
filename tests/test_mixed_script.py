"""Tests for mixed-script identifier detection (POST identifiers/mixed-script).

Covers: Latin/Greek/Cyrillic script classification by Unicode data name
prefix (combining marks, digits, underscores and full-width/mathematical
lookalike letters are script-neutral), two-or-more-scripts reporting with
per-character codepoint offsets and line/column, per-occurrence reporting
of repeated names in source order, reuse of the identifier lexical
boundaries (strings, comments and hard keywords skipped, confusable
keyword spellings skipped, Cyrillic keyword lookalikes reported), BOM /
CRLF / multi-line positions, lexical failures returning the shared 422
structure, and the analysis-only endpoint writing no records.

Non-ASCII characters are written as \\uXXXX escapes so the file's exact
codepoint composition is independent of editor normalisation.
"""

import pytest

from app.identifiers import IdentifierLexError, scan_mixed_scripts

CYR_A = "а"          # U+0430 CYRILLIC SMALL LETTER A
CYR_R = "р"          # U+0440 CYRILLIC SMALL LETTER ER
CYR_U = "у"          # U+0443 CYRILLIC SMALL LETTER U
CYR_T = "Т"          # U+0422 CYRILLIC CAPITAL LETTER TE
GRK_ALPHA = "α"      # U+03B1 GREEK SMALL LETTER ALPHA
COMBINING_ACUTE = "́"  # U+0301 COMBINING ACUTE ACCENT
FW_X = "Ｘ"          # U+FF38 FULLWIDTH LATIN CAPITAL X (name: FULLWIDTH ...)
MATH_X = "𝐗"         # U+1D417 MATHEMATICAL BOLD CAPITAL X (name: MATHEMATICAL ...)
FW_TRUE = "Ｔｒｕｅ"  # fullwidth spelling that NFKC-normalises to keyword True
BOM = "﻿"


# ----------------------------------------------------------- unit: scan ---

def test_latin_cyrillic_mix_reported_per_character():
    src = f"p{CYR_A}y = 1\n"
    report = scan_mixed_scripts(src).to_dict()
    assert report["identifier_count"] == 1
    assert report["finding_count"] == 1
    finding = report["findings"][0]
    assert finding["spelling"] == f"p{CYR_A}y"
    # scripts in first-appearance order within the spelling
    assert finding["scripts"] == ["latin", "cyrillic"]
    assert (finding["offset"], finding["end_offset"]) == (0, 3)
    assert (finding["line"], finding["column"]) == (1, 1)
    chars = finding["characters"]
    assert [c["char"] for c in chars] == ["p", CYR_A, "y"]
    assert [c["script"] for c in chars] == ["latin", "cyrillic", "latin"]
    assert [c["codepoint"] for c in chars] == ["U+0070", "U+0430", "U+0079"]
    assert [c["offset"] for c in chars] == [0, 1, 2]
    assert [c["column"] for c in chars] == [1, 2, 3]
    assert all(c["line"] == 1 for c in chars)
    # every reported character slice matches the original source
    for c in chars:
        assert src[c["offset"]] == c["char"]
    assert src[finding["offset"]:finding["end_offset"]] == finding["spelling"]


def test_single_script_identifiers_are_not_reported():
    # pure Latin, pure Cyrillic and Latin-with-digits/underscore names
    src = f"pay = 1\n{CYR_R}{CYR_A}{CYR_U} = 2\npay_2 = 3\n"
    report = scan_mixed_scripts(src).to_dict()
    assert report["identifier_count"] == 3
    assert report["finding_count"] == 0
    assert report["findings"] == []


def test_greek_latin_mix_and_three_scripts():
    report = scan_mixed_scripts(f"{GRK_ALPHA}bc = 1\n").to_dict()
    assert report["finding_count"] == 1
    assert report["findings"][0]["scripts"] == ["greek", "latin"]
    three = scan_mixed_scripts(
        f"{GRK_ALPHA}a{CYR_A} = 1\n"
    ).to_dict()
    assert three["findings"][0]["scripts"] == ["greek", "latin", "cyrillic"]


def test_digits_underscores_and_combining_marks_are_script_neutral():
    # 'a_1' carries only one script; a trailing combining mark inside a
    # mixed name is skipped while the letters around it keep their scripts.
    src = f"a_1 = 1\nb{CYR_A}{COMBINING_ACUTE} = 2\n"
    report = scan_mixed_scripts(src).to_dict()
    assert report["identifier_count"] == 2
    assert report["finding_count"] == 1
    finding = report["findings"][0]
    assert finding["spelling"] == f"b{CYR_A}{COMBINING_ACUTE}"
    assert finding["scripts"] == ["latin", "cyrillic"]
    # "a_1 = 1\n" is 8 codepoints; the identifier spans offsets 8..11 and
    # the combining mark at offset 10 is not listed among the characters
    assert (finding["offset"], finding["end_offset"]) == (8, 11)
    chars = finding["characters"]
    assert [c["char"] for c in chars] == ["b", CYR_A]
    assert [c["offset"] for c in chars] == [8, 9]
    assert [c["column"] for c in chars] == [1, 2]
    assert all(c["line"] == 2 for c in chars)


def test_fullwidth_and_math_letters_are_script_neutral():
    # Full-width and mathematical letters have Unicode names starting with
    # FULLWIDTH / MATHEMATICAL, not LATIN, so they never carry a script.
    src = f"{FW_X}{CYR_A} = 1\n{MATH_X} = 2\n"
    report = scan_mixed_scripts(src).to_dict()
    assert report["identifier_count"] == 2
    assert report["finding_count"] == 0


def test_keywords_skipped_but_cyrillic_lookalike_reported():
    # The full-width spelling NFKC-normalises to the keyword True and is
    # skipped; Cyrillic Т + 'rue' is not the keyword and mixes scripts.
    src = f"{FW_TRUE} = 1\n{CYR_T}rue = 2\n"
    report = scan_mixed_scripts(src).to_dict()
    assert report["identifier_count"] == 1
    assert report["finding_count"] == 1
    finding = report["findings"][0]
    assert finding["spelling"] == f"{CYR_T}rue"
    assert finding["scripts"] == ["cyrillic", "latin"]


def test_strings_and_comments_are_skipped():
    src = (
        f"# p{CYR_A}y in comment\n"
        f"s = 'p{CYR_A}y in string'\n"
        f"pay = 1\n"
    )
    report = scan_mixed_scripts(src).to_dict()
    # only s and pay survive; nothing inside comments or strings counts
    assert report["identifier_count"] == 2
    assert report["finding_count"] == 0


def test_repeated_name_reported_per_occurrence_in_source_order():
    src = f"p{CYR_A}y = 1\nx = p{CYR_A}y\n"
    report = scan_mixed_scripts(src).to_dict()
    assert report["identifier_count"] == 3
    assert report["finding_count"] == 2
    first, second = report["findings"]
    assert first["spelling"] == second["spelling"] == f"p{CYR_A}y"
    assert first["offset"] == 0
    # "pаy = 1\n" is 8 codepoints; "x = " is 4 more -> second at offset 12
    assert second["offset"] == 12
    assert (second["line"], second["column"]) == (2, 5)
    assert [c["offset"] for c in second["characters"]] == [12, 13, 14]


def test_multiple_distinct_findings_in_source_order():
    src = f"{GRK_ALPHA}1x = 1\np{CYR_A}y = 2\n"
    report = scan_mixed_scripts(src).to_dict()
    assert report["finding_count"] == 2
    first, second = report["findings"]
    assert first["spelling"] == f"{GRK_ALPHA}1x"
    assert first["scripts"] == ["greek", "latin"]
    # the digit is script-neutral and absent from the character list
    assert [c["char"] for c in first["characters"]] == [GRK_ALPHA, "x"]
    assert [c["offset"] for c in first["characters"]] == [0, 2]
    assert second["spelling"] == f"p{CYR_A}y"
    assert (second["offset"], second["line"]) == (8, 2)


def test_multiline_crlf_positions():
    src = f"x = 1\r\np{CYR_A}y = 2\r\n"
    report = scan_mixed_scripts(src).to_dict()
    finding = report["findings"][0]
    # "x = 1\r\n" is 7 codepoints; the identifier starts at offset 7
    assert (finding["offset"], finding["line"], finding["column"]) == (7, 2, 1)
    chars = finding["characters"]
    assert [c["offset"] for c in chars] == [7, 8, 9]
    assert [c["column"] for c in chars] == [1, 2, 3]
    assert all(c["line"] == 2 for c in chars)
    for c in chars:
        assert src[c["offset"]] == c["char"]


def test_bom_shifts_offsets_and_line1_columns():
    src = f"{BOM}p{CYR_A}y = 1\n"
    finding = scan_mixed_scripts(src).to_dict()["findings"][0]
    assert (finding["offset"], finding["line"], finding["column"]) == (1, 1, 2)
    assert [c["offset"] for c in finding["characters"]] == [1, 2, 3]
    assert [c["column"] for c in finding["characters"]] == [2, 3, 4]
    for c in finding["characters"]:
        assert src[c["offset"]] == c["char"]


def test_empty_and_comment_only_source():
    report = scan_mixed_scripts("").to_dict()
    assert report["identifier_count"] == 0
    assert report["finding_count"] == 0
    assert scan_mixed_scripts("# nothing\n").to_dict()["finding_count"] == 0


# ------------------------------------------------------- unit: lex errors --

@pytest.mark.parametrize(
    "source,error",
    [
        ("x = 1 $\n", "unexpected_character"),
        ("x = '''unterminated\n", "unterminated_string"),
        ("x = '", "unterminated_statement"),
        ("def f():\n  x=1\n y=2\n", "indentation_error"),
    ],
)
def test_lexical_failure_raises_with_position(source, error):
    with pytest.raises(IdentifierLexError) as exc:
        scan_mixed_scripts(source)
    assert exc.value.error == error
    assert exc.value.line >= 1
    assert exc.value.column >= 1
    assert 0 <= exc.value.offset <= len(source)


def test_unexpected_character_position_matches_normalization_scan():
    with pytest.raises(IdentifierLexError) as exc:
        scan_mixed_scripts("x = 1 $\n")
    assert (exc.value.offset, exc.value.line, exc.value.column) == (6, 1, 7)


# --------------------------------------------------------------- API: POST -

def test_post_mixed_script_shape(client):
    src = f"p{CYR_A}y = 1\npay = 2\n"
    resp = client.post(
        "/api/v1/identifiers/mixed-script",
        json={"source": src, "filename": "pay.py"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stored"] is False
    assert body["filename"] == "pay.py"
    assert body["source_length"] == len(src)
    report = body["report"]
    assert report["identifier_count"] == 2
    assert report["finding_count"] == 1
    finding = report["findings"][0]
    assert finding["spelling"] == f"p{CYR_A}y"
    assert finding["scripts"] == ["latin", "cyrillic"]
    assert [c["script"] for c in finding["characters"]] == [
        "latin", "cyrillic", "latin"
    ]
    assert [c["codepoint"] for c in finding["characters"]] == [
        "U+0070", "U+0430", "U+0079"
    ]


def test_post_filename_optional_and_clean_source(client):
    resp = client.post(
        "/api/v1/identifiers/mixed-script", json={"source": "pay = 1\n"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["filename"] is None
    assert body["report"]["identifier_count"] == 1
    assert body["report"]["finding_count"] == 0
    assert body["report"]["findings"] == []


def test_post_lex_failure_422_same_structure(client):
    resp = client.post(
        "/api/v1/identifiers/mixed-script", json={"source": "x = 1 $\n"}
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "unexpected_character"
    assert detail["offset"] == 6
    assert detail["line"] == 1 and detail["column"] == 7
    assert "message" in detail


def test_post_unterminated_string_422(client):
    resp = client.post(
        "/api/v1/identifiers/mixed-script",
        json={"source": "s = '''never ends\n"},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "unterminated_string"


def test_post_missing_source_field_422(client):
    resp = client.post(
        "/api/v1/identifiers/mixed-script", json={"filename": "m.py"}
    )
    assert resp.status_code == 422


def test_post_writes_no_records(client):
    resp = client.post(
        "/api/v1/identifiers/mixed-script",
        json={"source": f"p{CYR_A}y = 1\n"},
    )
    assert resp.status_code == 200
    # no audit record and no identifier report: the endpoint is read-only
    assert client.get("/api/v1/audits").json()["total"] == 0
    created = client.post(
        "/api/v1/identifiers/normalization", json={"source": "y = 1\n"}
    ).json()
    assert created["id"] == 1


def test_root_lists_mixed_script_endpoint(client):
    body = client.get("/").json()
    assert "POST /api/v1/identifiers/mixed-script" in body["endpoints"]
