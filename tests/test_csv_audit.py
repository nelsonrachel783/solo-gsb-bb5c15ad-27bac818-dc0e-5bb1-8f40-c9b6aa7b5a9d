"""Tests for the CSV formula-disguise audit endpoint (POST /api/v1/audits/csv).

Covers: CSV structure parsing (comma separation, double-quoted
enclosures, "" escapes, CRLF/LF record breaks, lone CR as content),
formula trigger detection (=, +, -, @) after skipping spaces, tabs and
Unicode bidi control characters, record/field numbers and original
line/column mapping, quoted newlines, escaped quotes and empty cells
never shifting records or positions, per-cell bidi risk levels reused
from the existing parser, 422 on unclosed/illegal quotes with the
original line/column, and the read-only endpoint writing no records.

Non-ASCII characters are written as \\uXXXX escapes so the file's exact
codepoint composition is independent of editor normalisation.
"""

import pytest

from app.csv_audit import CsvParseError, audit_csv_document

RLO = "‮"   # U+202E RIGHT-TO-LEFT OVERRIDE
PDF = "‬"   # U+202C POP DIRECTIONAL FORMATTING
LRI = "⁦"   # U+2066 LEFT-TO-RIGHT ISOLATE
PDI = "⁩"   # U+2069 POP DIRECTIONAL ISOLATE
LRM = "‎"   # U+200E LEFT-TO-RIGHT MARK


# ------------------------------------------------------- unit: detection --

def test_all_formula_chars_detected_in_field_order():
    report = audit_csv_document("=a,+b,-c,@d")
    assert report.record_count == 1
    assert report.field_count == 4
    assert [f.formula_char for f in report.findings] == ["=", "+", "-", "@"]
    assert [(f.record, f.field) for f in report.findings] == [
        (1, 1), (1, 2), (1, 3), (1, 4),
    ]
    assert [f.formula_offset for f in report.findings] == [0, 3, 6, 9]
    assert all(f.prefix == "" for f in report.findings)
    assert all(f.prefix_controls == [] for f in report.findings)
    assert all(f.risk_level == "info" for f in report.findings)


def test_non_formula_cells_are_not_reported():
    # formula chars away from the cell start do not count; empty cells
    # (between the trailing commas) are valid and report nothing
    report = audit_csv_document("abc,x=y,1+1,,")
    assert report.record_count == 1
    assert report.field_count == 5
    assert report.findings == []


def test_space_tab_and_bidi_prefix_skipped():
    doc = f"  \t{RLO}=cmd"
    report = audit_csv_document(doc)
    (finding,) = report.findings
    assert finding.formula_char == "="
    assert finding.formula_offset == 4
    assert finding.position == {"line": 1, "column": 5}
    assert finding.prefix == f"  \t{RLO}"
    controls = finding.prefix_controls
    assert [c["kind"] for c in controls] == ["space", "space", "tab", "RLO"]
    assert [c["offset"] for c in controls] == [0, 1, 2, 3]
    assert [c["codepoint"] for c in controls] == [
        "U+0020", "U+0020", "U+0009", "U+202E",
    ]
    assert [c["position"] for c in controls] == [
        {"line": 1, "column": 1}, {"line": 1, "column": 2},
        {"line": 1, "column": 3}, {"line": 1, "column": 4},
    ]
    # the unclosed RLO makes the cell itself critical
    assert finding.risk_level == "critical"


def test_cell_risk_levels_come_from_the_bidi_parser():
    doc = f"{RLO}=a,{LRI}=b{PDI},  =c"
    report = audit_csv_document(doc)
    # unclosed RLO -> critical; balanced LRI..PDI -> low; spaces -> info
    assert [f.risk_level for f in report.findings] == [
        "critical", "low", "info",
    ]


def test_tab_and_mark_prefix_keep_info_risk():
    doc = f"\t{LRM}+1"
    (finding,) = audit_csv_document(doc).findings
    assert finding.formula_char == "+"
    assert [c["kind"] for c in finding.prefix_controls] == ["tab", "LRM"]
    # LRM is a harmless mark: the cell stays info-level
    assert finding.risk_level == "info"


def test_prefix_only_cell_is_not_a_finding():
    report = audit_csv_document(f" \t{RLO} ,x")
    assert report.findings == []


# ------------------------------------------------------ unit: CSV shapes --

def test_quoted_cell_formula_offset_points_inside_quotes():
    (finding,) = audit_csv_document('"=cmd",x').findings
    assert finding.formula_offset == 1
    assert finding.position == {"line": 1, "column": 2}


def test_escaped_quotes_do_not_shift_positions():
    doc = '"a""b",=x'
    report = audit_csv_document(doc)
    assert report.field_count == 2
    (finding,) = report.findings
    assert (finding.record, finding.field) == (1, 2)
    assert finding.formula_offset == 7
    assert finding.position == {"line": 1, "column": 8}


def test_escaped_quote_after_formula_char_keeps_offsets():
    # '"="""' decodes to '="': the escape sits after the formula char
    (finding,) = audit_csv_document('"="""').findings
    assert finding.formula_char == "="
    assert finding.formula_offset == 1


def test_quoted_newline_keeps_record_and_counts_lines():
    doc = '"a\nb",=x\r\ny,z'
    report = audit_csv_document(doc)
    # the newline inside quotes does not start a new record...
    assert report.record_count == 2
    assert report.field_count == 4
    (finding,) = report.findings
    assert (finding.record, finding.field) == (1, 2)
    # ...but it does advance the original line number
    assert finding.formula_offset == 6
    assert finding.position == {"line": 2, "column": 4}


def test_quoted_crlf_counts_as_one_line():
    doc = '"a\r\nb",=x'
    (finding,) = audit_csv_document(doc).findings
    assert finding.formula_offset == 7
    assert finding.position == {"line": 2, "column": 4}


def test_record_numbers_continue_after_quoted_newline():
    doc = '"a\nb",c\r\n=d,e'
    report = audit_csv_document(doc)
    assert report.record_count == 2
    (finding,) = report.findings
    assert (finding.record, finding.field) == (2, 1)
    assert finding.formula_offset == 9
    assert finding.position == {"line": 3, "column": 1}


def test_crlf_record_breaks():
    doc = "a,b\r\n=c,d\r\n"
    report = audit_csv_document(doc)
    assert report.record_count == 2
    assert report.field_count == 4
    (finding,) = report.findings
    assert (finding.record, finding.field) == (2, 1)
    assert finding.formula_offset == 5
    assert finding.position == {"line": 2, "column": 1}


def test_lf_record_breaks():
    doc = "a\n=b\n"
    report = audit_csv_document(doc)
    assert report.record_count == 2
    (finding,) = report.findings
    assert (finding.record, finding.field) == (2, 1)
    assert finding.position == {"line": 2, "column": 1}


def test_lone_cr_is_field_content_not_a_record_break():
    doc = "a\rb,=c"
    report = audit_csv_document(doc)
    assert report.record_count == 1
    assert report.field_count == 2
    (finding,) = report.findings
    assert (finding.record, finding.field) == (1, 2)
    assert finding.formula_offset == 4
    assert finding.position == {"line": 1, "column": 5}


def test_empty_cells_do_not_shift_field_numbers():
    doc = ",,=x,\r\n,,"
    report = audit_csv_document(doc)
    assert report.record_count == 2
    # record 1: "", "", "=x", "" -- record 2: "", "", ""
    assert report.field_count == 7
    (finding,) = report.findings
    assert (finding.record, finding.field) == (1, 3)
    assert finding.formula_offset == 2
    assert finding.position == {"line": 1, "column": 3}


def test_field_numbers_reset_each_record():
    doc = "a,=x\r\nb,c,=y"
    report = audit_csv_document(doc)
    assert [(f.record, f.field) for f in report.findings] == [(1, 2), (2, 3)]


def test_blank_lines_are_empty_single_field_records():
    report = audit_csv_document("a\n\n=x")
    assert report.record_count == 3
    (finding,) = report.findings
    assert finding.record == 3
    assert finding.position == {"line": 3, "column": 1}


def test_trailing_newline_adds_no_record():
    report = audit_csv_document("a\n")
    assert report.record_count == 1
    assert report.field_count == 1


def test_empty_document_has_no_records():
    report = audit_csv_document("")
    assert report.record_count == 0
    assert report.field_count == 0
    assert report.findings == []


# ------------------------------------------------------- unit: 422 cases --

@pytest.mark.parametrize(
    "doc,offset",
    [
        ('"abc', 0),
        ('a,"bc', 2),
        ('"a\nb', 0),   # a newline inside quotes is content, not a close
        ('"a\rb', 0),
        ('"', 0),
    ],
)
def test_unclosed_quote_raises_with_offset(doc, offset):
    with pytest.raises(CsvParseError) as exc:
        audit_csv_document(doc)
    assert exc.value.error == "unclosed_quote"
    assert exc.value.offset == offset


@pytest.mark.parametrize(
    "doc,offset",
    [
        ('a"b', 1),      # quote inside an unquoted field
        ('"a"b', 3),     # content after the closing quote
        ('"a" b', 3),    # even whitespace may not follow the closing quote
        ('""=x', 2),     # empty quoted field followed by junk
        ('a,"b"c', 5),
    ],
)
def test_illegal_quote_raises_with_offset(doc, offset):
    with pytest.raises(CsvParseError) as exc:
        audit_csv_document(doc)
    assert exc.value.error == "illegal_quote"
    assert exc.value.offset == offset


# --------------------------------------------------------------- API: POST -

def test_post_csv_audit_shape(client):
    doc = f"name,note\r\nalice,ok\r\n  {RLO}=cmd,evil\r\n"
    resp = client.post(
        "/api/v1/audits/csv",
        json={"document": doc, "filename": "data.csv"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stored"] is False
    assert body["filename"] == "data.csv"
    assert body["document_length"] == len(doc) == 35
    assert body["record_count"] == 3
    assert body["field_count"] == 6
    assert body["finding_count"] == 1
    assert body["risk_level"] == "critical"

    (finding,) = body["findings"]
    assert finding["record"] == 3
    assert finding["field"] == 1
    assert finding["formula_char"] == "="
    assert finding["formula_offset"] == 24
    assert finding["position"] == {"line": 3, "column": 4}
    assert finding["prefix"] == f"  {RLO}"
    controls = finding["prefix_controls"]
    assert [c["kind"] for c in controls] == ["space", "space", "RLO"]
    assert [c["offset"] for c in controls] == [21, 22, 23]
    assert controls[2]["codepoint"] == "U+202E"
    assert controls[2]["position"] == {"line": 3, "column": 3}
    assert finding["risk_level"] == "critical"


def test_post_quoted_newline_and_escaped_quote(client):
    # field 2 decodes to '="x': formula after a quoted newline and an
    # escaped quote pair
    doc = '"a\nb","=""x"'
    resp = client.post("/api/v1/audits/csv", json={"document": doc})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["record_count"] == 1
    assert body["field_count"] == 2
    (finding,) = body["findings"]
    assert (finding["record"], finding["field"]) == (1, 2)
    assert finding["formula_offset"] == 7
    assert finding["position"] == {"line": 2, "column": 5}
    assert finding["prefix"] == ""
    assert finding["prefix_controls"] == []
    assert finding["risk_level"] == "info"


def test_post_clean_document_has_no_findings(client):
    resp = client.post(
        "/api/v1/audits/csv", json={"document": "a,b\r\nc,d\r\n"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["filename"] is None
    assert body["record_count"] == 2
    assert body["finding_count"] == 0
    assert body["findings"] == []
    assert body["risk_level"] == "info"


def test_post_unclosed_quote_422_with_position(client):
    resp = client.post(
        "/api/v1/audits/csv", json={"document": 'a,b\r\n"c'}
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "unclosed_quote"
    assert detail["offset"] == 5
    assert detail["line"] == 2
    assert detail["column"] == 1
    assert "message" in detail


def test_post_illegal_quote_422_with_position(client):
    resp = client.post(
        "/api/v1/audits/csv", json={"document": 'ab"c,d'}
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "illegal_quote"
    assert (detail["offset"], detail["line"], detail["column"]) == (2, 1, 3)


def test_post_content_after_closing_quote_422(client):
    resp = client.post(
        "/api/v1/audits/csv", json={"document": '"a"b'}
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "illegal_quote"
    assert detail["offset"] == 3


def test_post_missing_document_field_422(client):
    resp = client.post("/api/v1/audits/csv", json={"filename": "x.csv"})
    assert resp.status_code == 422


def test_post_writes_no_records(client):
    resp = client.post("/api/v1/audits/csv", json={"document": "=x,@y"})
    assert resp.status_code == 200
    # no audit record and no identifier report: the endpoint is read-only
    assert client.get("/api/v1/audits").json()["total"] == 0
    created = client.post(
        "/api/v1/identifiers/normalization", json={"source": "y = 1\n"}
    ).json()
    assert created["id"] == 1


def test_root_lists_csv_endpoint(client):
    body = client.get("/").json()
    assert "POST /api/v1/audits/csv" in body["endpoints"]
