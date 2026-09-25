"""API tests for GET /api/v1/audits/{id}/sarif (SARIF 2.1.0 export)."""

import copy
import hashlib
import json
import re

LRE = "‪"
RLE = "‫"
RLO = "‮"
PDF = "‬"
LRI = "⁦"
RLI = "⁦"
PDI = "⁩"
LRM = "‎"
ZWSP = "​"

FINGERPRINT_KEY = "bidi-audit/v1/sha256"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _post(client, text, filename=None):
    return client.post("/api/v1/audits", json={"text": text, "filename": filename})


def _sarif(client, audit_id):
    return client.get(f"/api/v1/audits/{audit_id}/sarif")


def _run(body):
    return body["runs"][0]


def _results(body):
    return _run(body)["results"]


def _find(body, rule_id):
    return [r for r in _results(body) if r["ruleId"] == rule_id]


def _region(result):
    return result["locations"][0]["physicalLocation"]["region"]


def _expected_fp(rule_id, codepoint, start, end):
    basis = f"{rule_id}|{codepoint}|{start}|{end}".encode("utf-8")
    return hashlib.sha256(basis).hexdigest()


# ---------------------------------------------------------------- envelope ---

def test_sarif_missing_record_is_404(client):
    resp = _sarif(client, 9999)
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"]


def test_sarif_content_type(client):
    audit_id = _post(client, "clean", "a.txt").json()["id"]
    resp = _sarif(client, audit_id)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/sarif+json")
    # body is valid JSON with non-ASCII content untouched
    json.loads(resp.content.decode("utf-8"))


def test_sarif_envelope_and_tool_metadata(client):
    audit_id = _post(client, "clean").json()["id"]
    body = _sarif(client, audit_id).json()

    assert body["version"] == "2.1.0"
    assert "2.1.0" in body["$schema"]
    assert len(body["runs"]) == 1
    driver = _run(body)["tool"]["driver"]
    assert driver["name"] == "bidi-audit"
    assert driver["version"]
    assert driver["semanticVersion"]
    assert _run(body)["invocations"] == [{"executionSuccessful": True}]


def test_sarif_clean_text_has_no_results_or_rules(client):
    audit_id = _post(client, "clean text", "a.txt").json()["id"]
    body = _sarif(client, audit_id).json()

    assert _results(body) == []
    assert _run(body)["tool"]["driver"]["rules"] == []


def test_sarif_marks_only_are_not_findings(client):
    # LRM is an info control but it is not an error and has no dangerous span.
    audit_id = _post(client, "a" + LRM + "b", "a.txt").json()["id"]
    body = _sarif(client, audit_id).json()
    assert _results(body) == []
    assert _run(body)["tool"]["driver"]["rules"] == []


# --------------------------------------------------------------- artifact uri ---

def test_sarif_location_uses_record_filename(client):
    audit_id = _post(client, "x" + RLO + "bad.exe" + PDF, "src/trojan.c").json()["id"]
    body = _sarif(client, audit_id).json()
    loc = _results(body)[0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/trojan.c"


def test_sarif_location_falls_back_to_audit_id(client):
    resp = _post(client, "x" + RLO + "bad.exe" + PDF, filename=None)
    audit_id = resp.json()["id"]
    body = _sarif(client, audit_id).json()
    loc = _results(body)[0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == f"audit-{audit_id}"


# --------------------------------------------------------------- risk levels ---

def test_sarif_balanced_rlo_emits_span_result_as_error(client):
    text = "x" + RLO + "bad.exe" + PDF
    audit_id = _post(client, text, "a.c").json()["id"]
    body = _sarif(client, audit_id).json()

    results = _results(body)
    assert len(results) == 1
    result = results[0]
    assert result["ruleId"] == "bidi/span-RLO"
    assert result["level"] == "error"
    assert "RLO override" in result["message"]["text"]
    assert _region(result) == {
        "startLine": 1, "startColumn": 2, "endLine": 1, "endColumn": 10,
        "snippet": {"text": "⟨RLO⟩bad.exe"},
    }
    assert result["partialFingerprints"][FINGERPRINT_KEY] == _expected_fp(
        "bidi/span-RLO", "U+202E", 1, 9
    )


def test_sarif_unclosed_rlo_emits_error_and_critical_control(client):
    text = RLO + "end.js"
    audit_id = _post(client, text, "x.js").json()["id"]
    body = _sarif(client, audit_id).json()

    assert {r["ruleId"] for r in _results(body)} == {
        "bidi/span-RLO", "bidi/unclosed-RLO"
    }
    for result in _results(body):
        assert result["level"] == "error"

    control = _find(body, "bidi/unclosed-RLO")[0]
    assert "never closed by PDF" in control["message"]["text"]
    assert _region(control) == {
        "startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 2,
        "snippet": {"text": "⟨RLO⟩"},
    }
    assert control["properties"]["codepoint"] == "U+202E"
    assert control["properties"]["logical_index"] == 0

    span = _find(body, "bidi/span-RLO")[0]
    assert "unclosed RLO" in span["message"]["text"]
    assert _region(span)["startColumn"] == 1
    assert _region(span)["endColumn"] == 8  # 7 code points -> exclusive col 8
    assert _region(span)["snippet"]["text"] == "⟨RLO⟩end.js"


def test_sarif_nesting_depth_overflow_is_critical_rule(client):
    text = LRE * 200  # first 125 are unclosed, the rest exceed the limit
    audit_id = _post(client, text, "deep.c").json()["id"]
    body = _sarif(client, audit_id).json()

    depth = _find(body, "bidi/nesting-depth-limit")
    assert len(depth) == 75
    assert all(r["level"] == "error" for r in depth)
    assert "depth limit" in depth[0]["message"]["text"]
    # over-limit controls are single-character findings, not spans
    region = _region(depth[0])
    assert region["startColumn"] == 126
    assert region["endColumn"] == 127
    rule = next(
        r for r in _run(body)["tool"]["driver"]["rules"]
        if r["id"] == "bidi/nesting-depth-limit"
    )
    assert rule["properties"]["security-severity"] == "critical"


def test_sarif_balanced_embedding_has_no_findings(client):
    # A balanced RLE..PDF has no error and no dangerous span -> empty report.
    audit_id = _post(client, "a" + RLE + "b" + PDF, "ok.c").json()["id"]
    body = _sarif(client, audit_id).json()
    assert _results(body) == []
    assert _run(body)["tool"]["driver"]["rules"] == []


def test_sarif_lone_pdf_is_warning(client):
    text = "x" + PDF
    audit_id = _post(client, text).json()["id"]
    body = _sarif(client, audit_id).json()

    results = _results(body)
    assert len(results) == 1
    result = results[0]
    assert result["ruleId"] == "bidi/orphan-PDF"
    assert result["level"] == "warning"
    assert "no matching embedding opener" in result["message"]["text"]
    assert _region(result)["startColumn"] == 2
    assert result["properties"]["abbreviation"] == "PDF"


def test_sarif_unclosed_embedding_is_warning_not_critical(client):
    # Unclosed LRE: control error is medium -> warning; its span is medium too.
    text = "a" + LRE + "bcd"
    audit_id = _post(client, text).json()["id"]
    body = _sarif(client, audit_id).json()

    levels = {r["ruleId"]: r["level"] for r in _results(body)}
    assert levels == {"bidi/unclosed-LRE": "warning", "bidi/span-LRE": "warning"}
    lre_rule = next(
        r for r in _run(body)["tool"]["driver"]["rules"]
        if r["id"] == "bidi/span-LRE"
    )
    assert lre_rule["defaultConfiguration"]["level"] == "warning"


# ---------------------------------------------------------- UTF-16 columns ---

def test_sarif_columns_are_utf16_units(client):
    # U+1F600 (😀) takes 2 UTF-16 code units; the RLO at code-point index 2
    # therefore starts at UTF-16 column 4, not 3.
    text = "😀x" + RLO + "y"
    audit_id = _post(client, text).json()["id"]
    body = _sarif(client, audit_id).json()

    control = _find(body, "bidi/unclosed-RLO")[0]
    assert _region(control)["startColumn"] == 4
    assert _region(control)["endColumn"] == 5  # RLO is BMP -> width 1

    span = _find(body, "bidi/span-RLO")[0]
    # span runs from RLO (cp 2) to end of text (cp 4): "y" sits at UTF-16 col 5
    assert _region(span) == {
        "startLine": 1, "startColumn": 4, "endLine": 1, "endColumn": 6,
        "snippet": {"text": "⟨RLO⟩y"},
    }


def test_sarif_multiline_span_uses_start_and_end_lines(client):
    text = "ab\n" + RLO + "cd\nef"
    audit_id = _post(client, text, "m.c").json()["id"]
    body = _sarif(client, audit_id).json()

    span = _find(body, "bidi/span-RLO")[0]
    region = _region(span)
    assert region["startLine"] == 2
    assert region["startColumn"] == 1
    assert region["endLine"] == 3
    assert region["endColumn"] == 3  # line 3 "ef" -> after "f"
    assert region["snippet"]["text"] == "⟨RLO⟩cd\\nef"

    control = _find(body, "bidi/unclosed-RLO")[0]
    assert _region(control)["startLine"] == 2
    assert _region(control)["startColumn"] == 1


# ------------------------------------------------------------- rules array ---

def test_sarif_rules_deduplicated_and_sorted(client):
    # Two RLOs + one orphan PDF: span rule shared by both spans, plus orphan
    # rule. Rules must appear once each, sorted by rule id.
    text = RLO + "a" + PDF + RLO + "b" + PDF + "x" + PDF
    audit_id = _post(client, text).json()["id"]
    body = _sarif(client, audit_id).json()

    ids = [r["id"] for r in _run(body)["tool"]["driver"]["rules"]]
    assert ids == ["bidi/orphan-PDF", "bidi/span-RLO"]

    rule = _run(body)["tool"]["driver"]["rules"][1]
    assert rule["shortDescription"]["text"]
    assert rule["fullDescription"]["text"]
    assert rule["name"] == "DangerousRLOSpan"
    assert rule["properties"]["security-severity"] == "high"
    assert rule["properties"]["tags"]


def test_sarif_every_result_references_declared_rule(client):
    audit_id = _post(client, RLO + "x" + PDF + "y" + LRI + "z", "a.c").json()["id"]
    body = _sarif(client, audit_id).json()
    declared = {r["id"] for r in _run(body)["tool"]["driver"]["rules"]}
    for result in _results(body):
        assert result["ruleId"] in declared


# ----------------------------------------------------- deterministic output ---

def test_sarif_results_sorted_deterministically(client):
    # lone PDI on line 3, RLO on line 1: results must be ordered by location.
    text = RLO + "a\n" + "b\nx" + PDI
    audit_id = _post(client, text).json()["id"]
    body = _sarif(client, audit_id).json()

    positions = [
        (_region(r)["startLine"], _region(r)["startColumn"], r["ruleId"])
        for r in _results(body)
    ]
    assert positions == sorted(positions)
    assert positions[0][0] == 1  # RLO findings first
    assert any(p[0] == 3 for p in positions)  # PDI on line 3 follows


def test_sarif_repeat_audit_same_fingerprint_different_row_ids(client):
    text = "x" + RLO + "bad.exe" + PDF
    first = _post(client, text, "f.c").json()["id"]
    second = _post(client, text, "f.c").json()["id"]
    assert first != second

    body1 = _sarif(client, first).json()
    body2 = _sarif(client, second).json()
    fp1 = _results(body1)[0]["partialFingerprints"]
    fp2 = _results(body2)[0]["partialFingerprints"]
    assert fp1 == fp2
    assert HEX64.match(fp1[FINGERPRINT_KEY])
    # fingerprint ignores the database id and stays identical for same content
    assert "audit" not in fp1[FINGERPRINT_KEY]


def test_sarif_fingerprint_varies_with_range_and_rule(client):
    balanced = _post(client, "x" + RLO + "ab" + PDF, "f.c").json()["id"]
    shifted = _post(client, "xy" + RLO + "ab" + PDF, "f.c").json()["id"]
    fp_balanced = _results(_sarif(client, balanced).json())[0][
        "partialFingerprints"][FINGERPRINT_KEY]
    fp_shifted = _results(_sarif(client, shifted).json())[0][
        "partialFingerprints"][FINGERPRINT_KEY]
    assert fp_balanced != fp_shifted
    assert fp_balanced == _expected_fp("bidi/span-RLO", "U+202E", 1, 4)
    assert fp_shifted == _expected_fp("bidi/span-RLO", "U+202E", 2, 5)


def test_sarif_full_document_is_json_stable(client):
    text = RLO + "a" + PDF + "y"
    audit_id = _post(client, text, "f.c").json()["id"]
    first = _sarif(client, audit_id).content
    second = _sarif(client, audit_id).content
    assert first == second


# ----------------------------------------------------- unified-diff records ---

def _post_diff(client, diff):
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    assert resp.status_code == 201, resp.text
    return resp.json()["items"][0]["id"]


def _two_hunk_diff(*, first_added, second_added, second_new=80,
                   second_old=80, path="f.py"):
    return (
        f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
        "@@ -1,1 +1,2 @@\n keep1\n"
        f"+{first_added}\n"
        f"@@ -{second_old},1 +{second_new},1 @@\n-gone\n"
        f"+{second_added}\n"
    )


def test_sarif_diff_control_locates_to_real_new_file_line(client):
    # The added line is new-file line 80, but raw_text is just the two added
    # lines concatenated: without relocation the RLO lands on SARIF line 2.
    audit_id = _post_diff(
        client,
        _two_hunk_diff(first_added="add1", second_added=f"x{RLO}bad{PDF}"),
    )
    body = _sarif(client, audit_id).json()

    results = _results(body)
    assert len(results) == 1
    assert _region(results[0]) == {
        "startLine": 80, "startColumn": 2, "endLine": 80, "endColumn": 6,
        "snippet": {"text": "⟨RLO⟩bad"},
    }


def test_sarif_diff_columns_are_utf16_on_real_line(client):
    # Astral emoji takes 2 UTF-16 code units before the RLO.
    audit_id = _post_diff(
        client,
        _two_hunk_diff(first_added="add1", second_added=f"😀x{RLO}y"),
    )
    body = _sarif(client, audit_id).json()

    control = _find(body, "bidi/unclosed-RLO")[0]
    assert _region(control)["startLine"] == 80
    assert _region(control)["startColumn"] == 4
    assert _region(control)["endColumn"] == 5

    span = _find(body, "bidi/span-RLO")[0]
    assert _region(span) == {
        "startLine": 80, "startColumn": 4, "endLine": 80, "endColumn": 6,
        "snippet": {"text": "⟨RLO⟩y\\n"},
    }


def test_sarif_diff_orphan_closer_locates_to_real_line(client):
    audit_id = _post_diff(
        client,
        _two_hunk_diff(first_added="add1", second_added=f"q{PDI}"),
    )
    body = _sarif(client, audit_id).json()

    result = _find(body, "bidi/orphan-PDI")[0]
    assert _region(result) == {
        "startLine": 80, "startColumn": 2, "endLine": 80, "endColumn": 3,
        "snippet": {"text": "⟨PDI⟩"},
    }


def test_sarif_diff_cross_gap_span_emits_only_audited_lines(client):
    # Unclosed RLO opens on added line 2; the next audited addition is new-file
    # line 80. Lines 3..79 are context/untouched and must not be covered, so
    # the one finding carries two physical locations instead of a region that
    # spans lines 2..80.
    diff = (
        "diff --git a/f.py b/f.py\n--- a/f.py\n+++ b/f.py\n"
        "@@ -1,1 +1,2 @@\n keep1\n"
        f"+{RLO}a\n"
        "@@ -80,1 +80,1 @@\n-gone\n+b\n"
    )
    audit_id = _post_diff(client, diff)
    body = _sarif(client, audit_id).json()

    span = _find(body, "bidi/span-RLO")[0]
    regions = [
        {k: v for k, v in loc["physicalLocation"]["region"].items()
         if k != "snippet"}
        for loc in span["locations"]
    ]
    assert regions == [
        {"startLine": 2, "startColumn": 1, "endLine": 2, "endColumn": 3},
        {"startLine": 80, "startColumn": 1, "endLine": 80, "endColumn": 2},
    ]
    # The escaped preview is attached to the primary location only.
    assert span["locations"][0]["physicalLocation"]["region"]["snippet"] == {
        "text": "⟨RLO⟩a\\nb\\n"
    }
    assert "snippet" not in span["locations"][1]["physicalLocation"]["region"]
    for loc in span["locations"]:
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "f.py"

    control = _find(body, "bidi/unclosed-RLO")[0]
    assert _region(control)["startLine"] == 2


def test_sarif_diff_consecutive_added_lines_stay_one_region(client):
    # Added lines inside one hunk are consecutive in the new file, so the span
    # keeps a single (multi-line) region with real line numbers.
    diff = (
        "--- a\n+++ b\n@@ -1,1 +1,4 @@\n keep\n"
        f"+{RLO}a\n+b\n+c\n"
    )
    audit_id = _post_diff(client, diff)
    body = _sarif(client, audit_id).json()

    span = _find(body, "bidi/span-RLO")[0]
    assert len(span["locations"]) == 1
    assert _region(span) == {
        "startLine": 2, "startColumn": 1, "endLine": 4, "endColumn": 2,
        "snippet": {"text": "⟨RLO⟩a\\nb\\nc\\n"},
    }


def test_sarif_diff_multi_hunk_groups_consecutive_and_gapped_runs(client):
    # Additions at new-file lines 2, 80, 81 (consecutive pair) and 200: the
    # unclosed span yields regions 2, 80-81 and 200, never 2..200.
    diff = (
        "diff --git a/f.py b/f.py\n--- a/f.py\n+++ b/f.py\n"
        "@@ -1,1 +1,2 @@\n keep\n"
        f"+{RLO}a\n"
        "@@ -78,4 +78,4 @@\n c\n d\n-g1\n-g2\n+bb\n+cc\n"
        "@@ -200,1 +200,1 @@\n-g3\n+z\n"
    )
    audit_id = _post_diff(client, diff)
    body = _sarif(client, audit_id).json()

    span = _find(body, "bidi/span-RLO")[0]
    line_pairs = [
        (loc["physicalLocation"]["region"]["startLine"],
         loc["physicalLocation"]["region"]["endLine"])
        for loc in span["locations"]
    ]
    assert line_pairs == [(2, 2), (80, 81), (200, 200)]


def test_sarif_diff_no_newline_last_line_clamps_end_column(client):
    diff = (
        "--- a\n+++ b\n@@ -1 +1 @@\n"
        f"-clean\n+{RLO}y\n"
        "\\ No newline at end of file\n"
    )
    audit_id = _post_diff(client, diff)
    body = _sarif(client, audit_id).json()

    span = _find(body, "bidi/span-RLO")[0]
    assert _region(span) == {
        "startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 3,
        "snippet": {"text": "⟨RLO⟩y"},
    }


def test_sarif_diff_fingerprint_matches_plain_record_of_same_text(client):
    diff = (
        "diff --git a/f.py b/f.py\n--- a/f.py\n+++ b/f.py\n"
        "@@ -1,1 +1,2 @@\n keep1\n"
        f"+{RLO}a\n"
        "@@ -80,1 +80,1 @@\n-gone\n+b\n"
    )
    diff_id = _post_diff(client, diff)
    diff_record = client.get(f"/api/v1/audits/{diff_id}").json()
    plain_id = _post(
        client, diff_record["raw_text"], diff_record["filename"]
    ).json()["id"]

    diff_fp = _results(_sarif(client, diff_id).json())
    plain_fp = _results(_sarif(client, plain_id).json())
    by_rule = lambda rs: {r["ruleId"]: r["partialFingerprints"] for r in rs}
    assert by_rule(diff_fp) == by_rule(plain_fp)
    # re-audit under another row id keeps the same fingerprints
    diff_id_2 = _post_diff(client, diff)
    assert by_rule(_results(_sarif(client, diff_id_2).json())) == by_rule(diff_fp)


def test_sarif_diff_legacy_meta_without_rebuilt_offsets(client):
    # Records written before rebuilt_start/rebuilt_end were persisted must
    # still relocate via the added_lines + raw_text reconstruction.
    diff = _two_hunk_diff(first_added="add1", second_added=f"x{RLO}bad{PDF}")
    audit_id = _post_diff(client, diff)
    record = client.get(f"/api/v1/audits/{audit_id}").json()
    legacy_meta = copy.deepcopy(record["meta"])
    for entry in legacy_meta["added_lines"]:
        entry.pop("rebuilt_start", None)
        entry.pop("rebuilt_end", None)

    from app.sarif import build_sarif
    doc = build_sarif({**record, "meta": legacy_meta})
    region = doc["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"]["region"]
    assert region["startLine"] == 80
    assert region["endLine"] == 80
    assert region["startColumn"] == 2
