"""SARIF export for unified-diff audit records (GET /api/v1/audits/{id}/sarif).

Diff records store only the rebuilt added lines as ``raw_text``; the export
must map findings back to the real new-file line numbers carried by
``meta.added_lines`` (columns in UTF-16 code units) and split spans crossing
hunk gaps into one location per contiguous run of audited added lines, so
unaudited lines are never covered by a region.  Fingerprints stay identical
to the plain-text export of the same content.
"""

import hashlib
import json

RLO = "‮"
PDF = "‬"

FINGERPRINT_KEY = "bidi-audit/v1/sha256"


def _post_diff(client, diff):
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    assert resp.status_code == 201, resp.text
    return resp.json()


def _sarif(client, audit_id):
    resp = client.get(f"/api/v1/audits/{audit_id}/sarif")
    assert resp.status_code == 200
    return resp.json()


def _results(body):
    return body["runs"][0]["results"]


def _find(body, rule_id):
    return [r for r in _results(body) if r["ruleId"] == rule_id]


def _regions(result):
    return [loc["physicalLocation"]["region"] for loc in result["locations"]]


# --------------------------------------------------------- real line numbers ---

def test_diff_control_maps_to_real_new_file_line(client):
    # 78 added lines in hunk 1, then a context line plus one added line in
    # hunk 2: the RLO sits on new-file line 80 but on line 79 of the rebuilt
    # text -- the export must use the new-file line number.
    hunk1 = "@@ -0,0 +1,78 @@\n" + "".join(f"+line{i}\n" for i in range(1, 79))
    hunk2 = "@@ -80,1 +79,2 @@\n ctx\n" + f"+{RLO}evil\n"
    diff = f"diff --git a/f.py b/f.py\n--- a/f.py\n+++ b/f.py\n{hunk1}{hunk2}"
    item = _post_diff(client, diff)["items"][0]
    assert item["added_lines"][-1]["new_line"] == 80

    body = _sarif(client, item["id"])

    control = _find(body, "bidi/unclosed-RLO")[0]
    (region,) = _regions(control)
    assert region == {
        "startLine": 80, "startColumn": 1, "endLine": 80, "endColumn": 2,
        "snippet": {"text": "⟨RLO⟩"},
    }

    span = _find(body, "bidi/span-RLO")[0]
    (region,) = _regions(span)
    assert region["startLine"] == 80
    assert region["endLine"] == 80
    assert region["startColumn"] == 1
    location = span["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "f.py"


def test_diff_span_crossing_hunk_gap_splits_locations(client):
    # Unclosed RLO on new-file line 10; the following added lines live at
    # new-file lines 51-52.  The span covers all three rebuilt lines, but
    # the unaudited gap (lines 11..50) must not appear in any region.
    diff = (
        "diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n"
        "@@ -9,0 +10,1 @@\n"
        f"+{RLO}x\n"
        "@@ -50,0 +51,2 @@\n"
        "+ab\n"
        "+cd\n"
    )
    item = _post_diff(client, diff)["items"][0]
    assert [l["new_line"] for l in item["added_lines"]] == [10, 51, 52]

    body = _sarif(client, item["id"])
    span = _find(body, "bidi/span-RLO")[0]
    regions = _regions(span)
    assert regions == [
        {"startLine": 10, "startColumn": 1, "endLine": 10, "endColumn": 4,
         "snippet": {"text": "⟨RLO⟩x\\n"}},
        {"startLine": 51, "startColumn": 1, "endLine": 52, "endColumn": 4,
         "snippet": {"text": "ab\\ncd\\n"}},
    ]
    # one result, one fingerprint: the finding itself is not duplicated
    assert len(span["partialFingerprints"][FINGERPRINT_KEY]) == 64

    control = _find(body, "bidi/unclosed-RLO")[0]
    (region,) = _regions(control)
    assert (region["startLine"], region["startColumn"]) == (10, 1)


def test_diff_contiguous_added_lines_keep_single_location(client):
    diff = (
        "--- a/f.c\n+++ b/f.c\n"
        "@@ -4,0 +5,2 @@\n"
        f"+{RLO}a\n"
        "+bc\n"
    )
    item = _post_diff(client, diff)["items"][0]
    assert [l["new_line"] for l in item["added_lines"]] == [5, 6]

    body = _sarif(client, item["id"])
    span = _find(body, "bidi/span-RLO")[0]
    (region,) = _regions(span)
    assert region == {
        "startLine": 5, "startColumn": 1, "endLine": 6, "endColumn": 4,
        "snippet": {"text": "⟨RLO⟩a\\nbc\\n"},
    }


def test_diff_balanced_span_and_orphan_pdf_use_real_lines(client):
    diff = (
        "--- a/f.c\n+++ b/f.c\n"
        "@@ -39,0 +40,1 @@\n"
        f"+a{RLO}b{PDF}\n"
        "@@ -44,0 +45,1 @@\n"
        f"+x{PDF}\n"
    )
    item = _post_diff(client, diff)["items"][0]
    assert [l["new_line"] for l in item["added_lines"]] == [40, 45]

    body = _sarif(client, item["id"])

    span = _find(body, "bidi/span-RLO")[0]
    (region,) = _regions(span)
    assert (region["startLine"], region["endLine"]) == (40, 40)
    # the span covers RLO..b (the closing PDF is not part of it)
    assert (region["startColumn"], region["endColumn"]) == (2, 4)

    orphan = _find(body, "bidi/orphan-PDF")[0]
    (region,) = _regions(orphan)
    assert (region["startLine"], region["startColumn"]) == (45, 2)

    # results stay sorted by their first location's real position
    assert [r["ruleId"] for r in _results(body)] == [
        "bidi/span-RLO", "bidi/orphan-PDF"
    ]


def test_diff_no_newline_at_end_of_file(client):
    diff = (
        "--- a/f.c\n+++ b/f.c\n"
        "@@ -6,0 +7,1 @@\n"
        f"+{RLO}y\n"
        "\\ No newline at end of file\n"
    )
    item = _post_diff(client, diff)["items"][0]
    body = _sarif(client, item["id"])
    span = _find(body, "bidi/span-RLO")[0]
    (region,) = _regions(span)
    assert region == {
        "startLine": 7, "startColumn": 1, "endLine": 7, "endColumn": 3,
        "snippet": {"text": "⟨RLO⟩y"},
    }


# ------------------------------------------------------------- UTF-16 columns ---

def test_diff_columns_are_utf16_units(client):
    # U+1F600 (😀) takes 2 UTF-16 code units; the RLO on new-file line 30
    # therefore starts at UTF-16 column 4, not 3.
    diff = (
        "--- a/e.c\n+++ b/e.c\n"
        "@@ -29,0 +30,1 @@\n"
        f"+😀x{RLO}y\n"
    )
    item = _post_diff(client, diff)["items"][0]
    assert item["added_lines"][0]["new_line"] == 30

    body = _sarif(client, item["id"])
    control = _find(body, "bidi/unclosed-RLO")[0]
    (region,) = _regions(control)
    assert (region["startLine"], region["startColumn"]) == (30, 4)
    assert region["endColumn"] == 5  # RLO is BMP -> width 1

    span = _find(body, "bidi/span-RLO")[0]
    (region,) = _regions(span)
    assert region["startLine"] == 30
    assert region["startColumn"] == 4


# --------------------------------------------------------------- fingerprints ---

def test_diff_fingerprint_stable_across_reaudits(client):
    diff = (
        "diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n"
        "@@ -9,0 +10,1 @@\n"
        f"+{RLO}x\n"
        "@@ -50,0 +51,2 @@\n"
        "+ab\n+cd\n"
    )
    first = _post_diff(client, diff)["items"][0]["id"]
    second = _post_diff(client, diff)["items"][0]["id"]
    assert first != second

    fp1 = _find(_sarif(client, first), "bidi/span-RLO")[0]["partialFingerprints"]
    fp2 = _find(_sarif(client, second), "bidi/span-RLO")[0]["partialFingerprints"]
    assert fp1 == fp2
    # the fingerprint is still over rule id, codepoint and the rebuilt-text
    # logical range (span covers the whole rebuilt text "RLO x \n ab \n cd \n")
    expected = hashlib.sha256(b"bidi/span-RLO|U+202E|0|9").hexdigest()
    assert fp1[FINGERPRINT_KEY] == expected


def test_diff_and_plain_record_share_fingerprint_for_same_content(client):
    diff = (
        "diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n"
        "@@ -9,0 +10,1 @@\n"
        f"+{RLO}x\n"
        "@@ -50,0 +51,2 @@\n"
        "+ab\n+cd\n"
    )
    diff_id = _post_diff(client, diff)["items"][0]["id"]
    plain_id = client.post(
        "/api/v1/audits",
        json={"text": f"{RLO}x\nab\ncd\n", "filename": "f.c"},
    ).json()["id"]

    fp_diff = _find(_sarif(client, diff_id), "bidi/span-RLO")[0][
        "partialFingerprints"]
    fp_plain = _find(_sarif(client, plain_id), "bidi/span-RLO")[0][
        "partialFingerprints"]
    assert fp_diff == fp_plain


# ------------------------------------------------------------- defensive meta ---

def test_diff_record_with_inconsistent_meta_falls_back(client):
    # If the stored meta no longer matches raw_text the export must not fail;
    # it falls back to the plain whole-text mapping.
    diff = (
        "--- a/f.c\n+++ b/f.c\n"
        "@@ -0,0 +1,1 @@\n"
        "+keep\n"
        "@@ -9,0 +10,1 @@\n"
        f"+{RLO}x\n"
    )
    item = _post_diff(client, diff)["items"][0]

    from app import database
    with database.connect() as conn:
        row = conn.execute(
            "SELECT meta_json FROM audits WHERE id = ?", (item["id"],)
        ).fetchone()
        meta = json.loads(row["meta_json"])
        meta["added_lines"] = meta["added_lines"][:1]  # corrupt the mapping
        conn.execute(
            "UPDATE audits SET meta_json = ? WHERE id = ?",
            (json.dumps(meta, ensure_ascii=False), item["id"]),
        )

    resp = client.get(f"/api/v1/audits/{item['id']}/sarif")
    assert resp.status_code == 200
    control = _find(resp.json(), "bidi/unclosed-RLO")[0]
    (region,) = _regions(control)
    # plain fallback: the RLO is on line 2 of the rebuilt text
    assert region["startLine"] == 2
