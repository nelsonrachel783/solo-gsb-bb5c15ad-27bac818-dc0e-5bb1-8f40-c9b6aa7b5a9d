"""Tests for the unified-diff audit endpoint (POST /api/v1/audits/diff).

Covers: multi-file/multi-hunk parsing, added-only analysis (removed and
context lines ignored), new-file line progression, "No newline" markers,
finding -> path/line/column/diff-line mapping with preserved logical
indices, one record per file, summary max risk, 422 on structural errors
and hunk-count mismatches (first error line, no writes), deleted files
and binary diffs producing no records, and stored meta/verify interplay.
"""

RLO = "‮"
PDF = "‬"
RLI = "⁦"
PDI = "⁩"
LRE = "‪"  # unclosed embedding force-terminated by PDI


# --------------------------------------------------------------- parsing ---

def _diff_with(path, body, *, old="a/", new="b/", preamble=True):
    head = f"diff --git {old}{path} {new}{path}\n" if preamble else ""
    return f"{head}--- {old}{path}\n+++ {new}{path}\n{body}"


def test_basic_mapping_api(client):
    diff = (
        "diff --git a/f.py b/f.py\n"
        "--- a/f.py\n+++ b/f.py\n"
        "@@ -1,2 +1,3 @@\n"
        " keep\n-old\n"
        f"+{RLO}x{PDF}\n"
        "+end\n"
    )
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["file_count"] == 1
    assert body["risk_level"] == "high"
    item = body["items"][0]
    assert item["path"] == "f.py"
    assert item["added_line_count"] == 2
    # removed/context text is absent from the audited text
    assert item["result"]["length"] == len(f"{RLO}x{PDF}\nend\n")
    loc = item["locations"]["controls"][0]
    # RLO on the first added line; the kept context occupies new line 1,
    # so this addition is new file line 2, column 1
    assert loc["path"] == "f.py"
    assert loc["position"] == {"line": 2, "column": 1}
    # diff line 7 is the addition; the '+' prefix shifts columns by one
    assert loc["diff_position"] == {"line": 7, "column": 2}
    assert loc["logical_index"] == 0
    assert loc["result_index"] == 0
    span = item["locations"]["dangerous_spans"][0]
    assert span["position"]["start"] == {"line": 2, "column": 1}
    assert span["diff_position"]["start"] == {"line": 7, "column": 2}


def test_only_added_lines_are_analysed(client):
    # RLO lives on a *removed* line: it must not be reported.
    diff = (
        "--- x\n+++ x\n"
        "@@ -1,2 +1,2 @@\n"
        f"-{RLO}evil.exe\n"
        "+clean line\n"
        " keep\n"
    )
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    assert resp.status_code == 201
    item = resp.json()["items"][0]
    assert item["risk_level"] == "info"
    assert item["control_count"] == 0
    assert item["locations"]["controls"] == []
    assert item["result"]["controls"] == []


def test_multi_hunk_line_progression_and_columns(client):
    diff = (
        "diff --git a/m.txt b/m.txt\n--- a/m.txt\n+++ b/m.txt\n"
        "@@ -10,1 +10,2 @@\n"
        "-old\n+keep\n"
        f"+ z{RLO}a\n"
        "@@ -30,1 +30,2 @@\n"
        f"-gone\n+q{RLI}z\n"
        f"+w{PDI}\n"
    )
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    assert resp.status_code == 201, resp.text
    item = resp.json()["items"][0]
    controls = item["locations"]["controls"]
    assert [(c["position"]["line"], c["position"]["column"]) for c in controls] == [
        (11, 3),   # second added line of hunk 1: " z<RLO>a"
        (30, 2),   # second hunk additions replace new line 30, RLI col 2
        (31, 2),   # next added line is 31
    ]
    assert [c["diff_position"]["line"] for c in controls] == [7, 10, 11]
    # diff column = new column + 1 (the leading '+')
    assert [c["diff_position"]["column"] for c in controls] == [4, 3, 3]
    # logical indices keep the original parse result intact
    assert [c["logical_index"] for c in controls] == \
        [c2["logical_index"] for c2 in item["result"]["controls"]]


def test_multi_file_one_record_each_and_max_risk(client):
    diff = (
        "diff --git a/clean.py b/clean.py\n--- a/clean.py\n+++ b/clean.py\n"
        "@@ -1 +1 @@\n-aa\n+bb\n"
        "diff --git a/evil.js b/evil.js\n--- a/evil.js\n+++ b/evil.js\n"
        f"@@ -1 +1 @@\n-ok\n+{RLO}bad.js{PDF}\n"
    )
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    body = resp.json()
    assert body["file_count"] == 2
    assert [i["path"] for i in body["items"]] == ["clean.py", "evil.js"]
    assert [i["risk_level"] for i in body["items"]] == ["info", "high"]
    assert body["risk_level"] == "high"
    listing = client.get("/api/v1/audits").json()
    assert listing["total"] == 2


def test_deleted_and_new_files_and_git_null(client):
    diff = (
        "diff --git a/gone.txt b/gone.txt\ndeleted file mode 100644\n"
        "--- a/gone.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n"
        "diff --git a/added.txt b/added.txt\nnew file mode 100644\n"
        "--- /dev/null\n+++ b/added.txt\n@@ -0,0 +1 @@\n+hello\n"
    )
    body = client.post("/api/v1/audits/diff", json={"diff": diff}).json()
    # deletion carries no additions -> no record; new file -> one record
    assert body["file_count"] == 1
    assert body["items"][0]["path"] == "added.txt"
    assert body["items"][0]["old_path"] is None


def test_no_newline_markers_ignored_from_text(client):
    diff = (
        "--- a\n+++ b\n@@ -1 +1 @@\n"
        f"-clean\n+{RLO}y\n"
        "\\ No newline at end of file\n"
    )
    body = client.post("/api/v1/audits/diff", json={"diff": diff}).json()
    item = body["items"][0]
    # rebuilt text has no trailing newline
    assert item["text_length"] == len(f"{RLO}y")
    assert item["added_lines"][0]["no_newline"] is True
    span = item["locations"]["dangerous_spans"][0]
    # unclosed override extends to the (half-open) end of the 2-char line:
    # RLO col 1, 'y' col 2, end col 3; diff columns add the '+' prefix
    assert span["position"]["end"] == {"line": 1, "column": 3}
    assert span["diff_position"]["end"] == {"line": 5, "column": 4}


def test_no_newline_mid_hunk_then_more_lines(client):
    diff = (
        "--- a\n+++ b\n@@ -0,0 +1,3 @@\n"
        f"+{RLO}a\n"
        "\\ No newline at end of file\n"
        "+bb\n+ccc\n"
    )
    body = client.post("/api/v1/audits/diff", json={"diff": diff}).json()
    item = body["items"][0]
    lines = item["added_lines"]
    assert [l["new_line"] for l in lines] == [1, 2, 3]
    assert lines[0]["no_newline"] is True
    assert lines[1]["no_newline"] is False
    # logical text: RLO a  (no newline) b b \n c c c \n
    assert item["result"]["controls"][0]["logical_index"] == 0


def test_files_without_additions_are_skipped(client):
    # pure deletion hunk + a context-only file
    diff = (
        "diff --git a/d.txt b/d.txt\n--- a/d.txt\n+++ b/d.txt\n"
        "@@ -1 +0,0 @@\n-x\n"
    )
    body = client.post("/api/v1/audits/diff", json={"diff": diff}).json()
    assert body["file_count"] == 0
    assert body["items"] == []
    assert body["risk_level"] == "info"
    assert client.get("/api/v1/audits").json()["total"] == 0


def test_binary_patch_sections_produce_no_records(client):
    diff = (
        "diff --git a/img.png b/img.png\nnew file mode 100644\n"
        "index 0000000..1111111\nBinary files /dev/null and b/img.png differ\n"
        "diff --git a/t.txt b/t.txt\n--- a/t.txt\n+++ b/t.txt\n"
        "@@ -1 +1 @@\n-a\n+b\n"
    )
    body = client.post("/api/v1/audits/diff", json={"diff": diff}).json()
    assert body["file_count"] == 1
    assert body["items"][0]["path"] == "t.txt"


def test_git_binary_patch_with_base84_body(client):
    diff = (
        "diff --git a/a.bin b/a.bin\nnew file mode 100644\n"
        "index 0000000..deadbee\nGIT binary patch\n"
        "literal 12\n"
        "Kcmcc=-062c=eDqJz)P\"jC10A\\i\n\n"
        "diff --git a/t.txt b/t.txt\n--- a/t.txt\n+++ b/t.txt\n"
        "@@ -1 +1 @@\n-a\n+b\n"
    )
    body = client.post("/api/v1/audits/diff", json={"diff": diff}).json()
    assert [i["path"] for i in body["items"]] == ["t.txt"]


def test_stored_record_carries_meta_and_verifies_consistent(client):
    diff = (
        "--- a/p.sh\n+++ b/p.sh\n@@ -1 +1,2 @@\n-z\n"
        f"+{RLO}sh\n+more\n"
    )
    body = client.post("/api/v1/audits/diff", json={"diff": diff}).json()
    rid = body["items"][0]["id"]
    detail = client.get(f"/api/v1/audits/{rid}").json()
    assert detail["filename"] == "p.sh"
    assert detail["meta"]["source"] == "unified_diff"
    assert detail["meta"]["new_path"] == "p.sh"
    assert detail["meta"]["locations"]["controls"]
    # raw text is the rebuilt additions only
    assert detail["raw_text"] == f"{RLO}sh\nmore\n"
    # verify recomputes the parse on raw_text: meta stays out of result
    verify = client.get(f"/api/v1/audits/{rid}/verify").json()
    assert verify["consistent"] is True
    assert verify["diff_count"] == 0


# ------------------------------------------------------------- errors 422 --

def test_empty_and_garbage_diff_422(client):
    for bad in ["", "   \n", "not a diff at all\n"]:
        resp = client.post("/api/v1/audits/diff", json={"diff": bad})
        assert resp.status_code == 422
        assert resp.json()["detail"]["line"] == 1


def test_hunk_count_mismatch_points_to_header_and_no_writes(client):
    # Header declares 1 old / 2 new lines but the body supplies neither:
    # the truncated hunk is detected when it closes at EOF and reported
    # against the header line.
    diff = "--- a\n+++ b\n@@ -1 +1,2 @@\n"
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "invalid_unified_diff"
    assert detail["line"] == 3  # the hunk header line
    assert "declares 1 old and 2 new" in detail["message"]
    assert client.get("/api/v1/audits").json()["total"] == 0


def test_extra_new_line_points_to_offending_body_line(client):
    diff = (
        "--- a\n+++ b\n@@ -1 +1 @@\n"
        " c\n+extra\n"
    )
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    assert resp.status_code == 422
    assert resp.json()["detail"]["line"] == 5  # the offending '+extra' line


def test_malformed_hunk_header_422(client):
    diff = "--- a\n+++ b\n@@ bogus @@\n+a\n"
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    assert resp.status_code == 422
    assert resp.json()["detail"]["line"] == 3


def test_hunk_without_file_header_422(client):
    resp = client.post(
        "/api/v1/audits/diff", json={"diff": "@@ -1 +1 @@\n+a\n"}
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["line"] == 1


def test_plus_header_without_minus_header_422(client):
    resp = client.post(
        "/api/v1/audits/diff", json={"diff": "+++ b/x\n@@ -1 +1 @@\n+a\n"}
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["line"] == 1


def test_invalid_body_prefix_422(client):
    diff = "--- a\n+++ b\n@@ -1 +1 @@\n?bad prefix\n"
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    assert resp.status_code == 422
    assert resp.json()["detail"]["line"] == 4


def test_invalid_no_newline_marker_422(client):
    diff = "--- a\n+++ b\n@@ -1 +1 @@\n+a\n\\ Not the expected marker\n"
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    assert resp.status_code == 422
    assert resp.json()["detail"]["line"] == 5


def test_dangling_no_newline_marker_422(client):
    diff = "--- a\n+++ b\n@@ -1 +1 @@\n\\ No newline at end of file\n"
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    assert resp.status_code == 422
    assert resp.json()["detail"]["line"] == 4


def test_error_in_second_file_reports_its_line(client):
    diff = (
        "diff --git a/ok b/ok\n--- a/ok\n+++ b/ok\n@@ -1 +1 @@\n-a\n+b\n"
        "diff --git a/bad b/bad\n--- a/bad\n+++ b/bad\n"
        "@@ -1 +1 @@\n-a\ngarbage\n"
    )
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    assert resp.status_code == 422
    assert resp.json()["detail"]["line"] == 12
    # first file must not have been persisted either
    assert client.get("/api/v1/audits").json()["total"] == 0


def test_header_without_hunks_422(client):
    # A plain (non-git) file header without any hunk is truncated/garbage.
    resp = client.post(
        "/api/v1/audits/diff",
        json={"diff": "--- x\ttime\n+++ x\ttime\n"},
    )
    assert resp.status_code == 422
    # headers exist but no hunk follows; reported against the '+++' line
    assert resp.json()["detail"]["line"] == 2


def test_git_preamble_without_hunks_is_valid_empty_file(client):
    # git prints no headers/hunks for an empty new file; the section exists
    # but carries no additions, so no record is written.
    diff = "diff --git a/empty b/empty\nnew file mode 100644\nindex 0000000..e69de29\n"
    body = client.post("/api/v1/audits/diff", json={"diff": diff}).json()
    assert body["file_count"] == 0
    assert client.get("/api/v1/audits").json()["total"] == 0


def test_git_preamble_empty_section_then_real_file(client):
    diff = (
        "diff --git a/empty b/empty\nnew file mode 100644\n"
        "index 0000000..e69de29\n"
        "diff --git a/t.txt b/t.txt\n--- a/t.txt\n+++ b/t.txt\n"
        "@@ -1 +1 @@\n-a\n+b\n"
    )
    body = client.post("/api/v1/audits/diff", json={"diff": diff}).json()
    assert [i["path"] for i in body["items"]] == ["t.txt"]


def test_quoted_git_paths_are_decoded(client):
    diff = (
        'diff --git "a/src/a b.txt" "b/src/a b.txt"\n'
        '--- "a/src/a b.txt"\n+++ "b/src/a b.txt"\n'
        "@@ -1 +1 @@\n-x\n+y\n"
    )
    body = client.post("/api/v1/audits/diff", json={"diff": diff}).json()
    assert body["items"][0]["path"] == "src/a b.txt"


def test_implicit_termination_error_maps_to_opener(client):
    # LRI + unclosed LRE on one added line, PDI on a later added line:
    # the error must map to the opener position (first parenthetical),
    # not the PDI that force-closed it.
    diff = (
        "--- a\n+++ b\n@@ -0,0 +1,3 @@\n"
        f"+{RLI}a{LRE}b\n"
        "+middle\n"
        f"+c{PDI}\n"
    )
    body = client.post("/api/v1/audits/diff", json={"diff": diff}).json()
    item = body["items"][0]
    assert item["error_count"] >= 1
    err = item["locations"]["errors"][0]
    # the LRE opener sits at column 3 of new file line 1
    assert err["position"] == {"line": 1, "column": 3}
    assert err["diff_position"]["line"] == 4  # the first '+' body line
    assert err["result_index"] == 0
    assert err["logical_index"] == 2


def test_crlf_diff_is_accepted(client):
    diff = (
        "--- a/x\r\n+++ b/x\r\n@@ -1 +1 @@\r\n-old\r\n"
        f"+{RLO}new{PDF}\r\n"
    )
    resp = client.post("/api/v1/audits/diff", json={"diff": diff})
    assert resp.status_code == 201
    item = resp.json()["items"][0]
    assert item["risk_level"] == "high"


# ------------------------------------------------------------ edge cases ---

def test_context_empty_line_and_plain_diff_prefixes(client):
    # plain diff -u keeps paths verbatim (no a/ b/ stripping)
    diff = (
        "--- odd name\ttimestamp here\n+++ odd name\ttimestamp here\n"
        "@@ -1 +1,2 @@\n-a\n+a\n+\n"
    )
    body = client.post("/api/v1/audits/diff", json={"diff": diff}).json()
    assert body["items"][0]["path"] == "odd name"
    # a genuinely empty added line adds an empty line to the rebuilt text
    assert body["items"][0]["text_length"] == len("a\n\n")


def test_missing_diff_field_is_pydantic_422(client):
    resp = client.post("/api/v1/audits/diff", json={"patch": "x"})
    assert resp.status_code == 422
