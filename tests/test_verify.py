"""API tests for GET /api/v1/audits/{id}/verify (recompute-and-diff)."""

import json

LRE = "‪"
RLO = "‮"
PDF = "‬"
LRI = "⁦"
PDI = "⁩"


def _post(client, text, filename=None):
    return client.post("/api/v1/audits", json={"text": text, "filename": filename})


def _verify(client, audit_id):
    return client.get(f"/api/v1/audits/{audit_id}/verify")


def _tamper_result(audit_id, mutate):
    """Rewrite the stored result_json in place (simulates bit-rot / drift)."""
    from app import database
    with database.connect() as conn:
        row = conn.execute(
            "SELECT result_json FROM audits WHERE id = ?", (audit_id,)
        ).fetchone()
        result = json.loads(row["result_json"])
        mutate(result)
        conn.execute(
            "UPDATE audits SET result_json = ? WHERE id = ?",
            (json.dumps(result, ensure_ascii=False), audit_id),
        )


def test_verify_missing_record_is_404(client):
    resp = _verify(client, 9999)
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"]


def test_verify_fresh_record_is_consistent(client):
    audit_id = _post(client, "x" + RLO + "evil.exe" + PDF, "patch.diff").json()["id"]
    resp = _verify(client, audit_id)
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == audit_id
    assert body["consistent"] is True
    assert body["diff_count"] == 0
    assert body["diffs"] == []


def test_verify_clean_record_is_consistent(client):
    audit_id = _post(client, "plain text, no controls").json()["id"]
    body = _verify(client, audit_id).json()
    assert body["consistent"] is True
    assert body["diffs"] == []


def test_verify_detects_tampered_scalar(client):
    audit_id = _post(client, RLO + "end.js").json()["id"]  # unclosed RLO

    def mutate(result):
        result["risk_level"] = "info"
        result["max_depth"] = 0

    _tamper_result(audit_id, mutate)
    body = _verify(client, audit_id).json()

    assert body["consistent"] is False
    assert body["diff_count"] == 2
    by_path = {d["path"]: d for d in body["diffs"]}
    assert by_path["/max_depth"] == {
        "path": "/max_depth",
        "stored": 0,
        "recomputed": 1,
        "stored_present": True,
        "recomputed_present": True,
    }
    assert by_path["/risk_level"]["stored"] == "info"
    assert by_path["/risk_level"]["recomputed"] == "critical"


def test_verify_array_diff_located_by_index(client):
    audit_id = _post(client, "a" + LRE + "bc" + PDF + "d").json()["id"]

    def mutate(result):
        result["controls"][0]["logical_index"] = 99
        result["controls"][1]["paired_with"] = None

    _tamper_result(audit_id, mutate)
    body = _verify(client, audit_id).json()

    assert body["consistent"] is False
    paths = [d["path"] for d in body["diffs"]]
    assert paths == ["/controls/0/logical_index", "/controls/1/paired_with"]
    first = body["diffs"][0]
    assert first["stored"] == 99
    assert first["recomputed"] == 1
    assert first["stored_present"] is True
    assert first["recomputed_present"] is True
    second = body["diffs"][1]
    assert second["stored"] is None
    assert second["recomputed"] == "U+202A"


def test_verify_distinguishes_missing_key_from_null(client):
    audit_id = _post(client, "a" + LRE + "bc" + PDF + "d").json()["id"]

    def mutate(result):
        # key deleted on one control, explicit null on another
        del result["controls"][0]["paired_with"]
        result["controls"][0]["scope_end"] = None

    _tamper_result(audit_id, mutate)
    body = _verify(client, audit_id).json()

    assert body["consistent"] is False
    by_path = {d["path"]: d for d in body["diffs"]}

    missing = by_path["/controls/0/paired_with"]
    assert missing["stored"] is None
    assert missing["recomputed"] == "U+202C"
    assert missing["stored_present"] is False
    assert missing["recomputed_present"] is True

    nulled = by_path["/controls/0/scope_end"]
    assert nulled["stored"] is None
    assert nulled["recomputed"] == 4
    # null is a real value: the field *is* present on the stored side
    assert nulled["stored_present"] is True
    assert nulled["recomputed_present"] is True


def test_verify_array_length_mismatch_reports_index(client):
    audit_id = _post(client, LRI + "abc").json()["id"]  # unclosed isolate: 1 error

    def mutate(result):
        result["errors"] = []          # drop the only error
        result["error_count"] = 0

    _tamper_result(audit_id, mutate)
    body = _verify(client, audit_id).json()

    assert body["consistent"] is False
    by_path = {d["path"]: d for d in body["diffs"]}
    extra = by_path["/errors/0"]
    assert extra["stored"] is None
    assert extra["stored_present"] is False
    assert extra["recomputed_present"] is True
    assert "never closed by PDI" in extra["recomputed"]
    assert by_path["/error_count"]["stored"] == 0
    assert by_path["/error_count"]["recomputed"] == 1


def test_verify_diffs_sorted_by_json_pointer(client):
    audit_id = _post(client, RLO + "end.js").json()["id"]

    def mutate(result):
        result["risk_level"] = "low"
        result["error_count"] = 5
        result["controls"][0]["is_orphan"] = False
        result["stats"]["unclosed_openers"] = 0

    _tamper_result(audit_id, mutate)
    body = _verify(client, audit_id).json()

    paths = [d["path"] for d in body["diffs"]]
    assert paths == sorted(paths)
    assert body["diff_count"] == len(paths)
    assert set(paths) == {
        "/controls/0/is_orphan",
        "/error_count",
        "/risk_level",
        "/stats/unclosed_openers",
    }


def test_verify_nested_object_diff(client):
    audit_id = _post(client, "x" + RLO + "bad" + PDF).json()["id"]

    def mutate(result):
        result["controls"][0]["position"]["column"] = 42

    _tamper_result(audit_id, mutate)
    body = _verify(client, audit_id).json()

    assert body["consistent"] is False
    assert body["diffs"] == [{
        "path": "/controls/0/position/column",
        "stored": 42,
        "recomputed": 2,
        "stored_present": True,
        "recomputed_present": True,
    }]


def test_verify_is_read_only(client):
    audit_id = _post(client, RLO + "end.js", "x.js").json()["id"]
    before = client.get(f"/api/v1/audits/{audit_id}").json()

    def mutate(result):
        result["risk_level"] = "info"

    _tamper_result(audit_id, mutate)
    body = _verify(client, audit_id).json()
    assert body["consistent"] is False

    # the stored record is untouched by verification (no repair/rewrite)
    after = client.get(f"/api/v1/audits/{audit_id}").json()
    assert after["result"]["risk_level"] == "info"   # tampered value persists
    assert after["created_at"] == before["created_at"]
    assert after["raw_text"] == before["raw_text"]

    # and verifying again reports the same diff (idempotent, no side effects)
    again = _verify(client, audit_id).json()
    assert again == body
