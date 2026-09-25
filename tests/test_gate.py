"""API tests for POST /api/v1/audits/gate (path-based risk gate)."""

import pytest

LRE = "‪"
RLO = "‮"
PDF = "‬"
RLI = "⁧"
PDI = "⁩"

CLEAN = "plain text, no controls"
LOW_RISK = LRE + "emb" + PDF
MEDIUM_RISK = RLI + "iso" + PDI
HIGH_RISK = RLO + "bad.exe" + PDF
CRITICAL_RISK = RLO + "end.js"


def _post(client, text, filename=None):
    return client.post("/api/v1/audits", json={"text": text, "filename": filename})


def _gate(client, ids, default_max_risk, rules=None):
    return client.post(
        "/api/v1/audits/gate",
        json={
            "ids": ids,
            "default_max_risk": default_max_risk,
            "rules": rules or [],
        },
    )


# ---------------------------------------------------------------------------
# Template matcher unit tests
# ---------------------------------------------------------------------------

from app.gate import GateRule, evaluate_record, select_rule  # noqa: E402


def _rules(specs):
    return [
        GateRule.make(index=i, template=template, max_risk=max_risk)
        for i, (template, max_risk) in enumerate(specs)
    ]


@pytest.mark.parametrize(
    "template,path,matches",
    [
        ("a/b.py", "a/b.py", True),
        ("a/b.py", "a/c.py", False),
        ("a/b.py", "a/b", False),
        ("src/*/app.py", "src/pkg/app.py", True),
        ("src/*/app.py", "src/app.py", False),       # * needs a segment
        ("src/*/app.py", "src/pkg/sub/app.py", False),
        ("src/**/app.py", "src/app.py", True),        # ** matches zero
        ("src/**/app.py", "src/pkg/app.py", True),    # ** matches one
        ("src/**/app.py", "src/pkg/sub/app.py", True),
        ("**/*.py", "a/b/c.py", True),
        ("**/*.py", "c.py", True),
        ("**", "a/b/c.py", True),
        ("**", "", True),
        ("*", "a", True),
        ("*", "a/b", False),
        ("a/**", "a/b/c", True),
        ("a/**", "b/c", False),
        ("a/**/b/**/c", "a/x/b/y/z/c", True),
        ("a/**/b/**/c", "a/b/c", True),
        ("a/**/b/**/c", "a/x/c", False),
        ("**/**/x", "x", True),
        ("a/b", "a/b/", False),
        ("/a/b", "/a/b", True),
        ("*/b/*", "a/b/c", True),
    ],
)
def test_template_matcher(template, path, matches):
    assert select_rule(path, _rules([(template, "info")])) is not None if matches \
        else select_rule(path, _rules([(template, "info")])) is None


def test_select_rule_most_fixed_segments_wins():
    rules = _rules([
        ("**/*.py", "low"),
        ("src/*/a.py", "critical"),
    ])
    rule = select_rule("src/pkg/a.py", rules)
    assert rule.template == "src/*/a.py"


def test_select_rule_tie_more_total_segments_wins():
    rules = _rules([
        ("**/a.py", "low"),
        ("src/**/a.py", "high"),
    ])
    # both have exactly one fixed segment ("a.py"); longer template wins
    rule = select_rule("src/pkg/a.py", rules)
    assert rule.template == "src/**/a.py"


def test_select_rule_still_tie_earliest_wins():
    rules = _rules([
        ("src/*/a.py", "low"),
        ("src/*/a.py", "high"),
    ])
    rule = select_rule("src/pkg/a.py", rules)
    assert rule.index == 0
    assert rule.max_risk == "low"


def test_select_rule_no_match_returns_none():
    assert select_rule("a/b.py", _rules([("src/**", "low")])) is None


# ---------------------------------------------------------------------------
# API tests
# ---------------------------------------------------------------------------

def test_gate_missing_record_is_404(client):
    audit_id = _post(client, CLEAN, "a.txt").json()["id"]
    resp = _gate(client, [audit_id, 9999], "high")
    assert resp.status_code == 404
    assert "9999" in resp.json()["detail"]
    assert _gate(client, [9999], "high").status_code == 404


def test_gate_default_threshold_without_rules(client):
    clean = _post(client, CLEAN, "a.txt").json()["id"]
    high = _post(client, HIGH_RISK, "b.txt").json()["id"]

    ok = _gate(client, [clean, high], "high").json()
    assert ok["passed"] is True
    assert ok["checked_count"] == 2
    assert ok["passed_count"] == 2
    assert ok["failed_count"] == 0
    assert ok["risk_level"] == "high"
    for item in ok["results"]:
        assert item["matched_rule"] is None
        assert item["used_default"] is True
        assert item["threshold"] == "high"

    blocked = _gate(client, [clean, high], "medium").json()
    assert blocked["passed"] is False
    assert blocked["passed_count"] == 1
    assert blocked["failed_count"] == 1
    by_id = {item["id"]: item for item in blocked["results"]}
    assert by_id[clean]["passed"] is True
    assert by_id[high]["passed"] is False
    assert by_id[high]["actual_risk"] == "high"


def test_gate_result_order_follows_request(client):
    first = _post(client, CLEAN, "a.txt").json()["id"]
    second = _post(client, CLEAN, "b.txt").json()["id"]
    body = _gate(client, [second, first], "high").json()
    assert [item["id"] for item in body["results"]] == [second, first]


def test_gate_path_rule_overrides_default(client):
    audit_id = _post(client, HIGH_RISK, "src/pkg/evil.py").json()["id"]
    body = _gate(
        client, [audit_id], "low",
        rules=[{"template": "**/*.py", "max_risk": "critical"}],
    ).json()
    item = body["results"][0]
    assert item["used_default"] is False
    assert item["matched_rule"] == {
        "index": 0, "template": "**/*.py", "max_risk": "critical"
    }
    assert item["threshold"] == "critical"
    assert item["passed"] is True
    assert body["passed"] is True


def test_gate_unmatched_path_uses_default(client):
    audit_id = _post(client, HIGH_RISK, "docs/notes.md").json()["id"]
    body = _gate(
        client, [audit_id], "low",
        rules=[{"template": "**/*.py", "max_risk": "critical"}],
    ).json()
    item = body["results"][0]
    assert item["used_default"] is True
    assert item["matched_rule"] is None
    assert item["threshold"] == "low"
    assert item["passed"] is False
    assert body["passed"] is False


def test_gate_missing_filename_uses_default(client):
    audit_id = _post(client, HIGH_RISK).json()["id"]
    body = _gate(
        client, [audit_id], "high",
        rules=[{"template": "**", "max_risk": "info"}],
    ).json()
    item = body["results"][0]
    assert item["filename"] is None
    assert item["used_default"] is True
    assert item["matched_rule"] is None
    assert item["threshold"] == "high"
    assert item["passed"] is True


def test_gate_star_matches_single_segment_only(client):
    direct = _post(client, MEDIUM_RISK, "pkg/mod/app.py").json()["id"]
    nested = _post(client, HIGH_RISK, "pkg/sub/deep/app.py").json()["id"]
    rules = [{"template": "pkg/*/app.py", "max_risk": "medium"}]

    body = _gate(client, [direct, nested], "low", rules=rules).json()
    by_id = {item["id"]: item for item in body["results"]}
    # one middle segment: matches; medium allowed -> passes
    assert by_id[direct]["matched_rule"]["template"] == "pkg/*/app.py"
    assert by_id[direct]["passed"] is True
    # two middle segments do not match '*'; falls back to default low -> fails
    assert by_id[nested]["matched_rule"] is None
    assert by_id[nested]["used_default"] is True
    assert by_id[nested]["passed"] is False


def test_gate_double_star_matches_zero_or_more(client):
    at_root = _post(client, CLEAN, "app.py").json()["id"]
    deep = _post(client, CLEAN, "a/b/c/app.py").json()["id"]
    other = _post(client, CLEAN, "readme.md").json()["id"]
    rules = [{"template": "**/app.py", "max_risk": "info"}]

    body = _gate(client, [at_root, deep, other], "high", rules=rules).json()
    by_id = {item["id"]: item for item in body["results"]}
    assert by_id[at_root]["matched_rule"] is not None
    assert by_id[deep]["matched_rule"] is not None
    assert by_id[other]["matched_rule"] is None


def test_gate_threshold_boundary_inclusive(client):
    medium = _post(client, MEDIUM_RISK, "a.txt").json()["id"]
    assert _gate(client, [medium], "medium").json()["passed"] is True
    assert _gate(client, [medium], "low").json()["passed"] is False


def test_gate_specificity_selection(client):
    # global rule allows only info; more specific rule allows critical.
    rules = [
        {"template": "**", "max_risk": "info"},
        {"template": "src/*/x.py", "max_risk": "critical"},
    ]
    audit_id = _post(client, CRITICAL_RISK, "src/pkg/x.py").json()["id"]
    body = _gate(client, [audit_id], "info", rules=rules).json()
    item = body["results"][0]
    assert item["matched_rule"]["template"] == "src/*/x.py"
    assert item["passed"] is True


def test_gate_duplicate_ids_evaluated_twice(client):
    audit_id = _post(client, CLEAN, "a.txt").json()["id"]
    body = _gate(client, [audit_id, audit_id], "high").json()
    assert body["checked_count"] == 2
    assert [item["id"] for item in body["results"]] == [audit_id, audit_id]


def test_gate_is_read_only(client):
    audit_id = _post(client, HIGH_RISK, "a.txt").json()["id"]
    before = client.get(f"/api/v1/audits/{audit_id}").json()
    _gate(client, [audit_id], "info")
    after = client.get(f"/api/v1/audits/{audit_id}").json()
    assert before == after
    assert client.get("/api/v1/audits").json()["total"] == 1


def test_gate_validation_errors(client):
    # empty id list
    assert _gate(client, [], "high").status_code == 422
    # invalid risk levels
    assert _gate(client, [1], "urgent").status_code == 422
    audit_id = _post(client, CLEAN).json()["id"]
    resp = client.post(
        "/api/v1/audits/gate",
        json={
            "ids": [audit_id],
            "default_max_risk": "high",
            "rules": [{"template": "", "max_risk": "low"}],
        },
    )
    assert resp.status_code == 422
    resp = client.post(
        "/api/v1/audits/gate",
        json={
            "ids": [audit_id],
            "default_max_risk": "high",
            "rules": [{"template": "**", "max_risk": "nope"}],
        },
    )
    assert resp.status_code == 422


def test_evaluate_record_helper_directly():
    record = {"id": 7, "filename": "src/a.py", "risk_level": "critical"}
    result = evaluate_record(
        record,
        default_max_risk="info",
        rules=_rules([("src/a.py", "critical")]),
    )
    assert result["id"] == 7
    assert result["actual_risk"] == "critical"
    assert result["threshold"] == "critical"
    assert result["passed"] is True
    assert result["used_default"] is False
