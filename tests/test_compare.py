"""API tests for POST /api/v1/audits/compare (regression comparison)."""

LRE = "‪"
RLO = "‮"
PDF = "‬"
LRI = "⁦"
PDI = "⁩"
LRM = "‎"


def _post(client, text, filename=None):
    return client.post("/api/v1/audits", json={"text": text, "filename": filename})


def _compare(client, before_id, after_id):
    return client.post("/api/v1/audits/compare",
                       json={"before_id": before_id, "after_id": after_id})


def test_compare_same_id_is_422(client):
    audit_id = _post(client, "hello").json()["id"]
    resp = _compare(client, audit_id, audit_id)
    assert resp.status_code == 422
    assert "different" in resp.json()["detail"]


def test_compare_missing_record_is_404(client):
    audit_id = _post(client, "hello").json()["id"]
    assert _compare(client, audit_id, 9999).status_code == 404
    assert _compare(client, 9999, audit_id).status_code == 404
    assert _compare(client, 9998, 9999).status_code == 404


def test_compare_identical_texts_is_unchanged(client):
    before = _post(client, "clean text", "a.txt").json()["id"]
    after = _post(client, "clean text", "b.txt").json()["id"]
    body = _compare(client, before, after).json()

    assert body["changed"] is False
    assert body["before_id"] == before
    assert body["after_id"] == after
    assert body["risk"] == {
        "before": "info", "after": "info",
        "changed": False, "direction": "unchanged", "order_delta": 0,
    }
    assert body["error_count"] == {"before": 0, "after": 0,
                                   "changed": False, "delta": 0}
    changes = body["control_changes"]
    assert changes == {"added": [], "removed": [],
                       "position_changed": [], "pairing_changed": []}
    # both sides' summaries are returned
    assert body["summary"]["before"]["id"] == before
    assert body["summary"]["before"]["filename"] == "a.txt"
    assert body["summary"]["after"]["id"] == after
    assert body["summary"]["after"]["filename"] == "b.txt"


def test_compare_added_and_removed_controls(client):
    before = _post(client, "clean").json()["id"]
    after = _post(client, "x" + RLO + "bad.exe" + PDF).json()["id"]
    body = _compare(client, before, after).json()

    assert body["changed"] is True
    changes = body["control_changes"]
    assert [a["abbreviation"] for a in changes["added"]] == ["RLO", "PDF"]
    assert changes["added"][0]["occurrence"] == 1
    assert changes["added"][0]["control"]["logical_index"] == 1
    assert changes["removed"] == []
    assert changes["position_changed"] == []
    assert changes["pairing_changed"] == []
    assert body["risk"]["before"] == "info"
    assert body["risk"]["after"] == "high"
    assert body["risk"]["direction"] == "escalated"

    # and in reverse the same pair shows up as removed
    reverse = _compare(client, after, before).json()
    assert reverse["changed"] is True
    assert [r["abbreviation"] for r in reverse["control_changes"]["removed"]] == [
        "RLO", "PDF"]
    assert reverse["control_changes"]["added"] == []
    assert reverse["risk"]["direction"] == "de-escalated"


def test_compare_position_change_only_when_pair_shifts(client):
    # Whole LRE..PDF pair shifted right by one: same partner, same span length.
    before = _post(client, "a" + LRE + "bc" + PDF + "d").json()["id"]
    after = _post(client, "xa" + LRE + "bc" + PDF + "d").json()["id"]
    body = _compare(client, before, after).json()

    assert body["changed"] is True
    changes = body["control_changes"]
    assert changes["added"] == []
    assert changes["removed"] == []
    assert changes["pairing_changed"] == []
    moved = changes["position_changed"]
    assert [m["abbreviation"] for m in moved] == ["LRE", "PDF"]
    assert moved[0]["logical_index"] == {"before": 1, "after": 2, "delta": 1}
    assert moved[0]["position"]["before"] == {"line": 1, "column": 2}
    assert moved[0]["position"]["after"] == {"line": 1, "column": 3}


def test_compare_pairing_scope_change_without_move(client):
    # Same opener position, but the PDF closer is dropped: scope now runs to
    # end of text and the LRE becomes an orphan.
    before = _post(client, "a" + LRE + "bc" + PDF + "d").json()["id"]
    after = _post(client, "a" + LRE + "bcd").json()["id"]
    body = _compare(client, before, after).json()

    assert body["changed"] is True
    changes = body["control_changes"]
    assert [r["abbreviation"] for r in changes["removed"]] == ["PDF"]
    assert changes["position_changed"] == []
    pairing = changes["pairing_changed"]
    assert len(pairing) == 1
    entry = pairing[0]
    assert entry["abbreviation"] == "LRE"
    assert entry["occurrence"] == 1
    assert entry["scope_end"] == {"before": 4, "after": 5}
    assert entry["scope_length"] == {"before": 3, "after": 4}
    assert entry["paired_with"] == {"before": "U+202C", "after": None}
    assert entry["is_orphan"] == {"before": False, "after": True}
    # risk escalated low -> medium and one new error appeared
    assert body["risk"]["before"] == "low"
    assert body["risk"]["after"] == "medium"
    assert body["risk"]["direction"] == "escalated"
    assert body["error_count"] == {"before": 0, "after": 1,
                                  "changed": True, "delta": 1}


def test_compare_pairs_by_abbreviation_and_appearance_order(client):
    # First RLO swaps place with the following "x" (so it moves while the PDF
    # and the *second* RLO stay put). Pairing is by abbreviation + occurrence,
    # so only RLO #1 is reported and there is no add/remove noise.
    before = _post(client, RLO + "x" + PDF + "y" + RLO + "z" + PDF).json()["id"]
    after = _post(client, "x" + RLO + PDF + "y" + RLO + "z" + PDF).json()["id"]
    body = _compare(client, before, after).json()

    assert body["changed"] is True
    changes = body["control_changes"]
    assert changes["added"] == []
    assert changes["removed"] == []
    moved = changes["position_changed"]
    assert [(m["abbreviation"], m["occurrence"]) for m in moved] == [("RLO", 1)]
    assert moved[0]["logical_index"] == {"before": 0, "after": 1, "delta": 1}
    # the moved RLO's PDF did not move, so its affected span shrank
    pairing = changes["pairing_changed"]
    assert [(p["abbreviation"], p["occurrence"]) for p in pairing] == [("RLO", 1)]
    assert pairing[0]["scope_length"] == {"before": 2, "after": 1}


def test_compare_marks_paired_by_occurrence(client):
    # LRM has no pairing; only its position is tracked.
    before = _post(client, "a" + LRM + "b").json()["id"]
    after = _post(client, "xy" + LRM + "b").json()["id"]
    body = _compare(client, before, after).json()

    assert body["changed"] is True
    changes = body["control_changes"]
    assert changes["pairing_changed"] == []
    moved = changes["position_changed"]
    assert len(moved) == 1
    assert moved[0]["abbreviation"] == "LRM"
    assert moved[0]["logical_index"]["delta"] == 1


def test_compare_risk_and_error_count(client):
    before = _post(client, "clean").json()["id"]
    after = _post(client, RLO + "end.js").json()["id"]  # unclosed RLO: critical
    body = _compare(client, before, after).json()

    assert body["changed"] is True
    assert body["risk"] == {
        "before": "info", "after": "critical",
        "changed": True, "direction": "escalated", "order_delta": 4,
    }
    assert body["error_count"] == {"before": 0, "after": 1,
                                   "changed": True, "delta": 1}
    assert body["summary"]["before"]["risk_level"] == "info"
    assert body["summary"]["after"]["risk_level"] == "critical"
    assert body["summary"]["after"]["error_count"] == 1


def test_compare_isolate_added_with_error(client):
    before = _post(client, "ok").json()["id"]
    after = _post(client, LRI + "abc").json()["id"]  # unclosed isolate
    body = _compare(client, before, after).json()

    assert body["changed"] is True
    changes = body["control_changes"]
    assert [a["abbreviation"] for a in changes["added"]] == ["LRI"]
    assert changes["added"][0]["control"]["is_orphan"] is True
    assert body["risk"]["after"] == "medium"
    assert body["error_count"]["delta"] == 1


def test_compare_invalid_body_is_422(client):
    assert client.post("/api/v1/audits/compare", json={}).status_code == 422
    assert client.post("/api/v1/audits/compare",
                       json={"before_id": 1}).status_code == 422
    assert client.post("/api/v1/audits/compare",
                       json={"before_id": "x", "after_id": 2}).status_code == 422
