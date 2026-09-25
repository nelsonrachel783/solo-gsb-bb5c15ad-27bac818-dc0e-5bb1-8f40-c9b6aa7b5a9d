"""Unit tests for the bidi parser + API smoke tests."""

# ---------------------------------------------------------------- parser ---

from app.bidi import parse_bidi, RiskLevel, escape_preview


def test_clean_text_is_info():
    r = parse_bidi("hello, world").to_dict()
    assert r["risk_level"] == "info"
    assert r["controls"] == []
    assert r["errors"] == []


def test_rlo_is_high_and_spans():
    text = "x" + "‮" + "malware.exe" + "‬"
    res = parse_bidi(text)
    assert res.risk == RiskLevel.HIGH
    rlo = [c for c in res.controls if c.abbreviation == "RLO"][0]
    assert rlo.logical_index == 1
    assert rlo.kind.value == "override"
    assert res.spans  # dangerous span produced
    preview = res.spans[0].escaped_preview
    assert "⟨RLO⟩" in preview
    assert "malware.exe" in preview  # readable logical order retained
    # original text must be untouched
    assert text[1] == "‮"


def test_unclosed_rlo_becomes_critical():
    text = "‮bad.exe"
    res = parse_bidi(text)
    assert res.risk == RiskLevel.CRITICAL
    assert any("never closed" in e for e in res.errors)
    rlo = res.controls[0]
    assert rlo.is_orphan is True
    assert rlo.scope_end == len(text)


def test_balanced_lre_pdf_pairs_scope_end():
    text = "a‪bc‬d"
    res = parse_bidi(text)
    lre, pdf = res.controls
    assert lre.paired_with == "U+202C"
    assert lre.scope_end == pdf.logical_index
    assert pdf.paired_with == "U+202A"
    assert lre.is_orphan is False


def test_lone_pdf_is_orphan_error():
    res = parse_bidi("x‬")
    pdf = res.controls[0]
    assert pdf.is_orphan is True
    assert any("no matching embedding" in e for e in res.errors)


def test_lone_pdi_is_orphan_error():
    res = parse_bidi("x⁩")
    assert any("no matching isolate" in e for e in res.errors)


def test_isolate_pairing():
    text = "⁦inner⁩"
    res = parse_bidi(text)
    lri, pdi = res.controls
    assert lri.paired_with == "U+2069"
    assert lri.scope_end == pdi.logical_index
    assert not lri.is_orphan


def test_unclosed_isolate_reported():
    res = parse_bidi("⁦abc")
    assert any("never closed by PDI" in e for e in res.errors)
    assert res.risk == RiskLevel.MEDIUM


def test_embedding_inside_isolate_implicit_close():
    # LRI ... LRE (no PDF) ... PDI  -> LRE force-closed with an error
    text = "⁦a‪b⁩"
    res = parse_bidi(text)
    msgs = " ".join(res.errors)
    assert "implicitly terminated by PDI" in msgs


def test_pdf_skips_unterminated_isolate_rule():
    # LRI then LRE then PDF: PDF matches the LRE despite the open LRI above
    text = "⁦‪x‬⁩"
    res = parse_bidi(text)
    lre = [c for c in res.controls if c.abbreviation == "LRE"][0]
    assert lre.paired_with == "U+202C"
    assert not lre.is_orphan


def test_line_and_column():
    text = "ab\n‮x"
    res = parse_bidi(text)
    rlo = res.controls[0]
    assert rlo.line == 2
    assert rlo.column == 1
    assert rlo.logical_index == 3


def test_nested_depth_reported():
    text = "‪‪‬x‬"
    res = parse_bidi(text).to_dict()
    assert res["max_depth"] == 2


def test_escaped_preview_marks_all_controls():
    p = escape_preview("‮⁦z⁩​")
    assert "⟨RLO⟩" in p
    assert "⟨LRI⟩" in p
    assert "⟨PDI⟩" in p
    assert "⟨U+200B⟩" in p


def test_marks_are_info():
    res = parse_bidi("a‎b‏c").to_dict()
    assert res["risk_level"] == "info"
    assert res["stats"]["by_abbreviation"]["RLM"] == 1


# ------------------------------------------------------------------- api ---

def _post(client, text, filename=None):
    return client.post("/api/v1/audits", json={"text": text, "filename": filename})


def test_api_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_api_create_and_get(client):
    resp = _post(client, "x‮bad", "trojan.txt")
    assert resp.status_code == 201
    body = resp.json()
    assert body["risk_level"] == "critical"
    assert body["result"]["error_count"] == 1
    detail = client.get(f"/api/v1/audits/{body['id']}").json()
    assert detail["filename"] == "trojan.txt"
    assert detail["raw_text"][1] == "‮"  # original preserved verbatim


def test_api_filter_by_risk_and_filename(client):
    _post(client, "clean", "a.txt")
    _post(client, "‮bad", "evil.txt")
    high = client.get("/api/v1/audits", params={"risk_level": "critical"}).json()
    assert high["total"] == 1
    assert high["items"][0]["filename"] == "evil.txt"

    by_name = client.get("/api/v1/audits", params={"filename": "evil"}).json()
    assert by_name["total"] == 1

    none = client.get("/api/v1/audits", params={"risk_level": "info",
                                                "filename": "nope"}).json()
    assert none["total"] == 0


def test_api_404(client):
    assert client.get("/api/v1/audits/9999").status_code == 404
