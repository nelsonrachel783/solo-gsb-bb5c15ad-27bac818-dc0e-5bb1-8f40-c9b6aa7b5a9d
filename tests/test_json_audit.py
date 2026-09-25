"""Tests for the JSON document audit endpoint (POST /api/v1/audits/json).

Covers: recursive auditing of string values (object keys never audited),
RFC 6901 JSON Pointers (incl. ~0/~1 escaping and array indices), string
token start/end offsets in the original document, control findings mapped
back to original line/column, \\u escape decoding, UTF-16 surrogate pairs,
ordinary escapes not misjudged as hits, one stored record per value,
422 on invalid JSON and duplicate keys (with no partial writes), and
stored meta/verify interplay.
"""

import pytest

RLO = "‮"   # U+202E, as a literal character
PDF = "‬"   # U+202C
RLI = "⁧"   # U+2067
PDI = "⁩"   # U+2069


# ------------------------------------------------------------- auditing ---

def test_basic_object_value_audited(client):
    doc = '{"name": "x\\u202Eevil.exe\\u202C"}'
    resp = client.post("/api/v1/audits/json",
                       json={"document": doc, "filename": "app.json"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["stored"] is True
    assert body["value_count"] == 1
    assert body["risk_level"] == "high"

    item = body["items"][0]
    assert item["pointer"] == "/name"
    # the string token spans from the opening quote to just past the
    # closing quote of the value
    assert item["span"] == {"start": 9, "end": 32}
    assert doc[item["span"]["start"]:item["span"]["end"]] == \
        '"x\\u202Eevil.exe\\u202C"'
    # the decoded value is what gets audited and stored
    assert item["text_length"] == len(f"x{RLO}evil.exe{PDF}")
    assert item["control_count"] == 2
    assert item["dangerous_span_count"] == 1

    controls = item["locations"]["controls"]
    assert [c["logical_index"] for c in controls] == [1, 10]
    # RLO comes from the ‮ escape: mapped to the escape's backslash
    assert controls[0]["offset"] == 11
    assert controls[0]["position"] == {"line": 1, "column": 12}
    assert controls[0]["pointer"] == "/name"
    assert controls[1]["offset"] == 25
    assert controls[1]["position"] == {"line": 1, "column": 26}

    span = item["locations"]["dangerous_spans"][0]
    assert span["start_logical_index"] == 1
    assert span["end_logical_index"] == 10
    assert span["offsets"] == {"start": 11, "end": 25}
    assert span["position"]["start"] == {"line": 1, "column": 12}


def test_keys_are_never_audited(client):
    # the RLO lives in the *key*; the value is clean
    doc = '{"\\u202Ekey": "clean"}'
    resp = client.post("/api/v1/audits/json", json={"document": doc})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["value_count"] == 1
    assert body["risk_level"] == "info"
    item = body["items"][0]
    assert item["control_count"] == 0
    assert item["result"]["controls"] == []
    # pointer uses the decoded key
    assert item["pointer"] == f"/{RLO}key"


def test_nested_pointers_and_escaping(client):
    doc = (
        '{"a": [{"b": "x' + RLO + '"}], '
        '"c/d": {"~e": ["ok", "y' + RLI + 'z' + PDI + '"]}}'
    )
    resp = client.post("/api/v1/audits/json", json={"document": doc})
    assert resp.status_code == 201, resp.text
    items = resp.json()["items"]
    pointers = [i["pointer"] for i in items]
    # '/' -> '~1' and '~' -> '~0' in pointer tokens; arrays use indices
    assert pointers == ["/a/0/b", "/c~1d/~0e/0", "/c~1d/~0e/1"]
    assert items[0]["risk_level"] == "critical"   # unclosed RLO
    assert items[1]["risk_level"] == "info"
    assert items[2]["risk_level"] == "medium"     # RLI
    assert resp.json()["risk_level"] == "critical"


def test_every_string_value_gets_a_record(client):
    doc = '{"clean": "a", "nums": [1, 2.5, true, null], "evil": "' + RLO + '"}'
    resp = client.post("/api/v1/audits/json",
                       json={"document": doc, "filename": "cfg.json"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    # only the two string values produce records; scalars are skipped
    assert body["value_count"] == 2
    assert body["risk_level"] == "critical"  # unclosed RLO

    listing = client.get("/api/v1/audits").json()
    assert listing["total"] == 2
    names = sorted(i["filename"] for i in listing["items"])
    assert names == ["cfg.json#/clean", "cfg.json#/evil"]

    detail = client.get(f"/api/v1/audits/{body['items'][1]['id']}").json()
    assert detail["raw_text"] == RLO
    assert detail["meta"]["source"] == "json_document"
    assert detail["meta"]["pointer"] == "/evil"
    assert detail["meta"]["span"] == body["items"][1]["span"]


def test_root_string_value(client):
    resp = client.post("/api/v1/audits/json",
                       json={"document": '"\\u202Ebad.exe"'})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["value_count"] == 1
    item = body["items"][0]
    assert item["pointer"] == ""          # root pointer is the empty string
    assert item["risk_level"] == "critical"  # unclosed RLO
    assert item["span"] == {"start": 0, "end": 15}
    err = item["locations"]["errors"][0]
    assert err["logical_index"] == 0
    assert err["offset"] == 1             # backslash of the ‮ escape
    assert err["position"] == {"line": 1, "column": 2}


def test_non_string_documents_produce_no_records(client):
    for doc in ("42", "-3.5e+2", "true", "null",
                '{"a": 1, "b": [true, null], "c": {}}', "[]", "{}"):
        resp = client.post("/api/v1/audits/json", json={"document": doc})
        assert resp.status_code == 201, (doc, resp.text)
        body = resp.json()
        assert body["value_count"] == 0, doc
        assert body["risk_level"] == "info"
        assert body["items"] == []
    assert client.get("/api/v1/audits").json()["total"] == 0


# ------------------------------------------------------- escape handling ---

def test_surrogate_pair_decodes_to_single_character(client):
    # U+1F600 GRINNING FACE written as a UTF-16 surrogate pair, then RLO
    doc = '["\\uD83D\\uDE00\\u202E"]'
    resp = client.post("/api/v1/audits/json", json={"document": doc})
    assert resp.status_code == 201, resp.text
    item = resp.json()["items"][0]
    assert item["text_length"] == 2       # one astral char + RLO
    control = item["locations"]["controls"][0]
    assert control["logical_index"] == 1
    # the RLO escape starts right after the two 6-char surrogate escapes
    assert control["offset"] == 14
    assert control["position"] == {"line": 1, "column": 15}


def test_ordinary_escapes_are_not_misjudged(client):
    # \\u202E is a literal backslash followed by "u202E" -- not a control
    doc = '{"k": "\\\\u202E", "e": "line\\n\\t\\"q\\" \\/ \\b\\f\\r"}'
    resp = client.post("/api/v1/audits/json", json={"document": doc})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["value_count"] == 2
    assert body["risk_level"] == "info"
    assert all(i["control_count"] == 0 for i in body["items"])
    assert client.get("/api/v1/audits").json()["total"] == 2


def test_literal_control_chars_in_values_are_audited(client):
    # a raw (unescaped) RLO character inside the JSON string value
    doc = '{"k": "a' + RLO + 'b"}'
    resp = client.post("/api/v1/audits/json", json={"document": doc})
    assert resp.status_code == 201, resp.text
    item = resp.json()["items"][0]
    control = item["locations"]["controls"][0]
    assert control["logical_index"] == 1
    assert control["offset"] == 8         # the literal character itself
    assert control["position"] == {"line": 1, "column": 9}


def test_multiline_document_positions(client):
    doc = '{\n  "a": "x",\n  "b": "y\\u202E"\n}'
    resp = client.post("/api/v1/audits/json", json={"document": doc})
    assert resp.status_code == 201, resp.text
    items = resp.json()["items"]
    assert [i["pointer"] for i in items] == ["/a", "/b"]
    control = items[1]["locations"]["controls"][0]
    assert control["position"] == {"line": 3, "column": 10}
    assert control["offset"] == doc.index("\\u202E")
    # unclosed RLO: error and span end map into the document too
    err = items[1]["locations"]["errors"][0]
    assert err["position"] == {"line": 3, "column": 10}
    span = items[1]["locations"]["dangerous_spans"][0]
    # span end == len(value) maps to the closing quote (content end)
    assert span["offsets"]["end"] == doc.index('"', span["offsets"]["start"])
    assert span["position"]["end"] == {"line": 3, "column": 16}


# ------------------------------------------------------------------ 422 ---

@pytest.mark.parametrize("doc", [
    "",                       # empty
    "   \n ",                 # whitespace only
    "{",                      # truncated object
    "[",                      # truncated array
    '{"a":}',                 # missing value
    '{"a" 1}',                # missing colon
    '{"a": 1,}',              # trailing comma
    "[1,]",                   # trailing comma in array
    "{'a': 1}",               # single quotes
    "{a: 1}",                 # unquoted key
    '"unterminated',          # unterminated string
    '"bad \\x escape"',       # invalid escape
    '"\\u202"',               # truncated \u escape
    '"\\uZZZZ"',              # non-hex \u escape
    '"\\uD800"',              # unpaired high surrogate
    '"\\uD800\\u0041"',       # high surrogate + non-low escape
    '"\\uDC00"',              # unpaired low surrogate
    '"a\nb"',                 # raw control character in string
    "01",                     # leading zero
    "1.",                     # missing fraction digits
    "1e",                     # missing exponent digits
    "-",                      # lone minus
    "+1",                     # leading plus
    "NaN",                    # not JSON
    "tru",                    # truncated literal
    "1 2",                    # trailing data
    '{"a": 1} x',             # trailing garbage
])
def test_invalid_json_returns_422_and_writes_nothing(client, doc):
    resp = client.post("/api/v1/audits/json", json={"document": doc})
    assert resp.status_code == 422, (doc, resp.text)
    detail = resp.json()["detail"]
    assert detail["error"] == "invalid_json_document"
    assert isinstance(detail["offset"], int)
    assert detail["line"] >= 1 and detail["column"] >= 1
    assert detail["message"]
    assert client.get("/api/v1/audits").json()["total"] == 0


def test_nesting_depth_limit(client):
    doc = "[" * 300 + "]" * 300
    resp = client.post("/api/v1/audits/json", json={"document": doc})
    assert resp.status_code == 422
    assert "nesting depth" in resp.json()["detail"]["message"]


def test_duplicate_keys_return_422_and_write_nothing(client):
    resp = client.post("/api/v1/audits/json",
                       json={"document": '{"a": 1, "a": 2}'})
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "duplicate_key"
    assert detail["key"] == "a"
    assert detail["pointer"] == ""        # root object
    assert detail["offset"] == 9          # the second key's quote
    assert client.get("/api/v1/audits").json()["total"] == 0


def test_duplicate_keys_decoded_and_nested(client):
    # "a" decodes to "a": duplicates are compared after decoding
    resp = client.post(
        "/api/v1/audits/json",
        json={"document": '{"ok": "v", "o": {"a": 1, "\\u0061": 2}}'},
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "duplicate_key"
    assert detail["key"] == "a"
    assert detail["pointer"] == "/o"
    # the earlier clean value must not have been persisted either
    assert client.get("/api/v1/audits").json()["total"] == 0


def test_missing_document_field_is_422(client):
    resp = client.post("/api/v1/audits/json", json={"filename": "x.json"})
    assert resp.status_code == 422


# ------------------------------------------------------------- storage ----

def test_records_verify_and_sarif_still_work(client):
    doc = '{"k": "x' + RLO + 'y' + PDF + '"}'
    resp = client.post("/api/v1/audits/json", json={"document": doc})
    assert resp.status_code == 201, resp.text
    audit_id = resp.json()["items"][0]["id"]

    verify = client.get(f"/api/v1/audits/{audit_id}/verify").json()
    assert verify["consistent"] is True
    assert verify["diffs"] == []

    sarif = client.get(f"/api/v1/audits/{audit_id}/sarif")
    assert sarif.status_code == 200
    assert sarif.headers["content-type"].startswith("application/sarif+json")


def test_filename_defaults_to_pointer_fragment(client):
    resp = client.post("/api/v1/audits/json",
                       json={"document": '{"a": ["x"]}'})
    assert resp.status_code == 201, resp.text
    listing = client.get("/api/v1/audits").json()
    assert listing["items"][0]["filename"] == "#/a/0"
