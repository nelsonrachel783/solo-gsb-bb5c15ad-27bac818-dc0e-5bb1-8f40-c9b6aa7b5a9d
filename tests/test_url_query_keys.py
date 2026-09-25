"""Tests for the URL query-key ambiguity audit (POST /api/v1/urls/query-keys).

Covers: query extraction (first '?', '#' fragment terminator, '?' inside
a fragment), splitting on the undecoded '&' and first '=' (values may
contain '=', zero-length segments skipped, empty keys kept), one-pass
percent/UTF-8 decoding with '+' as a space, NFKC collision grouping
(exact duplicates, percent-encoded twins, plus/space, full-width and
mathematical letters, precomposed vs decomposed accents), original-URL
key offsets, parameter values never being decoded or compared, 422 with
the original URL offset on invalid percent-encoding or UTF-8 (and never
a partial report), and the read-only endpoint writing no records.

Non-ASCII characters are written as \\uXXXX escapes so the file's exact
codepoint composition is independent of editor normalisation.
"""

import pytest

from app.url_audit import QueryKeyDecodeError, audit_url_query_keys

FW_X = "\uFF38"        # U+FF38 FULLWIDTH LATIN CAPITAL LETTER X
MATH_X = "\U0001D417"  # U+1D417 MATHEMATICAL BOLD CAPITAL X
E_ACUTE = "\u00E9"     # U+00E9 LATIN SMALL LETTER E WITH ACUTE
E_ACUTE_DECOMPOSED = "e\u0301"  # 'e' + U+0301 COMBINING ACUTE ACCENT
CJK_ZHONG = "\u4E2D"   # U+4E2D


# ---------------------------------------------------- unit: query span --

def test_no_query_string_yields_empty_report():
    report = audit_url_query_keys("https://example.com/path")
    assert report.query_start is None
    assert report.query_end is None
    assert report.parameter_count == 0
    assert report.distinct_key_count == 0
    assert report.parameters == []
    assert report.collisions == []


def test_empty_query_string_has_span_but_no_parameters():
    report = audit_url_query_keys("https://x/?")
    assert (report.query_start, report.query_end) == (11, 11)
    assert report.parameter_count == 0


def test_fragment_terminates_the_query():
    report = audit_url_query_keys("http://x/?a=1&a=2#frag")
    assert (report.query_start, report.query_end) == (10, 17)
    assert report.parameter_count == 2
    (collision,) = report.collisions
    assert [o.key_start for o in collision.occurrences] == [10, 14]


def test_question_mark_inside_fragment_starts_no_query():
    report = audit_url_query_keys("http://x/#f?a=1&a=2")
    assert report.query_start is None
    assert report.parameter_count == 0


def test_query_after_fragment_marker_is_not_split():
    report = audit_url_query_keys("?a=1#b=2&b=3")
    assert (report.query_start, report.query_end) == (1, 4)
    assert report.parameter_count == 1
    assert report.parameters[0].raw_key == "a"


def test_only_the_first_question_mark_opens_the_query():
    report = audit_url_query_keys("??a&a")
    assert (report.query_start, report.query_end) == (1, 5)
    assert [p.raw_key for p in report.parameters] == ["?a", "a"]
    assert report.collisions == []


# ----------------------------------------------- unit: parameter split --

def test_basic_split_and_key_offsets():
    url = "https://example.com/p?a=1&bb=2"
    report = audit_url_query_keys(url)
    assert (report.query_start, report.query_end) == (22, 30)
    assert report.parameter_count == 2
    assert report.distinct_key_count == 2
    assert [(p.key_start, p.key_end) for p in report.parameters] == [
        (22, 23), (26, 28),
    ]
    assert all(
        url[p.key_start:p.key_end] == p.raw_key for p in report.parameters
    )
    assert report.collisions == []


def test_value_may_contain_equals_sign():
    report = audit_url_query_keys("?a=b=c&a=d")
    assert [(p.key_start, p.key_end) for p in report.parameters] == [
        (1, 2), (7, 8),
    ]
    (collision,) = report.collisions
    assert collision.normalised == "a"
    assert [o.index for o in collision.occurrences] == [0, 1]


def test_key_without_value_participates():
    report = audit_url_query_keys("?flag&flag=1")
    assert [(p.key_start, p.key_end) for p in report.parameters] == [
        (1, 5), (6, 10),
    ]
    (collision,) = report.collisions
    assert collision.normalised == "flag"


def test_zero_length_segments_are_skipped():
    report = audit_url_query_keys("?&a=1&&b=2&")
    assert report.parameter_count == 2
    assert [p.raw_key for p in report.parameters] == ["a", "b"]
    assert [(p.key_start, p.key_end) for p in report.parameters] == [
        (2, 3), (7, 8),
    ]
    assert audit_url_query_keys("?&&").parameter_count == 0


def test_skipped_segments_do_not_consume_parameter_indices():
    report = audit_url_query_keys("?&a=1&&a=2")
    (collision,) = report.collisions
    assert [o.index for o in collision.occurrences] == [0, 1]
    assert [(o.key_start, o.key_end) for o in collision.occurrences] == [
        (2, 3), (7, 8),
    ]


def test_empty_keys_are_kept_and_collide():
    report = audit_url_query_keys("?=1&=2")
    assert report.parameter_count == 2
    assert [(p.key_start, p.key_end) for p in report.parameters] == [
        (1, 1), (4, 4),
    ]
    (collision,) = report.collisions
    assert collision.normalised == ""
    assert [o.raw_key for o in collision.occurrences] == ["", ""]


def test_encoded_separators_do_not_split():
    # %26 is '&' and %3D is '=' only *after* decoding: the split happens
    # on the undecoded characters, so each segment is one parameter
    report = audit_url_query_keys("?a%26b%3Dc=1&a%26b%3Dc=2")
    assert report.parameter_count == 2
    (collision,) = report.collisions
    assert collision.normalised == "a&b=c"
    assert [o.decoded_key for o in collision.occurrences] == ["a&b=c"] * 2


# ------------------------------------------------------ unit: decoding --

def test_plus_decodes_to_space_and_collides_with_percent_20():
    report = audit_url_query_keys("?a+b=1&a%20b=2")
    (collision,) = report.collisions
    assert collision.normalised == "a b"
    assert [(o.raw_key, o.decoded_key) for o in collision.occurrences] == [
        ("a+b", "a b"), ("a%20b", "a b"),
    ]
    assert [(o.key_start, o.key_end) for o in collision.occurrences] == [
        (1, 4), (7, 12),
    ]


def test_percent_2b_is_a_literal_plus_not_a_space():
    report = audit_url_query_keys("?a%2Bb=1&a+b=2")
    assert [p.decoded_key for p in report.parameters] == ["a+b", "a b"]
    assert report.collisions == []


def test_decoding_is_a_single_pass():
    # %2520 decodes to the literal text '%20', not to a space
    report = audit_url_query_keys("?a%2520b=1&a%20b=2")
    assert [p.decoded_key for p in report.parameters] == ["a%20b", "a b"]
    assert report.distinct_key_count == 2
    assert report.collisions == []


def test_literal_non_ascii_key_passes_through():
    url = "?%E4%B8%AD=1&\u4e2d=2"
    report = audit_url_query_keys(url)
    assert [p.decoded_key for p in report.parameters] == [
        CJK_ZHONG, CJK_ZHONG,
    ]
    (collision,) = report.collisions
    assert collision.normalised == CJK_ZHONG
    assert [(o.key_start, o.key_end) for o in collision.occurrences] == [
        (1, 10), (13, 14),
    ]


# --------------------------------------------------- unit: collisions --

def test_exact_duplicate_keys_collide():
    report = audit_url_query_keys("http://x/?a=1&a=2")
    (collision,) = report.collisions
    assert collision.normalised == "a"
    assert collision.occurrences[0].to_dict() == {
        "index": 0, "raw": "a", "decoded": "a", "start": 10, "end": 11,
    }
    assert collision.occurrences[1].to_dict() == {
        "index": 1, "raw": "a", "decoded": "a", "start": 14, "end": 15,
    }


def test_percent_encoded_twin_collides():
    report = audit_url_query_keys("?%61=1&a=2")
    (collision,) = report.collisions
    assert collision.normalised == "a"
    assert [(o.raw_key, o.decoded_key) for o in collision.occurrences] == [
        ("%61", "a"), ("a", "a"),
    ]
    assert [(o.key_start, o.key_end) for o in collision.occurrences] == [
        (1, 4), (7, 8),
    ]


def test_fullwidth_letter_collides_with_ascii():
    report = audit_url_query_keys("?%EF%BC%B8=1&X=2")
    (collision,) = report.collisions
    assert collision.normalised == "X"
    assert [(o.raw_key, o.decoded_key) for o in collision.occurrences] == [
        ("%EF%BC%B8", FW_X), ("X", "X"),
    ]
    assert [(o.key_start, o.key_end) for o in collision.occurrences] == [
        (1, 10), (13, 14),
    ]


def test_mathematical_letter_collides_with_ascii():
    report = audit_url_query_keys("?%F0%9D%90%97=1&X=2")
    (collision,) = report.collisions
    assert collision.normalised == "X"
    assert collision.occurrences[0].decoded_key == MATH_X
    assert [(o.key_start, o.key_end) for o in collision.occurrences] == [
        (1, 13), (16, 17),
    ]


def test_precomposed_and_decomposed_accents_collide():
    report = audit_url_query_keys("?%C3%A9=1&e%CC%81=2")
    (collision,) = report.collisions
    assert collision.normalised == E_ACUTE
    assert [(o.raw_key, o.decoded_key) for o in collision.occurrences] == [
        ("%C3%A9", E_ACUTE), ("e%CC%81", E_ACUTE_DECOMPOSED),
    ]


def test_case_difference_is_not_a_collision():
    report = audit_url_query_keys("?A=1&a=2&%41=3")
    assert [p.decoded_key for p in report.parameters] == ["A", "a", "A"]
    assert report.distinct_key_count == 2
    (collision,) = report.collisions
    # only the two 'A' spellings collide (exact duplicate + %41 twin)
    assert collision.normalised == "A"
    assert [o.index for o in collision.occurrences] == [0, 2]


def test_collision_groups_follow_first_occurrence_order():
    report = audit_url_query_keys("?b=1&a=2&b=3&a=4")
    assert [c.normalised for c in report.collisions] == ["b", "a"]
    assert [o.index for o in report.collisions[0].occurrences] == [0, 2]
    assert [o.index for o in report.collisions[1].occurrences] == [1, 3]


def test_three_or_more_occurrences_form_one_group():
    report = audit_url_query_keys("?a=1&a=2&a=3")
    (collision,) = report.collisions
    assert collision.to_dict()["occurrence_count"] == 3
    assert [o.index for o in collision.occurrences] == [0, 1, 2]


def test_offsets_are_codepoint_offsets_after_non_ascii_prefix():
    url = "https://x/\u00e9?a=1&a=2"
    report = audit_url_query_keys(url)
    (collision,) = report.collisions
    assert [(o.key_start, o.key_end) for o in collision.occurrences] == [
        (12, 13), (16, 17),
    ]
    assert url[12:13] == "a" and url[16:17] == "a"


# ----------------------------------------- unit: values never touched --

def test_invalid_percent_encoding_in_values_is_ignored():
    report = audit_url_query_keys("?a=%zz&b=%&c=%FF")
    assert report.parameter_count == 3
    assert report.collisions == []


def test_identical_values_do_not_collide():
    report = audit_url_query_keys("?x=%FF&y=%FF")
    assert report.parameter_count == 2
    assert report.distinct_key_count == 2
    assert report.collisions == []


# ------------------------------------------------------- unit: 422 cases --

@pytest.mark.parametrize(
    "url,offset,index",
    [
        ("?%=1", 1, 0),          # '%' not followed by hex digits
        ("?%2=1", 1, 0),         # truncated triplet at the '=' boundary
        ("?%", 1, 0),            # '%' at the very end of the URL
        ("?ab%zz=1", 3, 0),      # non-hex digits
        ("?a=1&b%", 6, 1),       # error in a later parameter
        ("?ok=1&%=2", 6, 1),
    ],
)
def test_invalid_percent_encoding_raises_with_url_offset(url, offset, index):
    with pytest.raises(QueryKeyDecodeError) as exc:
        audit_url_query_keys(url)
    assert exc.value.error == "invalid_percent_encoding"
    assert exc.value.offset == offset
    assert exc.value.parameter_index == index


@pytest.mark.parametrize(
    "url,offset",
    [
        ("?%ff=1", 1),        # 0xFF is never valid UTF-8
        ("?%c3=1", 1),        # truncated two-byte sequence
        ("?%80=1", 1),        # lone continuation byte
        ("?%e0%80=1", 1),     # invalid continuation: anchored at the seq start
        ("?a%ff=1", 2),       # offset tracks the '%' inside the key
        ("?x=1&%ff=2", 5),    # error in a later parameter
    ],
)
def test_invalid_utf8_raises_with_url_offset(url, offset):
    with pytest.raises(QueryKeyDecodeError) as exc:
        audit_url_query_keys(url)
    assert exc.value.error == "invalid_utf8"
    assert exc.value.offset == offset


def test_first_invalid_key_wins():
    with pytest.raises(QueryKeyDecodeError) as exc:
        audit_url_query_keys("?%zz=1&%=2")
    assert exc.value.offset == 1


# --------------------------------------------------------------- API: POST -

def test_post_collision_report_shape(client):
    url = (
        "https://example.com/p?a=1&%61=2&a+b=3&a%20b=4"
        "&%EF%BC%B8=5&X=6#frag"
    )
    resp = client.post("/api/v1/urls/query-keys", json={"url": url})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["stored"] is False
    assert body["url_length"] == len(url)
    assert body["query"] == {"start": 22, "end": 61}
    assert body["parameter_count"] == 6
    assert body["distinct_key_count"] == 3
    assert body["collision_count"] == 3
    assert [c["normalised"] for c in body["collisions"]] == [
        "a", "a b", "X",
    ]
    first = body["collisions"][0]
    assert first["occurrence_count"] == 2
    assert first["occurrences"] == [
        {"index": 0, "raw": "a", "decoded": "a", "start": 22, "end": 23},
        {"index": 1, "raw": "%61", "decoded": "a", "start": 26, "end": 29},
    ]
    second = body["collisions"][1]
    assert [(o["raw"], o["decoded"]) for o in second["occurrences"]] == [
        ("a+b", "a b"), ("a%20b", "a b"),
    ]
    third = body["collisions"][2]
    assert [(o["raw"], o["decoded"]) for o in third["occurrences"]] == [
        ("%EF%BC%B8", FW_X), ("X", "X"),
    ]


def test_post_clean_url_has_no_collisions(client):
    resp = client.post(
        "/api/v1/urls/query-keys",
        json={"url": "https://example.com/p?a=1&b=2"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["parameter_count"] == 2
    assert body["distinct_key_count"] == 2
    assert body["collision_count"] == 0
    assert body["collisions"] == []


def test_post_url_without_query(client):
    resp = client.post(
        "/api/v1/urls/query-keys", json={"url": "https://example.com/"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] is None
    assert body["parameter_count"] == 0
    assert body["collisions"] == []


def test_post_values_are_never_decoded(client):
    resp = client.post(
        "/api/v1/urls/query-keys", json={"url": "?a=%zz&b=%"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["parameter_count"] == 2
    assert body["collision_count"] == 0


def test_post_invalid_percent_encoding_422(client):
    resp = client.post("/api/v1/urls/query-keys", json={"url": "?ab%zz=1"})
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "invalid_percent_encoding"
    assert detail["offset"] == 3
    assert detail["line"] == 1
    assert detail["column"] == 4
    assert detail["parameter_index"] == 0
    assert "message" in detail


def test_post_invalid_utf8_422(client):
    resp = client.post("/api/v1/urls/query-keys", json={"url": "?x=1&%ff=2"})
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "invalid_utf8"
    assert detail["offset"] == 5
    assert detail["parameter_index"] == 1


def test_post_422_reports_line_and_column_in_the_url(client):
    resp = client.post(
        "/api/v1/urls/query-keys", json={"url": "http://x/\n?%zz=1"}
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["offset"] == 11
    assert (detail["line"], detail["column"]) == (2, 2)


def test_post_422_never_returns_a_partial_report(client):
    # the first two keys collide, but the third key fails to decode:
    # the response carries only the error detail
    resp = client.post(
        "/api/v1/urls/query-keys", json={"url": "?a=1&a=2&%zz=3"}
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["detail"]["error"] == "invalid_percent_encoding"
    assert body["detail"]["offset"] == 9
    assert "collisions" not in body
    assert "collision_count" not in body


def test_post_missing_url_field_422(client):
    resp = client.post("/api/v1/urls/query-keys", json={})
    assert resp.status_code == 422


def test_post_writes_no_records(client):
    resp = client.post(
        "/api/v1/urls/query-keys", json={"url": "?a=1&a=2"}
    )
    assert resp.status_code == 200
    # no audit record and no identifier report: the endpoint is read-only
    assert client.get("/api/v1/audits").json()["total"] == 0
    created = client.post(
        "/api/v1/identifiers/normalization", json={"source": "y = 1\n"}
    ).json()
    assert created["id"] == 1


def test_root_lists_url_query_keys_endpoint(client):
    body = client.get("/").json()
    assert "POST /api/v1/urls/query-keys" in body["endpoints"]
