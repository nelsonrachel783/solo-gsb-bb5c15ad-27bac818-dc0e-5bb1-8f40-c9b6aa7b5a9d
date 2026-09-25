"""FastAPI application: Unicode bidirectional text security audit API."""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from .bidi import RiskLevel, parse_bidi
from .compare import compare_audits
from .csv_audit import CsvParseError, audit_csv_document
from .database import (
    count_audits,
    get_audit,
    get_identifier_report,
    init_db,
    insert_audit,
    insert_identifier_report,
    query_audits,
)
from .diff_audit import DiffParseError, audit_diff, highest_risk
from .gate import GateRule, evaluate_record
from .identifiers import (
    CollisionGroupNotFoundError,
    IdentifierLexError,
    preview_collision_fix,
    scan_identifiers,
    scan_mixed_scripts,
)
from .json_audit import (
    DuplicateKeyError,
    JsonParseError,
    audit_json_document,
    line_col,
)
from .sarif import build_sarif
from .schemas import (
    AuditRequest,
    CompareRequest,
    CsvAuditRequest,
    DiffAuditRequest,
    GateRequest,
    IdentifierCollisionFixRequest,
    IdentifierNormalizationRequest,
    JsonAuditRequest,
    MixedScriptRequest,
    UrlQueryKeysRequest,
)
from .url_audit import QueryKeyDecodeError, audit_url_query_keys
from .verify import verify_audit_record

app = FastAPI(
    title="Unicode Bidi Text Security Audit API",
    description=(
        "Audits text for Unicode bidirectional control characters "
        "(U+202A..U+2069, marks, invisible operators). Reports codepoints, "
        "logical indices, pairing/nesting scope, unclosed-character errors "
        "and produces escaped previews of dangerous spans without modifying "
        "the original text."
    ),
    version="1.0.0",
)


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "bidi-audit"}


@app.post("/api/v1/audits", status_code=201)
def create_audit(payload: AuditRequest) -> dict:
    """Parse and audit one text payload, persist the record."""
    result = parse_bidi(payload.text).to_dict()
    audit_id = insert_audit(
        filename=payload.filename, text=payload.text, result=result
    )
    return {"id": audit_id, "risk_level": result["risk_level"],
            "stored": True, "result": result}


@app.post("/api/v1/audits/compare")
def compare_records(payload: CompareRequest) -> dict:
    """Compare two stored audit records as a before/after regression."""
    if payload.before_id == payload.after_id:
        raise HTTPException(
            status_code=422,
            detail="before_id and after_id must reference different records",
        )
    before = get_audit(payload.before_id)
    if before is None:
        raise HTTPException(status_code=404, detail="before audit record not found")
    after = get_audit(payload.after_id)
    if after is None:
        raise HTTPException(status_code=404, detail="after audit record not found")
    return compare_audits(before, after)


@app.post("/api/v1/audits/gate")
def gate_records(payload: GateRequest) -> dict:
    """Apply a path-based risk gate to a batch of stored audit records.

    Read-only: no record is created or modified.  Each record is matched
    against the ordered path rules on its stored file name; records without
    a file name or whose file name matches nothing use the default maximum
    risk.  A record passes when its actual risk does not exceed the
    applicable threshold.  If any referenced ID does not exist the whole
    request fails with 404.
    """
    rules = [
        GateRule.make(index=i, template=spec.template,
                      max_risk=spec.max_risk.value)
        for i, spec in enumerate(payload.rules)
    ]

    # Resolve every record before evaluating anything so the endpoint never
    # returns a partial report when an ID is missing.
    records = []
    for audit_id in payload.ids:
        record = get_audit(audit_id)
        if record is None:
            raise HTTPException(
                status_code=404,
                detail=f"audit record {audit_id} not found",
            )
        records.append(record)

    results = [
        evaluate_record(
            record,
            default_max_risk=payload.default_max_risk.value,
            rules=rules,
        )
        for record in records
    ]

    return {
        "passed": all(item["passed"] for item in results),
        "default_max_risk": payload.default_max_risk.value,
        "checked_count": len(results),
        "passed_count": sum(1 for item in results if item["passed"]),
        "failed_count": sum(1 for item in results if not item["passed"]),
        "risk_level": highest_risk(
            [item["actual_risk"] for item in results]
        ),
        "results": results,
    }


@app.post("/api/v1/audits/diff", status_code=201)
def create_diff_audit(payload: DiffAuditRequest) -> dict:
    """Audit only the added lines of a unified diff.

    Parses multi-file / multi-hunk unified diff text and, for every file
    containing added lines, rebuilds that file's added content in new-file
    order, runs the bidi parser on it and maps each finding back to the
    new-file path/line/column and to the diff line it came from.  One
    record is persisted per file.  A structurally invalid diff (or a hunk
    whose body does not match its header counts) yields 422 with the first
    offending diff line and writes nothing.
    """
    try:
        audits = audit_diff(payload.diff)
    except DiffParseError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_unified_diff",
                "line": exc.line_no,
                "message": exc.message,
            },
        )

    # Only persist after the entire diff has parsed and audited cleanly,
    # so a malformed input never writes partial records.
    items = []
    for audit in audits:
        audit_id = insert_audit(
            filename=audit.new_path,
            text=audit.text,
            result=audit.result,
            meta=audit.meta,
        )
        items.append({
            "id": audit_id,
            "stored": True,
            "path": audit.new_path,
            "old_path": audit.old_path,
            "text_length": audit.result["length"],
            "risk_level": audit.result["risk_level"],
            "max_depth": audit.result["max_depth"],
            "error_count": audit.result["error_count"],
            "control_count": audit.result["stats"]["total_control_chars"],
            "dangerous_span_count": audit.result["stats"]["dangerous_span_count"],
            "added_line_count": len(audit.entries),
            "added_lines": audit.meta["added_lines"],
            "result": audit.result,
            "locations": audit.locations,
        })

    return {
        "stored": True,
        "file_count": len(items),
        "risk_level": highest_risk([item["risk_level"] for item in items]),
        "items": items,
    }


@app.post("/api/v1/audits/json", status_code=201)
def create_json_audit(payload: JsonAuditRequest) -> dict:
    """Audit every string value of a raw JSON document.

    Parses the document strictly (RFC 8259), recursively walks objects
    and arrays and runs the bidi parser on every string *value* (object
    keys are never audited).  Each finding carries the value's RFC 6901
    JSON Pointer, the string token's start/end offsets in the original
    document, and every control character's decoded position mapped back
    to the original document's line/column (``\\u`` escapes and UTF-16
    surrogate pairs included).  One record is persisted per string
    value.  Invalid JSON or a duplicate object key yields 422 and writes
    nothing.
    """
    try:
        audits = audit_json_document(payload.document)
    except DuplicateKeyError as exc:
        line, column = line_col(payload.document, exc.offset)
        raise HTTPException(
            status_code=422,
            detail={
                "error": "duplicate_key",
                "key": exc.key,
                "pointer": exc.pointer,
                "offset": exc.offset,
                "line": line,
                "column": column,
                "message": exc.message,
            },
        )
    except JsonParseError as exc:
        line, column = line_col(payload.document, exc.offset)
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_json_document",
                "offset": exc.offset,
                "line": line,
                "column": column,
                "message": exc.message,
            },
        )

    # Only persist after the entire document has parsed and audited
    # cleanly, so a malformed input never writes partial records.
    items = []
    for audit in audits:
        filename = (
            f"{payload.filename}#{audit.pointer}"
            if payload.filename is not None
            else f"#{audit.pointer}"
        )
        audit_id = insert_audit(
            filename=filename,
            text=audit.text,
            result=audit.result,
            meta=audit.meta,
        )
        items.append({
            "id": audit_id,
            "stored": True,
            "pointer": audit.pointer,
            "span": audit.span,
            "text_length": audit.result["length"],
            "risk_level": audit.result["risk_level"],
            "max_depth": audit.result["max_depth"],
            "error_count": audit.result["error_count"],
            "control_count": audit.result["stats"]["total_control_chars"],
            "dangerous_span_count":
                audit.result["stats"]["dangerous_span_count"],
            "result": audit.result,
            "locations": audit.locations,
        })

    return {
        "stored": True,
        "value_count": len(items),
        "risk_level": highest_risk([item["risk_level"] for item in items]),
        "items": items,
    }


@app.post("/api/v1/audits/csv")
def audit_csv_formula_cells(payload: CsvAuditRequest) -> dict:
    """Flag CSV cells disguised as spreadsheet formulas.

    Parses the raw CSV text (comma-separated fields, double-quoted
    enclosures with ``""`` escapes, CRLF/LF record breaks) and checks
    every cell: after skipping a prefix of spaces, tabs and Unicode
    bidi control characters, a first character of ``=``, ``+``, ``-``
    or ``@`` is reported with its 1-based record/field numbers, the
    formula character's offset and line/column in the original
    document, the skipped prefix characters and the cell's bidi risk
    level from the existing parser.  Read-only: nothing is persisted.
    Unclosed or illegal quotes yield 422 with the original line/column.
    """
    try:
        report = audit_csv_document(payload.document)
    except CsvParseError as exc:
        line, column = line_col(payload.document, exc.offset)
        raise HTTPException(
            status_code=422,
            detail={
                "error": exc.error,
                "offset": exc.offset,
                "line": line,
                "column": column,
                "message": exc.message,
            },
        )
    findings = [finding.to_dict() for finding in report.findings]
    return {
        "stored": False,
        "filename": payload.filename,
        "document_length": len(payload.document),
        "record_count": report.record_count,
        "field_count": report.field_count,
        "finding_count": len(findings),
        "risk_level": highest_risk([f["risk_level"] for f in findings]),
        "findings": findings,
    }


@app.post("/api/v1/urls/query-keys")
def audit_url_query_key_collisions(payload: UrlQueryKeysRequest) -> dict:
    """Report query keys that collide after decoding and NFKC.

    The raw URL's query component (from the first ``?`` to the first
    ``#`` or the end) is split on the undecoded ``&`` and ``=``
    characters, keeping every key's start/end codepoint offsets in the
    original URL.  Each key is decoded once (percent triplets as UTF-8,
    ``+`` as a space) and NFKC normalised; two or more keys collapsing
    to the same normalised form are returned as a collision group with
    their raw keys, decoded keys, parameter indices and offsets.
    Parameter values are never decoded or compared.  Read-only: nothing
    is persisted.  An invalid percent triplet or invalid UTF-8 in a key
    yields 422 with the original-URL offset and no partial report.
    """
    try:
        report = audit_url_query_keys(payload.url)
    except QueryKeyDecodeError as exc:
        line, column = line_col(payload.url, exc.offset)
        raise HTTPException(
            status_code=422,
            detail={
                "error": exc.error,
                "offset": exc.offset,
                "line": line,
                "column": column,
                "parameter_index": exc.parameter_index,
                "message": exc.message,
            },
        )
    query = (
        {"start": report.query_start, "end": report.query_end}
        if report.query_start is not None
        else None
    )
    collisions = [collision.to_dict() for collision in report.collisions]
    return {
        "stored": False,
        "url_length": len(payload.url),
        "query": query,
        "parameter_count": report.parameter_count,
        "distinct_key_count": report.distinct_key_count,
        "collision_count": len(collisions),
        "collisions": collisions,
    }


@app.post("/api/v1/identifiers/normalization", status_code=201)
def create_identifier_normalization(payload: IdentifierNormalizationRequest) -> dict:
    """Extract Python identifiers and report NFKC normalisation collisions.

    The source is lexed per Python's lexical rules: comments, strings and
    hard keywords never count as identifiers.  Every surviving identifier
    is Unicode NFKC normalised, and a collision is reported only when the
    same normalised form has at least two distinct raw spellings (mere
    repetition or case differences are not collisions).  Occurrences are
    returned in source order with their codepoint offsets.  The whole
    report is persisted as an independent record.  A lexical failure
    yields 422 with the original-source position and writes nothing.
    """
    try:
        report = scan_identifiers(payload.source).to_dict()
    except IdentifierLexError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error": exc.error,
                "offset": exc.offset,
                "line": exc.line,
                "column": exc.column,
                "message": exc.message,
            },
        )

    report_id = insert_identifier_report(
        filename=payload.filename, source=payload.source, report=report
    )
    return {
        "id": report_id,
        "stored": True,
        "filename": payload.filename,
        "source_length": len(payload.source),
        "report": report,
    }


@app.get("/api/v1/identifiers/normalization/{report_id}")
def read_identifier_normalization(report_id: int) -> dict:
    """Read one stored identifier normalisation collision report."""
    record = get_identifier_report(report_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail="identifier normalization report not found",
        )
    return record


@app.post("/api/v1/identifiers/mixed-script")
def report_mixed_script_identifiers(payload: MixedScriptRequest) -> dict:
    """Detect identifiers mixing Latin, Greek and Cyrillic letters.

    The source is lexed with the same scanner as the normalization report:
    comments, strings and hard keywords never count as identifiers.  Inside
    each surviving identifier only characters whose Unicode name starts
    with LATIN, GREEK or CYRILLIC carry a script; combining marks, digits
    and underscores are script-neutral.  Every identifier whose letters
    span two or more scripts is reported once per occurrence, in source
    order, with its raw spelling, the scripts involved and each
    script-carrying character's codepoint offset and line/column.  The
    endpoint is analysis-only: nothing is persisted.  A lexical failure
    yields 422 with the original-source position.
    """
    try:
        report = scan_mixed_scripts(payload.source).to_dict()
    except IdentifierLexError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error": exc.error,
                "offset": exc.offset,
                "line": exc.line,
                "column": exc.column,
                "message": exc.message,
            },
        )
    return {
        "stored": False,
        "filename": payload.filename,
        "source_length": len(payload.source),
        "report": report,
    }


@app.post("/api/v1/identifiers/normalization/fix-preview")
def preview_identifier_collision_fix(
    payload: IdentifierCollisionFixRequest,
) -> dict:
    """Preview fixing one NFKC collision group without storing anything.

    The source is lexed with the same scanner as the normalization report
    and the requested group is located by its NFKC normalised name.  Only
    the group's non-canonical identifier spellings are rewritten to the
    normalised spelling; string literals, comments and every other
    character are preserved verbatim, as are the BOM and line endings.
    The response lists every edit (original-source codepoint span, raw
    spelling, replacement), carries the fixed source and reports the
    collisions found by rescanning it.  A lexical failure, or a name that
    does not identify a collision group, yields 422 and writes no record.
    """
    try:
        preview = preview_collision_fix(
            payload.source, payload.normalised_name
        )
    except IdentifierLexError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error": exc.error,
                "offset": exc.offset,
                "line": exc.line,
                "column": exc.column,
                "message": exc.message,
            },
        )
    except CollisionGroupNotFoundError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "collision_group_not_found",
                "normalised": exc.normalised,
                "message": (
                    "no NFKC collision group with normalised name "
                    f"{exc.normalised!r}; a fixable group requires at "
                    "least two distinct raw identifier spellings"
                ),
            },
        )

    body = preview.to_dict()
    return {
        "stored": False,
        "source_length": len(payload.source),
        "fixed_source_length": len(preview.fixed_source),
        **body,
    }


@app.get("/api/v1/audits")
def list_audits(
    risk_level: Optional[RiskLevel] = Query(
        default=None, description="Filter by risk level "
        "(info|low|medium|high|critical)"
    ),
    filename: Optional[str] = Query(
        default=None, description="Case-insensitive substring match on filename"
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    rl = risk_level.value if risk_level is not None else None
    items = query_audits(risk_level=rl, filename=filename,
                         limit=limit, offset=offset)
    total = count_audits(risk_level=rl, filename=filename)
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@app.get("/api/v1/audits/{audit_id}")
def read_audit(audit_id: int) -> dict:
    record = get_audit(audit_id)
    if record is None:
        raise HTTPException(status_code=404, detail="audit record not found")
    return record


@app.get(
    "/api/v1/audits/{audit_id}/verify",
    responses={404: {"description": "audit record not found"}},
)
def verify_audit(audit_id: int) -> dict:
    """Re-run the parser on the stored text and diff against the stored
    result. Read-only: the record is never repaired or rewritten."""
    record = get_audit(audit_id)
    if record is None:
        raise HTTPException(status_code=404, detail="audit record not found")
    return verify_audit_record(record)


@app.get(
    "/api/v1/audits/{audit_id}/sarif",
    response_class=JSONResponse,
    responses={
        200: {
            "content": {"application/sarif+json": {}},
            "description": "SARIF 2.1.0 document for the stored audit",
        },
        404: {"description": "audit record not found"},
    },
)
def export_audit_sarif(audit_id: int) -> JSONResponse:
    """Export one stored audit as a SARIF 2.1.0 document."""
    record = get_audit(audit_id)
    if record is None:
        raise HTTPException(status_code=404, detail="audit record not found")
    sarif = build_sarif(record)
    return JSONResponse(
        sarif, media_type="application/sarif+json; charset=utf-8"
    )


@app.get("/")
def root() -> dict:
    return {
        "service": "bidi-audit",
        "docs": "/docs",
        "endpoints": [
            "POST /api/v1/audits",
            "POST /api/v1/audits/diff",
            "POST /api/v1/audits/json",
            "POST /api/v1/audits/csv",
            "POST /api/v1/audits/compare",
            "POST /api/v1/audits/gate",
            "POST /api/v1/identifiers/normalization",
            "POST /api/v1/identifiers/normalization/fix-preview",
            "POST /api/v1/identifiers/mixed-script",
            "POST /api/v1/urls/query-keys",
            "GET  /api/v1/audits",
            "GET  /api/v1/audits/{id}",
            "GET  /api/v1/audits/{id}/verify",
            "GET  /api/v1/audits/{id}/sarif",
            "GET  /api/v1/identifiers/normalization/{id}",
            "GET  /health",
        ],
    }
