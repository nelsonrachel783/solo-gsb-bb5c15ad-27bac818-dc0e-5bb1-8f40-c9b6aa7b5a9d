"""Pydantic schemas for the audit API."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field

from .bidi import RiskLevel


class AuditRequest(BaseModel):
    text: str = Field(..., description="Text to audit. Sent verbatim; never rewritten.")
    filename: Optional[str] = Field(
        default=None,
        max_length=4096,
        description="Optional source file name for later lookup.",
    )


class AuditCreated(BaseModel):
    id: int
    risk_level: RiskLevel
    stored: bool = True
    result: dict


class CompareRequest(BaseModel):
    before_id: int = Field(
        ..., ge=1, description="ID of the earlier audit record (baseline)."
    )
    after_id: int = Field(
        ..., ge=1, description="ID of the later audit record (regression)."
    )


class DiffAuditRequest(BaseModel):
    diff: str = Field(
        ...,
        description=(
            "Unified diff text (multi-file, multi-hunk). Only added lines "
            "(those starting with '+') are audited; headers, removed and "
            "context lines are ignored."
        ),
    )


class JsonAuditRequest(BaseModel):
    document: str = Field(
        ...,
        description=(
            "Raw JSON document text. Parsed strictly (RFC 8259): duplicate "
            "object keys and malformed input are rejected with 422. Every "
            "string value (object values and array elements, never object "
            "keys) is audited for bidi controls."
        ),
    )
    filename: Optional[str] = Field(
        default=None,
        max_length=4096,
        description=(
            "Optional document name. Stored records are named "
            "'<filename>#<json-pointer>' ('#<json-pointer>' when omitted)."
        ),
    )


class CsvAuditRequest(BaseModel):
    document: str = Field(
        ...,
        description=(
            "Raw CSV document text. Parsed as comma-separated fields with "
            "double-quoted enclosures ('\"\"' escapes a quote inside them) "
            "and CRLF/LF record breaks; unclosed or misplaced quotes are "
            "rejected with 422. Every cell is checked for a spreadsheet "
            "formula trigger (=, +, -, @) hidden behind a prefix of "
            "spaces, tabs or Unicode bidi control characters."
        ),
    )
    filename: Optional[str] = Field(
        default=None,
        max_length=4096,
        description="Optional document name, echoed back in the response.",
    )


class IdentifierNormalizationRequest(BaseModel):
    source: str = Field(
        ...,
        description=(
            "Python source code. Identifiers are extracted per Python's "
            "lexical rules (comments, strings and hard keywords skipped) "
            "and compared after Unicode NFKC normalisation."
        ),
    )
    filename: Optional[str] = Field(
        default=None,
        max_length=4096,
        description="Optional source file name for later lookup.",
    )


class MixedScriptRequest(BaseModel):
    source: str = Field(
        ...,
        description=(
            "Python source code. Identifiers are extracted per Python's "
            "lexical rules (comments, strings and hard keywords skipped) "
            "and checked for spellings that mix Latin, Greek and Cyrillic "
            "letters inside a single identifier."
        ),
    )
    filename: Optional[str] = Field(
        default=None,
        max_length=4096,
        description="Optional source file name, echoed back in the response.",
    )


class UrlQueryKeysRequest(BaseModel):
    url: str = Field(
        ...,
        description=(
            "Raw URL. The query component (from the first '?' to the "
            "first '#' or the end) is split on the undecoded '&' and "
            "'=' characters; every parameter key is decoded once "
            "(percent triplets as UTF-8, '+' as a space) and NFKC "
            "normalised, and keys collapsing to the same normalised "
            "form are reported as collision groups. Values are never "
            "decoded or compared."
        ),
    )


class IdentifierCollisionFixRequest(BaseModel):
    source: str = Field(
        ...,
        description=(
            "Python source code to preview the fix on. It is rescanned "
            "per Python's lexical rules before and after the edit; nothing "
            "is persisted."
        ),
    )
    normalised_name: str = Field(
        ...,
        min_length=1,
        description=(
            "NFKC normalised name of the collision group to fix. It is "
            "NFKC normalised itself before matching, so a raw spelling "
            "that normalises to the group name is accepted too. Only "
            "groups with at least two distinct raw spellings exist; any "
            "other name yields 422."
        ),
    )


class GateRuleSpec(BaseModel):
    template: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description=(
            "Path template split on '/'. Within a segment '*' matches any "
            "run of characters (never crossing '/'); a standalone '**' "
            "segment matches zero or more segments. Segments without '*' "
            "are literal matches."
        ),
    )
    max_risk: RiskLevel = Field(
        ..., description="Highest risk level allowed on paths matching this rule."
    )


class GateRequest(BaseModel):
    ids: List[int] = Field(
        ...,
        min_length=1,
        max_length=500,
        description="IDs of stored audit records to evaluate, in order.",
    )
    default_max_risk: RiskLevel = Field(
        ...,
        description=(
            "Highest risk level allowed for records without a file name or "
            "whose file name matches no rule."
        ),
    )
    rules: List[GateRuleSpec] = Field(
        default_factory=list,
        max_length=500,
        description=(
            "Ordered path rules. For each record the matching rule with the "
            "most literal segments wins; ties go to the template with more "
            "total segments, then to the earlier rule."
        ),
    )
