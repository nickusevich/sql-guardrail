from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from sqlguard.result import VerificationResult, Violation


class VerifyRequest(BaseModel):
    # extra="forbid" turns typos like {"squl": "..."} into a 422 instead of
    # silently dropping the field and validating an empty SQL string.
    model_config = ConfigDict(extra="forbid")

    sql: str = Field(
        ...,
        description=(
            "The SQL string to validate. Hard byte cap comes from "
            "policy.limits.max_sql_length."
        ),
    )
    context: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Per-request values resolved into policy placeholders "
            '(e.g. {"tenant_id": 42} fills "${tenant_id}" in require_predicate). '
            "MUST come from the authenticated session, never from the LLM prompt."
        ),
    )


class ViolationOut(BaseModel):
    code: str = Field(..., description="Machine-readable violation code.")
    category: str = Field(
        ...,
        description="Coarse grouping: denied | invalid | limit | parse | policy.",
    )
    message: str = Field(..., description="Human-readable explanation of the denial.")
    suggestion: str | None = Field(
        default=None,
        description="Corrective hint suitable to feed back to an LLM for retry.",
    )

    @classmethod
    def from_violation(cls, v: Violation) -> ViolationOut:
        return cls(
            code=v.code.value,
            category=v.category.value,
            message=v.message,
            suggestion=v.suggestion,
        )


class VerifyResponse(BaseModel):
    allowed: bool = Field(..., description="True if the SQL passed every policy rule.")
    statement_kind: str = Field(
        ...,
        description=(
            "Top-level statement type: SELECT | INSERT | UPDATE | DELETE | "
            "MERGE | UNKNOWN."
        ),
    )
    violations: list[ViolationOut] = Field(
        default_factory=list,
        description="Empty when allowed=True. One entry per failed rule when allowed=False.",
    )

    @classmethod
    def from_result(cls, r: VerificationResult) -> VerifyResponse:
        return cls(
            allowed=r.allowed,
            statement_kind=r.statement_kind,
            violations=[ViolationOut.from_violation(v) for v in r.violations],
        )


class HealthResponse(BaseModel):
    status: str = Field(..., description='"ok" when policy is loaded.')
    policy_loaded: bool
    version: str
