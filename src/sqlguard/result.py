from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


def _truncate(s: str, limit: int = 80) -> str:
    """Bound the length of user-controlled strings echoed in violation
    messages. Adversarial inputs can include 5000-char identifiers or
    SQL fragments; echoing them verbatim spams logs and can break UIs
    that render messages without truncation. The U+2026 ellipsis marks
    the truncation so callers don't mistake the suffix for the original.
    """
    if len(s) <= limit:
        return s
    return s[:limit] + "…"


class ViolationCode(str, Enum):
    WRITE_FORBIDDEN = "WRITE_FORBIDDEN"
    LOCK_FORBIDDEN = "LOCK_FORBIDDEN"
    DATA_MODIFYING_CTE = "DATA_MODIFYING_CTE"
    STATEMENT_FORBIDDEN = "STATEMENT_FORBIDDEN"  # CALL, SET, VACUUM, LISTEN, etc.
    MULTI_STATEMENT = "MULTI_STATEMENT"
    TABLE_DENIED = "TABLE_DENIED"
    COLUMN_DENIED = "COLUMN_DENIED"
    SELECT_STAR = "SELECT_STAR"
    ALWAYS_TRUE_PREDICATE = "ALWAYS_TRUE_PREDICATE"
    MISSING_REQUIRED_PREDICATE = "MISSING_REQUIRED_PREDICATE"
    FUNCTION_NOT_ALLOWED = "FUNCTION_NOT_ALLOWED"  # not in policy.allowed_functions
    RECURSIVE_CTE = "RECURSIVE_CTE"
    CARTESIAN_JOIN = "CARTESIAN_JOIN"
    # NATURAL JOIN matches columns implicitly by name, bypassing the
    # column allowlist (those columns never reach the AST as Identifiers).
    NATURAL_JOIN_FORBIDDEN = "NATURAL_JOIN_FORBIDDEN"
    LIMIT_REQUIRED = "LIMIT_REQUIRED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"  # LIMIT N where N > policy.limits.max_limit_value
    OFFSET_EXCEEDED = "OFFSET_EXCEEDED"  # OFFSET N where N > policy.limits.max_offset_value
    MAX_JOINS_EXCEEDED = "MAX_JOINS_EXCEEDED"
    MAX_SUBQUERY_DEPTH = "MAX_SUBQUERY_DEPTH"
    PARSE_ERROR = "PARSE_ERROR"
    POLICY_ERROR = "POLICY_ERROR"


class ViolationCategory(str, Enum):
    """Coarse grouping of violation codes for callers that don't want to
    branch on each of the ~20 codes individually. Most consumers just
    need: "did anything deny-ish fire?" — check `category == DENIED`.

    DENIED  — the query is forbidden by policy (writes, locks, denied
              tables/columns/functions, etc.). Default category for any
              code not otherwise mapped — fail closed.
    INVALID — the query is structurally wrong for the policy (tautology,
              missing required predicate). Often LLM mistakes.
    LIMIT   — the query exceeds a DoS cap (joins, depth, LIMIT, OFFSET).
    PARSE   — the query couldn't be parsed or is malformed.
    POLICY  — the policy itself is misconfigured (missing context value,
              etc.). Surface to the operator, not the end user.
    """

    DENIED = "denied"
    INVALID = "invalid"
    LIMIT = "limit"
    PARSE = "parse"
    POLICY = "policy"


# Unmapped codes default to DENIED (fail-closed). Add new codes here
# explicitly to override.
_CATEGORY: dict[ViolationCode, ViolationCategory] = {
    # DENIED — categorical bans
    ViolationCode.WRITE_FORBIDDEN: ViolationCategory.DENIED,
    ViolationCode.LOCK_FORBIDDEN: ViolationCategory.DENIED,
    ViolationCode.DATA_MODIFYING_CTE: ViolationCategory.DENIED,
    ViolationCode.STATEMENT_FORBIDDEN: ViolationCategory.DENIED,
    ViolationCode.MULTI_STATEMENT: ViolationCategory.DENIED,
    ViolationCode.TABLE_DENIED: ViolationCategory.DENIED,
    ViolationCode.COLUMN_DENIED: ViolationCategory.DENIED,
    ViolationCode.SELECT_STAR: ViolationCategory.DENIED,
    ViolationCode.FUNCTION_NOT_ALLOWED: ViolationCategory.DENIED,
    ViolationCode.RECURSIVE_CTE: ViolationCategory.DENIED,
    ViolationCode.CARTESIAN_JOIN: ViolationCategory.DENIED,
    ViolationCode.NATURAL_JOIN_FORBIDDEN: ViolationCategory.DENIED,
    # INVALID — structural problems with the query under this policy
    ViolationCode.ALWAYS_TRUE_PREDICATE: ViolationCategory.INVALID,
    ViolationCode.MISSING_REQUIRED_PREDICATE: ViolationCategory.INVALID,
    # LIMIT — DoS caps
    ViolationCode.LIMIT_REQUIRED: ViolationCategory.LIMIT,
    ViolationCode.LIMIT_EXCEEDED: ViolationCategory.LIMIT,
    ViolationCode.OFFSET_EXCEEDED: ViolationCategory.LIMIT,
    ViolationCode.MAX_JOINS_EXCEEDED: ViolationCategory.LIMIT,
    ViolationCode.MAX_SUBQUERY_DEPTH: ViolationCategory.LIMIT,
    # PARSE / POLICY
    ViolationCode.PARSE_ERROR: ViolationCategory.PARSE,
    ViolationCode.POLICY_ERROR: ViolationCategory.POLICY,
}


@dataclass(frozen=True)
class Violation:
    code: ViolationCode
    message: str
    suggestion: str | None = None

    @property
    def category(self) -> ViolationCategory:
        """Coarse grouping for callers that only need 'was this denied?'.

        Unmapped codes default to DENIED so new codes added without
        thinking about the category fail closed.
        """
        return _CATEGORY.get(self.code, ViolationCategory.DENIED)


@dataclass(frozen=True)
class VerificationResult:
    allowed: bool
    violations: tuple[Violation, ...] = field(default_factory=tuple)
    statement_kind: str = "UNKNOWN"

    def has_category(self, category: ViolationCategory) -> bool:
        """True if any violation in this result has the given category.

        Common idiom: `if result.has_category(ViolationCategory.DENIED): ...`
        — the simple "should I reject this query?" check that doesn't
        require enumerating the violation codes.
        """
        return any(v.category == category for v in self.violations)
