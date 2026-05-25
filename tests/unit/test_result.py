from __future__ import annotations

from sqlguard.result import VerificationResult, Violation, ViolationCategory, ViolationCode


def test_empty_result_has_no_violations() -> None:
    r = VerificationResult(allowed=True)
    assert r.violations == ()
    assert r.allowed is True


def test_violation_carries_category() -> None:
    v = Violation(code=ViolationCode.WRITE_FORBIDDEN, message="x")
    assert v.category == ViolationCategory.DENIED


def test_has_category_finds_match() -> None:
    vs = (
        Violation(code=ViolationCode.SELECT_STAR, message="x"),
        Violation(code=ViolationCode.LIMIT_EXCEEDED, message="y"),
    )
    r = VerificationResult(allowed=False, violations=vs)
    assert r.has_category(ViolationCategory.DENIED)  # SELECT_STAR
    assert r.has_category(ViolationCategory.LIMIT)   # LIMIT_EXCEEDED
    assert not r.has_category(ViolationCategory.PARSE)
