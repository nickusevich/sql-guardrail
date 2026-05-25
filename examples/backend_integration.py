"""How to wire sql-guardrail into a backend so tenant_id is enforced per request.

The pattern is:
  - Policy is LOADED ONCE at app startup (rules are static)
  - tenant_id comes from the AUTHENTICATED request (JWT/session/header),
    NOT from anything the LLM produced and NOT from the user's prompt
  - Each request calls verify(sql, policy, context={"tenant_id": <that user's id>})
  - The policy's require_predicate forces the SQL to contain
    `account_id = <that exact tenant_id>` — wrong values fail the check.

Run this file directly to see four scenarios across two different users.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlguard import Policy, VerificationResult, verify

# ---------------------------------------------------------------------------
# Startup: load the policy ONCE. In FastAPI this would go in a lifespan hook,
# or be assigned to `app.state.policy`. In Django, AppConfig.ready().
# ---------------------------------------------------------------------------
POLICY: Policy = Policy.from_yaml(Path(__file__).parent / "policy.yml")


# ---------------------------------------------------------------------------
# Per-request: a User comes from your auth layer (JWT decode, session lookup,
# OAuth, whatever). The KEY point is the tenant_id is server-side data,
# attached to the authenticated identity. The LLM and the user's prompt
# never get to choose it.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: int
    tenant_id: int  # filled from the JWT claim / session, not from the prompt


class GuardrailRejection(Exception):
    def __init__(self, result: VerificationResult) -> None:
        self.result = result
        super().__init__(
            "; ".join(f"{v.code.value}: {v.message}" for v in result.violations)
        )


def handle_question(user: AuthenticatedUser, sql_from_llm: str) -> VerificationResult:
    """The request handler. In FastAPI this would be inside an endpoint."""
    # context is built from the AUTHENTICATED identity — never from anything
    # the user typed or the LLM generated.
    result = verify(
        sql_from_llm,
        POLICY,
        context={"tenant_id": user.tenant_id, "user_id": user.user_id},
    )
    if not result.allowed:
        raise GuardrailRejection(result)
    return result
    # In a real handler you'd also do (defense in depth):
    #   with conn.transaction(read_only=True):
    #       conn.execute("SET LOCAL statement_timeout = '5s'")
    #       conn.execute(f"SET LOCAL app.tenant_id = {user.tenant_id}")  # for RLS
    #       return conn.execute(sql_from_llm)


# ---------------------------------------------------------------------------
# Demo: two different users, same policy, different outcomes.
# ---------------------------------------------------------------------------
def main() -> None:
    alice = AuthenticatedUser(user_id=1, tenant_id=42)
    bob = AuthenticatedUser(user_id=2, tenant_id=99)

    # The `orders` table is `large: true` in examples/policy.yml, so every
    # query against it needs an explicit LIMIT — otherwise LIMIT_REQUIRED
    # fires and the request is denied even if the tenant predicate is right.
    cases = [
        # (user, sql, expected_outcome)
        (
            alice,
            "SELECT id, total FROM orders WHERE account_id = 42 LIMIT 100",
            "ALLOW — Alice's tenant_id matches the predicate.",
        ),
        (
            bob,
            "SELECT id, total FROM orders WHERE account_id = 42 LIMIT 100",
            "DENY — same SQL, but Bob's tenant_id is 99 not 42. "
            "Bob can't query Alice's data even if the LLM generated this SQL.",
        ),
        (
            alice,
            "SELECT id, total FROM orders LIMIT 100",
            "DENY — Alice's request, but the LLM forgot the tenant filter.",
        ),
        (
            bob,
            "SELECT id, total FROM orders WHERE account_id = 99 LIMIT 100",
            "ALLOW — Bob's tenant_id matches.",
        ),
    ]

    for user, sql, label in cases:
        print(f"\n--- user={user.user_id} tenant={user.tenant_id} ---")
        print(f"SQL: {sql}")
        try:
            handle_question(user, sql)
            print(f"OK   {label}")
        except GuardrailRejection as e:
            print(f"DENY {label}")
            for v in e.result.violations:
                print(f"     [{v.code.value}] {v.message}")


if __name__ == "__main__":
    main()
