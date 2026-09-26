import pytest

from pydantic import ValidationError

from app.auth import Principal
from app.security_context import SecurityContext


def make_principal() -> Principal:

    return Principal(
        username="alice",
        role="ANALYST",
        retrieval_access="restricted",
    )


def test_security_context_snapshots_principal_claims():

    principal = make_principal()

    context = SecurityContext.from_principal(
        principal,
        tenant_id="tenant-a",
        session_id="session-123",
    )

    assert context.principal_id == "alice"
    assert context.role == "ANALYST"
    assert context.retrieval_access == "restricted"
    assert context.tenant_id == "tenant-a"
    assert context.session_id == "session-123"


def test_security_context_is_immutable():

    principal = make_principal()

    context = SecurityContext.from_principal(
        principal,
        tenant_id="tenant-a",
        session_id="session-123",
    )

    with pytest.raises(
        ValidationError
    ):

        context.session_id = "session-456"


def test_security_context_rejects_empty_session_id():

    principal = make_principal()

    with pytest.raises(
        ValidationError
    ):

        SecurityContext.from_principal(
            principal,
            tenant_id="tenant-a",
            session_id="",
        )


def test_security_context_rejects_empty_tenant_id():

    principal = make_principal()

    with pytest.raises(
        ValidationError
    ):

        SecurityContext.from_principal(
            principal,
            tenant_id="",
            session_id="session-123",
        )


def test_security_context_contains_only_execution_claims():

    principal = make_principal()

    context = SecurityContext.from_principal(
        principal,
        tenant_id="tenant-a",
        session_id="session-123",
    )

    assert set(
        context.model_dump().keys()
    ) == {
        "principal_id",
        "role",
        "retrieval_access",
        "tenant_id",
        "session_id",
    }