import pytest

from pydantic import ValidationError

from app.auth import Principal

from app.retrieval_authorization import (
    RetrievalPrincipal,
    build_retrieval_principal,
)

from app.security_context import (
    SecurityContext,
)


def make_security_context(
    *,
    username: str = "alice",
    tenant_id: str = "tenant-a",
    retrieval_access: str = "standard",
) -> SecurityContext:

    principal = Principal(
        username=username,
        role="ANALYST",
        retrieval_access=retrieval_access,
    )

    return SecurityContext.from_principal(
        principal,
        tenant_id=tenant_id,
        session_id="server-owned-session",
    )


def test_retrieval_principal_is_derived_from_security_context():

    security_context = make_security_context(
        username="alice",
        tenant_id="tenant-a",
        retrieval_access="restricted",
    )

    principal = build_retrieval_principal(
        security_context
    )

    assert principal.principal_id == "alice"
    assert principal.tenant_id == "tenant-a"

    assert (
        principal.retrieval_access
        == "restricted"
    )


def test_retrieval_principal_is_immutable():

    principal = build_retrieval_principal(
        make_security_context()
    )

    with pytest.raises(ValidationError):
        principal.tenant_id = "tenant-b"


def test_retrieval_principal_rejects_extra_authority_claims():

    with pytest.raises(ValidationError):

        RetrievalPrincipal.model_validate(
            {
                "principal_id": "alice",
                "tenant_id": "tenant-a",
                "retrieval_access": "standard",
                "role": "APPROVER",
            }
        )


def test_standard_retrieval_access_is_preserved():

    principal = build_retrieval_principal(
        make_security_context(
            retrieval_access="standard"
        )
    )

    assert (
        principal.retrieval_access
        == "standard"
    )
