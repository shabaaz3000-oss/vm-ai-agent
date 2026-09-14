import pytest

from fastapi import HTTPException

from pydantic import ValidationError

from app.auth import Principal

from app.retrieval_authorization import (
    get_retrieval_access,
)


# -------------------------------------------------
# STANDARD ANALYST ACCESS
# -------------------------------------------------


def test_standard_analyst_receives_standard_access():

    principal = Principal(
        username="api-analyst",
        role="ANALYST",
        retrieval_access="standard",
    )

    assert (
        get_retrieval_access(
            principal
        )
        == "standard"
    )


# -------------------------------------------------
# APPROVER ACCESS REMAINS STANDARD
# -------------------------------------------------


def test_approver_does_not_automatically_receive_restricted_access():

    principal = Principal(
        username="api-approver",
        role="APPROVER",
        retrieval_access="standard",
    )

    assert (
        get_retrieval_access(
            principal
        )
        == "standard"
    )


# -------------------------------------------------
# EXPLICIT RESTRICTED ACCESS
# -------------------------------------------------


def test_explicit_restricted_principal_receives_restricted_access():

    principal = Principal(
        username="api-restricted-analyst",
        role="ANALYST",
        retrieval_access="restricted",
    )

    assert (
        get_retrieval_access(
            principal
        )
        == "restricted"
    )


# -------------------------------------------------
# INVALID ACCESS CLAIM REJECTED BY MODEL
# -------------------------------------------------


def test_invalid_retrieval_access_is_rejected_by_principal_model():

    with pytest.raises(
        ValidationError
    ):

        Principal(
            username="attacker",
            role="ANALYST",
            retrieval_access="admin",
        )


# -------------------------------------------------
# DEFENSE-IN-DEPTH RUNTIME VALIDATION
# -------------------------------------------------


def test_tampered_principal_access_is_rejected_at_policy_boundary():

    principal = Principal.model_construct(
        username="tampered-user",
        role="ANALYST",
        retrieval_access="admin",
    )

    with pytest.raises(
        HTTPException
    ) as error:

        get_retrieval_access(
            principal
        )

    assert (
        error.value.status_code
        == 403
    )


# -------------------------------------------------
# APPROVER AND RETRIEVAL PRIVILEGE ARE INDEPENDENT
# -------------------------------------------------


def test_restricted_access_does_not_require_approver_role():

    principal = Principal(
        username="api-restricted-analyst",
        role="ANALYST",
        retrieval_access="restricted",
    )

    assert (
        principal.role
        == "ANALYST"
    )

    assert (
        get_retrieval_access(
            principal
        )
        == "restricted"
    )