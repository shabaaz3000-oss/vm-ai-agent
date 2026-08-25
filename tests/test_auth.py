import pytest

from fastapi import HTTPException

from fastapi.security import (
    HTTPAuthorizationCredentials,
)

import app.auth as auth


# -------------------------------------------------
# TEST TOKEN CONFIGURATION
# -------------------------------------------------


def configure_tokens(
    monkeypatch
):

    monkeypatch.setenv(
        "VM_AI_ANALYST_TOKEN",
        "analyst-secret-token"
    )

    monkeypatch.setenv(
        "VM_AI_APPROVER_TOKEN",
        "approver-secret-token"
    )


# -------------------------------------------------
# ANALYST AUTHENTICATION
# -------------------------------------------------


def test_valid_analyst_token_authenticates(
    monkeypatch
):

    configure_tokens(
        monkeypatch
    )

    principal = auth.authenticate_token(
        "analyst-secret-token"
    )

    assert (
        principal.username
        == "api-analyst"
    )

    assert (
        principal.role
        == "ANALYST"
    )


# -------------------------------------------------
# APPROVER AUTHENTICATION
# -------------------------------------------------


def test_valid_approver_token_authenticates(
    monkeypatch
):

    configure_tokens(
        monkeypatch
    )

    principal = auth.authenticate_token(
        "approver-secret-token"
    )

    assert (
        principal.username
        == "api-approver"
    )

    assert (
        principal.role
        == "APPROVER"
    )


# -------------------------------------------------
# INVALID TOKEN
# -------------------------------------------------


def test_invalid_token_is_rejected(
    monkeypatch
):

    configure_tokens(
        monkeypatch
    )

    with pytest.raises(
        HTTPException
    ) as error:

        auth.authenticate_token(
            "wrong-token"
        )

    assert (
        error.value.status_code
        == 401
    )


# -------------------------------------------------
# MISSING CREDENTIALS
# -------------------------------------------------


def test_missing_credentials_are_rejected():

    with pytest.raises(
        HTTPException
    ) as error:

        auth.require_authenticated_user(
            credentials=None
        )

    assert (
        error.value.status_code
        == 401
    )


# -------------------------------------------------
# ANALYST CANNOT APPROVE
# -------------------------------------------------


def test_analyst_cannot_use_approver_role():

    analyst = auth.Principal(
        username="api-analyst",
        role="ANALYST",
    )

    with pytest.raises(
        HTTPException
    ) as error:

        auth.require_approver(
            principal=analyst
        )

    assert (
        error.value.status_code
        == 403
    )

    assert (
        "approver role"
        in error.value.detail.lower()
    )


# -------------------------------------------------
# APPROVER IS AUTHORIZED
# -------------------------------------------------


def test_approver_role_is_authorized():

    approver = auth.Principal(
        username="api-approver",
        role="APPROVER",
    )

    result = auth.require_approver(
        principal=approver
    )

    assert (
        result.username
        == "api-approver"
    )

    assert (
        result.role
        == "APPROVER"
    )