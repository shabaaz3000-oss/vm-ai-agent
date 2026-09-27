import pytest

from pydantic import ValidationError

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

    monkeypatch.setenv(
        "VM_AI_RESTRICTED_ANALYST_TOKEN",
        "restricted-analyst-secret-token"
    )

    monkeypatch.setenv(
        "VM_AI_SESSION_ADMIN_TOKEN",
        "session-admin-secret-token"
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

    assert (
        principal.retrieval_access
        == "standard"
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

    assert (
        principal.retrieval_access
        == "standard"
    )


# -------------------------------------------------
# RESTRICTED ANALYST AUTHENTICATION
# -------------------------------------------------


def test_valid_restricted_analyst_token_authenticates(
    monkeypatch
):

    configure_tokens(
        monkeypatch
    )

    principal = auth.authenticate_token(
        "restricted-analyst-secret-token"
    )

    assert (
        principal.username
        == "api-restricted-analyst"
    )

    assert (
        principal.role
        == "ANALYST"
    )

    assert (
        principal.retrieval_access
        == "restricted"
    )


# -------------------------------------------------
# DEFAULT RETRIEVAL ACCESS
# -------------------------------------------------


def test_principal_defaults_to_standard_retrieval_access():

    principal = auth.Principal(
        username="test-user",
        role="ANALYST",
    )

    assert (
        principal.retrieval_access
        == "standard"
    )


# -------------------------------------------------
# APPROVER DOES NOT IMPLY RESTRICTED ACCESS
# -------------------------------------------------


def test_approver_role_does_not_imply_restricted_access():

    principal = auth.Principal(
        username="test-approver",
        role="APPROVER",
    )

    assert (
        principal.retrieval_access
        == "standard"
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
# RESTRICTED ANALYST STILL CANNOT APPROVE
# -------------------------------------------------


def test_restricted_analyst_cannot_use_approver_role():

    analyst = auth.Principal(
        username="api-restricted-analyst",
        role="ANALYST",
        retrieval_access="restricted",
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

    assert (
        result.retrieval_access
        == "standard"
    )

# -------------------------------------------------
# SESSION REVOCATION AUTHORITY
# -------------------------------------------------


def test_principal_defaults_to_self_session_revocation():

    principal = auth.Principal(
        username="test-user",
        role="ANALYST",
    )

    assert (
        principal.session_revocation_access
        == "self"
    )


def test_session_revocation_authority_is_independent_of_role():

    principal = auth.Principal(
        username="test-admin",
        role="ANALYST",
        session_revocation_access="tenant_admin",
    )

    assert principal.role == "ANALYST"

    assert (
        principal.session_revocation_access
        == "tenant_admin"
    )


def test_approver_does_not_automatically_gain_session_admin():

    principal = auth.Principal(
        username="test-approver",
        role="APPROVER",
    )

    assert (
        principal.session_revocation_access
        == "self"
    )



# -------------------------------------------------
# SESSION REVOCATION AUTHORITY HARDENING
# -------------------------------------------------


def test_invalid_session_revocation_authority_is_rejected():

    with pytest.raises(
        ValidationError
    ):

        auth.Principal(
            username="test-user",
            role="ANALYST",
            session_revocation_access="global_admin",
        )


def test_analyst_token_remains_self_only_for_session_revocation(
    monkeypatch,
):

    configure_tokens(
        monkeypatch
    )

    principal = auth.authenticate_token(
        "analyst-secret-token"
    )

    assert (
        principal.session_revocation_access
        == "self"
    )


def test_approver_token_remains_self_only_for_session_revocation(
    monkeypatch,
):

    configure_tokens(
        monkeypatch
    )

    principal = auth.authenticate_token(
        "approver-secret-token"
    )

    assert (
        principal.session_revocation_access
        == "self"
    )


def test_restricted_analyst_token_remains_self_only_for_session_revocation(
    monkeypatch,
):

    configure_tokens(
        monkeypatch
    )

    principal = auth.authenticate_token(
        "restricted-analyst-secret-token"
    )

    assert (
        principal.session_revocation_access
        == "self"
    )


# -------------------------------------------------
# TENANT SESSION ADMINISTRATOR
# -------------------------------------------------


def test_valid_session_admin_token_authenticates(
    monkeypatch,
):

    configure_tokens(
        monkeypatch
    )

    principal = auth.authenticate_token(
        "session-admin-secret-token"
    )

    assert (
        principal.username
        == "api-session-admin"
    )

    assert principal.role == "ANALYST"

    assert (
        principal.retrieval_access
        == "standard"
    )

    assert (
        principal.session_revocation_access
        == "tenant_admin"
    )


def test_session_admin_does_not_gain_approver_authority(
    monkeypatch,
):

    configure_tokens(
        monkeypatch
    )

    principal = auth.authenticate_token(
        "session-admin-secret-token"
    )

    with pytest.raises(
        HTTPException
    ) as error:

        auth.require_approver(
            principal=principal
        )

    assert (
        error.value.status_code
        == 403
    )


def test_session_admin_does_not_gain_restricted_retrieval(
    monkeypatch,
):

    configure_tokens(
        monkeypatch
    )

    principal = auth.authenticate_token(
        "session-admin-secret-token"
    )

    assert (
        principal.retrieval_access
        == "standard"
    )


def test_session_admin_authority_is_not_role_derived(
    monkeypatch,
):

    configure_tokens(
        monkeypatch
    )

    principal = auth.authenticate_token(
        "session-admin-secret-token"
    )

    assert principal.role == "ANALYST"

    assert (
        principal.session_revocation_access
        == "tenant_admin"
    )
