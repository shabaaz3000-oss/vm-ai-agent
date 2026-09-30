import pytest

from pydantic import ValidationError

from app.enterprise_identity import EnterpriseIdentity


def make_identity() -> EnterpriseIdentity:

    return EnterpriseIdentity(
        issuer=(
            "https://login.example.test/"
            "enterprise/v2.0"
        ),
        subject="subject-123",
        identity_provider_tenant_id=(
            "directory-tenant-456"
        ),
    )


# -------------------------------------------------
# AUTHORITATIVE IDENTITY FACTS
# -------------------------------------------------


def test_enterprise_identity_preserves_authoritative_facts():

    identity = make_identity()

    assert identity.issuer == (
        "https://login.example.test/"
        "enterprise/v2.0"
    )

    assert identity.subject == "subject-123"

    assert (
        identity.identity_provider_tenant_id
        == "directory-tenant-456"
    )


def test_enterprise_identity_normalizes_outer_whitespace():

    identity = EnterpriseIdentity(
        issuer="  https://issuer.example.test  ",
        subject="  subject-123  ",
        identity_provider_tenant_id=(
            "  directory-tenant-456  "
        ),
    )

    assert identity.issuer == (
        "https://issuer.example.test"
    )

    assert identity.subject == "subject-123"

    assert (
        identity.identity_provider_tenant_id
        == "directory-tenant-456"
    )


# -------------------------------------------------
# FAIL-CLOSED REQUIRED IDENTITY
# -------------------------------------------------


@pytest.mark.parametrize(
    "field_name",
    [
        "issuer",
        "subject",
        "identity_provider_tenant_id",
    ],
)
@pytest.mark.parametrize(
    "invalid_value",
    [
        "",
        "   ",
    ],
)
def test_enterprise_identity_rejects_empty_authoritative_values(
    field_name,
    invalid_value,
):

    values = {
        "issuer": "https://issuer.example.test",
        "subject": "subject-123",
        "identity_provider_tenant_id":
            "directory-tenant-456",
    }

    values[field_name] = invalid_value

    with pytest.raises(ValidationError):

        EnterpriseIdentity(
            **values
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "issuer",
        "subject",
        "identity_provider_tenant_id",
    ],
)
@pytest.mark.parametrize(
    "invalid_value",
    [
        None,
        123,
        [],
        {},
    ],
)
def test_enterprise_identity_rejects_non_string_identity_values(
    field_name,
    invalid_value,
):

    values = {
        "issuer": "https://issuer.example.test",
        "subject": "subject-123",
        "identity_provider_tenant_id":
            "directory-tenant-456",
    }

    values[field_name] = invalid_value

    with pytest.raises(ValidationError):

        EnterpriseIdentity(
            **values
        )


# -------------------------------------------------
# IMMUTABILITY
# -------------------------------------------------


def test_enterprise_identity_is_immutable():

    identity = make_identity()

    with pytest.raises(
        ValidationError
    ):
        identity.subject = "forged-subject"


# -------------------------------------------------
# AUTHENTICATION / AUTHORIZATION SEPARATION
# -------------------------------------------------


@pytest.mark.parametrize(
    (
        "forbidden_field",
        "forbidden_value",
    ),
    [
        (
            "tenant_id",
            "tenant-a",
        ),
        (
            "role",
            "APPROVER",
        ),
        (
            "retrieval_access",
            "restricted",
        ),
        (
            "session_revocation_access",
            "tenant_admin",
        ),
        (
            "groups",
            [
                "Executive",
                "Security-Admins",
            ],
        ),
    ],
)
def test_enterprise_identity_rejects_application_authority_claims(
    forbidden_field,
    forbidden_value,
):

    values = {
        "issuer": "https://issuer.example.test",
        "subject": "subject-123",
        "identity_provider_tenant_id":
            "directory-tenant-456",
    }

    values[
        forbidden_field
    ] = forbidden_value

    with pytest.raises(ValidationError):

        EnterpriseIdentity(
            **values
        )


# -------------------------------------------------
# CREDENTIAL SEPARATION
# -------------------------------------------------


@pytest.mark.parametrize(
    "credential_field",
    [
        "token",
        "access_token",
        "raw_access_token",
        "id_token",
        "refresh_token",
    ],
)
def test_enterprise_identity_rejects_raw_credentials(
    credential_field,
):

    values = {
        "issuer": "https://issuer.example.test",
        "subject": "subject-123",
        "identity_provider_tenant_id":
            "directory-tenant-456",
    }

    values[
        credential_field
    ] = "SECRET-CREDENTIAL"

    with pytest.raises(ValidationError):

        EnterpriseIdentity(
            **values
        )


def test_enterprise_identity_serialization_contains_no_authority_or_token():

    identity = make_identity()

    assert identity.model_dump() == {
        "issuer": (
            "https://login.example.test/"
            "enterprise/v2.0"
        ),
        "subject": "subject-123",
        "identity_provider_tenant_id":
            "directory-tenant-456",
    }


def test_enterprise_identity_schema_has_only_authentication_facts():

    assert set(
        EnterpriseIdentity.model_fields
    ) == {
        "issuer",
        "subject",
        "identity_provider_tenant_id",
    }
