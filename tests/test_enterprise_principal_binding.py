import json

import pytest

from pydantic import ValidationError

from app.enterprise_identity import EnterpriseIdentity

from app.enterprise_principal_binding import (
    ENTERPRISE_PRINCIPAL_BINDINGS_ENV,
    EnterprisePrincipalBinding,
    EnterprisePrincipalBindingError,
    build_enterprise_principal,
    load_enterprise_principal_bindings,
    resolve_enterprise_principal,
)


ISSUER = (
    "https://login.microsoftonline.com/"
    "11111111-1111-1111-1111-111111111111/"
    "v2.0"
)

TENANT_ID = (
    "11111111-1111-1111-1111-111111111111"
)

SUBJECT = "subject-123"


# -------------------------------------------------
# HELPERS
# -------------------------------------------------


def identity(
    *,
    issuer=ISSUER,
    tenant_id=TENANT_ID,
    subject=SUBJECT,
):

    return EnterpriseIdentity(
        issuer=issuer,
        identity_provider_tenant_id=
            tenant_id,
        subject=subject,
    )


def binding(
    *,
    issuer=ISSUER,
    tenant_id=TENANT_ID,
    subject=SUBJECT,
    principal_id="enterprise-analyst",
    role="ANALYST",
    retrieval_access="standard",
    session_revocation_access="self",
):

    return EnterprisePrincipalBinding(
        issuer=issuer,
        identity_provider_tenant_id=
            tenant_id,
        subject=subject,
        principal_id=principal_id,
        role=role,
        retrieval_access=
            retrieval_access,
        session_revocation_access=
            session_revocation_access,
    )


def encoded_bindings(
    *items,
):

    return {
        ENTERPRISE_PRINCIPAL_BINDINGS_ENV:
            json.dumps(
                list(items)
            )
    }


def binding_dict(
    *,
    issuer=ISSUER,
    tenant_id=TENANT_ID,
    subject=SUBJECT,
    principal_id="enterprise-analyst",
    role="ANALYST",
    retrieval_access="standard",
    session_revocation_access="self",
):

    return {
        "issuer": issuer,
        "identity_provider_tenant_id":
            tenant_id,
        "subject": subject,
        "principal_id": principal_id,
        "role": role,
        "retrieval_access":
            retrieval_access,
        "session_revocation_access":
            session_revocation_access,
    }


# -------------------------------------------------
# EXACT IDENTITY BINDING
# -------------------------------------------------


def test_exact_enterprise_identity_builds_application_principal():

    principal = build_enterprise_principal(
        identity(),
        bindings=(
            binding(),
        ),
    )

    assert principal.username == (
        "enterprise-analyst"
    )

    assert principal.role == "ANALYST"

    assert (
        principal.retrieval_access
        == "standard"
    )

    assert (
        principal.session_revocation_access
        == "self"
    )


def test_server_binding_controls_all_application_authority():

    principal = build_enterprise_principal(
        identity(),
        bindings=(
            binding(
                principal_id=
                    "security-approver",
                role="APPROVER",
                retrieval_access=
                    "restricted",
                session_revocation_access=
                    "tenant_admin",
            ),
        ),
    )

    assert principal.username == (
        "security-approver"
    )

    assert principal.role == "APPROVER"

    assert (
        principal.retrieval_access
        == "restricted"
    )

    assert (
        principal.session_revocation_access
        == "tenant_admin"
    )


# -------------------------------------------------
# FULL AUTHORITY TUPLE
# -------------------------------------------------


def test_same_subject_in_different_tenant_is_not_authorized():

    with pytest.raises(
        EnterprisePrincipalBindingError
    ):

        build_enterprise_principal(
            identity(
                tenant_id=(
                    "22222222-2222-2222-2222-222222222222"
                )
            ),
            bindings=(
                binding(),
            ),
        )


def test_same_subject_from_different_issuer_is_not_authorized():

    with pytest.raises(
        EnterprisePrincipalBindingError
    ):

        build_enterprise_principal(
            identity(
                issuer=(
                    "https://login.microsoftonline.com/"
                    "22222222-2222-2222-2222-222222222222/"
                    "v2.0"
                )
            ),
            bindings=(
                binding(),
            ),
        )


def test_unknown_subject_is_not_authorized():

    with pytest.raises(
        EnterprisePrincipalBindingError
    ):

        build_enterprise_principal(
            identity(
                subject="unknown-subject"
            ),
            bindings=(
                binding(),
            ),
        )


def test_subject_alone_never_authorizes_identity():

    legitimate = binding()

    attacker = identity(
        issuer=(
            "https://attacker.example.test/v2.0"
        ),
        tenant_id=(
            "99999999-9999-9999-9999-999999999999"
        ),
        subject=legitimate.subject,
    )

    with pytest.raises(
        EnterprisePrincipalBindingError
    ):

        build_enterprise_principal(
            attacker,
            bindings=(
                legitimate,
            ),
        )


# -------------------------------------------------
# BINDING MODEL
# -------------------------------------------------


def test_binding_is_immutable():

    trusted = binding()

    with pytest.raises(
        ValidationError
    ):
        trusted.role = "APPROVER"


def test_binding_normalizes_identity_and_principal_values():

    trusted = EnterprisePrincipalBinding(
        issuer=f"  {ISSUER}  ",
        identity_provider_tenant_id=
            f"  {TENANT_ID}  ",
        subject="  subject-123  ",
        principal_id=
            "  enterprise-analyst  ",
        role="ANALYST",
    )

    assert trusted.issuer == ISSUER

    assert (
        trusted.identity_provider_tenant_id
        == TENANT_ID
    )

    assert trusted.subject == SUBJECT

    assert trusted.principal_id == (
        "enterprise-analyst"
    )


def test_binding_schema_contains_no_internal_tenant():

    assert "tenant_id" not in (
        EnterprisePrincipalBinding.model_fields
    )


@pytest.mark.parametrize(
    (
        "forbidden_field",
        "value",
    ),
    [
        (
            "tenant_id",
            "tenant-a",
        ),
        (
            "access_token",
            "SECRET",
        ),
        (
            "groups",
            [
                "Security-Admins",
            ],
        ),
        (
            "email",
            "admin@example.test",
        ),
        (
            "preferred_username",
            "admin@example.test",
        ),
    ],
)
def test_binding_rejects_untrusted_or_future_authority_fields(
    forbidden_field,
    value,
):

    values = binding_dict()

    values[
        forbidden_field
    ] = value

    with pytest.raises(
        ValidationError
    ):

        EnterprisePrincipalBinding(
            **values
        )


@pytest.mark.parametrize(
    (
        "field_name",
        "invalid_value",
    ),
    [
        (
            "issuer",
            "",
        ),
        (
            "subject",
            "   ",
        ),
        (
            "identity_provider_tenant_id",
            None,
        ),
        (
            "principal_id",
            123,
        ),
    ],
)
def test_binding_rejects_invalid_required_identity_values(
    field_name,
    invalid_value,
):

    values = binding_dict()

    values[
        field_name
    ] = invalid_value

    with pytest.raises(
        ValidationError
    ):

        EnterprisePrincipalBinding(
            **values
        )


@pytest.mark.parametrize(
    (
        "field_name",
        "invalid_value",
    ),
    [
        (
            "role",
            "ADMIN",
        ),
        (
            "retrieval_access",
            "superuser",
        ),
        (
            "session_revocation_access",
            "global_admin",
        ),
    ],
)
def test_binding_rejects_invalid_application_authority(
    field_name,
    invalid_value,
):

    values = binding_dict()

    values[
        field_name
    ] = invalid_value

    with pytest.raises(
        ValidationError
    ):

        EnterprisePrincipalBinding(
            **values
        )


# -------------------------------------------------
# CONFIGURATION LOADING
# -------------------------------------------------


def test_load_valid_server_side_bindings():

    loaded = (
        load_enterprise_principal_bindings(
            encoded_bindings(
                binding_dict()
            )
        )
    )

    assert isinstance(
        loaded,
        tuple,
    )

    assert len(loaded) == 1

    assert loaded[0] == binding()


@pytest.mark.parametrize(
    "environment",
    [
        {},
        {
            ENTERPRISE_PRINCIPAL_BINDINGS_ENV:
                "",
        },
        {
            ENTERPRISE_PRINCIPAL_BINDINGS_ENV:
                "   ",
        },
    ],
)
def test_missing_or_blank_binding_configuration_fails_closed(
    environment,
):

    with pytest.raises(
        EnterprisePrincipalBindingError
    ):

        load_enterprise_principal_bindings(
            environment
        )


def test_invalid_json_fails_closed():

    with pytest.raises(
        EnterprisePrincipalBindingError
    ):

        load_enterprise_principal_bindings(
            {
                ENTERPRISE_PRINCIPAL_BINDINGS_ENV:
                    "{not-json"
            }
        )


@pytest.mark.parametrize(
    "decoded",
    [
        {},
        "binding",
        123,
        [],
    ],
)
def test_non_list_or_empty_binding_configuration_fails_closed(
    decoded,
):

    with pytest.raises(
        EnterprisePrincipalBindingError
    ):

        load_enterprise_principal_bindings(
            {
                ENTERPRISE_PRINCIPAL_BINDINGS_ENV:
                    json.dumps(
                        decoded
                    )
            }
        )


def test_non_object_binding_entry_fails_closed():

    with pytest.raises(
        EnterprisePrincipalBindingError
    ):

        load_enterprise_principal_bindings(
            encoded_bindings(
                "not-an-object"
            )
        )


def test_duplicate_identity_authority_fails_closed():

    first = binding_dict(
        principal_id="principal-one"
    )

    second = binding_dict(
        principal_id="principal-two"
    )

    with pytest.raises(
        EnterprisePrincipalBindingError
    ):

        load_enterprise_principal_bindings(
            encoded_bindings(
                first,
                second,
            )
        )


def test_duplicate_application_principal_fails_closed():

    first = binding_dict(
        subject="subject-one",
        principal_id=
            "shared-principal",
    )

    second = binding_dict(
        subject="subject-two",
        principal_id=
            "shared-principal",
    )

    with pytest.raises(
        EnterprisePrincipalBindingError
    ):

        load_enterprise_principal_bindings(
            encoded_bindings(
                first,
                second,
            )
        )


# -------------------------------------------------
# SERVER CONFIGURATION RESOLUTION
# -------------------------------------------------


def test_resolve_enterprise_principal_uses_server_configuration():

    environment = encoded_bindings(
        binding_dict(
            principal_id=
                "configured-principal",
            role="APPROVER",
            retrieval_access=
                "restricted",
        )
    )

    principal = (
        resolve_enterprise_principal(
            identity(),
            environment=environment,
        )
    )

    assert principal.username == (
        "configured-principal"
    )

    assert principal.role == (
        "APPROVER"
    )

    assert (
        principal.retrieval_access
        == "restricted"
    )


def test_resolution_failure_does_not_echo_identity_values():

    secret_subject = (
        "sensitive-subject-value"
    )

    with pytest.raises(
        EnterprisePrincipalBindingError
    ) as captured:

        build_enterprise_principal(
            identity(
                subject=secret_subject
            ),
            bindings=(
                binding(),
            ),
        )

    assert secret_subject not in str(
        captured.value
    )
