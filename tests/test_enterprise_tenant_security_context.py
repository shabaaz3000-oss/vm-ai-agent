import json

import pytest

from pydantic import ValidationError

from app.enterprise_identity import EnterpriseIdentity

from app.enterprise_principal_binding import (
    ENTERPRISE_PRINCIPAL_BINDINGS_ENV,
    EnterprisePrincipalBinding,
    EnterprisePrincipalBindingError,
)

from app.enterprise_security_context import (
    EnterpriseSecurityContextError,
    build_enterprise_security_context,
    resolve_enterprise_security_context,
)

from app.enterprise_tenant_binding import (
    ENTERPRISE_TENANT_BINDINGS_ENV,
    EnterpriseTenantBinding,
    EnterpriseTenantBindingError,
    load_enterprise_tenant_bindings,
    resolve_enterprise_tenant,
    resolve_enterprise_tenant_from_environment,
)


ISSUER = (
    "https://login.microsoftonline.com/"
    "11111111-1111-1111-1111-111111111111/"
    "v2.0"
)

IDP_TENANT_ID = (
    "11111111-1111-1111-1111-111111111111"
)

SUBJECT = "subject-123"

INTERNAL_TENANT_ID = "tenant-a"

SESSION_ID = "server-session-123"


# -------------------------------------------------
# HELPERS
# -------------------------------------------------


def identity(
    *,
    issuer=ISSUER,
    tenant_id=IDP_TENANT_ID,
    subject=SUBJECT,
):

    return EnterpriseIdentity(
        issuer=issuer,
        identity_provider_tenant_id=
            tenant_id,
        subject=subject,
    )


def tenant_binding(
    *,
    issuer=ISSUER,
    idp_tenant_id=IDP_TENANT_ID,
    internal_tenant_id=
        INTERNAL_TENANT_ID,
):

    return EnterpriseTenantBinding(
        issuer=issuer,
        identity_provider_tenant_id=
            idp_tenant_id,
        tenant_id=
            internal_tenant_id,
    )


def principal_binding(
    *,
    issuer=ISSUER,
    idp_tenant_id=IDP_TENANT_ID,
    subject=SUBJECT,
    principal_id=
        "enterprise-analyst",
    role="ANALYST",
    retrieval_access=
        "standard",
    session_revocation_access=
        "self",
):

    return EnterprisePrincipalBinding(
        issuer=issuer,
        identity_provider_tenant_id=
            idp_tenant_id,
        subject=subject,
        principal_id=
            principal_id,
        role=role,
        retrieval_access=
            retrieval_access,
        session_revocation_access=
            session_revocation_access,
    )


def tenant_binding_dict(
    *,
    issuer=ISSUER,
    idp_tenant_id=IDP_TENANT_ID,
    internal_tenant_id=
        INTERNAL_TENANT_ID,
):

    return {
        "issuer": issuer,
        "identity_provider_tenant_id":
            idp_tenant_id,
        "tenant_id":
            internal_tenant_id,
    }


def principal_binding_dict():

    return {
        "issuer": ISSUER,
        "identity_provider_tenant_id":
            IDP_TENANT_ID,
        "subject": SUBJECT,
        "principal_id":
            "enterprise-analyst",
        "role": "ANALYST",
        "retrieval_access":
            "standard",
        "session_revocation_access":
            "self",
    }


def environment(
    *,
    tenant_bindings=None,
    principal_bindings=None,
):

    if tenant_bindings is None:

        tenant_bindings = [
            tenant_binding_dict()
        ]

    if principal_bindings is None:

        principal_bindings = [
            principal_binding_dict()
        ]

    return {
        ENTERPRISE_TENANT_BINDINGS_ENV:
            json.dumps(
                tenant_bindings
            ),

        ENTERPRISE_PRINCIPAL_BINDINGS_ENV:
            json.dumps(
                principal_bindings
            ),
    }


# -------------------------------------------------
# TENANT MAPPING
# -------------------------------------------------


def test_enterprise_tenant_maps_to_internal_application_tenant():

    resolved = resolve_enterprise_tenant(
        identity(),
        bindings=(
            tenant_binding(),
        ),
    )

    assert resolved == (
        INTERNAL_TENANT_ID
    )


def test_idp_tenant_is_not_automatically_internal_tenant():

    resolved = resolve_enterprise_tenant(
        identity(),
        bindings=(
            tenant_binding(),
        ),
    )

    assert resolved != (
        IDP_TENANT_ID
    )


def test_same_idp_tenant_from_wrong_issuer_is_rejected():

    attacker = identity(
        issuer=(
            "https://attacker.example.test/v2.0"
        )
    )

    with pytest.raises(
        EnterpriseTenantBindingError
    ):

        resolve_enterprise_tenant(
            attacker,
            bindings=(
                tenant_binding(),
            ),
        )


def test_unknown_idp_tenant_is_rejected():

    attacker = identity(
        tenant_id=(
            "99999999-9999-9999-9999-999999999999"
        )
    )

    with pytest.raises(
        EnterpriseTenantBindingError
    ):

        resolve_enterprise_tenant(
            attacker,
            bindings=(
                tenant_binding(),
            ),
        )


def test_subject_does_not_control_tenant_mapping():

    alice = resolve_enterprise_tenant(
        identity(
            subject="alice"
        ),
        bindings=(
            tenant_binding(),
        ),
    )

    bob = resolve_enterprise_tenant(
        identity(
            subject="bob"
        ),
        bindings=(
            tenant_binding(),
        ),
    )

    assert alice == bob == (
        INTERNAL_TENANT_ID
    )


# -------------------------------------------------
# TENANT BINDING MODEL
# -------------------------------------------------


def test_tenant_binding_is_immutable():

    trusted = tenant_binding()

    with pytest.raises(
        ValidationError
    ):
        trusted.tenant_id = "tenant-b"


def test_tenant_binding_normalizes_values():

    trusted = EnterpriseTenantBinding(
        issuer=f"  {ISSUER}  ",
        identity_provider_tenant_id=
            f"  {IDP_TENANT_ID}  ",
        tenant_id="  tenant-a  ",
    )

    assert trusted.issuer == ISSUER

    assert (
        trusted.identity_provider_tenant_id
        == IDP_TENANT_ID
    )

    assert trusted.tenant_id == (
        INTERNAL_TENANT_ID
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
            "identity_provider_tenant_id",
            "   ",
        ),
        (
            "tenant_id",
            None,
        ),
        (
            "tenant_id",
            123,
        ),
    ],
)
def test_tenant_binding_rejects_invalid_values(
    field_name,
    invalid_value,
):

    values = tenant_binding_dict()

    values[
        field_name
    ] = invalid_value

    with pytest.raises(
        ValidationError
    ):

        EnterpriseTenantBinding(
            **values
        )


@pytest.mark.parametrize(
    (
        "forbidden_field",
        "value",
    ),
    [
        (
            "subject",
            "subject-123",
        ),
        (
            "role",
            "APPROVER",
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
    ],
)
def test_tenant_binding_rejects_unrelated_authority(
    forbidden_field,
    value,
):

    values = tenant_binding_dict()

    values[
        forbidden_field
    ] = value

    with pytest.raises(
        ValidationError
    ):

        EnterpriseTenantBinding(
            **values
        )


# -------------------------------------------------
# SERVER-SIDE CONFIGURATION
# -------------------------------------------------


def test_load_valid_tenant_binding_configuration():

    loaded = (
        load_enterprise_tenant_bindings(
            environment()
        )
    )

    assert isinstance(
        loaded,
        tuple,
    )

    assert loaded == (
        tenant_binding(),
    )


@pytest.mark.parametrize(
    "source",
    [
        {},
        {
            ENTERPRISE_TENANT_BINDINGS_ENV:
                "",
        },
        {
            ENTERPRISE_TENANT_BINDINGS_ENV:
                "   ",
        },
    ],
)
def test_missing_tenant_binding_configuration_fails_closed(
    source,
):

    with pytest.raises(
        EnterpriseTenantBindingError
    ):

        load_enterprise_tenant_bindings(
            source
        )


def test_invalid_tenant_binding_json_fails_closed():

    with pytest.raises(
        EnterpriseTenantBindingError
    ):

        load_enterprise_tenant_bindings(
            {
                ENTERPRISE_TENANT_BINDINGS_ENV:
                    "{invalid-json"
            }
        )


@pytest.mark.parametrize(
    "decoded",
    [
        {},
        [],
        "tenant-a",
        123,
    ],
)
def test_invalid_tenant_binding_structure_fails_closed(
    decoded,
):

    with pytest.raises(
        EnterpriseTenantBindingError
    ):

        load_enterprise_tenant_bindings(
            {
                ENTERPRISE_TENANT_BINDINGS_ENV:
                    json.dumps(
                        decoded
                    )
            }
        )


def test_non_object_tenant_binding_entry_fails_closed():

    with pytest.raises(
        EnterpriseTenantBindingError
    ):

        load_enterprise_tenant_bindings(
            {
                ENTERPRISE_TENANT_BINDINGS_ENV:
                    json.dumps(
                        [
                            "not-an-object"
                        ]
                    )
            }
        )


def test_duplicate_external_tenant_authority_fails_closed():

    first = tenant_binding_dict(
        internal_tenant_id=
            "tenant-a"
    )

    second = tenant_binding_dict(
        internal_tenant_id=
            "tenant-b"
    )

    with pytest.raises(
        EnterpriseTenantBindingError
    ):

        load_enterprise_tenant_bindings(
            {
                ENTERPRISE_TENANT_BINDINGS_ENV:
                    json.dumps(
                        [
                            first,
                            second,
                        ]
                    )
            }
        )


def test_multiple_idp_tenants_may_map_to_same_internal_tenant():

    second_idp_tenant = (
        "22222222-2222-2222-2222-222222222222"
    )

    loaded = (
        load_enterprise_tenant_bindings(
            {
                ENTERPRISE_TENANT_BINDINGS_ENV:
                    json.dumps(
                        [
                            tenant_binding_dict(),
                            tenant_binding_dict(
                                idp_tenant_id=
                                    second_idp_tenant,
                            ),
                        ]
                    )
            }
        )
    )

    assert len(loaded) == 2

    assert {
        item.tenant_id
        for item in loaded
    } == {
        INTERNAL_TENANT_ID
    }


def test_resolve_tenant_from_server_configuration():

    resolved = (
        resolve_enterprise_tenant_from_environment(
            identity(),
            environment=environment(),
        )
    )

    assert resolved == (
        INTERNAL_TENANT_ID
    )


def test_tenant_resolution_error_does_not_echo_identity_value():

    sensitive_tenant = (
        "sensitive-idp-tenant"
    )

    with pytest.raises(
        EnterpriseTenantBindingError
    ) as captured:

        resolve_enterprise_tenant(
            identity(
                tenant_id=sensitive_tenant
            ),
            bindings=(
                tenant_binding(),
            ),
        )

    assert sensitive_tenant not in str(
        captured.value
    )


# -------------------------------------------------
# SECURITY CONTEXT CONSTRUCTION
# -------------------------------------------------


def test_security_context_is_derived_from_same_enterprise_identity():

    context = (
        build_enterprise_security_context(
            identity(),
            session_id=
                SESSION_ID,
            principal_bindings=(
                principal_binding(),
            ),
            tenant_bindings=(
                tenant_binding(),
            ),
        )
    )

    assert context.principal_id == (
        "enterprise-analyst"
    )

    assert context.role == (
        "ANALYST"
    )

    assert context.retrieval_access == (
        "standard"
    )

    assert (
        context.session_revocation_access
        == "self"
    )

    assert context.tenant_id == (
        INTERNAL_TENANT_ID
    )

    assert context.session_id == (
        SESSION_ID
    )


def test_security_context_snapshots_server_authorization():

    context = (
        build_enterprise_security_context(
            identity(),
            session_id=
                SESSION_ID,
            principal_bindings=(
                principal_binding(
                    principal_id=
                        "security-approver",
                    role="APPROVER",
                    retrieval_access=
                        "restricted",
                    session_revocation_access=
                        "tenant_admin",
                ),
            ),
            tenant_bindings=(
                tenant_binding(
                    internal_tenant_id=
                        "tenant-security",
                ),
            ),
        )
    )

    assert context.principal_id == (
        "security-approver"
    )

    assert context.role == (
        "APPROVER"
    )

    assert context.retrieval_access == (
        "restricted"
    )

    assert (
        context.session_revocation_access
        == "tenant_admin"
    )

    assert context.tenant_id == (
        "tenant-security"
    )


def test_security_context_is_immutable():

    context = (
        build_enterprise_security_context(
            identity(),
            session_id=
                SESSION_ID,
            principal_bindings=(
                principal_binding(),
            ),
            tenant_bindings=(
                tenant_binding(),
            ),
        )
    )

    with pytest.raises(
        ValidationError
    ):
        context.tenant_id = "tenant-b"


def test_identity_with_principal_but_no_tenant_binding_fails_closed():

    with pytest.raises(
        EnterpriseTenantBindingError
    ):

        build_enterprise_security_context(
            identity(),
            session_id=
                SESSION_ID,
            principal_bindings=(
                principal_binding(),
            ),
            tenant_bindings=(
                tenant_binding(
                    idp_tenant_id=(
                        "22222222-2222-2222-2222-222222222222"
                    )
                ),
            ),
        )


def test_identity_with_tenant_but_no_principal_binding_fails_closed():

    with pytest.raises(
        EnterprisePrincipalBindingError
    ):

        build_enterprise_security_context(
            identity(),
            session_id=
                SESSION_ID,
            principal_bindings=(
                principal_binding(
                    subject=
                        "different-subject"
                ),
            ),
            tenant_bindings=(
                tenant_binding(),
            ),
        )


@pytest.mark.parametrize(
    "invalid_session_id",
    [
        "",
        "   ",
        " server-session-123",
        "server-session-123 ",
        None,
        123,
    ],
)
def test_invalid_server_session_identity_is_rejected(
    invalid_session_id,
):

    with pytest.raises(
        EnterpriseSecurityContextError
    ):

        build_enterprise_security_context(
            identity(),
            session_id=
                invalid_session_id,
            principal_bindings=(
                principal_binding(),
            ),
            tenant_bindings=(
                tenant_binding(),
            ),
        )


def test_resolve_complete_security_context_from_server_configuration():

    context = (
        resolve_enterprise_security_context(
            identity(),
            session_id=
                SESSION_ID,
            environment=
                environment(),
        )
    )

    assert context.principal_id == (
        "enterprise-analyst"
    )

    assert context.tenant_id == (
        INTERNAL_TENANT_ID
    )

    assert context.session_id == (
        SESSION_ID
    )
