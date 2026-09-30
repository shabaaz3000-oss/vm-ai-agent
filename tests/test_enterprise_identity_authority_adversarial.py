from __future__ import annotations

import inspect

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from types import SimpleNamespace

import jwt
import pytest

from cryptography.hazmat.primitives.asymmetric import rsa

from pydantic import ValidationError

from app.api import app as api_app

from app.auth import Principal

from app.enterprise_authorization_evidence import (
    ValidatedEnterpriseToken,
)

from app.enterprise_principal_binding import (
    EnterprisePrincipalBinding,
    EnterprisePrincipalBindingError,
)

from app.enterprise_security_context import (
    build_enterprise_retrieval_principal_from_validated_token,
    build_enterprise_security_context,
)

from app.enterprise_tenant_binding import (
    EnterpriseTenantBinding,
)

from app.entra_token_validator import (
    EntraAccessTokenValidator,
    EntraTokenValidationSettings,
    EnterpriseTokenValidationError,
)

from app.mcp_server import (
    mcp_get_asset_details,
    mcp_get_finding,
    mcp_get_threat_intel,
    mcp_search_knowledge,
)

from app.mcp_session import (
    MCPSessionAccessDenied,
    MCPSessionManager,
    MCPSessionRevoked,
)

from app.mcp_tenant import resolve_mcp_tenant

from app.models import KnowledgeChunk

from app.retrieval_authorization import (
    RetrievalPrincipal,
    evaluate_knowledge_chunk_authorization,
)

from app.retriever import KnowledgeRetriever

from app.security_context import SecurityContext

from app.tools.dispatcher import (
    ToolExecutionContext,
    dispatch_llm_tool,
)

from app.tools.knowledge import search_knowledge

from app.tools.openai_tools import build_openai_tools


# -------------------------------------------------
# TEST AUTHORITY
# -------------------------------------------------


IDP_TENANT = (
    "11111111-1111-1111-1111-111111111111"
)

AUDIENCE = (
    "22222222-2222-2222-2222-222222222222"
)

ISSUER = (
    "https://login.microsoftonline.com/"
    f"{IDP_TENANT}/v2.0"
)

SUBJECT = "enterprise-subject-123"

DIRECTORY_OBJECT_ID = (
    "33333333-3333-3333-3333-333333333333"
)

GROUP_A = (
    "44444444-4444-4444-4444-444444444444"
)

GROUP_B = (
    "55555555-5555-5555-5555-555555555555"
)

INTERNAL_TENANT = "tenant-internal-a"

PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

PUBLIC_KEY = PRIVATE_KEY.public_key()

ATTACKER_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)


class StaticJWKClient:

    def __init__(
        self,
        key,
    ) -> None:

        self.key = key

    def get_signing_key_from_jwt(
        self,
        token,
    ):

        return SimpleNamespace(
            key=self.key
        )


def validation_settings(
) -> EntraTokenValidationSettings:

    return EntraTokenValidationSettings(
        issuer=ISSUER,
        audience=AUDIENCE,
        identity_provider_tenant_id=
            IDP_TENANT,
        jwks_uri=(
            f"{ISSUER}/discovery/v2.0/keys"
        ),
        leeway_seconds=0,
    )


def validator(
) -> EntraAccessTokenValidator:

    return EntraAccessTokenValidator(
        validation_settings(),
        jwks_client=
            StaticJWKClient(
                PUBLIC_KEY
            ),
    )


def claims(
    **overrides,
):

    now = datetime.now(
        timezone.utc
    )

    values = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": SUBJECT,
        "tid": IDP_TENANT,
        "oid": DIRECTORY_OBJECT_ID,
        "iat": now,
        "nbf": now - timedelta(
            seconds=1
        ),
        "exp": now + timedelta(
            minutes=5
        ),
    }

    values.update(
        overrides
    )

    return values


def token_for(
    token_claims=None,
    *,
    private_key=PRIVATE_KEY,
):

    return jwt.encode(
        (
            claims()
            if token_claims is None
            else token_claims
        ),
        private_key,
        algorithm="RS256",
        headers={
            "kid": "step47-8-test-key"
        },
    )


def validated_token(
    **claim_overrides,
) -> ValidatedEnterpriseToken:

    return validator().validate_token(
        token_for(
            claims(
                **claim_overrides
            )
        )
    )


def principal_binding(
    *,
    subject=SUBJECT,
    role="ANALYST",
    retrieval_access="standard",
):

    return EnterprisePrincipalBinding(
        issuer=ISSUER,
        identity_provider_tenant_id=
            IDP_TENANT,
        subject=subject,
        principal_id="enterprise-alice",
        role=role,
        retrieval_access=
            retrieval_access,
        session_revocation_access="self",
    )


def tenant_binding():

    return EnterpriseTenantBinding(
        issuer=ISSUER,
        identity_provider_tenant_id=
            IDP_TENANT,
        tenant_id=INTERNAL_TENANT,
    )


def group_protected_chunk(
    group_id=GROUP_A,
):

    return KnowledgeChunk(
        chunk_id="group-doc:0:test",
        source_id="group-doc",
        source_name="group-doc.md",
        chunk_number=0,
        content="Restricted enterprise group guidance.",
        source_sha256="a" * 64,
        trust_tier="trusted_reference",
        access_level="standard",
        tenant_id=INTERNAL_TENANT,
        allowed_group_ids=(
            group_id,
        ),
    )


# -------------------------------------------------
# CRYPTOGRAPHIC TOKEN ATTACKS
# -------------------------------------------------


def test_forged_signature_cannot_create_enterprise_authority():

    forged = token_for(
        private_key=
            ATTACKER_PRIVATE_KEY
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate_token(
            forged
        )


def test_expired_token_cannot_create_enterprise_authority():

    expired = claims(
        exp=(
            datetime.now(
                timezone.utc
            )
            - timedelta(
                minutes=5
            )
        )
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate_token(
            token_for(
                expired
            )
        )


@pytest.mark.parametrize(
    "claim_override",
    [
        {
            "iss":
                "https://attacker.invalid/v2.0",
        },
        {
            "aud":
                "attacker-controlled-audience",
        },
        {
            "tid":
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        },
    ],
)
def test_trusted_signature_does_not_override_trust_configuration(
    claim_override,
):

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate_token(
            token_for(
                claims(
                    **claim_override
                )
            )
        )


# -------------------------------------------------
# SERVER-OWNED APPLICATION AUTHORIZATION
# -------------------------------------------------


def test_token_app_roles_cannot_self_elevate_application_role():

    token = validated_token(
        roles=[
            "APPROVER",
            "Global.Admin",
        ],
        groups=[
            GROUP_A,
        ],
    )

    context = build_enterprise_security_context(
        token.identity,
        session_id="server-session",
        principal_bindings=(
            principal_binding(
                role="ANALYST",
                retrieval_access=
                    "standard",
            ),
        ),
        tenant_bindings=(
            tenant_binding(),
        ),
    )

    assert context.role == "ANALYST"

    assert (
        context.retrieval_access
        == "standard"
    )


def test_idp_tenant_is_not_copied_into_internal_tenant_scope():

    token = validated_token(
        groups=[
            GROUP_A,
        ],
    )

    retrieval = (
        build_enterprise_retrieval_principal_from_validated_token(
            token,
            session_id="server-session",
            principal_bindings=(
                principal_binding(),
            ),
            tenant_bindings=(
                tenant_binding(),
            ),
        )
    )

    assert (
        retrieval.tenant_id
        == INTERNAL_TENANT
    )

    assert (
        retrieval.tenant_id
        != IDP_TENANT
    )


def test_unknown_signed_subject_cannot_reuse_known_application_binding():

    token = validated_token(
        sub="attacker-subject",
        groups=[
            GROUP_A,
        ],
    )

    with pytest.raises(
        EnterprisePrincipalBindingError
    ):

        build_enterprise_security_context(
            token.identity,
            session_id="server-session",
            principal_bindings=(
                principal_binding(),
            ),
            tenant_bindings=(
                tenant_binding(),
            ),
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "principal_id",
        "tenant_id",
        "role",
        "retrieval_access",
        "group_ids",
    ],
)
def test_enterprise_retrieval_builder_exposes_no_caller_authority_override(
    field_name,
):

    parameters = inspect.signature(
        build_enterprise_retrieval_principal_from_validated_token
    ).parameters

    assert field_name not in parameters


def test_validated_token_rejects_injected_application_authorization_fields():

    token = validated_token(
        groups=[
            GROUP_A,
        ],
    )

    payload = token.model_dump()

    payload[
        "tenant_id"
    ] = "attacker-tenant"

    payload[
        "role"
    ] = "APPROVER"

    payload[
        "retrieval_access"
    ] = "restricted"

    with pytest.raises(
        ValidationError
    ):

        ValidatedEnterpriseToken.model_validate(
            payload
        )


# -------------------------------------------------
# GROUP AUTHORITY FAIL-CLOSED ATTACKS
# -------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        lambda: validated_token(),
        lambda: validated_token(
            _claim_names={
                "groups": "src1"
            },
        ),
    ],
)
def test_incomplete_group_authority_cannot_unlock_group_document(
    token,
):

    retrieval = (
        build_enterprise_retrieval_principal_from_validated_token(
            token(),
            session_id="server-session",
            principal_bindings=(
                principal_binding(),
            ),
            tenant_bindings=(
                tenant_binding(),
            ),
        )
    )

    assert retrieval.group_ids is None

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=
                group_protected_chunk(),
            retrieval_principal=
                retrieval,
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "group_membership_unavailable"
    )


def test_authoritative_nonmember_cannot_claim_group_access():

    token = validated_token(
        groups=[
            GROUP_B,
        ],
    )

    retrieval = (
        build_enterprise_retrieval_principal_from_validated_token(
            token,
            session_id="server-session",
            principal_bindings=(
                principal_binding(),
            ),
            tenant_bindings=(
                tenant_binding(),
            ),
        )
    )

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=
                group_protected_chunk(
                    GROUP_A
                ),
            retrieval_principal=
                retrieval,
        )
    )

    assert decision.allowed is False
    assert decision.reason == "group_acl_denied"


def test_tampered_group_authority_fails_closed_at_policy_boundary():

    tampered = RetrievalPrincipal.model_construct(
        principal_id="enterprise-alice",
        tenant_id=INTERNAL_TENANT,
        retrieval_access="standard",
        group_ids=(
            "attacker-controlled-group",
        ),
    )

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=
                group_protected_chunk(),
            retrieval_principal=
                tampered,
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "invalid_group_authority"
    )


def test_retrieval_principal_rejects_unrelated_authority_fields():

    with pytest.raises(
        ValidationError
    ):

        RetrievalPrincipal(
            principal_id="enterprise-alice",
            tenant_id=INTERNAL_TENANT,
            retrieval_access="standard",
            group_ids=(),
            role="APPROVER",
            oid=DIRECTORY_OBJECT_ID,
            sub=SUBJECT,
            tid=IDP_TENANT,
        )


def test_legacy_caller_access_cannot_override_trusted_retrieval_principal():

    subject = KnowledgeRetriever(
        index=[]
    )

    trusted = RetrievalPrincipal(
        principal_id="enterprise-alice",
        tenant_id=INTERNAL_TENANT,
        retrieval_access="standard",
        group_ids=(),
    )

    with pytest.raises(
        ValueError,
        match="caller_access cannot be supplied",
    ):

        subject.retrieve(
            query="security guidance",
            caller_access="restricted",
            retrieval_principal=
                trusted,
        )


# -------------------------------------------------
# EXTERNAL TOOL / MCP AUTHORITY-INJECTION SURFACES
# -------------------------------------------------


def test_openai_tool_schemas_expose_no_identity_authority_arguments():

    for tool in build_openai_tools():

        parameters = tool[
            "parameters"
        ]

        assert parameters[
            "properties"
        ] == {}

        assert (
            parameters[
                "additionalProperties"
            ]
            is False
        )


@pytest.mark.parametrize(
    "mcp_function",
    [
        mcp_get_finding,
        mcp_get_asset_details,
        mcp_get_threat_intel,
        mcp_search_knowledge,
    ],
)
def test_mcp_tool_functions_accept_no_client_identity_arguments(
    mcp_function,
):

    assert (
        len(
            inspect.signature(
                mcp_function
            ).parameters
        )
        == 0
    )


def test_search_knowledge_interface_exposes_no_identity_override_fields():

    parameters = inspect.signature(
        search_knowledge
    ).parameters

    forbidden = {
        "tenant_id",
        "principal_id",
        "role",
        "retrieval_access",
        "group_ids",
        "oid",
        "sub",
        "tid",
        "retrieval_principal",
    }

    assert not (
        forbidden
        & set(
            parameters
        )
    )


def test_mcp_tenant_resolver_exposes_no_caller_tenant_argument():

    parameters = inspect.signature(
        resolve_mcp_tenant
    ).parameters

    assert "tenant_id" not in parameters


def test_http_workflow_endpoints_expose_no_request_identity_authority():

    schema = api_app.openapi()

    protected_operations = (
        (
            "/workflows",
            "post",
        ),
        (
            "/workflows/{workflow_id}",
            "get",
        ),
        (
            "/workflows/{workflow_id}/approve",
            "post",
        ),
        (
            "/workflows/{workflow_id}/reject",
            "post",
        ),
        (
            "/workflows/{workflow_id}/reconcile",
            "post",
        ),
    )

    forbidden = {
        "tenant_id",
        "principal_id",
        "role",
        "retrieval_access",
        "group_ids",
        "oid",
        "sub",
        "tid",
    }

    for path, method in protected_operations:

        operation = (
            schema[
                "paths"
            ][
                path
            ][
                method
            ]
        )

        assert (
            "requestBody"
            not in operation
        )

        parameter_names = {
            parameter[
                "name"
            ]
            for parameter
            in operation.get(
                "parameters",
                [],
            )
        }

        assert not (
            forbidden
            & parameter_names
        )


# -------------------------------------------------
# SESSION / MUTABLE-IDENTITY ATTACKS
# -------------------------------------------------


@pytest.mark.parametrize(
    (
        "attribute",
        "value",
        "message",
    ),
    [
        (
            "username",
            "attacker",
            "principal mismatch",
        ),
        (
            "role",
            "APPROVER",
            "role mismatch",
        ),
        (
            "retrieval_access",
            "restricted",
            "retrieval access mismatch",
        ),
    ],
)
def test_mutable_principal_drift_is_rejected_before_tool_execution(
    attribute,
    value,
    message,
):

    principal = Principal(
        username="enterprise-alice",
        role="ANALYST",
        retrieval_access="standard",
    )

    context = SecurityContext.from_principal(
        principal,
        tenant_id=INTERNAL_TENANT,
        session_id="server-session",
    )

    execution = ToolExecutionContext(
        principal=principal,
        security_context=context,
    )

    setattr(
        principal,
        attribute,
        value,
    )

    with pytest.raises(
        ValueError,
        match=message,
    ):

        dispatch_llm_tool(
            tool_name="get_finding",
            context=execution,
        )


def test_cross_tenant_session_value_cannot_build_security_context():

    manager = MCPSessionManager()

    principal = Principal(
        username="enterprise-alice",
        role="ANALYST",
    )

    session = manager.create_session(
        principal,
        tenant_id=INTERNAL_TENANT,
    )

    with pytest.raises(
        MCPSessionAccessDenied
    ):

        manager.build_security_context(
            principal,
            session_id=
                session.session_id,
            tenant_id=
                "attacker-tenant",
        )


def test_revoked_stale_session_cannot_recreate_execution_authority():

    manager = MCPSessionManager()

    principal = Principal(
        username="enterprise-alice",
        role="ANALYST",
    )

    session = manager.create_session(
        principal,
        tenant_id=INTERNAL_TENANT,
    )

    manager.revoke_session(
        principal,
        session_id=
            session.session_id,
        tenant_id=
            INTERNAL_TENANT,
    )

    with pytest.raises(
        MCPSessionRevoked
    ):

        manager.build_security_context(
            principal,
            session_id=
                session.session_id,
            tenant_id=
                INTERNAL_TENANT,
        )
