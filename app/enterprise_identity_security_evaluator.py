from __future__ import annotations

import inspect
import json

from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path
from types import SimpleNamespace

import jwt

from cryptography.hazmat.primitives.asymmetric import rsa

from pydantic import ValidationError

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

from app.models import (
    KnowledgeChunk,
)

from app.retrieval_authorization import (
    evaluate_knowledge_chunk_authorization,
)


# -------------------------------------------------
# PROJECT PATH
# -------------------------------------------------


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


ENTERPRISE_IDENTITY_SECURITY_CORPUS_PATH = (
    PROJECT_ROOT
    / "evals"
    / "enterprise_identity_security_cases.json"
)


# -------------------------------------------------
# SYNTHETIC ENTERPRISE IDENTITY AUTHORITY
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

SUBJECT = (
    "enterprise-security-eval-subject"
)

DIRECTORY_OBJECT_ID = (
    "33333333-3333-3333-3333-333333333333"
)

GROUP_A = (
    "44444444-4444-4444-4444-444444444444"
)

GROUP_B = (
    "55555555-5555-5555-5555-555555555555"
)

INTERNAL_TENANT = (
    "enterprise-security-eval-tenant"
)


TRUSTED_PRIVATE_KEY = (
    rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
)

TRUSTED_PUBLIC_KEY = (
    TRUSTED_PRIVATE_KEY.public_key()
)

ATTACKER_PRIVATE_KEY = (
    rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
)


# -------------------------------------------------
# RESULT TYPES
# -------------------------------------------------


@dataclass(frozen=True)
class EnterpriseIdentityCaseResult:

    case_id: str

    expected_behavior: str

    observed_achieved: bool

    execution_error: str | None

    passed: bool


@dataclass(frozen=True)
class EnterpriseIdentitySecurityEvaluationResult:

    total_cases: int

    allowed_cases: int
    blocked_cases: int
    authority_protection_cases: int

    passed_cases: int
    failed_cases: int

    unexpected_allows: int
    unexpected_blocks: int

    authority_failures: int
    execution_errors: int

    passed: bool


# -------------------------------------------------
# STATIC JWKS CLIENT
# -------------------------------------------------


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


# -------------------------------------------------
# CORPUS
# -------------------------------------------------


def load_enterprise_identity_security_cases(
    path: Path = (
        ENTERPRISE_IDENTITY_SECURITY_CORPUS_PATH
    ),
) -> list[dict]:

    cases = json.loads(
        path.read_text(
            encoding="utf-8-sig"
        )
    )

    if not isinstance(
        cases,
        list,
    ):
        raise ValueError(
            "Enterprise identity security corpus "
            "must contain a JSON list."
        )

    return cases


# -------------------------------------------------
# TRUSTED EVALUATION CONFIGURATION
# -------------------------------------------------


def _settings(
) -> EntraTokenValidationSettings:

    return EntraTokenValidationSettings(
        issuer=ISSUER,
        audience=AUDIENCE,
        identity_provider_tenant_id=
            IDP_TENANT,
        jwks_uri=(
            "https://login.microsoftonline.com/"
            "common/discovery/v2.0/keys"
        ),
        leeway_seconds=0,
    )


def _validator(
) -> EntraAccessTokenValidator:

    return EntraAccessTokenValidator(
        _settings(),
        jwks_client=
            StaticJWKClient(
                TRUSTED_PUBLIC_KEY
            ),
    )


def _claims(
    **overrides,
) -> dict:

    now = datetime.now(
        timezone.utc
    )

    values = {
        "iss":
            ISSUER,

        "aud":
            AUDIENCE,

        "sub":
            SUBJECT,

        "tid":
            IDP_TENANT,

        "oid":
            DIRECTORY_OBJECT_ID,

        "iat":
            int(
                now.timestamp()
            ),

        "nbf":
            int(
                (
                    now
                    - timedelta(
                        seconds=1
                    )
                ).timestamp()
            ),

        "exp":
            int(
                (
                    now
                    + timedelta(
                        minutes=5
                    )
                ).timestamp()
            ),
    }

    values.update(
        overrides
    )

    return values


def _token(
    token_claims: dict | None = None,
    *,
    private_key=TRUSTED_PRIVATE_KEY,
) -> str:

    return jwt.encode(
        (
            _claims()
            if token_claims is None
            else token_claims
        ),
        private_key,
        algorithm="RS256",
        headers={
            "kid":
                "enterprise-security-eval-key"
        },
    )


def _validated_token(
    **claim_overrides,
) -> ValidatedEnterpriseToken:

    return _validator().validate_token(
        _token(
            _claims(
                **claim_overrides
            )
        )
    )


def _principal_binding(
) -> EnterprisePrincipalBinding:

    return EnterprisePrincipalBinding(
        issuer=ISSUER,

        identity_provider_tenant_id=
            IDP_TENANT,

        subject=SUBJECT,

        principal_id=
            "enterprise-security-eval-user",

        role="ANALYST",

        retrieval_access="standard",

        session_revocation_access="self",
    )


def _tenant_binding(
) -> EnterpriseTenantBinding:

    return EnterpriseTenantBinding(
        issuer=ISSUER,

        identity_provider_tenant_id=
            IDP_TENANT,

        tenant_id=
            INTERNAL_TENANT,
    )


def _build_retrieval_authority(
    token: ValidatedEnterpriseToken,
):

    return (
        build_enterprise_retrieval_principal_from_validated_token(
            token,

            session_id=
                "enterprise-security-eval-session",

            principal_bindings=(
                _principal_binding(),
            ),

            tenant_bindings=(
                _tenant_binding(),
            ),
        )
    )


def _group_document(
) -> KnowledgeChunk:

    return KnowledgeChunk(
        chunk_id=
            "enterprise-group-document:0:security-eval",

        source_id=
            "enterprise-group-document",

        source_name=
            "enterprise-group-document.md",

        chunk_number=0,

        content=(
            "Synthetic enterprise group-protected "
            "security reference."
        ),

        source_sha256=
            "e" * 64,

        trust_tier=
            "trusted_reference",

        access_level=
            "standard",

        tenant_id=
            INTERNAL_TENANT,

        allowed_group_ids=(
            GROUP_A,
        ),
    )


def _group_access_succeeded(
    token: ValidatedEnterpriseToken,
) -> bool:

    retrieval_principal = (
        _build_retrieval_authority(
            token
        )
    )

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=
                _group_document(),

            retrieval_principal=
                retrieval_principal,
        )
    )

    return decision.allowed


# -------------------------------------------------
# OBSERVE ONE ATTACK / CONTROL
# -------------------------------------------------


def observe_enterprise_identity_case(
    case: dict,
) -> bool:
    """
    Return whether the requested operation or attack
    achieved its objective.

    For legitimate allow cases, True is expected.

    For block/protect_authority cases, True means the
    attacker successfully crossed or changed trusted
    authority and is therefore a security failure.
    """

    attack = case[
        "attack"
    ]

    # -------------------------------------------------
    # LEGITIMATE VALID TOKEN
    # -------------------------------------------------

    if attack == "valid_token":

        validated = (
            _validated_token(
                groups=[
                    GROUP_A,
                ]
            )
        )

        return (
            validated.identity.issuer
            == ISSUER

            and validated.identity.subject
            == SUBJECT

            and (
                validated.identity
                .identity_provider_tenant_id
                == IDP_TENANT
            )
        )

    # -------------------------------------------------
    # LEGITIMATE GROUP-AUTHORIZED RETRIEVAL
    # -------------------------------------------------

    if attack == "valid_group_member":

        return _group_access_succeeded(
            _validated_token(
                groups=[
                    GROUP_A,
                ]
            )
        )

    # -------------------------------------------------
    # FORGED SIGNATURE
    # -------------------------------------------------

    if attack == "forged_signature":

        forged = _token(
            private_key=
                ATTACKER_PRIVATE_KEY
        )

        try:

            _validator().validate_token(
                forged
            )

        except EnterpriseTokenValidationError:

            return False

        return True

    # -------------------------------------------------
    # EXPIRED TOKEN
    # -------------------------------------------------

    if attack == "expired_token":

        expired = _claims(
            exp=int(
                (
                    datetime.now(
                        timezone.utc
                    )
                    - timedelta(
                        minutes=5
                    )
                ).timestamp()
            )
        )

        try:

            _validator().validate_token(
                _token(
                    expired
                )
            )

        except EnterpriseTokenValidationError:

            return False

        return True

    # -------------------------------------------------
    # WRONG ISSUER
    # -------------------------------------------------

    if attack == "wrong_issuer":

        try:

            _validator().validate_token(
                _token(
                    _claims(
                        iss=(
                            "https://attacker.invalid/"
                            "v2.0"
                        )
                    )
                )
            )

        except EnterpriseTokenValidationError:

            return False

        return True

    # -------------------------------------------------
    # WRONG AUDIENCE
    # -------------------------------------------------

    if attack == "wrong_audience":

        try:

            _validator().validate_token(
                _token(
                    _claims(
                        aud=(
                            "attacker-controlled-audience"
                        )
                    )
                )
            )

        except EnterpriseTokenValidationError:

            return False

        return True

    # -------------------------------------------------
    # WRONG IDENTITY-PROVIDER TENANT
    # -------------------------------------------------

    if attack == "wrong_idp_tenant":

        try:

            _validator().validate_token(
                _token(
                    _claims(
                        tid=(
                            "aaaaaaaa-aaaa-aaaa-aaaa-"
                            "aaaaaaaaaaaa"
                        )
                    )
                )
            )

        except EnterpriseTokenValidationError:

            return False

        return True

    # -------------------------------------------------
    # UNKNOWN SIGNED SUBJECT
    # -------------------------------------------------

    if attack == "unknown_subject":

        token = (
            _validated_token(
                sub="attacker-subject",

                groups=[
                    GROUP_A,
                ],
            )
        )

        try:

            _build_retrieval_authority(
                token
            )

        except EnterprisePrincipalBindingError:

            return False

        return True

    # -------------------------------------------------
    # TOKEN ROLE SELF-ELEVATION
    # -------------------------------------------------

    if attack == "token_role_self_elevation":

        token = (
            _validated_token(
                roles=[
                    "APPROVER",
                    "Global.Admin",
                ],

                groups=[
                    GROUP_A,
                ],
            )
        )

        context = (
            build_enterprise_security_context(
                token.identity,

                session_id=
                    "enterprise-security-eval-session",

                principal_bindings=(
                    _principal_binding(),
                ),

                tenant_bindings=(
                    _tenant_binding(),
                ),
            )
        )

        # True means the token claim successfully
        # replaced server-owned application role authority.

        return (
            context.role
            != "ANALYST"
        )

    # -------------------------------------------------
    # EXTERNAL TENANT → INTERNAL TENANT INJECTION
    # -------------------------------------------------

    if attack == "external_tenant_internal_tenant":

        retrieval_principal = (
            _build_retrieval_authority(
                _validated_token(
                    groups=[
                        GROUP_A,
                    ]
                )
            )
        )

        # True means external IdP tenancy replaced or
        # corrupted the application-owned tenant mapping.

        return not (
            retrieval_principal.tenant_id
            == INTERNAL_TENANT

            and retrieval_principal.tenant_id
            != IDP_TENANT
        )

    # -------------------------------------------------
    # MISSING GROUP AUTHORITY
    # -------------------------------------------------

    if attack == "missing_groups_group_access":

        return _group_access_succeeded(
            _validated_token()
        )

    # -------------------------------------------------
    # UNRESOLVED GROUP OVERAGE
    # -------------------------------------------------

    if attack == "unresolved_overage_group_access":

        return _group_access_succeeded(
            _validated_token(
                _claim_names={
                    "groups":
                        "src1"
                },
            )
        )

    # -------------------------------------------------
    # AUTHORITATIVE GROUP NONMEMBER
    # -------------------------------------------------

    if attack == "authoritative_nonmember":

        return _group_access_succeeded(
            _validated_token(
                groups=[
                    GROUP_B,
                ]
            )
        )

    # -------------------------------------------------
    # CALLER AUTHORITY OVERRIDE SURFACE
    # -------------------------------------------------

    if attack == "builder_override_surface":

        parameters = (
            inspect.signature(
                build_enterprise_retrieval_principal_from_validated_token
            )
            .parameters
        )

        forbidden = {
            "principal_id",
            "tenant_id",
            "role",
            "retrieval_access",
            "group_ids",
        }

        # True means caller-controlled authority became
        # part of the trusted enterprise builder API.

        return bool(
            forbidden
            & set(
                parameters
            )
        )

    # -------------------------------------------------
    # VALIDATED TOKEN AUTHORIZATION INJECTION
    # -------------------------------------------------

    if attack == "validated_token_extra_authority":

        validated = (
            _validated_token(
                groups=[
                    GROUP_A,
                ]
            )
        )

        payload = (
            validated.model_dump()
        )

        payload[
            "tenant_id"
        ] = "attacker-tenant"

        payload[
            "role"
        ] = "APPROVER"

        payload[
            "retrieval_access"
        ] = "restricted"

        payload[
            "group_ids"
        ] = [
            GROUP_A
        ]

        try:

            ValidatedEnterpriseToken.model_validate(
                payload
            )

        except ValidationError:

            return False

        return True

    # -------------------------------------------------
    # RAW TOKEN RETENTION
    # -------------------------------------------------

    if attack == "raw_token_retention":

        raw_token = (
            _token(
                _claims(
                    groups=[
                        GROUP_A,
                    ]
                )
            )
        )

        validated = (
            _validator().validate_token(
                raw_token
            )
        )

        # True means bearer credential material crossed
        # the validated identity boundary and remained
        # reachable through trusted state.

        return (
            raw_token
            in repr(
                validated
            )

            or raw_token
            in validated.model_dump_json()
        )

    raise ValueError(
        "Unknown enterprise identity attack: "
        f"{attack}"
    )


# -------------------------------------------------
# EVALUATE ONE CASE
# -------------------------------------------------


def evaluate_enterprise_identity_case(
    case: dict,
) -> EnterpriseIdentityCaseResult:

    expected = case[
        "expected_behavior"
    ]

    if expected not in {
        "allow",
        "block",
        "protect_authority",
    }:

        raise ValueError(
            "Unknown enterprise identity expected "
            f"behavior: {expected}"
        )

    observed_achieved = False
    execution_error = None

    try:

        observed_achieved = (
            observe_enterprise_identity_case(
                case
            )
        )

    except Exception as error:

        execution_error = (
            type(error).__name__
        )

    if execution_error is not None:

        passed = False

    elif expected == "allow":

        passed = (
            observed_achieved
            is True
        )

    else:

        passed = (
            observed_achieved
            is False
        )

    return EnterpriseIdentityCaseResult(
        case_id=
            case["id"],

        expected_behavior=
            expected,

        observed_achieved=
            observed_achieved,

        execution_error=
            execution_error,

        passed=
            passed,
    )


# -------------------------------------------------
# RUN COMPLETE CORPUS
# -------------------------------------------------


def run_enterprise_identity_security_evaluation(
    path: Path = (
        ENTERPRISE_IDENTITY_SECURITY_CORPUS_PATH
    ),
) -> EnterpriseIdentitySecurityEvaluationResult:

    cases = (
        load_enterprise_identity_security_cases(
            path
        )
    )

    results = [
        evaluate_enterprise_identity_case(
            case
        )
        for case in cases
    ]

    allowed_cases = sum(
        1
        for case in cases
        if case[
            "expected_behavior"
        ] == "allow"
    )

    blocked_cases = sum(
        1
        for case in cases
        if case[
            "expected_behavior"
        ] == "block"
    )

    authority_protection_cases = sum(
        1
        for case in cases
        if case[
            "expected_behavior"
        ] == "protect_authority"
    )

    passed_cases = sum(
        1
        for result in results
        if result.passed
    )

    failed_cases = (
        len(results)
        - passed_cases
    )

    unexpected_allows = sum(
        1
        for result in results
        if (
            result.execution_error
            is None

            and result.expected_behavior
            in {
                "block",
                "protect_authority",
            }

            and result.observed_achieved
        )
    )

    unexpected_blocks = sum(
        1
        for result in results
        if (
            result.execution_error
            is None

            and result.expected_behavior
            == "allow"

            and not result.observed_achieved
        )
    )

    authority_failures = sum(
        1
        for result in results
        if (
            result.execution_error
            is None

            and result.expected_behavior
            == "protect_authority"

            and result.observed_achieved
        )
    )

    execution_errors = sum(
        1
        for result in results
        if result.execution_error
        is not None
    )

    return EnterpriseIdentitySecurityEvaluationResult(
        total_cases=
            len(results),

        allowed_cases=
            allowed_cases,

        blocked_cases=
            blocked_cases,

        authority_protection_cases=
            authority_protection_cases,

        passed_cases=
            passed_cases,

        failed_cases=
            failed_cases,

        unexpected_allows=
            unexpected_allows,

        unexpected_blocks=
            unexpected_blocks,

        authority_failures=
            authority_failures,

        execution_errors=
            execution_errors,

        passed=(
            failed_cases == 0
            and execution_errors == 0
        ),
    )
