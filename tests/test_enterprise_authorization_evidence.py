from __future__ import annotations

from datetime import datetime
from datetime import timedelta
from datetime import timezone
from types import SimpleNamespace

import jwt
import pytest

from cryptography.hazmat.primitives.asymmetric import rsa

from app.entra_token_validator import (
    EntraAccessTokenValidator,
    EntraTokenValidationSettings,
    EnterpriseTokenValidationError,
)

from app.enterprise_authorization_evidence import (
    EnterpriseGroupMembershipUnavailable,
    require_authoritative_group_ids,
)


ISSUER = (
    "https://login.microsoftonline.com/"
    "11111111-1111-1111-1111-111111111111/"
    "v2.0"
)

TENANT_ID = (
    "11111111-1111-1111-1111-111111111111"
)

AUDIENCE = (
    "22222222-2222-2222-2222-222222222222"
)

SUBJECT = "enterprise-subject-123"

OID = (
    "33333333-3333-3333-3333-333333333333"
)

GROUP_ONE = (
    "44444444-4444-4444-4444-444444444444"
)

GROUP_TWO = (
    "55555555-5555-5555-5555-555555555555"
)

JWKS_URI = (
    "https://login.microsoftonline.com/"
    f"{TENANT_ID}/discovery/v2.0/keys"
)


PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

PUBLIC_KEY = PRIVATE_KEY.public_key()


class StaticJWKClient:

    def get_signing_key_from_jwt(
        self,
        token,
    ):

        return SimpleNamespace(
            key=PUBLIC_KEY
        )


def settings():

    return EntraTokenValidationSettings(
        issuer=ISSUER,
        audience=AUDIENCE,
        identity_provider_tenant_id=
            TENANT_ID,
        jwks_uri=JWKS_URI,
        leeway_seconds=0,
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
        "tid": TENANT_ID,
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
    token_claims,
):

    return jwt.encode(
        token_claims,
        PRIVATE_KEY,
        algorithm="RS256",
        headers={
            "kid": "test-key"
        },
    )


def validator():

    return EntraAccessTokenValidator(
        settings(),
        jwks_client=
            StaticJWKClient(),
    )


# -------------------------------------------------
# VALID ROLE + GROUP EVIDENCE
# -------------------------------------------------


def test_validated_token_contains_authoritative_role_and_group_evidence():

    token = token_for(
        claims(
            oid=OID,
            roles=[
                "VM.Approver",
                "VM.Reader",
            ],
            groups=[
                GROUP_TWO,
                GROUP_ONE,
            ],
        )
    )

    result = validator().validate_token(
        token
    )

    assert result.identity.subject == (
        SUBJECT
    )

    assert result.authorization.app_roles == (
        "VM.Approver",
        "VM.Reader",
    )

    assert (
        result.authorization.group_membership_state
        == "complete"
    )

    assert result.authorization.group_ids == (
        GROUP_ONE,
        GROUP_TWO,
    )

    assert (
        result.authorization.directory_object_id
        == OID
    )


def test_existing_validate_interface_remains_identity_only():

    token = token_for(
        claims(
            roles=[
                "VM.Reader"
            ]
        )
    )

    identity = validator().validate(
        token
    )

    assert identity.subject == SUBJECT

    assert set(
        identity.model_dump()
    ) == {
        "issuer",
        "subject",
        "identity_provider_tenant_id",
    }


# -------------------------------------------------
# GROUP CLAIM ABSENCE VS COMPLETE EMPTY
# -------------------------------------------------


def test_absent_group_claim_is_not_treated_as_complete_empty_membership():

    result = validator().validate_token(
        token_for(
            claims()
        )
    )

    evidence = result.authorization

    assert (
        evidence.group_membership_state
        == "not_present"
    )

    assert evidence.group_ids == ()

    with pytest.raises(
        EnterpriseGroupMembershipUnavailable
    ):

        require_authoritative_group_ids(
            evidence
        )


def test_explicit_empty_groups_claim_is_complete():

    result = validator().validate_token(
        token_for(
            claims(
                groups=[]
            )
        )
    )

    evidence = result.authorization

    assert (
        evidence.group_membership_state
        == "complete"
    )

    assert (
        require_authoritative_group_ids(
            evidence
        )
        == ()
    )


# -------------------------------------------------
# GROUP OVERAGE
# -------------------------------------------------


def test_claim_names_group_overage_is_detected():

    result = validator().validate_token(
        token_for(
            claims(
                oid=OID,
                _claim_names={
                    "groups": "src1"
                },
                _claim_sources={
                    "src1": {
                        "endpoint": (
                            "https://attacker.example.test/"
                            "groups"
                        )
                    }
                },
            )
        )
    )

    evidence = result.authorization

    assert (
        evidence.group_membership_state
        == "overage"
    )

    assert evidence.group_ids == ()

    with pytest.raises(
        EnterpriseGroupMembershipUnavailable
    ):

        require_authoritative_group_ids(
            evidence
        )


def test_hasgroups_overage_is_detected():

    result = validator().validate_token(
        token_for(
            claims(
                oid=OID,
                hasgroups=True,
            )
        )
    )

    assert (
        result.authorization
        .group_membership_state
        == "overage"
    )


def test_overage_and_inline_groups_is_rejected():

    token = token_for(
        claims(
            oid=OID,
            groups=[
                GROUP_ONE
            ],
            _claim_names={
                "groups": "src1"
            },
        )
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate_token(
            token
        )


def test_group_overage_without_oid_is_rejected():

    token = token_for(
        claims(
            _claim_names={
                "groups": "src1"
            }
        )
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate_token(
            token
        )


# -------------------------------------------------
# MALFORMED ROLES
# -------------------------------------------------


@pytest.mark.parametrize(
    "invalid_roles",
    [
        "VM.Reader",
        [
            ""
        ],
        [
            "   "
        ],
        [
            123
        ],
    ],
)
def test_malformed_roles_claim_is_rejected(
    invalid_roles,
):

    token = token_for(
        claims(
            roles=invalid_roles
        )
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate_token(
            token
        )


# -------------------------------------------------
# MALFORMED GROUPS
# -------------------------------------------------


@pytest.mark.parametrize(
    "invalid_groups",
    [
        GROUP_ONE,
        [
            ""
        ],
        [
            "not-a-guid"
        ],
        [
            123
        ],
    ],
)
def test_malformed_groups_claim_is_rejected(
    invalid_groups,
):

    token = token_for(
        claims(
            groups=invalid_groups
        )
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate_token(
            token
        )


# -------------------------------------------------
# CANONICALIZATION
# -------------------------------------------------


def test_duplicate_roles_and_groups_are_canonicalized():

    result = validator().validate_token(
        token_for(
            claims(
                roles=[
                    "VM.Reader",
                    "VM.Reader",
                ],
                groups=[
                    GROUP_ONE.upper(),
                    GROUP_ONE,
                ],
            )
        )
    )

    assert result.authorization.app_roles == (
        "VM.Reader",
    )

    assert result.authorization.group_ids == (
        GROUP_ONE,
    )


# -------------------------------------------------
# MALFORMED OVERAGE SIGNALS
# -------------------------------------------------


@pytest.mark.parametrize(
    "claim_names",
    [
        "groups",
        [],
        {
            "groups": ""
        },
    ],
)
def test_malformed_claim_names_is_rejected(
    claim_names,
):

    token = token_for(
        claims(
            oid=OID,
            _claim_names=
                claim_names,
        )
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate_token(
            token
        )


def test_hasgroups_false_is_rejected():

    token = token_for(
        claims(
            oid=OID,
            hasgroups=False,
        )
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate_token(
            token
        )


# -------------------------------------------------
# DISTRIBUTED CLAIM URL IS NOT AUTHORITY
# -------------------------------------------------


def test_token_supplied_overage_endpoint_is_not_stored_or_trusted():

    malicious_endpoint = (
        "https://attacker.example.test/"
        "steal-token"
    )

    result = validator().validate_token(
        token_for(
            claims(
                oid=OID,
                _claim_names={
                    "groups": "src1"
                },
                _claim_sources={
                    "src1": {
                        "endpoint":
                            malicious_endpoint
                    }
                },
            )
        )
    )

    serialized = str(
        result.model_dump()
    )

    assert malicious_endpoint not in serialized


# -------------------------------------------------
# RAW TOKEN HYGIENE
# -------------------------------------------------


def test_validated_token_result_does_not_store_raw_token():

    token = token_for(
        claims(
            oid=OID,
            roles=[
                "VM.Reader"
            ],
            groups=[
                GROUP_ONE
            ],
        )
    )

    result = validator().validate_token(
        token
    )

    assert token not in str(
        result.model_dump()
    )
