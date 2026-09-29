from __future__ import annotations

from datetime import datetime
from datetime import timedelta
from datetime import timezone
from types import SimpleNamespace

import jwt
import pytest

from cryptography.hazmat.primitives.asymmetric import rsa

from jwt.exceptions import PyJWKClientError

from app.entra_token_validator import (
    ALLOWED_SIGNING_ALGORITHMS,
    EntraAccessTokenValidator,
    EntraTokenValidationSettings,
    EnterpriseTokenValidationError,
)


ISSUER = (
    "https://login.microsoftonline.com/"
    "11111111-1111-1111-1111-111111111111/"
    "v2.0"
)

AUDIENCE = (
    "22222222-2222-2222-2222-222222222222"
)

TENANT_ID = (
    "11111111-1111-1111-1111-111111111111"
)

SUBJECT = "enterprise-subject-123"

JWKS_URI = (
    "https://login.microsoftonline.com/"
    f"{TENANT_ID}/discovery/v2.0/keys"
)


# -------------------------------------------------
# TEST KEY MATERIAL
# -------------------------------------------------


PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

PUBLIC_KEY = PRIVATE_KEY.public_key()


SECOND_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)


# -------------------------------------------------
# TEST JWKS CLIENT
# -------------------------------------------------


class StaticJWKClient:

    def __init__(
        self,
        key,
    ):

        self.key = key

        self.received_token = None

    def get_signing_key_from_jwt(
        self,
        token,
    ):

        self.received_token = token

        return SimpleNamespace(
            key=self.key
        )


class RejectingJWKClient:

    def get_signing_key_from_jwt(
        self,
        token,
    ):

        raise PyJWKClientError(
            "unknown signing key"
        )


# -------------------------------------------------
# HELPERS
# -------------------------------------------------


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
    token_claims=None,
    *,
    private_key=PRIVATE_KEY,
    algorithm="RS256",
):

    return jwt.encode(
        (
            claims()
            if token_claims is None
            else token_claims
        ),
        private_key,
        algorithm=algorithm,
        headers={
            "kid": "test-key-1"
        },
    )


def validator(
    *,
    key=PUBLIC_KEY,
):

    return EntraAccessTokenValidator(
        settings(),
        jwks_client=
            StaticJWKClient(
                key
            ),
    )


# -------------------------------------------------
# FIXED CRYPTO POLICY
# -------------------------------------------------


def test_signing_algorithm_policy_is_fixed_to_rs256():

    assert ALLOWED_SIGNING_ALGORITHMS == (
        "RS256",
    )


# -------------------------------------------------
# VALID TOKEN
# -------------------------------------------------


def test_valid_access_token_creates_enterprise_identity():

    identity = validator().validate(
        token_for()
    )

    assert identity.issuer == ISSUER

    assert identity.subject == SUBJECT

    assert (
        identity.identity_provider_tenant_id
        == TENANT_ID
    )


def test_raw_token_is_not_stored_in_enterprise_identity():

    token = token_for()

    identity = validator().validate(
        token
    )

    serialized = str(
        identity.model_dump()
    )

    assert token not in serialized

    assert set(
        identity.model_dump()
    ) == {
        "issuer",
        "subject",
        "identity_provider_tenant_id",
    }


# -------------------------------------------------
# SIGNATURE VALIDATION
# -------------------------------------------------


def test_invalid_signature_is_rejected():

    forged = token_for(
        private_key=
            SECOND_PRIVATE_KEY
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate(
            forged
        )


def test_unknown_signing_key_is_rejected():

    subject = EntraAccessTokenValidator(
        settings(),
        jwks_client=
            RejectingJWKClient(),
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        subject.validate(
            token_for()
        )


def test_non_rs256_algorithm_is_rejected():

    token = jwt.encode(
        claims(),
        "a" * 64,
        algorithm="HS256",
        headers={
            "kid": "forged-hmac-key"
        },
    )

    subject = EntraAccessTokenValidator(
        settings(),
        jwks_client=
            StaticJWKClient(
                "a" * 64
            ),
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        subject.validate(
            token
        )


# -------------------------------------------------
# ISSUER / AUDIENCE
# -------------------------------------------------


def test_wrong_issuer_is_rejected():

    forged_claims = claims(
        iss=(
            "https://login.microsoftonline.com/"
            "99999999-9999-9999-9999-999999999999/"
            "v2.0"
        )
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate(
            token_for(
                forged_claims
            )
        )


def test_wrong_audience_is_rejected():

    forged_claims = claims(
        aud=(
            "33333333-3333-3333-3333-333333333333"
        )
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate(
            token_for(
                forged_claims
            )
        )


def test_multiple_audiences_are_rejected_fail_closed():

    forged_claims = claims(
        aud=[
            AUDIENCE,
            "another-api",
        ]
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate(
            token_for(
                forged_claims
            )
        )


# -------------------------------------------------
# TOKEN LIFETIME
# -------------------------------------------------


def test_expired_token_is_rejected():

    now = datetime.now(
        timezone.utc
    )

    forged_claims = claims(
        iat=
            now - timedelta(
                minutes=10
            ),
        nbf=
            now - timedelta(
                minutes=10
            ),
        exp=
            now - timedelta(
                minutes=5
            ),
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate(
            token_for(
                forged_claims
            )
        )


def test_future_not_before_is_rejected():

    now = datetime.now(
        timezone.utc
    )

    forged_claims = claims(
        iat=now,
        nbf=
            now + timedelta(
                minutes=5
            ),
        exp=
            now + timedelta(
                minutes=10
            ),
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate(
            token_for(
                forged_claims
            )
        )


def test_future_issued_at_is_rejected():

    now = datetime.now(
        timezone.utc
    )

    forged_claims = claims(
        iat=
            now + timedelta(
                minutes=5
            ),
        nbf=
            now - timedelta(
                seconds=1
            ),
        exp=
            now + timedelta(
                minutes=10
            ),
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate(
            token_for(
                forged_claims
            )
        )


# -------------------------------------------------
# TENANT BINDING
# -------------------------------------------------


def test_wrong_identity_provider_tenant_is_rejected():

    forged_claims = claims(
        tid=(
            "99999999-9999-9999-9999-999999999999"
        )
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate(
            token_for(
                forged_claims
            )
        )


# -------------------------------------------------
# REQUIRED CLAIMS
# -------------------------------------------------


@pytest.mark.parametrize(
    "missing_claim",
    [
        "iss",
        "aud",
        "exp",
        "nbf",
        "iat",
        "sub",
        "tid",
    ],
)
def test_required_security_claims_cannot_be_omitted(
    missing_claim,
):

    token_claims = claims()

    del token_claims[
        missing_claim
    ]

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate(
            token_for(
                token_claims
            )
        )


# -------------------------------------------------
# MALFORMED IDENTITY
# -------------------------------------------------


@pytest.mark.parametrize(
    "invalid_subject",
    [
        "",
        "   ",
    ],
)
def test_empty_subject_is_rejected(
    invalid_subject,
):

    forged_claims = claims(
        sub=invalid_subject
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate(
            token_for(
                forged_claims
            )
        )


@pytest.mark.parametrize(
    "invalid_tenant",
    [
        "",
        "   ",
    ],
)
def test_empty_tenant_is_rejected(
    invalid_tenant,
):

    forged_claims = claims(
        tid=invalid_tenant
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate(
            token_for(
                forged_claims
            )
        )


def test_blank_token_is_rejected_before_jwt_processing():

    with pytest.raises(
        EnterpriseTokenValidationError
    ):

        validator().validate(
            "   "
        )


# -------------------------------------------------
# ERROR HYGIENE
# -------------------------------------------------


def test_validation_error_does_not_echo_raw_token():

    token = token_for(
        claims(
            aud="wrong-api"
        )
    )

    with pytest.raises(
        EnterpriseTokenValidationError
    ) as captured:

        validator().validate(
            token
        )

    assert token not in str(
        captured.value
    )
