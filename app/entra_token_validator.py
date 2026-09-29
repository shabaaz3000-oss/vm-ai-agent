from __future__ import annotations

from typing import Any

import jwt

from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError
from jwt.exceptions import PyJWTError

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import field_validator

from app.enterprise_identity import EnterpriseIdentity


# -------------------------------------------------
# FIXED CRYPTOGRAPHIC POLICY
# -------------------------------------------------


ALLOWED_SIGNING_ALGORITHMS = (
    "RS256",
)


# -------------------------------------------------
# VALIDATION FAILURE
# -------------------------------------------------


class EnterpriseTokenValidationError(
    RuntimeError
):
    """
    Raised when an enterprise access token cannot be
    authenticated against the trusted IdP configuration.

    Low-level JWT details and token contents are deliberately
    not exposed through this exception.
    """


# -------------------------------------------------
# TRUSTED VALIDATOR CONFIGURATION
# -------------------------------------------------


class EntraTokenValidationSettings(BaseModel):
    """
    Server-controlled validation settings for one trusted
    Microsoft Entra tenant and one protected API audience.

    These values must come from trusted application
    configuration, never from token claims or request input.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    issuer: str = Field(
        min_length=1
    )

    audience: str = Field(
        min_length=1
    )

    identity_provider_tenant_id: str = Field(
        min_length=1
    )

    jwks_uri: str = Field(
        min_length=1
    )

    leeway_seconds: int = Field(
        default=60,
        ge=0,
        le=300,
    )

    @field_validator(
        "issuer",
        "audience",
        "identity_provider_tenant_id",
        "jwks_uri",
        mode="before",
    )
    @classmethod
    def normalize_required_setting(
        cls,
        value,
    ) -> str:

        if not isinstance(
            value,
            str,
        ):
            raise ValueError(
                "Entra validation settings must "
                "be strings."
            )

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Entra validation settings must "
                "not be empty."
            )

        return normalized


# -------------------------------------------------
# ENTRA ACCESS TOKEN VALIDATOR
# -------------------------------------------------


class EntraAccessTokenValidator:
    """
    Validate Microsoft Entra access tokens before identity
    enters the application's trusted security boundary.

    Security properties:

    - signing key comes from trusted JWKS configuration
    - signing algorithm is fixed server-side to RS256
    - issuer must exactly match trusted configuration
    - audience must exactly match this API
    - exp, nbf, and iat are validated
    - subject is mandatory
    - tenant ID is mandatory and must match configuration
    - raw credentials are never stored in EnterpriseIdentity
    """

    def __init__(
        self,
        settings: EntraTokenValidationSettings,
        *,
        jwks_client: Any | None = None,
    ) -> None:

        self._settings = settings

        self._jwks_client = (
            jwks_client
            if jwks_client is not None
            else PyJWKClient(
                settings.jwks_uri
            )
        )

    def validate(
        self,
        token: str,
    ) -> EnterpriseIdentity:
        """
        Cryptographically validate an Entra access token and
        return only the authenticated enterprise identity
        facts required by the application trust boundary.
        """

        if (
            not isinstance(
                token,
                str,
            )
            or not token.strip()
        ):
            raise EnterpriseTokenValidationError(
                "Enterprise access token validation failed."
            )

        encoded_token = token.strip()

        try:

            signing_key = (
                self._jwks_client
                .get_signing_key_from_jwt(
                    encoded_token
                )
            )

            claims = jwt.decode(
                encoded_token,
                signing_key.key,
                algorithms=list(
                    ALLOWED_SIGNING_ALGORITHMS
                ),
                audience=
                    self._settings.audience,
                issuer=
                    self._settings.issuer,
                leeway=
                    self._settings.leeway_seconds,
                options={
                    "require": [
                        "iss",
                        "aud",
                        "exp",
                        "nbf",
                        "iat",
                        "sub",
                        "tid",
                    ],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_sub": True,
                    "strict_aud": True,
                },
            )

        except (
            PyJWTError,
            PyJWKClientError,
            ValueError,
            TypeError,
        ) as exc:

            raise EnterpriseTokenValidationError(
                "Enterprise access token validation failed."
            ) from exc

        tenant_id = claims.get(
            "tid"
        )

        if (
            not isinstance(
                tenant_id,
                str,
            )
            or tenant_id.strip()
            != self._settings.identity_provider_tenant_id
        ):
            raise EnterpriseTokenValidationError(
                "Enterprise access token validation failed."
            )

        issuer = claims.get(
            "iss"
        )

        subject = claims.get(
            "sub"
        )

        try:

            return EnterpriseIdentity(
                issuer=issuer,
                subject=subject,
                identity_provider_tenant_id=
                    tenant_id,
            )

        except Exception as exc:

            raise EnterpriseTokenValidationError(
                "Enterprise access token validation failed."
            ) from exc
