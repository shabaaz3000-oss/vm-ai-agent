from __future__ import annotations

from typing import Any

import jwt

from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError
from jwt.exceptions import PyJWTError

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import ValidationError
from pydantic import field_validator

from app.enterprise_authorization_evidence import (
    EnterpriseAuthorizationEvidence,
    ValidatedEnterpriseToken,
)

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
    authenticated against trusted IdP configuration.

    Raw token values and low-level JWT details are never
    included in the public error message.
    """


# -------------------------------------------------
# TRUSTED VALIDATOR CONFIGURATION
# -------------------------------------------------


class EntraTokenValidationSettings(BaseModel):
    """
    Server-controlled validation settings for one trusted
    Microsoft Entra tenant and protected API audience.
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
    or authorization evidence crosses the trust boundary.
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

    # -------------------------------------------------
    # CRYPTOGRAPHIC CLAIM VALIDATION
    # -------------------------------------------------

    def _decode_verified_claims(
        self,
        token: str,
    ) -> dict[str, Any]:

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

        if not isinstance(
            claims,
            dict,
        ):
            raise EnterpriseTokenValidationError(
                "Enterprise access token validation failed."
            )

        return claims

    # -------------------------------------------------
    # AUTHENTICATED IDENTITY
    # -------------------------------------------------

    def _build_identity(
        self,
        claims: dict[str, Any],
    ) -> EnterpriseIdentity:

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

        try:

            return EnterpriseIdentity(
                issuer=
                    claims.get(
                        "iss"
                    ),
                subject=
                    claims.get(
                        "sub"
                    ),
                identity_provider_tenant_id=
                    tenant_id,
            )

        except ValidationError as exc:

            raise EnterpriseTokenValidationError(
                "Enterprise access token validation failed."
            ) from exc

    # -------------------------------------------------
    # AUTHORIZATION EVIDENCE
    # -------------------------------------------------

    def _build_authorization_evidence(
        self,
        claims: dict[str, Any],
    ) -> EnterpriseAuthorizationEvidence:

        raw_roles = claims.get(
            "roles",
            [],
        )

        if not isinstance(
            raw_roles,
            list,
        ):
            raise EnterpriseTokenValidationError(
                "Enterprise access token validation failed."
            )

        # ---------------------------------------------
        # DETECT GROUP OVERAGE
        # ---------------------------------------------

        group_overage = False

        if "_claim_names" in claims:

            claim_names = claims[
                "_claim_names"
            ]

            if not isinstance(
                claim_names,
                dict,
            ):
                raise EnterpriseTokenValidationError(
                    "Enterprise access token validation failed."
                )

            if "groups" in claim_names:

                source_name = claim_names[
                    "groups"
                ]

                if (
                    not isinstance(
                        source_name,
                        str,
                    )
                    or not source_name.strip()
                ):
                    raise EnterpriseTokenValidationError(
                        "Enterprise access token validation failed."
                    )

                group_overage = True

        if "hasgroups" in claims:

            if claims[
                "hasgroups"
            ] is not True:
                raise EnterpriseTokenValidationError(
                    "Enterprise access token validation failed."
                )

            group_overage = True

        groups_present = (
            "groups" in claims
        )

        if (
            group_overage
            and groups_present
        ):
            raise EnterpriseTokenValidationError(
                "Enterprise access token validation failed."
            )

        # ---------------------------------------------
        # GROUP MEMBERSHIP STATE
        # ---------------------------------------------

        if group_overage:

            group_state = "overage"
            raw_groups = []

        elif groups_present:

            group_state = "complete"
            raw_groups = claims[
                "groups"
            ]

            if not isinstance(
                raw_groups,
                list,
            ):
                raise EnterpriseTokenValidationError(
                    "Enterprise access token validation failed."
                )

        else:

            group_state = "not_present"
            raw_groups = []

        raw_oid = claims.get(
            "oid"
        )

        try:

            return EnterpriseAuthorizationEvidence(
                app_roles=
                    raw_roles,
                group_ids=
                    raw_groups,
                group_membership_state=
                    group_state,
                directory_object_id=
                    raw_oid,
            )

        except ValidationError as exc:

            raise EnterpriseTokenValidationError(
                "Enterprise access token validation failed."
            ) from exc

    # -------------------------------------------------
    # FULL VALIDATED TOKEN
    # -------------------------------------------------

    def validate_token(
        self,
        token: str,
    ) -> ValidatedEnterpriseToken:
        """
        Validate one access token and return only trusted,
        normalized identity and authorization evidence.

        Raw token material and distributed-claim URLs are
        deliberately excluded from the returned object.
        """

        claims = (
            self._decode_verified_claims(
                token
            )
        )

        identity = (
            self._build_identity(
                claims
            )
        )

        authorization = (
            self._build_authorization_evidence(
                claims
            )
        )

        return ValidatedEnterpriseToken(
            identity=identity,
            authorization=authorization,
        )

    # -------------------------------------------------
    # BACKWARD-COMPATIBLE IDENTITY INTERFACE
    # -------------------------------------------------

    def validate(
        self,
        token: str,
    ) -> EnterpriseIdentity:
        """
        Preserve the Step 47.3 identity-only interface.

        All validation still flows through the complete
        validated-token path.
        """

        return self.validate_token(
            token
        ).identity
