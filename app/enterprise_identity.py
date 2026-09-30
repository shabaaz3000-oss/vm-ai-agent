from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import field_validator


# -------------------------------------------------
# AUTHORITATIVE ENTERPRISE IDENTITY
# -------------------------------------------------


class EnterpriseIdentity(BaseModel):
    """
    Immutable identity facts established by a trusted
    enterprise identity-provider validation boundary.

    EnterpriseIdentity represents authentication facts
    only. It deliberately does not contain application
    authorization decisions such as:

    - internal tenant_id
    - workflow role
    - retrieval_access
    - session_revocation_access
    - document authorization
    - group-derived application permissions

    Those values must be established separately by
    trusted application authorization logic.

    Raw bearer tokens, access tokens, refresh tokens,
    ID tokens, signatures, and other credentials must
    never be stored in this model.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    # OIDC issuer that authenticated the subject.
    issuer: str = Field(
        min_length=1
    )

    # Stable IdP subject identifier.
    #
    # This is intentionally opaque. Application code
    # must not infer privileges from its contents.
    subject: str = Field(
        min_length=1
    )

    # Authoritative tenant / directory identifier from
    # the identity provider.
    #
    # This is NOT the application's internal tenant_id.
    # A later trusted mapping step will bind this value
    # to internal tenancy.
    identity_provider_tenant_id: str = Field(
        min_length=1
    )

    @field_validator(
        "issuer",
        "subject",
        "identity_provider_tenant_id",
        mode="before",
    )
    @classmethod
    def normalize_required_identity_value(
        cls,
        value,
    ) -> str:
        """
        Normalize surrounding whitespace while rejecting
        absent, non-string, or empty authoritative values.
        """

        if not isinstance(
            value,
            str,
        ):
            raise ValueError(
                "Enterprise identity values must "
                "be strings."
            )

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Enterprise identity values must "
                "not be empty."
            )

        return normalized
