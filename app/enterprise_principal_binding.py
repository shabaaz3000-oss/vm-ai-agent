from __future__ import annotations

import json
import os

from typing import Literal
from typing import Mapping
from typing import Sequence

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import ValidationError
from pydantic import field_validator

from app.auth import Principal
from app.enterprise_identity import EnterpriseIdentity


# -------------------------------------------------
# CONFIGURATION
# -------------------------------------------------


ENTERPRISE_PRINCIPAL_BINDINGS_ENV = (
    "VM_AI_ENTERPRISE_PRINCIPAL_BINDINGS"
)


# -------------------------------------------------
# BINDING FAILURE
# -------------------------------------------------


class EnterprisePrincipalBindingError(
    RuntimeError
):
    """
    Raised when a validated enterprise identity cannot be
    safely bound to exactly one application Principal.

    Failure messages intentionally avoid exposing identity
    values or trusted authorization configuration.
    """


# -------------------------------------------------
# TRUSTED ENTERPRISE PRINCIPAL BINDING
# -------------------------------------------------


class EnterprisePrincipalBinding(BaseModel):
    """
    Immutable server-controlled mapping from one validated
    enterprise identity to one application Principal.

    Identity matching uses the complete authoritative tuple:

        issuer
        identity_provider_tenant_id
        subject

    Application authorization is deliberately stored here,
    rather than trusted from token claims.

    This model intentionally excludes:

    - internal tenant_id
    - raw tokens
    - IdP group claims
    - request-supplied authorization
    - session identity

    Internal tenant mapping is a separate trust boundary.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    issuer: str = Field(
        min_length=1
    )

    identity_provider_tenant_id: str = Field(
        min_length=1
    )

    subject: str = Field(
        min_length=1
    )

    principal_id: str = Field(
        min_length=1
    )

    role: Literal[
        "ANALYST",
        "APPROVER",
    ]

    retrieval_access: Literal[
        "standard",
        "restricted",
    ] = "standard"

    session_revocation_access: Literal[
        "self",
        "tenant_admin",
    ] = "self"

    @field_validator(
        "issuer",
        "identity_provider_tenant_id",
        "subject",
        "principal_id",
        mode="before",
    )
    @classmethod
    def normalize_required_string(
        cls,
        value,
    ) -> str:

        if not isinstance(
            value,
            str,
        ):
            raise ValueError(
                "Enterprise principal binding values "
                "must be strings."
            )

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Enterprise principal binding values "
                "must not be empty."
            )

        return normalized

    @property
    def identity_key(
        self,
    ) -> tuple[
        str,
        str,
        str,
    ]:
        """
        Exact trusted identity tuple used for authorization
        binding.

        Subject alone is never sufficient.
        """

        return (
            self.issuer,
            self.identity_provider_tenant_id,
            self.subject,
        )


# -------------------------------------------------
# LOAD SERVER-SIDE BINDINGS
# -------------------------------------------------


def load_enterprise_principal_bindings(
    environment: Mapping[str, str] | None = None,
) -> tuple[
    EnterprisePrincipalBinding,
    ...,
]:
    """
    Load enterprise identity-to-Principal mappings only from
    trusted server-side configuration.

    No implicit development identity or authorization mapping
    is provided. Missing configuration fails closed.
    """

    source = (
        os.environ
        if environment is None
        else environment
    )

    raw_bindings = source.get(
        ENTERPRISE_PRINCIPAL_BINDINGS_ENV
    )

    if (
        raw_bindings is None
        or not raw_bindings.strip()
    ):
        raise EnterprisePrincipalBindingError(
            "Enterprise principal bindings are not configured."
        )

    try:

        decoded = json.loads(
            raw_bindings
        )

    except json.JSONDecodeError as exc:

        raise EnterprisePrincipalBindingError(
            "Enterprise principal bindings are invalid."
        ) from exc

    if (
        not isinstance(
            decoded,
            list,
        )
        or not decoded
    ):
        raise EnterprisePrincipalBindingError(
            "Enterprise principal bindings are invalid."
        )

    bindings: list[
        EnterprisePrincipalBinding
    ] = []

    try:

        for item in decoded:

            if not isinstance(
                item,
                dict,
            ):
                raise EnterprisePrincipalBindingError(
                    "Enterprise principal bindings are invalid."
                )

            bindings.append(
                EnterprisePrincipalBinding.model_validate(
                    item
                )
            )

    except ValidationError as exc:

        raise EnterprisePrincipalBindingError(
            "Enterprise principal bindings are invalid."
        ) from exc

    seen_identity_keys: set[
        tuple[
            str,
            str,
            str,
        ]
    ] = set()

    seen_principal_ids: set[str] = set()

    for binding in bindings:

        if (
            binding.identity_key
            in seen_identity_keys
        ):
            raise EnterprisePrincipalBindingError(
                "Enterprise principal bindings contain "
                "duplicate identity authority."
            )

        if (
            binding.principal_id
            in seen_principal_ids
        ):
            raise EnterprisePrincipalBindingError(
                "Enterprise principal bindings contain "
                "duplicate application principals."
            )

        seen_identity_keys.add(
            binding.identity_key
        )

        seen_principal_ids.add(
            binding.principal_id
        )

    return tuple(
        bindings
    )


# -------------------------------------------------
# BUILD APPLICATION PRINCIPAL
# -------------------------------------------------


def build_enterprise_principal(
    identity: EnterpriseIdentity,
    *,
    bindings: Sequence[
        EnterprisePrincipalBinding
    ],
) -> Principal:
    """
    Bind one already-validated enterprise identity to exactly
    one server-authorized application Principal.

    No authorization value is accepted from the token,
    request, MCP arguments, or model output.
    """

    identity_key = (
        identity.issuer,
        identity.identity_provider_tenant_id,
        identity.subject,
    )

    matches = [
        binding
        for binding in bindings
        if binding.identity_key
        == identity_key
    ]

    if len(matches) != 1:
        raise EnterprisePrincipalBindingError(
            "Enterprise identity is not authorized."
        )

    binding = matches[0]

    return Principal(
        username=
            binding.principal_id,
        role=
            binding.role,
        retrieval_access=
            binding.retrieval_access,
        session_revocation_access=
            binding.session_revocation_access,
    )


# -------------------------------------------------
# RESOLVE FROM SERVER CONFIGURATION
# -------------------------------------------------


def resolve_enterprise_principal(
    identity: EnterpriseIdentity,
    *,
    environment: Mapping[str, str] | None = None,
) -> Principal:
    """
    Resolve a validated enterprise identity using the
    authoritative server-side binding configuration.
    """

    return build_enterprise_principal(
        identity,
        bindings=
            load_enterprise_principal_bindings(
                environment
            ),
    )
