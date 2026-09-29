from __future__ import annotations

import json
import os

from typing import Mapping
from typing import Sequence

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import ValidationError
from pydantic import field_validator

from app.enterprise_identity import EnterpriseIdentity


# -------------------------------------------------
# CONFIGURATION
# -------------------------------------------------


ENTERPRISE_TENANT_BINDINGS_ENV = (
    "VM_AI_ENTERPRISE_TENANT_BINDINGS"
)


# -------------------------------------------------
# RESOLUTION FAILURE
# -------------------------------------------------


class EnterpriseTenantBindingError(
    RuntimeError
):
    """
    Raised when a validated enterprise identity cannot be
    safely mapped to exactly one internal application tenant.

    Failure messages deliberately avoid exposing identity or
    trusted tenant configuration values.
    """


# -------------------------------------------------
# TRUSTED TENANT BINDING
# -------------------------------------------------


class EnterpriseTenantBinding(BaseModel):
    """
    Immutable server-controlled mapping from an external
    identity-provider tenant to an internal application tenant.

    The external authority key is:

        issuer
        identity_provider_tenant_id

    The internal tenant_id remains an application-owned value
    and is never copied automatically from the IdP tenant ID.
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

    tenant_id: str = Field(
        min_length=1
    )

    @field_validator(
        "issuer",
        "identity_provider_tenant_id",
        "tenant_id",
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
                "Enterprise tenant binding values "
                "must be strings."
            )

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Enterprise tenant binding values "
                "must not be empty."
            )

        return normalized

    @property
    def identity_provider_key(
        self,
    ) -> tuple[
        str,
        str,
    ]:
        """
        Exact external tenant authority key.

        IdP tenant ID alone is not sufficient because the
        issuer is part of the authenticated trust boundary.
        """

        return (
            self.issuer,
            self.identity_provider_tenant_id,
        )


# -------------------------------------------------
# LOAD SERVER-SIDE TENANT BINDINGS
# -------------------------------------------------


def load_enterprise_tenant_bindings(
    environment: Mapping[str, str] | None = None,
) -> tuple[
    EnterpriseTenantBinding,
    ...,
]:
    """
    Load trusted external-to-internal tenant mappings from
    server-side configuration.

    Missing or malformed configuration fails closed.
    """

    source = (
        os.environ
        if environment is None
        else environment
    )

    raw_bindings = source.get(
        ENTERPRISE_TENANT_BINDINGS_ENV
    )

    if (
        raw_bindings is None
        or not raw_bindings.strip()
    ):
        raise EnterpriseTenantBindingError(
            "Enterprise tenant bindings are not configured."
        )

    try:

        decoded = json.loads(
            raw_bindings
        )

    except json.JSONDecodeError as exc:

        raise EnterpriseTenantBindingError(
            "Enterprise tenant bindings are invalid."
        ) from exc

    if (
        not isinstance(
            decoded,
            list,
        )
        or not decoded
    ):
        raise EnterpriseTenantBindingError(
            "Enterprise tenant bindings are invalid."
        )

    bindings: list[
        EnterpriseTenantBinding
    ] = []

    try:

        for item in decoded:

            if not isinstance(
                item,
                dict,
            ):
                raise EnterpriseTenantBindingError(
                    "Enterprise tenant bindings are invalid."
                )

            bindings.append(
                EnterpriseTenantBinding.model_validate(
                    item
                )
            )

    except ValidationError as exc:

        raise EnterpriseTenantBindingError(
            "Enterprise tenant bindings are invalid."
        ) from exc

    seen_authority_keys: set[
        tuple[
            str,
            str,
        ]
    ] = set()

    for binding in bindings:

        if (
            binding.identity_provider_key
            in seen_authority_keys
        ):
            raise EnterpriseTenantBindingError(
                "Enterprise tenant bindings contain "
                "duplicate tenant authority."
            )

        seen_authority_keys.add(
            binding.identity_provider_key
        )

    return tuple(
        bindings
    )


# -------------------------------------------------
# RESOLVE INTERNAL TENANT
# -------------------------------------------------


def resolve_enterprise_tenant(
    identity: EnterpriseIdentity,
    *,
    bindings: Sequence[
        EnterpriseTenantBinding
    ],
) -> str:
    """
    Resolve internal application tenancy exclusively from the
    validated enterprise identity and trusted server mapping.

    No caller-selected internal tenant is accepted.
    """

    identity_provider_key = (
        identity.issuer,
        identity.identity_provider_tenant_id,
    )

    matches = [
        binding
        for binding in bindings
        if binding.identity_provider_key
        == identity_provider_key
    ]

    if len(matches) != 1:
        raise EnterpriseTenantBindingError(
            "Enterprise tenant is not authorized."
        )

    return matches[0].tenant_id


def resolve_enterprise_tenant_from_environment(
    identity: EnterpriseIdentity,
    *,
    environment: Mapping[str, str] | None = None,
) -> str:
    """
    Resolve internal tenancy using only authoritative
    server-side mapping configuration.
    """

    return resolve_enterprise_tenant(
        identity,
        bindings=
            load_enterprise_tenant_bindings(
                environment
            ),
    )
