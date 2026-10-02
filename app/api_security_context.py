from __future__ import annotations

import json
import os

from uuid import uuid4

from app.auth import Principal
from app.security_context import SecurityContext
from app.security_observability_integrations import (
    emit_api_tenant_binding_denied_security_event,
)


# -------------------------------------------------
# SERVER-OWNED API TENANT AUTHORITY
# -------------------------------------------------


API_TENANT_BINDINGS_ENV = (
    "VM_AI_API_TENANT_BINDINGS"
)


class APIContextConfigurationError(
    RuntimeError
):
    """
    Raised when trusted server configuration cannot produce an
    authoritative API tenant binding.
    """


class APITenantBindingError(
    PermissionError
):
    """
    Raised when an authenticated API principal is not authorized
    for any configured tenant.
    """


def _validate_normalized_nonblank(
    value: object,
    *,
    field_name: str,
) -> str:

    if not isinstance(
        value,
        str,
    ):

        raise APIContextConfigurationError(
            f"{field_name} must be a string."
        )

    if (
        not value
        or not value.strip()
        or value != value.strip()
    ):

        raise APIContextConfigurationError(
            f"{field_name} must be a "
            "non-blank normalized string."
        )

    if len(value) > 256:

        raise APIContextConfigurationError(
            f"{field_name} is too long."
        )

    return value


def load_api_tenant_bindings(
) -> dict[str, str]:
    """
    Load the exact authenticated-principal -> tenant mapping from
    server-owned process configuration.

    No request, model, workflow, ticket, MCP argument, or caller
    field participates in tenant selection.
    """

    raw = os.environ.get(
        API_TENANT_BINDINGS_ENV
    )

    if raw is None:

        raise APIContextConfigurationError(
            f"{API_TENANT_BINDINGS_ENV} "
            "must be configured."
        )

    try:

        decoded = json.loads(
            raw
        )

    except json.JSONDecodeError as error:

        raise APIContextConfigurationError(
            f"{API_TENANT_BINDINGS_ENV} "
            "must contain valid JSON."
        ) from error

    if not isinstance(
        decoded,
        dict,
    ):

        raise APIContextConfigurationError(
            f"{API_TENANT_BINDINGS_ENV} "
            "must contain a JSON object."
        )

    if not decoded:

        raise APIContextConfigurationError(
            f"{API_TENANT_BINDINGS_ENV} "
            "must not be empty."
        )

    bindings: dict[
        str,
        str,
    ] = {}

    for (
        raw_principal,
        raw_tenant,
    ) in decoded.items():

        principal_id = (
            _validate_normalized_nonblank(
                raw_principal,
                field_name=
                    "API principal binding key",
            )
        )

        tenant_id = (
            _validate_normalized_nonblank(
                raw_tenant,
                field_name=
                    "API tenant binding value",
            )
        )

        bindings[
            principal_id
        ] = tenant_id

    return bindings


def resolve_api_tenant(
    principal: Principal,
) -> str:
    """
    Resolve tenant authority exclusively from authenticated
    Principal identity and server-owned configuration.
    """

    if not isinstance(
        principal,
        Principal,
    ):

        raise TypeError(
            "principal must be an authenticated Principal."
        )

    bindings = (
        load_api_tenant_bindings()
    )

    tenant_id = bindings.get(
        principal.username
    )

    if tenant_id is None:

        emit_api_tenant_binding_denied_security_event()

        raise APITenantBindingError(
            "Authenticated principal has no "
            "trusted API tenant binding."
        )

    return tenant_id


def build_api_security_context(
    principal: Principal,
) -> SecurityContext:
    """
    Build immutable trusted API execution authority.

    Security-significant values are derived only from:

    - authenticated Principal claims,
    - server-owned principal -> tenant configuration,
    - a server-generated session identifier.

    tenant_id and session_id are deliberately not parameters.
    """

    if not isinstance(
        principal,
        Principal,
    ):

        raise TypeError(
            "principal must be an authenticated Principal."
        )

    tenant_id = (
        resolve_api_tenant(
            principal
        )
    )

    session_id = (
        "api-"
        + uuid4().hex
    )

    return (
        SecurityContext.from_principal(
            principal,
            tenant_id=
                tenant_id,
            session_id=
                session_id,
        )
    )
