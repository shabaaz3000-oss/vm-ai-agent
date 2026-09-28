from __future__ import annotations

import json
import os

from typing import Mapping

from app.auth import Principal


DEFAULT_LOCAL_PRINCIPAL_ID = "mcp-local-analyst"
DEFAULT_LOCAL_TENANT_ID = "local-development"


class MCPTenantResolutionError(
    RuntimeError
):
    """
    Raised when authoritative MCP tenant membership
    cannot be safely established.
    """


def load_trusted_mcp_tenant_bindings(
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """
    Load trusted principal-to-tenant bindings from
    server-side configuration.

    Local development receives one explicit default
    binding for the server-owned MCP identity.

    Production requires explicit tenant bindings and
    fails closed when they are missing.
    """

    source = (
        os.environ
        if environment is None
        else environment
    )

    runtime_environment = (
        source.get(
            "VM_AI_ENV",
            "local",
        )
        .strip()
        .lower()
    )

    raw_bindings = source.get(
        "VM_AI_MCP_TENANT_BINDINGS"
    )

    if raw_bindings is None:

        if runtime_environment == "production":
            raise MCPTenantResolutionError(
                "VM_AI_MCP_TENANT_BINDINGS must be "
                "explicitly configured in production."
            )

        return {
            DEFAULT_LOCAL_PRINCIPAL_ID:
                DEFAULT_LOCAL_TENANT_ID,
        }

    try:
        decoded = json.loads(
            raw_bindings
        )

    except json.JSONDecodeError as exc:
        raise MCPTenantResolutionError(
            "VM_AI_MCP_TENANT_BINDINGS must contain "
            "valid JSON."
        ) from exc

    if not isinstance(
        decoded,
        dict,
    ):
        raise MCPTenantResolutionError(
            "VM_AI_MCP_TENANT_BINDINGS must be a "
            "JSON object mapping principal IDs "
            "to tenant IDs."
        )

    bindings: dict[str, str] = {}

    for principal_id, tenant_id in decoded.items():

        if (
            not isinstance(
                principal_id,
                str,
            )
            or not principal_id.strip()
        ):
            raise MCPTenantResolutionError(
                "MCP tenant binding principal IDs "
                "must be non-empty strings."
            )

        if (
            not isinstance(
                tenant_id,
                str,
            )
            or not tenant_id.strip()
        ):
            raise MCPTenantResolutionError(
                "MCP tenant binding tenant IDs "
                "must be non-empty strings."
            )

        bindings[
            principal_id.strip()
        ] = tenant_id.strip()

    if not bindings:
        raise MCPTenantResolutionError(
            "VM_AI_MCP_TENANT_BINDINGS must contain "
            "at least one trusted binding."
        )

    return bindings


def resolve_mcp_tenant(
    principal: Principal,
    *,
    environment: Mapping[str, str] | None = None,
) -> str:
    """
    Resolve tenant membership exclusively from trusted
    server-side identity configuration.

    Tenant identity is never accepted from an MCP tool
    argument or other caller-controlled tenant value.
    """

    bindings = (
        load_trusted_mcp_tenant_bindings(
            environment
        )
    )

    tenant_id = bindings.get(
        principal.username
    )

    if tenant_id is None:
        raise MCPTenantResolutionError(
            "No trusted MCP tenant binding exists "
            f"for principal {principal.username!r}."
        )

    return tenant_id
