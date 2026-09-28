import inspect

import pytest

from app.auth import Principal

from app.mcp_tenant import (
    DEFAULT_LOCAL_TENANT_ID,
    MCPTenantResolutionError,
    load_trusted_mcp_tenant_bindings,
    resolve_mcp_tenant,
)


def principal(
    username: str = "mcp-local-analyst",
) -> Principal:

    return Principal(
        username=username,
        role="ANALYST",
        retrieval_access="standard",
    )


def test_local_server_identity_uses_trusted_default():

    tenant_id = resolve_mcp_tenant(
        principal()
    )

    assert (
        tenant_id
        == DEFAULT_LOCAL_TENANT_ID
    )


def test_configured_binding_is_authoritative():

    tenant_id = resolve_mcp_tenant(
        principal(
            "alice"
        ),
        environment={
            "VM_AI_MCP_TENANT_BINDINGS":
                '{"alice": "tenant-a"}',
        },
    )

    assert tenant_id == "tenant-a"


def test_unbound_principal_is_rejected():

    with pytest.raises(
        MCPTenantResolutionError
    ):
        resolve_mcp_tenant(
            principal(
                "mallory"
            ),
            environment={
                "VM_AI_MCP_TENANT_BINDINGS":
                    '{"alice": "tenant-a"}',
            },
        )


def test_production_requires_explicit_bindings():

    with pytest.raises(
        MCPTenantResolutionError
    ):
        load_trusted_mcp_tenant_bindings(
            {
                "VM_AI_ENV":
                    "production",
            }
        )


def test_invalid_binding_json_is_rejected():

    with pytest.raises(
        MCPTenantResolutionError
    ):
        load_trusted_mcp_tenant_bindings(
            {
                "VM_AI_MCP_TENANT_BINDINGS":
                    "{not-json}",
            }
        )


def test_non_object_binding_configuration_is_rejected():

    with pytest.raises(
        MCPTenantResolutionError
    ):
        load_trusted_mcp_tenant_bindings(
            {
                "VM_AI_MCP_TENANT_BINDINGS":
                    '["tenant-a"]',
            }
        )


def test_empty_tenant_binding_is_rejected():

    with pytest.raises(
        MCPTenantResolutionError
    ):
        load_trusted_mcp_tenant_bindings(
            {
                "VM_AI_MCP_TENANT_BINDINGS":
                    '{"alice": ""}',
            }
        )


def test_resolver_accepts_no_caller_tenant_argument():

    parameters = inspect.signature(
        resolve_mcp_tenant
    ).parameters

    assert "tenant_id" not in parameters
