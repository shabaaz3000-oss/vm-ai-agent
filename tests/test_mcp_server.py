import pytest

from mcp import Client

import app.mcp_server as mcp_server_module

from app.mcp_server import (
    mcp,
    require_mcp_read_spec,
)

from app.tools.registry import ToolSpec


@pytest.fixture
def anyio_backend():

    return "asyncio"


# -------------------------------------------------
# MCP TOOL EXPOSURE
# -------------------------------------------------


@pytest.mark.anyio
async def test_mcp_exposes_only_expected_read_tools():

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        listed = await client.list_tools()

        tool_names = [
            tool.name
            for tool in listed.tools
        ]

        assert tool_names == [
            "get_finding",
            "get_asset_details",
            "get_threat_intel",
            "search_knowledge",
        ]

# -------------------------------------------------
# GET THREAT INTEL
# -------------------------------------------------


@pytest.mark.anyio
async def test_mcp_get_threat_intel_executes_successfully():

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        result = await client.call_tool(
            "get_threat_intel",
            {},
        )

        assert result.is_error is False

        assert (
            result.structured_content
            is not None
        )

        assert (
            "cve"
            in result.structured_content
        )

# -------------------------------------------------
# MCP IDENTITY IS SERVER CONTROLLED
# -------------------------------------------------


@pytest.mark.anyio
async def test_mcp_identity_is_not_model_controlled():

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        listed = await client.list_tools()

        for tool in listed.tools:

            properties = (
                tool.input_schema
                .get(
                    "properties",
                    {},
                )
            )

            assert (
                "username"
                not in properties
            )

            assert (
                "role"
                not in properties
            )

            assert (
                "retrieval_access"
                not in properties
            )

            assert properties == {}


# -------------------------------------------------
# GET FINDING
# -------------------------------------------------


@pytest.mark.anyio
async def test_mcp_get_finding_executes_successfully():

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        result = await client.call_tool(
            "get_finding",
            {},
        )

        assert result.is_error is False

        assert (
            result.structured_content
            is not None
        )

        assert (
            "finding_id"
            in result.structured_content
        )


# -------------------------------------------------
# GET ASSET DETAILS
# -------------------------------------------------


@pytest.mark.anyio
async def test_mcp_get_asset_details_executes_successfully():

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        result = await client.call_tool(
            "get_asset_details",
            {},
        )

        assert result.is_error is False

        assert (
            result.structured_content
            is not None
        )

        assert (
            "asset_name"
            in result.structured_content
        )


# -------------------------------------------------
# SENSITIVE TOOL EXPOSURE
# -------------------------------------------------


@pytest.mark.anyio
async def test_mcp_exposes_knowledge_but_not_action_tools():

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        listed = await client.list_tools()

        tool_names = {
            tool.name
            for tool in listed.tools
        }

        assert (
            "search_knowledge"
            in tool_names
        )

        assert (
            "execute_ticket_workflow"
            not in tool_names
        )


# -------------------------------------------------
# UNKNOWN / HIDDEN TOOL FAILS CLOSED
# -------------------------------------------------


@pytest.mark.anyio
async def test_mcp_unknown_tool_fails_closed():

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        result = await client.call_tool(
            "execute_ticket_workflow",
            {},
        )

        assert result.is_error is True

        assert (
            result.structured_content
            is None
        )


# -------------------------------------------------
# MCP EXPOSURE POLICY
# -------------------------------------------------


def test_mcp_policy_rejects_non_llm_visible_tool():

    with pytest.raises(
        RuntimeError,
        match="not LLM-visible",
    ):

        require_mcp_read_spec(
            "execute_ticket_workflow"
        )


def test_mcp_policy_rejects_action_tool(
    monkeypatch,
):

    action_spec = ToolSpec(
        name="synthetic_action",
        description="Synthetic action tool.",
        kind="action",
        llm_visible=True,
        requires_human_approval=False,
    )

    monkeypatch.setattr(
        mcp_server_module,
        "get_tool_spec",
        lambda tool_name: action_spec,
    )

    with pytest.raises(
        RuntimeError,
        match="not a read-only tool",
    ):

        require_mcp_read_spec(
            "synthetic_action"
        )


def test_mcp_policy_rejects_human_approval_tool(
    monkeypatch,
):

    approval_spec = ToolSpec(
        name="synthetic_approval_tool",
        description="Synthetic approval tool.",
        kind="read",
        llm_visible=True,
        requires_human_approval=True,
    )

    monkeypatch.setattr(
        mcp_server_module,
        "get_tool_spec",
        lambda tool_name: approval_spec,
    )

    with pytest.raises(
        RuntimeError,
        match="requires human approval",
    ):

        require_mcp_read_spec(
            "synthetic_approval_tool"
        )