import pytest

from mcp import Client

from app.mcp_server import mcp


@pytest.fixture
def anyio_backend():

    return "asyncio"


@pytest.mark.anyio
async def test_mcp_exposes_only_get_finding():

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
            "get_finding"
        ]


@pytest.mark.anyio
async def test_mcp_identity_is_not_model_controlled():

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        listed = await client.list_tools()

        tool = listed.tools[0]

        properties = (
            tool.input_schema
            .get(
                "properties",
                {},
            )
        )

        assert "username" not in properties
        assert "role" not in properties
        assert "retrieval_access" not in properties

        assert properties == {}


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

@pytest.mark.anyio
async def test_mcp_does_not_expose_sensitive_tools():

    async with Client(
        mcp,
        raise_exceptions=True,
    ) as client:

        listed = await client.list_tools()

        tool_names = {
            tool.name
            for tool in listed.tools
        }

        assert "search_knowledge" not in tool_names

        assert (
            "execute_ticket_workflow"
            not in tool_names
        )


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

        assert result.structured_content is None