import pytest

from mcp import Client
from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from app.auth import Principal

from app.tools.dispatcher import (
    ToolExecutionContext,
    dispatch_llm_tool,
)


# -------------------------------------------------
# PYTEST / ANYIO
# -------------------------------------------------


@pytest.fixture
def anyio_backend():

    return "asyncio"


# -------------------------------------------------
# CROSS-TOOL CAPABILITY ESCALATION
# -------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(
    "role",
    [
        "ANALYST",
        "APPROVER",
    ],
)
async def test_allowed_read_does_not_grant_action_authority(
    role,
    monkeypatch,
):

    test_server = MCPServer(
        "MCP Cross Tool Security Test"
    )

    principal = Principal(
        username=
            f"cross-tool-test-{role.lower()}",
        role=role,
        retrieval_access="standard",
    )

    context = ToolExecutionContext(
        principal=principal,
    )

    read_sentinel = {
        "status": "read-success"
    }

    # -------------------------------------------------
    # ALLOW THE FIRST READ TO SUCCEED
    # -------------------------------------------------

    monkeypatch.setattr(
        "app.tools.dispatcher.get_finding",
        lambda **kwargs:
            read_sentinel,
    )

    # -------------------------------------------------
    # TEST MCP TOOL
    # -------------------------------------------------
    #
    # The first operation is an authorized read.
    #
    # The tool then attempts to use that successful
    # read as a stepping stone to invoke the hidden
    # privileged ticket workflow.
    #
    # Authorization must be reevaluated for the
    # second operation.
    # -------------------------------------------------

    @test_server.tool(
        name="read_then_escalate",
        description=(
            "Security evaluation tool that "
            "attempts cross-tool escalation."
        ),
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    def read_then_escalate():

        read_result = dispatch_llm_tool(
            tool_name="get_finding",
            context=context,
        )

        assert (
            read_result
            == read_sentinel
        )

        # This second operation must NOT inherit
        # authority from the successful read.
        return dispatch_llm_tool(
            tool_name=
                "execute_ticket_workflow",
            context=
                context,
        )

    # -------------------------------------------------
    # EXECUTE THROUGH REAL MCP CLIENT / SERVER
    # -------------------------------------------------

    async with Client(
        test_server,
        raise_exceptions=True,
    ) as client:

        listed = await client.list_tools()

        tool_names = [
            tool.name
            for tool in listed.tools
        ]

        assert (
            "read_then_escalate"
            in tool_names
        )

        assert (
            "execute_ticket_workflow"
            not in tool_names
        )

        result = await client.call_tool(
            "read_then_escalate",
            {},
        )

    # -------------------------------------------------
    # SECURITY INVARIANT
    # -------------------------------------------------
    #
    # The first read succeeded.
    #
    # The subsequent privileged action was still
    # independently rejected.
    # -------------------------------------------------

    assert result.is_error is True