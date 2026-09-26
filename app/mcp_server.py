from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from app.auth import Principal
from app.models import VulnerabilityFinding

from app.tools.dispatcher import (
    ToolExecutionContext,
    dispatch_llm_tool,
)

from app.tools.registry import (
    get_tool_spec,
)


# -------------------------------------------------
# MCP SERVER
# -------------------------------------------------


mcp = MCPServer(
    "VM AI Agent"
)


# -------------------------------------------------
# LOCAL MCP IDENTITY
# -------------------------------------------------
#
# Step 38 initially uses stdio for local development.
#
# stdio does not carry HTTP bearer authentication.
# Therefore identity is established server-side and
# is NOT exposed as an MCP tool argument.
#
# This is deliberately least-privileged.
# -------------------------------------------------


LOCAL_MCP_PRINCIPAL = Principal(
    username="mcp-local-analyst",
    role="ANALYST",
    retrieval_access="standard",
)


# -------------------------------------------------
# GET FINDING MCP TOOL POLICY
# -------------------------------------------------


GET_FINDING_SPEC = get_tool_spec(
    "get_finding"
)


if (
    not GET_FINDING_SPEC.llm_visible
    or GET_FINDING_SPEC.kind != "read"
):

    raise RuntimeError(
        "get_finding is not approved "
        "for MCP read-only exposure."
    )


# -------------------------------------------------
# GET FINDING MCP TOOL
# -------------------------------------------------


@mcp.tool(
    name=GET_FINDING_SPEC.name,

    description=
        GET_FINDING_SPEC.description,

    annotations=ToolAnnotations(
        read_only_hint=True,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
def mcp_get_finding() -> VulnerabilityFinding:

    context = ToolExecutionContext(
        principal=
            LOCAL_MCP_PRINCIPAL,
    )

    result = dispatch_llm_tool(
        tool_name="get_finding",
        context=context,
    )

    if not isinstance(
        result,
        VulnerabilityFinding,
    ):

        raise TypeError(
            "get_finding returned an "
            "unexpected result type."
        )

    return result


# -------------------------------------------------
# ENTRY POINT
# -------------------------------------------------


def main() -> None:

    mcp.run()


if __name__ == "__main__":

    main()