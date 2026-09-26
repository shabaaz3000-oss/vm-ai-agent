from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from app.auth import Principal

from app.models import (
    AssetContext,
    VulnerabilityFinding,
)

from app.tools.dispatcher import (
    ToolExecutionContext,
    dispatch_llm_tool,
)

from app.tools.registry import (
    ToolSpec,
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
# Identity is established server-side and is NOT
# exposed as an MCP tool argument.
#
# This is deliberately least-privileged.
# -------------------------------------------------


LOCAL_MCP_PRINCIPAL = Principal(
    username="mcp-local-analyst",
    role="ANALYST",
    retrieval_access="standard",
)


# -------------------------------------------------
# MCP READ-ONLY EXPOSURE POLICY
# -------------------------------------------------


MCP_READ_TOOL_NAMES = (
    "get_finding",
    "get_asset_details",
)


def require_mcp_read_spec(
    tool_name: str,
) -> ToolSpec:

    spec = get_tool_spec(
        tool_name
    )

    if not spec.llm_visible:

        raise RuntimeError(
            f"{tool_name} is not LLM-visible "
            "and cannot be exposed through MCP."
        )

    if spec.kind != "read":

        raise RuntimeError(
            f"{tool_name} is not a read-only tool "
            "and cannot be exposed through MCP."
        )

    if spec.requires_human_approval:

        raise RuntimeError(
            f"{tool_name} requires human approval "
            "and cannot be exposed through the "
            "read-only MCP boundary."
        )

    return spec


GET_FINDING_SPEC = (
    require_mcp_read_spec(
        "get_finding"
    )
)


GET_ASSET_DETAILS_SPEC = (
    require_mcp_read_spec(
        "get_asset_details"
    )
)


# -------------------------------------------------
# MCP EXECUTION CONTEXT
# -------------------------------------------------


def build_mcp_execution_context(
) -> ToolExecutionContext:

    return ToolExecutionContext(
        principal=
            LOCAL_MCP_PRINCIPAL,
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

    result = dispatch_llm_tool(
        tool_name="get_finding",
        context=
            build_mcp_execution_context(),
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
# GET ASSET DETAILS MCP TOOL
# -------------------------------------------------


@mcp.tool(
    name=GET_ASSET_DETAILS_SPEC.name,

    description=
        GET_ASSET_DETAILS_SPEC.description,

    annotations=ToolAnnotations(
        read_only_hint=True,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
def mcp_get_asset_details() -> AssetContext:

    result = dispatch_llm_tool(
        tool_name="get_asset_details",
        context=
            build_mcp_execution_context(),
    )

    if not isinstance(
        result,
        AssetContext,
    ):

        raise TypeError(
            "get_asset_details returned an "
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