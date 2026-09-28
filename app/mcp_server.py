from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from app.auth import Principal
from app.mcp_session_runtime import (
    build_mcp_session_manager,
)
from app.security_context import SecurityContext

from app.mcp_rag_context import (
    build_mcp_rag_execution_context,
)

from app.models import (
    AssetContext,
    RetrievedEvidence,
    ThreatIntel,
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
# LOCAL MCP SESSION
# -------------------------------------------------
#
# Stdio development uses one server-owned identity
# and one server-generated MCP session.
#
# Neither tenant identity nor session identity is
# exposed through MCP tool arguments.
# -------------------------------------------------


LOCAL_MCP_TENANT_ID = (
    "local-development"
)


LOCAL_MCP_SESSION_MANAGER = (
    build_mcp_session_manager()
)


LOCAL_MCP_SESSION = (
    LOCAL_MCP_SESSION_MANAGER
    .create_session(
        LOCAL_MCP_PRINCIPAL,
        tenant_id=LOCAL_MCP_TENANT_ID,
    )
)


# -------------------------------------------------
# MCP READ-ONLY EXPOSURE POLICY
# -------------------------------------------------


MCP_READ_TOOL_NAMES = (
    "get_finding",
    "get_asset_details",
    "get_threat_intel",
    "search_knowledge",
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


GET_THREAT_INTEL_SPEC = (
    require_mcp_read_spec(
        "get_threat_intel"
    )
)


SEARCH_KNOWLEDGE_SPEC = (
    require_mcp_read_spec(
        "search_knowledge"
    )
)


# -------------------------------------------------
# MCP EXECUTION CONTEXT
# -------------------------------------------------


def build_mcp_security_context(
) -> SecurityContext:
    """
    Revalidate the server-owned MCP session before
    constructing trusted execution context.
    """

    return (
        LOCAL_MCP_SESSION_MANAGER
        .build_security_context(
            LOCAL_MCP_PRINCIPAL,
            session_id=
                LOCAL_MCP_SESSION.session_id,
            tenant_id=
                LOCAL_MCP_TENANT_ID,
        )
    )


def build_mcp_execution_context(
) -> ToolExecutionContext:

    return ToolExecutionContext(
        principal=
            LOCAL_MCP_PRINCIPAL,

        security_context=
            build_mcp_security_context(),
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
# GET THREAT INTEL MCP TOOL
# -------------------------------------------------


@mcp.tool(
    name=GET_THREAT_INTEL_SPEC.name,

    description=
        GET_THREAT_INTEL_SPEC.description,

    annotations=ToolAnnotations(
        read_only_hint=True,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
def mcp_get_threat_intel() -> ThreatIntel:

    result = dispatch_llm_tool(
        tool_name="get_threat_intel",
        context=
            build_mcp_execution_context(),
    )

    if not isinstance(
        result,
        ThreatIntel,
    ):

        raise TypeError(
            "get_threat_intel returned an "
            "unexpected result type."
        )

    return result


# -------------------------------------------------
# SEARCH KNOWLEDGE MCP TOOL
# -------------------------------------------------


@mcp.tool(
    name=SEARCH_KNOWLEDGE_SPEC.name,

    description=
        SEARCH_KNOWLEDGE_SPEC.description,

    annotations=ToolAnnotations(
        read_only_hint=True,
        idempotent_hint=True,
        open_world_hint=False,
    ),
)
def mcp_search_knowledge(
) -> list[RetrievedEvidence]:

    # -------------------------------------------------
    # BUILD SECURITY-SIGNIFICANT CONTEXT SERVER-SIDE
    # -------------------------------------------------

    base_context = (
        build_mcp_execution_context()
    )

    context = (
        build_mcp_rag_execution_context(
            base_context
        )
    )

    # -------------------------------------------------
    # EXECUTE THROUGH EXISTING SECURE DISPATCHER
    # -------------------------------------------------

    result = dispatch_llm_tool(
        tool_name="search_knowledge",
        context=context,
    )

    # -------------------------------------------------
    # ENFORCE EXPECTED RESPONSE CONTRACT
    # -------------------------------------------------

    if not isinstance(
        result,
        list,
    ):

        raise TypeError(
            "search_knowledge returned an "
            "unexpected result type."
        )

    if not all(
        isinstance(
            item,
            RetrievedEvidence,
        )
        for item in result
    ):

        raise TypeError(
            "search_knowledge returned an "
            "unexpected evidence item type."
        )

    return result


# -------------------------------------------------
# ENTRY POINT
# -------------------------------------------------


def main() -> None:

    mcp.run()


if __name__ == "__main__":

    main()