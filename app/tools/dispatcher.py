from dataclasses import dataclass

from app.auth import Principal
from app.audit import log_event

from app.models import (
    AssetContext,
    RiskResult,
    VulnerabilityFinding,
)

from app.retriever import KnowledgeRetriever

from app.tools.assets import (
    get_asset_details,
)

from app.tools.findings import (
    get_finding,
)

from app.tools.knowledge import (
    search_knowledge,
)

from app.tools.registry import (
    get_tool_spec,
)

from app.tools.threat_intel import (
    get_threat_intel,
)


# -------------------------------------------------
# TRUSTED TOOL EXECUTION CONTEXT
# -------------------------------------------------


@dataclass(
    frozen=True
)
class ToolExecutionContext:

    principal: Principal

    finding: VulnerabilityFinding | None = None

    asset: AssetContext | None = None

    risk: RiskResult | None = None

    retriever: KnowledgeRetriever | None = None


# -------------------------------------------------
# LLM TOOL DISPATCHER
# -------------------------------------------------


def dispatch_llm_tool(
    tool_name: str,
    context: ToolExecutionContext,
):

    log_event(
        "LLM_TOOL_DISPATCH_REQUESTED",
        {
            "tool": tool_name,
            "username":
                context.principal.username,
            "role":
                context.principal.role,
        },
    )

    # -------------------------------------------------
    # 1. REQUIRE REGISTERED TOOL
    # -------------------------------------------------

    try:

        spec = get_tool_spec(
            tool_name
        )

    except KeyError:

        log_event(
            "LLM_TOOL_DISPATCH_BLOCKED",
            {
                "tool": tool_name,
                "username":
                    context.principal.username,
                "reason":
                    "unknown_tool",
            },
        )

        raise

    # -------------------------------------------------
    # 2. REQUIRE LLM VISIBILITY
    # -------------------------------------------------

    if not spec.llm_visible:

        log_event(
            "LLM_TOOL_DISPATCH_BLOCKED",
            {
                "tool": tool_name,
                "username":
                    context.principal.username,
                "reason":
                    "tool_not_llm_visible",
            },
        )

        raise PermissionError(
            "Tool is not available "
            "to the LLM."
        )

    # -------------------------------------------------
    # 3. LLM MAY ONLY DISPATCH READ TOOLS
    # -------------------------------------------------

    if spec.kind != "read":

        log_event(
            "LLM_TOOL_DISPATCH_BLOCKED",
            {
                "tool": tool_name,
                "username":
                    context.principal.username,
                "reason":
                    "non_read_tool",
            },
        )

        raise PermissionError(
            "LLM tool dispatch is restricted "
            "to read-only tools."
        )

    # -------------------------------------------------
    # 4. DISPATCH ALLOWLISTED TOOL
    # -------------------------------------------------

    if tool_name == "get_finding":

        result = get_finding(
            principal=
                context.principal,
        )

    elif tool_name == "get_asset_details":

        result = get_asset_details(
            principal=
                context.principal,
        )

    elif tool_name == "get_threat_intel":

        result = get_threat_intel(
            principal=
                context.principal,
        )

    elif tool_name == "search_knowledge":

        if (
            context.finding is None
            or context.asset is None
            or context.risk is None
            or context.retriever is None
        ):

            raise ValueError(
                "search_knowledge requires "
                "server-controlled finding, "
                "asset, risk, and retriever "
                "context."
            )

        result = search_knowledge(
            principal=
                context.principal,

            finding=
                context.finding,

            asset=
                context.asset,

            risk=
                context.risk,

            retriever=
                context.retriever,
        )

    else:

        # Defense in depth.
        #
        # Registry entries must also have an
        # explicit dispatcher implementation.

        raise KeyError(
            f"No dispatcher implementation "
            f"for tool: {tool_name}"
        )

    # -------------------------------------------------
    # 5. AUDIT SUCCESSFUL DISPATCH
    # -------------------------------------------------

    log_event(
        "LLM_TOOL_DISPATCHED",
        {
            "tool": tool_name,
            "username":
                context.principal.username,
            "role":
                context.principal.role,
        },
    )

    return result