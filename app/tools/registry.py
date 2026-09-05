from dataclasses import dataclass
from typing import Literal


# -------------------------------------------------
# TOOL TYPES
# -------------------------------------------------


ToolKind = Literal[
    "read",
    "action",
]


# -------------------------------------------------
# TOOL SPECIFICATION
# -------------------------------------------------


@dataclass(
    frozen=True
)
class ToolSpec:

    name: str

    description: str

    kind: ToolKind

    llm_visible: bool

    requires_human_approval: bool = False


# -------------------------------------------------
# TOOL REGISTRY
# -------------------------------------------------


TOOL_REGISTRY = {

    "get_finding":
        ToolSpec(
            name="get_finding",

            description=(
                "Retrieve the validated "
                "vulnerability finding."
            ),

            kind="read",

            llm_visible=True,
        ),

    "get_asset_details":
        ToolSpec(
            name="get_asset_details",

            description=(
                "Retrieve validated asset "
                "security context."
            ),

            kind="read",

            llm_visible=True,
        ),

    "get_threat_intel":
        ToolSpec(
            name="get_threat_intel",

            description=(
                "Retrieve validated threat "
                "intelligence."
            ),

            kind="read",

            llm_visible=True,
        ),

    "search_knowledge":
        ToolSpec(
            name="search_knowledge",

            description=(
                "Retrieve authorized "
                "vulnerability-management "
                "reference evidence using "
                "a constrained retrieval query."
            ),

            kind="read",

            llm_visible=True,
        ),

    "execute_ticket_workflow":
        ToolSpec(
            name="execute_ticket_workflow",

            description=(
                "Execute a previously prepared "
                "and human-approved ticket-bound "
                "workflow."
            ),

            kind="action",

            llm_visible=False,

            requires_human_approval=True,
        ),
}


# -------------------------------------------------
# GET TOOL SPECIFICATION
# -------------------------------------------------


def get_tool_spec(
    tool_name: str,
) -> ToolSpec:

    try:

        return TOOL_REGISTRY[
            tool_name
        ]

    except KeyError:

        raise KeyError(
            f"Unknown tool: {tool_name}"
        ) from None


# -------------------------------------------------
# GET LLM-VISIBLE TOOLS
# -------------------------------------------------


def get_llm_visible_tools() -> list[ToolSpec]:

    return [
        tool
        for tool in TOOL_REGISTRY.values()
        if tool.llm_visible
    ]