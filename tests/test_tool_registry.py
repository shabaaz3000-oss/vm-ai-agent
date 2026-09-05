from app.tools.authorization import (
    TOOL_PERMISSIONS,
)

from app.tools.registry import (
    TOOL_REGISTRY,
    get_llm_visible_tools,
    get_tool_spec,
)


# -------------------------------------------------
# EXPECTED TOOLS ARE REGISTERED
# -------------------------------------------------


def test_expected_tools_are_registered():

    assert set(
        TOOL_REGISTRY
    ) == {
        "get_finding",
        "get_asset_details",
        "get_threat_intel",
        "search_knowledge",
        "execute_ticket_workflow",
    }


# -------------------------------------------------
# AUTHORIZATION AND REGISTRY STAY ALIGNED
# -------------------------------------------------


def test_registry_matches_authorized_tool_names():

    authorized_tools = set()

    for tools in (
        TOOL_PERMISSIONS.values()
    ):

        authorized_tools.update(
            tools
        )

    assert (
        set(TOOL_REGISTRY)
        == authorized_tools
    )


# -------------------------------------------------
# READ TOOLS ARE LLM VISIBLE
# -------------------------------------------------


def test_read_tools_are_llm_visible():

    expected = {
        "get_finding",
        "get_asset_details",
        "get_threat_intel",
        "search_knowledge",
    }

    visible = {
        tool.name
        for tool in get_llm_visible_tools()
    }

    assert visible == expected


# -------------------------------------------------
# EXECUTION TOOL IS HIDDEN FROM LLM
# -------------------------------------------------


def test_execution_tool_is_not_llm_visible():

    tool = get_tool_spec(
        "execute_ticket_workflow"
    )

    assert tool.llm_visible is False

    assert (
        tool.requires_human_approval
        is True
    )

    assert tool.kind == "action"


# -------------------------------------------------
# ALL LLM-VISIBLE TOOLS ARE READ ONLY
# -------------------------------------------------


def test_llm_visible_tools_are_read_only():

    tools = get_llm_visible_tools()

    assert tools

    assert all(
        tool.kind == "read"
        for tool in tools
    )


# -------------------------------------------------
# UNKNOWN TOOL IS REJECTED
# -------------------------------------------------


def test_unknown_tool_is_rejected():

    try:

        get_tool_spec(
            "run_arbitrary_command"
        )

    except KeyError as error:

        assert (
            "Unknown tool"
            in str(error)
        )

    else:

        raise AssertionError(
            "Unknown tool was accepted."
        )