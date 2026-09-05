from app.tools.openai_tools import (
    build_openai_tools,
)


# -------------------------------------------------
# ONLY EXPECTED TOOLS ARE EXPOSED
# -------------------------------------------------


def test_only_llm_visible_tools_are_exposed():

    tools = build_openai_tools()

    names = {
        tool["name"]
        for tool in tools
    }

    assert names == {
        "get_finding",
        "get_asset_details",
        "get_threat_intel",
        "search_knowledge",
    }


# -------------------------------------------------
# EXECUTION TOOL IS NEVER EXPOSED
# -------------------------------------------------


def test_execution_tool_is_not_exposed():

    tools = build_openai_tools()

    names = {
        tool["name"]
        for tool in tools
    }

    assert (
        "execute_ticket_workflow"
        not in names
    )


# -------------------------------------------------
# ALL TOOLS USE STRICT SCHEMAS
# -------------------------------------------------


def test_all_tools_use_strict_schemas():

    tools = build_openai_tools()

    assert tools

    for tool in tools:

        assert (
            tool["type"]
            == "function"
        )

        assert (
            tool["strict"]
            is True
        )

        assert (
            tool["parameters"][
                "additionalProperties"
            ]
            is False
        )


# -------------------------------------------------
# MODEL CANNOT SUPPLY TOOL ARGUMENTS
# -------------------------------------------------


def test_llm_tools_accept_no_arguments():

    tools = build_openai_tools()

    for tool in tools:

        schema = tool[
            "parameters"
        ]

        assert (
            schema["properties"]
            == {}
        )

        assert (
            schema["required"]
            == []
        )


# -------------------------------------------------
# TOOL DEFINITIONS MATCH REGISTRY COUNT
# -------------------------------------------------


def test_four_read_tools_are_exposed():

    tools = build_openai_tools()

    assert len(tools) == 4