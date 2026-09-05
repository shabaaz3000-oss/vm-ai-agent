from types import SimpleNamespace

import pytest

from pydantic import BaseModel

from app.auth import Principal

from app import agent


# -------------------------------------------------
# HELPERS
# -------------------------------------------------


def make_principal():

    return Principal(
        username="test-analyst",
        role="ANALYST",
    )


class FakeRisk(BaseModel):
    rating: str
    score: int
    sla_hours: int


def function_response(
    name,
    call_id,
    arguments="{}",
):

    return SimpleNamespace(
        output=[
            SimpleNamespace(
                type="function_call",
                name=name,
                call_id=call_id,
                arguments=arguments,
            )
        ],
        output_text="",
    )


def final_response(
    text,
):

    return SimpleNamespace(
        output=[],
        output_text=text,
    )


class FakeResponses:

    def __init__(
        self,
        responses,
    ):

        self.responses = list(
            responses
        )

        self.calls = []


    def create(
        self,
        **kwargs,
    ):

        self.calls.append(
            kwargs
        )

        if not self.responses:

            raise AssertionError(
                "Unexpected OpenAI call."
            )

        return self.responses.pop(
            0
        )


class FakeClient:

    def __init__(
        self,
        responses,
    ):

        self.responses = (
            FakeResponses(
                responses
            )
        )


# -------------------------------------------------
# INITIAL TURN EXPOSES ONLY REQUIRED READ TOOLS
# -------------------------------------------------


def test_initial_tools_exclude_knowledge_and_action():

    tools = agent._build_turn_tools(
        finding=None,
        asset=None,
        threat=None,
        knowledge_used=False,
    )

    names = {
        tool["name"]
        for tool in tools
    }

    assert names == {
        "get_finding",
        "get_asset_details",
        "get_threat_intel",
    }

    assert (
        "search_knowledge"
        not in names
    )

    assert (
        "execute_ticket_workflow"
        not in names
    )


# -------------------------------------------------
# KNOWLEDGE BECOMES AVAILABLE AFTER CORE CONTEXT
# -------------------------------------------------


def test_knowledge_tool_requires_core_context():

    tools = agent._build_turn_tools(
        finding=object(),
        asset=object(),
        threat=object(),
        knowledge_used=False,
    )

    names = {
        tool["name"]
        for tool in tools
    }

    assert names == {
        "search_knowledge"
    }


# -------------------------------------------------
# EMPTY ARGUMENT OBJECT IS ACCEPTED
# -------------------------------------------------


def test_empty_tool_arguments_are_accepted():

    agent._validate_empty_tool_arguments(
        "{}"
    )


# -------------------------------------------------
# MODEL SUPPLIED ARGUMENTS ARE REJECTED
# -------------------------------------------------


def test_nonempty_tool_arguments_are_rejected():

    with pytest.raises(
        PermissionError
    ):

        agent._validate_empty_tool_arguments(
            '{"caller_access":"restricted"}'
        )


# -------------------------------------------------
# AGENT PERFORMS CONTROLLED TOOL LOOP
# -------------------------------------------------


def test_agent_runs_controlled_read_tool_loop(
    monkeypatch,
):

    client = FakeClient(
        [
            function_response(
                "get_finding",
                "call-1",
            ),

            function_response(
                "get_asset_details",
                "call-2",
            ),

            function_response(
                "get_threat_intel",
                "call-3",
            ),

            final_response(
                "Investigation complete."
            ),
        ]
    )

    finding = {
        "finding": "test"
    }

    asset = {
        "asset": "test"
    }

    threat = {
        "threat": "test"
    }

    risk = FakeRisk(
        rating="CRITICAL",
        score=100,
        sla_hours=24,
    )

    def fake_dispatch(
        tool_name,
        context,
    ):

        mapping = {
            "get_finding":
                finding,

            "get_asset_details":
                asset,

            "get_threat_intel":
                threat,
        }

        return mapping[
            tool_name
        ]

    risk_inputs = {}

    def fake_calculate_risk(
        finding,
        asset,
        threat,
    ):

        risk_inputs[
            "finding"
        ] = finding

        risk_inputs[
            "asset"
        ] = asset

        risk_inputs[
            "threat"
        ] = threat

        return risk

    monkeypatch.setattr(
        agent,
        "dispatch_llm_tool",
        fake_dispatch,
    )

    monkeypatch.setattr(
        agent,
        "validate_provider_relationships",
        lambda **kwargs: None,
    )

    monkeypatch.setattr(
        agent,
        "calculate_risk",
        fake_calculate_risk,
    )

    monkeypatch.setattr(
        agent,
        "_inspect_tool_result",
        lambda **kwargs: [],
    )

    monkeypatch.setattr(
        agent,
        "log_event",
        lambda *args, **kwargs: None,
    )

    result = agent.run_agent(
        principal=make_principal(),
        user_request=(
            "Investigate the current "
            "vulnerability."
        ),
        openai_client=client,
        model="test-model",
    )

    assert (
        result
        == "Investigation complete."
    )

    assert (
        risk_inputs["finding"]
        is finding
    )

    assert (
        risk_inputs["asset"]
        is asset
    )

    assert (
        risk_inputs["threat"]
        is threat
    )

    assert (
        len(
            client.responses.calls
        )
        == 4
    )

    first_request = (
        client.responses.calls[
            0
        ]
    )

    assert (
        first_request[
            "parallel_tool_calls"
        ]
        is False
    )

    assert (
        first_request[
            "tool_choice"
        ]
        == "required"
    )


# -------------------------------------------------
# MODEL CANNOT CALL TOOL NOT EXPOSED THIS TURN
# -------------------------------------------------


def test_agent_blocks_hidden_action_tool(
    monkeypatch,
):

    client = FakeClient(
        [
            function_response(
                "execute_ticket_workflow",
                "call-action",
            ),
        ]
    )

    monkeypatch.setattr(
        agent,
        "log_event",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(
        PermissionError
    ):

        agent.run_agent(
            principal=
                make_principal(),

            user_request=
                "Investigate vulnerability.",

            openai_client=
                client,

            model=
                "test-model",
        )