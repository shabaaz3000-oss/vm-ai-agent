import inspect

import pytest

from app.auth import Principal

from app.tools import dispatcher

from app.tools.dispatcher import (
    ToolExecutionContext,
)


# -------------------------------------------------
# TEST PRINCIPAL
# -------------------------------------------------


def make_principal():

    return Principal(
        username="test-analyst",
        role="ANALYST",
    )


# -------------------------------------------------
# REGISTERED READ TOOL CAN BE DISPATCHED
# -------------------------------------------------


def test_get_finding_can_be_dispatched(
    monkeypatch,
):

    expected = object()

    received_principal = None

    def fake_get_finding(
        principal,
    ):

        nonlocal received_principal

        received_principal = principal

        return expected

    monkeypatch.setattr(
        dispatcher,
        "get_finding",
        fake_get_finding,
    )

    monkeypatch.setattr(
        dispatcher,
        "log_event",
        lambda *args, **kwargs: None,
    )

    principal = make_principal()

    context = ToolExecutionContext(
        principal=principal,
    )

    result = dispatcher.dispatch_llm_tool(
        tool_name="get_finding",
        context=context,
    )

    assert result is expected

    assert (
        received_principal
        is principal
    )


# -------------------------------------------------
# HIDDEN ACTION TOOL CANNOT BE DISPATCHED
# -------------------------------------------------


def test_execution_tool_is_blocked_from_llm(
    monkeypatch,
):

    monkeypatch.setattr(
        dispatcher,
        "log_event",
        lambda *args, **kwargs: None,
    )

    context = ToolExecutionContext(
        principal=make_principal(),
    )

    with pytest.raises(
        PermissionError
    ):

        dispatcher.dispatch_llm_tool(
            tool_name=
                "execute_ticket_workflow",

            context=context,
        )


# -------------------------------------------------
# UNKNOWN TOOL IS REJECTED
# -------------------------------------------------


def test_unknown_tool_is_rejected(
    monkeypatch,
):

    monkeypatch.setattr(
        dispatcher,
        "log_event",
        lambda *args, **kwargs: None,
    )

    context = ToolExecutionContext(
        principal=make_principal(),
    )

    with pytest.raises(
        KeyError
    ):

        dispatcher.dispatch_llm_tool(
            tool_name=
                "run_arbitrary_command",

            context=context,
        )


# -------------------------------------------------
# KNOWLEDGE SEARCH REQUIRES TRUSTED CONTEXT
# -------------------------------------------------


def test_search_knowledge_requires_context(
    monkeypatch,
):

    monkeypatch.setattr(
        dispatcher,
        "log_event",
        lambda *args, **kwargs: None,
    )

    context = ToolExecutionContext(
        principal=make_principal(),
    )

    with pytest.raises(
        ValueError
    ):

        dispatcher.dispatch_llm_tool(
            tool_name="search_knowledge",
            context=context,
        )


# -------------------------------------------------
# KNOWLEDGE SEARCH USES SERVER CONTEXT
# -------------------------------------------------


def test_search_knowledge_uses_server_context(
    monkeypatch,
):

    principal = make_principal()

    finding = object()
    asset = object()
    risk = object()
    retriever = object()

    received = {}

    expected = [
        object(),
    ]

    def fake_search_knowledge(
        principal,
        finding,
        asset,
        risk,
        retriever,
    ):

        received[
            "principal"
        ] = principal

        received[
            "finding"
        ] = finding

        received[
            "asset"
        ] = asset

        received[
            "risk"
        ] = risk

        received[
            "retriever"
        ] = retriever

        return expected

    monkeypatch.setattr(
        dispatcher,
        "search_knowledge",
        fake_search_knowledge,
    )

    monkeypatch.setattr(
        dispatcher,
        "log_event",
        lambda *args, **kwargs: None,
    )

    context = ToolExecutionContext(
        principal=principal,
        finding=finding,
        asset=asset,
        risk=risk,
        retriever=retriever,
    )

    result = dispatcher.dispatch_llm_tool(
        tool_name="search_knowledge",
        context=context,
    )

    assert result is expected

    assert (
        received["principal"]
        is principal
    )

    assert (
        received["finding"]
        is finding
    )

    assert (
        received["asset"]
        is asset
    )

    assert (
        received["risk"]
        is risk
    )

    assert (
        received["retriever"]
        is retriever
    )


# -------------------------------------------------
# MODEL CANNOT PASS ARBITRARY TOOL ARGUMENTS
# -------------------------------------------------


def test_dispatcher_accepts_only_name_and_context():

    signature = inspect.signature(
        dispatcher.dispatch_llm_tool
    )

    assert list(
        signature.parameters
    ) == [
        "tool_name",
        "context",
    ]