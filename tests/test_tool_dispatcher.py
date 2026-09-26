import inspect

import pytest

from app.auth import Principal
from app.security_context import SecurityContext

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


# -------------------------------------------------
# TRUSTED SECURITY CONTEXT BINDING
# -------------------------------------------------


def test_tool_execution_context_accepts_matching_security_context():

    principal = make_principal()

    security_context = SecurityContext(
        principal_id=principal.username,
        role=principal.role,
        retrieval_access=(
            principal.retrieval_access
        ),
        tenant_id="tenant-a",
        session_id="session-123",
    )

    context = ToolExecutionContext(
        principal=principal,
        security_context=security_context,
    )

    assert (
        context.security_context
        is security_context
    )

    assert (
        context.security_context.tenant_id
        == "tenant-a"
    )

    assert (
        context.security_context.session_id
        == "session-123"
    )


def test_tool_execution_context_rejects_principal_id_mismatch():

    principal = make_principal()

    security_context = SecurityContext(
        principal_id="different-user",
        role=principal.role,
        retrieval_access=(
            principal.retrieval_access
        ),
        tenant_id="tenant-a",
        session_id="session-123",
    )

    with pytest.raises(
        ValueError,
        match="principal mismatch",
    ):

        ToolExecutionContext(
            principal=principal,
            security_context=security_context,
        )


def test_tool_execution_context_rejects_role_mismatch():

    principal = make_principal()

    security_context = SecurityContext(
        principal_id=principal.username,
        role="APPROVER",
        retrieval_access=(
            principal.retrieval_access
        ),
        tenant_id="tenant-a",
        session_id="session-123",
    )

    with pytest.raises(
        ValueError,
        match="role mismatch",
    ):

        ToolExecutionContext(
            principal=principal,
            security_context=security_context,
        )


def test_tool_execution_context_rejects_retrieval_access_mismatch():

    principal = make_principal()

    security_context = SecurityContext(
        principal_id=principal.username,
        role=principal.role,
        retrieval_access="restricted",
        tenant_id="tenant-a",
        session_id="session-123",
    )

    with pytest.raises(
        ValueError,
        match="retrieval access mismatch",
    ):

        ToolExecutionContext(
            principal=principal,
            security_context=security_context,
        )


def test_dispatcher_revalidates_security_binding_before_execution(
    monkeypatch,
):

    principal = make_principal()

    security_context = SecurityContext(
        principal_id=principal.username,
        role=principal.role,
        retrieval_access=(
            principal.retrieval_access
        ),
        tenant_id="tenant-a",
        session_id="session-123",
    )

    context = ToolExecutionContext(
        principal=principal,
        security_context=security_context,
    )

    tool_called = False

    def fake_get_finding(
        principal,
    ):

        nonlocal tool_called

        tool_called = True

        return object()

    monkeypatch.setattr(
        dispatcher,
        "get_finding",
        fake_get_finding,
    )

    # Simulate mutable identity drift after the trusted
    # session context has already been established.
    principal.role = "APPROVER"

    with pytest.raises(
        ValueError,
        match="role mismatch",
    ):

        dispatcher.dispatch_llm_tool(
            tool_name="get_finding",
            context=context,
        )

    assert tool_called is False



# -------------------------------------------------
# SESSION / TENANT AUDIT CORRELATION
# -------------------------------------------------


def test_dispatch_audit_contains_trusted_session_correlation(
    monkeypatch,
):

    principal = make_principal()

    security_context = SecurityContext(
        principal_id=principal.username,
        role=principal.role,
        retrieval_access=
            principal.retrieval_access,
        tenant_id="tenant-a",
        session_id="raw-session-secret",
    )

    context = ToolExecutionContext(
        principal=principal,
        security_context=security_context,
    )

    events = []

    def fake_log_event(
        event_type,
        details=None,
    ):

        events.append(
            (
                event_type,
                details or {},
            )
        )

    monkeypatch.setattr(
        dispatcher,
        "log_event",
        fake_log_event,
    )

    monkeypatch.setattr(
        dispatcher,
        "get_finding",
        lambda principal: object(),
    )

    dispatcher.dispatch_llm_tool(
        tool_name="get_finding",
        context=context,
    )

    requested = events[0][1]

    dispatched = events[-1][1]

    for details in (
        requested,
        dispatched,
    ):

        assert (
            details["principal_id"]
            == principal.username
        )

        assert (
            details["tenant_id"]
            == "tenant-a"
        )

        assert (
            details[
                "session_correlation_id"
            ]
            == security_context
            .session_correlation_id
        )

        assert (
            "raw-session-secret"
            not in str(details)
        )


def test_blocked_dispatch_audit_keeps_session_correlation(
    monkeypatch,
):

    principal = make_principal()

    security_context = SecurityContext(
        principal_id=principal.username,
        role=principal.role,
        retrieval_access=
            principal.retrieval_access,
        tenant_id="tenant-a",
        session_id="raw-session-secret",
    )

    context = ToolExecutionContext(
        principal=principal,
        security_context=security_context,
    )

    events = []

    def fake_log_event(
        event_type,
        details=None,
    ):

        events.append(
            (
                event_type,
                details or {},
            )
        )

    monkeypatch.setattr(
        dispatcher,
        "log_event",
        fake_log_event,
    )

    with pytest.raises(
        KeyError
    ):

        dispatcher.dispatch_llm_tool(
            tool_name="does_not_exist",
            context=context,
        )

    blocked = [
        details
        for event_type, details
        in events
        if event_type
        == "LLM_TOOL_DISPATCH_BLOCKED"
    ]

    assert len(blocked) == 1

    details = blocked[0]

    assert (
        details["tenant_id"]
        == "tenant-a"
    )

    assert (
        details[
            "session_correlation_id"
        ]
        == security_context
        .session_correlation_id
    )

    assert (
        "raw-session-secret"
        not in str(details)
    )
