from types import SimpleNamespace

import pytest

from fastapi import HTTPException
from fastapi import status

from app.auth import Principal

from app.tools import knowledge


# -------------------------------------------------
# TEST DATA
# -------------------------------------------------


def make_principal(
    role="ANALYST",
):

    return Principal(
        username="test-user",
        role=role,
    )


# -------------------------------------------------
# DEFAULT PASS-THROUGH RAG SECURITY
# -------------------------------------------------


@pytest.fixture(
    autouse=True
)
def pass_through_rag_security(
    monkeypatch,
):

    def fake_secure(
        evidence,
    ):

        return SimpleNamespace(
            safe_evidence=evidence,
            quarantined_chunk_ids=[],
            categories=[],
        )

    monkeypatch.setattr(
        knowledge,
        "secure_retrieved_evidence",
        fake_secure,
    )


# -------------------------------------------------
# ANALYST CAN SEARCH KNOWLEDGE
# -------------------------------------------------


def test_analyst_can_search_knowledge(
    monkeypatch,
):

    principal = make_principal()

    expected_evidence = [
        object(),
        object(),
    ]

    class FakeRetriever:

        def retrieve(
            self,
            query,
            top_k,
            min_similarity,
            caller_access,
        ):

            return expected_evidence

    monkeypatch.setattr(
        knowledge,
        "build_retrieval_query",
        lambda **kwargs:
            "safe constrained query",
    )

    monkeypatch.setattr(
        knowledge,
        "log_event",
        lambda *args, **kwargs: None,
    )

    result = knowledge.search_knowledge(
        principal=principal,
        finding=object(),
        asset=object(),
        risk=object(),
        retriever=FakeRetriever(),
    )

    assert result is expected_evidence


# -------------------------------------------------
# CONSTRAINED QUERY IS USED
# -------------------------------------------------


def test_search_knowledge_uses_constrained_query(
    monkeypatch,
):

    principal = make_principal()

    received_query = None

    class FakeRetriever:

        def retrieve(
            self,
            query,
            top_k,
            min_similarity,
            caller_access,
        ):

            nonlocal received_query

            received_query = query

            return []

    monkeypatch.setattr(
        knowledge,
        "build_retrieval_query",
        lambda **kwargs:
            "trusted structured query",
    )

    monkeypatch.setattr(
        knowledge,
        "log_event",
        lambda *args, **kwargs: None,
    )

    knowledge.search_knowledge(
        principal=principal,
        finding=object(),
        asset=object(),
        risk=object(),
        retriever=FakeRetriever(),
    )

    assert (
        received_query
        == "trusted structured query"
    )


# -------------------------------------------------
# STANDARD RETRIEVAL ACCESS IS ENFORCED
# -------------------------------------------------


def test_search_knowledge_uses_standard_access(
    monkeypatch,
):

    principal = make_principal(
        role="APPROVER",
    )

    received_access = None

    class FakeRetriever:

        def retrieve(
            self,
            query,
            top_k,
            min_similarity,
            caller_access,
        ):

            nonlocal received_access

            received_access = caller_access

            return []

    monkeypatch.setattr(
        knowledge,
        "build_retrieval_query",
        lambda **kwargs:
            "safe query",
    )

    monkeypatch.setattr(
        knowledge,
        "log_event",
        lambda *args, **kwargs: None,
    )

    knowledge.search_knowledge(
        principal=principal,
        finding=object(),
        asset=object(),
        risk=object(),
        retriever=FakeRetriever(),
    )

    assert (
        received_access
        == "standard"
    )


# -------------------------------------------------
# DENIED REQUEST DOES NOT RETRIEVE
# -------------------------------------------------


def test_denied_tool_does_not_retrieve(
    monkeypatch,
):

    principal = make_principal()

    query_built = False
    retrieval_called = False

    def deny_tool(
        principal,
        tool_name,
    ):

        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            detail="Denied",
        )

    def fake_build_query(
        **kwargs,
    ):

        nonlocal query_built

        query_built = True

        return "query"

    class FakeRetriever:

        def retrieve(
            self,
            **kwargs,
        ):

            nonlocal retrieval_called

            retrieval_called = True

            return []

    monkeypatch.setattr(
        knowledge,
        "require_tool_permission",
        deny_tool,
    )

    monkeypatch.setattr(
        knowledge,
        "build_retrieval_query",
        fake_build_query,
    )

    monkeypatch.setattr(
        knowledge,
        "log_event",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(
        HTTPException
    ) as exc_info:

        knowledge.search_knowledge(
            principal=principal,
            finding=object(),
            asset=object(),
            risk=object(),
            retriever=FakeRetriever(),
        )

    assert (
        exc_info.value.status_code
        == 403
    )

    assert query_built is False

    assert retrieval_called is False


# -------------------------------------------------
# SUSPICIOUS RAG EVIDENCE IS QUARANTINED
# -------------------------------------------------


def test_suspicious_rag_evidence_is_not_returned(
    monkeypatch,
):

    principal = make_principal()

    safe_item = object()
    malicious_item = object()

    events = []

    class FakeRetriever:

        def retrieve(
            self,
            **kwargs,
        ):

            return [
                safe_item,
                malicious_item,
            ]

    monkeypatch.setattr(
        knowledge,
        "build_retrieval_query",
        lambda **kwargs:
            "safe query",
    )

    def fake_secure(
        evidence,
    ):

        assert evidence == [
            safe_item,
            malicious_item,
        ]

        return SimpleNamespace(
            safe_evidence=[
                safe_item,
            ],

            quarantined_chunk_ids=[
                "chunk-malicious",
            ],

            categories=[
                "instruction_override",
            ],
        )

    def fake_log_event(
        event,
        data=None,
    ):

        events.append(
            (
                event,
                data,
            )
        )

    monkeypatch.setattr(
        knowledge,
        "secure_retrieved_evidence",
        fake_secure,
    )

    monkeypatch.setattr(
        knowledge,
        "log_event",
        fake_log_event,
    )

    result = knowledge.search_knowledge(
        principal=principal,
        finding=object(),
        asset=object(),
        risk=object(),
        retriever=FakeRetriever(),
    )

    assert result == [
        safe_item,
    ]

    assert (
        malicious_item
        not in result
    )

    event_names = [
        event
        for event, data
        in events
    ]

    assert (
        "TOOL_RAG_EVIDENCE_QUARANTINED"
        in event_names
    )


# -------------------------------------------------
# SUCCESSFUL SEARCH IS AUDITED
# -------------------------------------------------


def test_search_knowledge_is_audited(
    monkeypatch,
):

    principal = make_principal()

    events = []

    class FakeRetriever:

        def retrieve(
            self,
            **kwargs,
        ):

            return [
                object(),
            ]

    monkeypatch.setattr(
        knowledge,
        "build_retrieval_query",
        lambda **kwargs:
            "safe query",
    )

    def fake_log_event(
        event,
        data=None,
    ):

        events.append(
            (
                event,
                data,
            )
        )

    monkeypatch.setattr(
        knowledge,
        "log_event",
        fake_log_event,
    )

    knowledge.search_knowledge(
        principal=principal,
        finding=object(),
        asset=object(),
        risk=object(),
        retriever=FakeRetriever(),
    )

    event_names = [
        event
        for event, data
        in events
    ]

    assert (
        "TOOL_REQUESTED"
        in event_names
    )

    assert (
        "TOOL_EXECUTED"
        in event_names
    )

    executed_event = next(
        data
        for event, data
        in events
        if event
        == "TOOL_EXECUTED"
    )

    assert (
        executed_event[
            "result_count"
        ]
        == 1
    )