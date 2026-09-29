from __future__ import annotations

import json

from app.models import (
    KnowledgeChunk,
)

from app.retrieval_authorization import (
    RetrievalPrincipal,
    evaluate_knowledge_chunk_authorization,
)

from app.retriever import (
    KnowledgeRetriever,
)

from app.vector_index import (
    IndexedChunk,
)

import app.retriever as retriever_module


def principal(
    *,
    principal_id: str = "alice",
    tenant_id: str = "tenant-a",
    retrieval_access: str = "standard",
) -> RetrievalPrincipal:

    return RetrievalPrincipal(
        principal_id=principal_id,
        tenant_id=tenant_id,
        retrieval_access=retrieval_access,
    )


def chunk(
    *,
    tenant_id: str | None = "tenant-a",
    access_level: str = "standard",
    allowed_principal_ids=None,
    source_id: str = "policy",
    content: str = "SAFE DOCUMENT CONTENT",
) -> KnowledgeChunk:

    return KnowledgeChunk(
        chunk_id=f"{source_id}:0:audit",
        source_id=source_id,
        source_name=f"{source_id}.md",
        chunk_number=0,
        content=content,
        source_sha256="a" * 64,
        trust_tier="trusted_reference",
        access_level=access_level,
        tenant_id=tenant_id,
        allowed_principal_ids=
            allowed_principal_ids,
    )


def indexed(
    value: KnowledgeChunk,
) -> IndexedChunk:

    return IndexedChunk(
        chunk=value,
        embedding=[
            1.0,
            0.0,
        ],
    )


def capture_events(
    monkeypatch,
):

    events = []

    def fake_log_event(
        event_type,
        details=None,
    ):

        events.append(
            {
                "event_type":
                    event_type,

                "details":
                    details or {},
            }
        )

    monkeypatch.setattr(
        retriever_module,
        "log_event",
        fake_log_event,
    )

    return events


def test_structured_decision_reports_allowed():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(),
            retrieval_principal=
                principal(),
        )
    )

    assert decision.allowed is True
    assert decision.reason == "allowed"


def test_structured_decision_reports_tenant_mismatch():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                tenant_id="tenant-b",
            ),
            retrieval_principal=
                principal(
                    tenant_id="tenant-a",
                ),
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "tenant_mismatch"
    )


def test_structured_decision_reports_acl_denial():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                allowed_principal_ids=(
                    "bob",
                ),
            ),
            retrieval_principal=
                principal(
                    principal_id="alice",
                ),
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "principal_acl_denied"
    )


def test_structured_decision_reports_missing_tenant_scope():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                tenant_id=None,
            ),
            retrieval_principal=
                principal(),
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "missing_tenant_scope"
    )


def test_structured_decision_reports_classification_denial():

    decision = (
        evaluate_knowledge_chunk_authorization(
            chunk=chunk(
                access_level="restricted",
            ),
            retrieval_principal=
                principal(
                    retrieval_access=
                        "standard",
                ),
        )
    )

    assert decision.allowed is False

    assert (
        decision.reason
        == "classification_denied"
    )


def test_allowed_chunk_emits_safe_authorization_audit(
    monkeypatch,
):

    events = capture_events(
        monkeypatch
    )

    search_indexes = []

    allowed_chunk = chunk(
        source_id="allowed-policy",
        content=
            "TOP-SECRET-CONTENT-MUST-NOT-BE-LOGGED",
    )

    def fake_search_vector_index(
        *,
        query,
        index,
        top_k,
    ):

        search_indexes.append(
            list(index)
        )

        return []

    monkeypatch.setattr(
        retriever_module,
        "search_vector_index",
        fake_search_vector_index,
    )

    retriever = KnowledgeRetriever(
        index=[
            indexed(
                allowed_chunk
            )
        ]
    )

    result = retriever.retrieve(
        query="security guidance",
        retrieval_principal=
            principal(),
    )

    assert result == []

    assert len(
        search_indexes
    ) == 1

    assert len(events) == 1

    event = events[0]

    assert (
        event["event_type"]
        == "RAG_AUTHORIZATION_ALLOWED"
    )

    assert event["details"] == {
        "principal_id":
            "alice",

        "tenant_id":
            "tenant-a",

        "source_id":
            "allowed-policy",

        "chunk_id":
            "allowed-policy:0:audit",

        "decision":
            "allowed",

        "reason":
            "allowed",
    }

    serialized = json.dumps(
        event
    )

    assert (
        "TOP-SECRET-CONTENT-MUST-NOT-BE-LOGGED"
        not in serialized
    )

    assert "embedding" not in serialized
    assert "query" not in serialized
    assert "session_id" not in serialized


def test_cross_tenant_denial_is_audited_before_search(
    monkeypatch,
):

    events = capture_events(
        monkeypatch
    )

    search_called = False

    def fake_search_vector_index(
        **kwargs,
    ):

        nonlocal search_called

        search_called = True

        return []

    monkeypatch.setattr(
        retriever_module,
        "search_vector_index",
        fake_search_vector_index,
    )

    retriever = KnowledgeRetriever(
        index=[
            indexed(
                chunk(
                    tenant_id=
                        "tenant-b",

                    source_id=
                        "tenant-b-policy",
                )
            )
        ]
    )

    result = retriever.retrieve(
        query="security guidance",
        retrieval_principal=
            principal(
                tenant_id="tenant-a",
            ),
    )

    assert result == []

    assert search_called is False

    assert len(events) == 1

    assert (
        events[0]["event_type"]
        == "RAG_AUTHORIZATION_DENIED"
    )

    assert (
        events[0]["details"]["reason"]
        == "tenant_mismatch"
    )

    assert (
        events[0]["details"]["decision"]
        == "denied"
    )


def test_acl_denial_is_audited_before_search(
    monkeypatch,
):

    events = capture_events(
        monkeypatch
    )

    retriever = KnowledgeRetriever(
        index=[
            indexed(
                chunk(
                    source_id=
                        "principal-only",

                    allowed_principal_ids=(
                        "bob",
                    ),
                )
            )
        ]
    )

    result = retriever.retrieve(
        query="security guidance",
        retrieval_principal=
            principal(
                principal_id="alice",
            ),
    )

    assert result == []

    assert len(events) == 1

    assert (
        events[0]["details"]["reason"]
        == "principal_acl_denied"
    )


def test_restricted_classification_denial_is_audited(
    monkeypatch,
):

    events = capture_events(
        monkeypatch
    )

    retriever = KnowledgeRetriever(
        index=[
            indexed(
                chunk(
                    source_id=
                        "restricted-policy",

                    access_level=
                        "restricted",
                )
            )
        ]
    )

    result = retriever.retrieve(
        query="security guidance",
        retrieval_principal=
            principal(
                retrieval_access=
                    "standard",
            ),
    )

    assert result == []

    assert len(events) == 1

    assert (
        events[0]["details"]["reason"]
        == "classification_denied"
    )


def test_legacy_retrieval_does_not_invent_identity_audit(
    monkeypatch,
):

    events = capture_events(
        monkeypatch
    )

    monkeypatch.setattr(
        retriever_module,
        "search_vector_index",
        lambda **kwargs: [],
    )

    retriever = KnowledgeRetriever(
        index=[
            indexed(
                chunk(
                    tenant_id=None,
                )
            )
        ]
    )

    result = retriever.retrieve(
        query="security guidance",
        caller_access="standard",
    )

    assert result == []

    assert events == []
