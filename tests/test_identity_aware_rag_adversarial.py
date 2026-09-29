import json

from app.models import (
    KnowledgeChunk,
)

from app.retrieval_authorization import (
    RetrievalPrincipal,
)

from app.retriever import (
    KnowledgeRetriever,
)

from app.vector_index import (
    IndexedChunk,
    SearchResult,
)

import app.retriever as retriever_module


def principal(
    *,
    principal_id="alice",
    tenant_id="tenant-a",
    retrieval_access="standard",
):

    return RetrievalPrincipal(
        principal_id=principal_id,
        tenant_id=tenant_id,
        retrieval_access=retrieval_access,
    )


def chunk(
    *,
    source_id,
    tenant_id,
    content,
    access_level="standard",
    allowed_principal_ids=None,
):

    return KnowledgeChunk(
        chunk_id=f"{source_id}:0:attack",
        source_id=source_id,
        source_name=f"{source_id}.md",
        chunk_number=0,
        content=content,
        source_sha256="b" * 64,
        trust_tier="trusted_reference",
        access_level=access_level,
        tenant_id=tenant_id,
        allowed_principal_ids=
            allowed_principal_ids,
    )


def indexed(
    value,
    embedding=None,
):

    return IndexedChunk(
        chunk=value,
        embedding=(
            embedding
            or [1.0, 0.0]
        ),
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


# ============================================================
# CROSS-TENANT HIGH-SIMILARITY ATTACK
# ============================================================

def test_cross_tenant_secret_never_enters_semantic_search(
    monkeypatch,
):

    secret = (
        "TENANT-B-ULTRA-SECRET-001"
    )

    tenant_a = indexed(
        chunk(
            source_id="tenant-a-safe",
            tenant_id="tenant-a",
            content="approved tenant A guidance",
        ),
        embedding=[0.1, 0.9],
    )

    tenant_b = indexed(
        chunk(
            source_id="tenant-b-secret",
            tenant_id="tenant-b",
            content=secret,
        ),
        # Attacker-controlled/highly similar-looking chunk.
        embedding=[1.0, 0.0],
    )

    received_index = None

    def fake_search_vector_index(
        *,
        query,
        index,
        top_k,
    ):

        nonlocal received_index

        received_index = list(index)

        return []

    monkeypatch.setattr(
        retriever_module,
        "search_vector_index",
        fake_search_vector_index,
    )

    events = capture_events(
        monkeypatch
    )

    retriever = KnowledgeRetriever(
        index=[
            tenant_a,
            tenant_b,
        ]
    )

    result = retriever.retrieve(
        query=secret,
        retrieval_principal=
            principal(
                tenant_id="tenant-a",
            ),
    )

    assert result == []

    assert received_index == [
        tenant_a
    ]

    assert tenant_b not in received_index

    serialized_events = json.dumps(
        events
    )

    assert secret not in serialized_events

    denied = [
        event
        for event in events
        if (
            event["event_type"]
            == "RAG_AUTHORIZATION_DENIED"
        )
    ]

    assert len(denied) == 1

    assert (
        denied[0]["details"]["reason"]
        == "tenant_mismatch"
    )


# ============================================================
# SAME-TENANT CROSS-USER ACL ATTACK
# ============================================================

def test_same_tenant_user_cannot_cross_document_acl(
    monkeypatch,
):

    alice_secret = (
        "ALICE-PRIVATE-DOCUMENT-001"
    )

    alice_only = indexed(
        chunk(
            source_id="alice-private",
            tenant_id="tenant-a",
            content=alice_secret,
            allowed_principal_ids=(
                "alice",
            ),
        )
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

    events = capture_events(
        monkeypatch
    )

    retriever = KnowledgeRetriever(
        index=[
            alice_only
        ]
    )

    result = retriever.retrieve(
        query=alice_secret,
        retrieval_principal=
            principal(
                principal_id="bob",
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
        == "principal_acl_denied"
    )

    assert (
        alice_secret
        not in json.dumps(events)
    )


# ============================================================
# RESTRICTED CLASSIFICATION PRIVILEGE ATTACK
# ============================================================

def test_standard_user_cannot_retrieve_restricted_document(
    monkeypatch,
):

    restricted_secret = (
        "RESTRICTED-KNOWLEDGE-SECRET-001"
    )

    restricted = indexed(
        chunk(
            source_id="restricted-doc",
            tenant_id="tenant-a",
            content=restricted_secret,
            access_level="restricted",
        )
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

    events = capture_events(
        monkeypatch
    )

    retriever = KnowledgeRetriever(
        index=[
            restricted
        ]
    )

    result = retriever.retrieve(
        query=restricted_secret,
        retrieval_principal=
            principal(
                retrieval_access="standard",
            ),
    )

    assert result == []

    assert search_called is False

    assert (
        events[0]["details"]["reason"]
        == "classification_denied"
    )


# ============================================================
# UNSCOPED DOCUMENT FAIL-CLOSED ATTACK
# ============================================================

def test_unscoped_document_cannot_be_retrieved_by_enterprise_principal(
    monkeypatch,
):

    unscoped_secret = (
        "UNSCOPED-LEGACY-SECRET-001"
    )

    unscoped = indexed(
        chunk(
            source_id="legacy-unscoped",
            tenant_id=None,
            content=unscoped_secret,
        )
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

    events = capture_events(
        monkeypatch
    )

    retriever = KnowledgeRetriever(
        index=[
            unscoped
        ]
    )

    result = retriever.retrieve(
        query=unscoped_secret,
        retrieval_principal=
            principal(),
    )

    # Fail closed before semantic search.
    assert result == []
    assert search_called is False

    # Denial remains observable without leaking content.
    assert len(events) == 1

    assert (
        events[0]["event_type"]
        == "RAG_AUTHORIZATION_DENIED"
    )

    assert (
        events[0]["details"]["reason"]
        == "missing_tenant_scope"
    )

    assert (
        unscoped_secret
        not in json.dumps(events)
    )




# ============================================================
# MALICIOUS SEARCH BACKEND / DEFENSE-IN-DEPTH
# ============================================================

def test_adversarial_search_backend_cannot_return_cross_tenant_chunk(
    monkeypatch,
):

    secret = (
        "BACKEND-INJECTED-TENANT-B-SECRET"
    )

    allowed_chunk = chunk(
        source_id="allowed",
        tenant_id="tenant-a",
        content="allowed content",
    )

    unauthorized_chunk = chunk(
        source_id="unauthorized",
        tenant_id="tenant-b",
        content=secret,
    )

    allowed_indexed = indexed(
        allowed_chunk
    )

    unauthorized_indexed = indexed(
        unauthorized_chunk
    )

    # Simulate a buggy or compromised vector backend that
    # ignores the authorized index and injects a forbidden
    # result anyway.
    def malicious_search_vector_index(
        *,
        query,
        index,
        top_k,
    ):

        assert index == [
            allowed_indexed
        ]

        return [
            SearchResult(
                chunk=
                    unauthorized_chunk,

                similarity=
                    1.0,
            )
        ]

    monkeypatch.setattr(
        retriever_module,
        "search_vector_index",
        malicious_search_vector_index,
    )

    capture_events(
        monkeypatch
    )

    retriever = KnowledgeRetriever(
        index=[
            allowed_indexed,
            unauthorized_indexed,
        ]
    )

    result = retriever.retrieve(
        query=secret,
        retrieval_principal=
            principal(
                tenant_id="tenant-a",
            ),
    )

    # Defense-in-depth authorization after vector search
    # rejects the injected cross-tenant chunk.
    assert result == []


# ============================================================
# AUTHORIZED USER CONTROL CASE
# ============================================================

def test_explicitly_authorized_user_can_reach_search(
    monkeypatch,
):

    alice_doc = indexed(
        chunk(
            source_id="alice-doc",
            tenant_id="tenant-a",
            content="Alice authorized content",
            allowed_principal_ids=(
                "alice",
            ),
        )
    )

    received_index = None

    def fake_search_vector_index(
        *,
        query,
        index,
        top_k,
    ):

        nonlocal received_index

        received_index = list(index)

        return []

    monkeypatch.setattr(
        retriever_module,
        "search_vector_index",
        fake_search_vector_index,
    )

    capture_events(
        monkeypatch
    )

    retriever = KnowledgeRetriever(
        index=[
            alice_doc
        ]
    )

    result = retriever.retrieve(
        query="authorized content",
        retrieval_principal=
            principal(
                principal_id="alice",
                tenant_id="tenant-a",
            ),
    )

    assert result == []

    assert received_index == [
        alice_doc
    ]
