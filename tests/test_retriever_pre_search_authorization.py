import app.retriever as retriever_module

from app.models import KnowledgeChunk

from app.retrieval_authorization import (
    is_knowledge_chunk_authorized,
)

from app.retriever import (
    KnowledgeRetriever,
)

from app.vector_index import (
    IndexedChunk,
)


# -------------------------------------------------
# HELPERS
# -------------------------------------------------


def make_chunk(
    *,
    source_id: str,
    access_level: str,
) -> KnowledgeChunk:

    return KnowledgeChunk(
        chunk_id=f"{source_id}:0:test",
        source_id=source_id,
        source_name=f"{source_id}.md",
        chunk_number=0,
        content=(
            f"{source_id} security guidance"
        ),
        source_sha256="a" * 64,
        trust_tier="trusted_reference",
        access_level=access_level,
    )


def make_indexed_chunk(
    *,
    source_id: str,
    access_level: str,
) -> IndexedChunk:

    return IndexedChunk(
        chunk=make_chunk(
            source_id=source_id,
            access_level=access_level,
        ),
        embedding=[1.0, 0.0],
    )


# -------------------------------------------------
# DEFAULT DENY
# -------------------------------------------------


def test_unknown_document_classification_is_denied():

    chunk = make_chunk(
        source_id="unknown",
        access_level="standard",
    )

    # model_copy(update=...) deliberately bypasses normal
    # validation so the policy itself is tested against an
    # unexpected future/invalid classification.

    unknown_chunk = chunk.model_copy(
        update={
            "access_level":
                "future-secret"
        }
    )

    assert (
        is_knowledge_chunk_authorized(
            caller_access="standard",
            chunk=unknown_chunk,
        )
        is False
    )

    assert (
        is_knowledge_chunk_authorized(
            caller_access="restricted",
            chunk=unknown_chunk,
        )
        is False
    )


# -------------------------------------------------
# STANDARD CALLER ? RESTRICTED CHUNK NEVER SEARCHED
# -------------------------------------------------


def test_standard_caller_filters_restricted_chunk_before_search(
    monkeypatch,
):

    standard = make_indexed_chunk(
        source_id="standard",
        access_level="standard",
    )

    restricted = make_indexed_chunk(
        source_id="restricted",
        access_level="restricted",
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

    retriever = KnowledgeRetriever(
        index=[
            standard,
            restricted,
        ]
    )

    result = retriever.retrieve(
        query="security guidance",
        caller_access="standard",
    )

    assert result == []

    assert received_index == [
        standard
    ]


# -------------------------------------------------
# RESTRICTED CALLER ? BOTH CLASSES SEARCHABLE
# -------------------------------------------------


def test_restricted_caller_searches_authorized_standard_and_restricted(
    monkeypatch,
):

    standard = make_indexed_chunk(
        source_id="standard",
        access_level="standard",
    )

    restricted = make_indexed_chunk(
        source_id="restricted",
        access_level="restricted",
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

    retriever = KnowledgeRetriever(
        index=[
            standard,
            restricted,
        ]
    )

    retriever.retrieve(
        query="security guidance",
        caller_access="restricted",
    )

    assert received_index == [
        standard,
        restricted,
    ]


# -------------------------------------------------
# EMPTY AUTHORIZED CORPUS ? SEARCH NEVER EXECUTES
# -------------------------------------------------


def test_no_authorized_chunks_skips_semantic_search(
    monkeypatch,
):

    search_called = False

    def fake_search_vector_index(
        *,
        query,
        index,
        top_k,
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
            make_indexed_chunk(
                source_id="restricted",
                access_level="restricted",
            )
        ]
    )

    result = retriever.retrieve(
        query="security guidance",
        caller_access="standard",
    )

    assert result == []

    assert search_called is False
