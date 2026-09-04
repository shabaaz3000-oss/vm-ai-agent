from unittest.mock import patch

import pytest

from app.models import KnowledgeChunk

from app.retriever import KnowledgeRetriever

from app.vector_index import (
    IndexedChunk,
    SearchResult,
)


# -------------------------------------------------
# TEST CHUNK HELPERS
# -------------------------------------------------


def _make_chunk() -> KnowledgeChunk:

    return KnowledgeChunk(
        chunk_id=
            "policy:0:123456789abc",

        source_id=
            "policy",

        source_name=
            "policy.md",

        chunk_number=0,

        content=
            "Apply approved security patches.",

        source_sha256=
            "a" * 64,

        trust_tier=
            "trusted_reference",

        access_level=
            "standard",
    )


def _make_restricted_chunk() -> KnowledgeChunk:

    return KnowledgeChunk(
        chunk_id=
            "restricted:0:123456789abc",

        source_id=
            "restricted",

        source_name=
            "restricted.md",

        chunk_number=0,

        content=
            "Sensitive internal architecture.",

        source_sha256=
            "b" * 64,

        trust_tier=
            "trusted_reference",

        access_level=
            "restricted",
    )


# -------------------------------------------------
# BASIC RETRIEVAL TESTS
# -------------------------------------------------


def test_retriever_returns_evidence():

    chunk = _make_chunk()

    index = [
        IndexedChunk(
            chunk=chunk,
            embedding=[
                1.0,
                0.0,
            ],
        )
    ]

    retriever = (
        KnowledgeRetriever(
            index=index
        )
    )

    with patch(
        "app.retriever.search_vector_index"
    ) as mock_search:

        mock_search.return_value = [
            SearchResult(
                chunk=chunk,
                similarity=0.82,
            )
        ]

        evidence = retriever.retrieve(
            query=
                "How should I remediate?"
        )

    assert len(evidence) == 1

    assert (
        evidence[0].source_name
        == "policy.md"
    )

    assert (
        evidence[0].similarity
        == 0.82
    )

    assert (
        evidence[0].trust_tier
        == "trusted_reference"
    )

    assert (
        evidence[0].access_level
        == "standard"
    )


def test_retriever_filters_low_similarity():

    chunk = _make_chunk()

    retriever = (
        KnowledgeRetriever(
            index=[]
        )
    )

    with patch(
        "app.retriever.search_vector_index"
    ) as mock_search:

        mock_search.return_value = [
            SearchResult(
                chunk=chunk,
                similarity=0.20,
            )
        ]

        evidence = retriever.retrieve(
            query=
                "test query",

            min_similarity=
                0.50,
        )

    assert evidence == []


def test_retriever_rejects_empty_query():

    retriever = (
        KnowledgeRetriever(
            index=[]
        )
    )

    with pytest.raises(
        ValueError
    ):

        retriever.retrieve(
            query="   "
        )


# -------------------------------------------------
# RETRIEVAL AUTHORIZATION TESTS
# -------------------------------------------------


def test_standard_caller_cannot_retrieve_restricted():

    chunk = (
        _make_restricted_chunk()
    )

    retriever = (
        KnowledgeRetriever(
            index=[]
        )
    )

    with patch(
        "app.retriever.search_vector_index"
    ) as mock_search:

        mock_search.return_value = [
            SearchResult(
                chunk=chunk,
                similarity=0.95,
            )
        ]

        evidence = retriever.retrieve(
            query=
                "internal architecture",

            caller_access=
                "standard",
        )

    assert evidence == []


def test_restricted_caller_can_retrieve_restricted():

    chunk = (
        _make_restricted_chunk()
    )

    retriever = (
        KnowledgeRetriever(
            index=[]
        )
    )

    with patch(
        "app.retriever.search_vector_index"
    ) as mock_search:

        mock_search.return_value = [
            SearchResult(
                chunk=chunk,
                similarity=0.95,
            )
        ]

        evidence = retriever.retrieve(
            query=
                "internal architecture",

            caller_access=
                "restricted",
        )

    assert len(evidence) == 1

    assert (
        evidence[0].source_name
        == "restricted.md"
    )

    assert (
        evidence[0].access_level
        == "restricted"
    )

    assert (
        evidence[0].similarity
        == 0.95
    )


def test_unauthorized_result_does_not_crowd_out_allowed_result():

    restricted_chunk = (
        _make_restricted_chunk()
    )

    standard_chunk = (
        _make_chunk()
    )

    retriever = (
        KnowledgeRetriever(
            index=[
                IndexedChunk(
                    chunk=
                        restricted_chunk,

                    embedding=[
                        1.0,
                        0.0,
                    ],
                ),

                IndexedChunk(
                    chunk=
                        standard_chunk,

                    embedding=[
                        0.9,
                        0.1,
                    ],
                ),
            ]
        )
    )

    with patch(
        "app.retriever.search_vector_index"
    ) as mock_search:

        mock_search.return_value = [
            SearchResult(
                chunk=
                    restricted_chunk,

                similarity=
                    0.99,
            ),

            SearchResult(
                chunk=
                    standard_chunk,

                similarity=
                    0.80,
            ),
        ]

        evidence = retriever.retrieve(
            query=
                "security guidance",

            top_k=1,

            caller_access=
                "standard",
        )

    assert len(evidence) == 1

    assert (
        evidence[0].source_name
        == "policy.md"
    )

    assert (
        evidence[0].access_level
        == "standard"
    )

    assert (
        evidence[0].similarity
        == 0.80
    )