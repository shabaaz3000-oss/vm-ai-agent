from dataclasses import dataclass

from app.embeddings import (
    cosine_similarity,
    get_embedding,
    get_embeddings,
)

from app.models import KnowledgeChunk


@dataclass(frozen=True)
class IndexedChunk:
    chunk: KnowledgeChunk
    embedding: list[float]


@dataclass(frozen=True)
class SearchResult:
    chunk: KnowledgeChunk
    similarity: float


def build_vector_index(
    chunks: list[KnowledgeChunk],
) -> list[IndexedChunk]:

    if not chunks:
        return []

    texts = [
        chunk.content
        for chunk in chunks
    ]

    embeddings = get_embeddings(
        texts
    )

    return [
        IndexedChunk(
            chunk=chunk,
            embedding=embedding,
        )
        for chunk, embedding
        in zip(
            chunks,
            embeddings,
        )
    ]


def search_vector_index(
    query: str,
    index: list[IndexedChunk],
    top_k: int = 3,
) -> list[SearchResult]:

    cleaned_query = query.strip()

    if not cleaned_query:
        raise ValueError(
            "Search query cannot be empty."
        )

    if top_k <= 0:
        raise ValueError(
            "top_k must be positive."
        )

    if not index:
        return []

    query_embedding = get_embedding(
        cleaned_query
    )

    results = []

    for indexed_chunk in index:

        similarity = cosine_similarity(
            query_embedding,
            indexed_chunk.embedding,
        )

        results.append(
            SearchResult(
                chunk=indexed_chunk.chunk,
                similarity=similarity,
            )
        )

    results.sort(
        key=lambda result:
        result.similarity,
        reverse=True,
    )

    return results[:top_k]