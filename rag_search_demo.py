from app.rag_ingestion import (
    build_knowledge_chunks,
)

from app.vector_index import (
    build_vector_index,
    search_vector_index,
)


chunks = build_knowledge_chunks()

print(
    "Knowledge chunks:",
    len(chunks),
)


index = build_vector_index(
    chunks
)

print(
    "Indexed chunks:",
    len(index),
)


query = (
    "How can I verify that a "
    "vulnerability was actually fixed?"
)


results = search_vector_index(
    query=query,
    index=index,
    top_k=3,
)


print()
print(
    "Query:",
    query
)

print()


for position, result in enumerate(
    results,
    start=1,
):

    print(
        f"RESULT {position}"
    )

    print(
        "Similarity:",
        round(
            result.similarity,
            4
        )
    )

    print(
        "Source:",
        result.chunk.source_name
    )

    print(
        "Chunk:",
        result.chunk.chunk_number
    )

    print(
        "Chunk ID:",
        result.chunk.chunk_id
    )

    print()

    print(
        result.chunk.content
    )

    print()
    print(
        "-" * 60
    )
    print()