from app.retriever import (
    KnowledgeRetriever,
)


retriever = (
    KnowledgeRetriever
    .from_trusted_knowledge()
)


queries = [
    (
        "How can I verify that a "
        "vulnerability was fixed?"
    ),
    (
        "What can I do if I cannot "
        "patch immediately?"
    ),
    (
        "Who should make the final "
        "risk decision?"
    ),
]


for query in queries:

    print()
    print("=" * 70)

    print(
        "QUERY:",
        query
    )

    print("=" * 70)

    evidence = retriever.retrieve(
        query=query,
        top_k=2,
    )

    for position, item in enumerate(
        evidence,
        start=1,
    ):

        print()
        print(
            f"EVIDENCE {position}"
        )

        print(
            "Similarity:",
            round(
                item.similarity,
                4
            )
        )

        print(
            "Source:",
            item.source_name
        )

        print(
            "Chunk:",
            item.chunk_number
        )

        print(
            "Trust:",
            item.trust_tier
        )

        print(
            "SHA-256:",
            item.source_sha256[:12]
        )

        print()

        print(
            item.content
        )