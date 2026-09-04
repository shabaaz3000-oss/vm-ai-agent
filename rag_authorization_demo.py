from app.rag_ingestion import (
    load_trusted_documents,
)

from app.retriever import (
    KnowledgeRetriever,
)


# -------------------------------------------------
# 1. SHOW SERVER-CONTROLLED CLASSIFICATION
# -------------------------------------------------


documents = load_trusted_documents()

print()
print("=" * 70)
print("KNOWLEDGE DOCUMENT CLASSIFICATION")
print("=" * 70)


for document in documents:

    print()

    print(
        "Source:",
        document.source_name
    )

    print(
        "Trust Tier:",
        document.trust_tier
    )

    print(
        "Access Level:",
        document.access_level
    )


# -------------------------------------------------
# 2. BUILD RETRIEVER
# -------------------------------------------------


retriever = (
    KnowledgeRetriever
    .from_trusted_knowledge()
)


query = (
    "privileged network architecture "
    "administrative access management "
    "network vulnerability scanners"
)


# -------------------------------------------------
# 3. STANDARD CALLER
# -------------------------------------------------


standard_results = (
    retriever.retrieve(
        query=query,
        top_k=3,
        min_similarity=0.0,
        caller_access="standard",
    )
)


print()
print("=" * 70)
print("STANDARD CALLER RESULTS")
print("=" * 70)

print()
print(
    "Query:",
    query
)


if not standard_results:

    print()
    print(
        "No authorized evidence returned."
    )


for position, item in enumerate(
    standard_results,
    start=1,
):

    print()
    print(
        f"RESULT {position}"
    )

    print(
        "Source:",
        item.source_name
    )

    print(
        "Similarity:",
        round(
            item.similarity,
            4
        )
    )

    print(
        "Access Level:",
        item.access_level
    )


# -------------------------------------------------
# 4. RESTRICTED CALLER
# -------------------------------------------------


restricted_results = (
    retriever.retrieve(
        query=query,
        top_k=3,
        min_similarity=0.0,
        caller_access="restricted",
    )
)


print()
print("=" * 70)
print("RESTRICTED CALLER RESULTS")
print("=" * 70)

print()
print(
    "Query:",
    query
)


if not restricted_results:

    print()
    print(
        "No authorized evidence returned."
    )


for position, item in enumerate(
    restricted_results,
    start=1,
):

    print()
    print(
        f"RESULT {position}"
    )

    print(
        "Source:",
        item.source_name
    )

    print(
        "Similarity:",
        round(
            item.similarity,
            4
        )
    )

    print(
        "Access Level:",
        item.access_level
    )