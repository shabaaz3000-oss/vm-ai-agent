from fastapi import HTTPException

from app.auth import Principal
from app.audit import log_event

from app.models import (
    AssetContext,
    RetrievedEvidence,
    RiskResult,
    VulnerabilityFinding,
)

from app.rag_security import (
    secure_retrieved_evidence,
)

from app.retrieval_query import (
    build_retrieval_query,
)

from app.retriever import (
    KnowledgeRetriever,
)

from app.tools.authorization import (
    require_tool_permission,
)


# -------------------------------------------------
# SEARCH SECURITY KNOWLEDGE TOOL
# -------------------------------------------------


def search_knowledge(
    principal: Principal,
    finding: VulnerabilityFinding,
    asset: AssetContext,
    risk: RiskResult,
    retriever: KnowledgeRetriever,
    top_k: int = 3,
    min_similarity: float = 0.0,
) -> list[RetrievedEvidence]:

    log_event(
        "TOOL_REQUESTED",
        {
            "tool": "search_knowledge",
            "username": principal.username,
            "role": principal.role,
        },
    )

    try:

        require_tool_permission(
            principal=principal,
            tool_name="search_knowledge",
        )

    except HTTPException:

        log_event(
            "TOOL_ACCESS_DENIED",
            {
                "tool": "search_knowledge",
                "username": principal.username,
                "role": principal.role,
            },
        )

        raise

    # -------------------------------------------------
    # BUILD CONSTRAINED RETRIEVAL QUERY
    # -------------------------------------------------
    #
    # The LLM does not supply an arbitrary retrieval
    # query. The query is derived from validated,
    # structured security data.
    # -------------------------------------------------

    query = build_retrieval_query(
        finding=finding,
        asset=asset,
        risk=risk,
    )

    # -------------------------------------------------
    # RETRIEVE AUTHORIZED KNOWLEDGE
    # -------------------------------------------------

    retrieved_evidence = retriever.retrieve(
        query=query,
        top_k=top_k,
        min_similarity=min_similarity,
        caller_access="standard",
    )

    # -------------------------------------------------
    # SECURITY-INSPECT RETRIEVED CONTENT
    # -------------------------------------------------
    #
    # Authorization determines whether a caller may
    # retrieve a chunk.
    #
    # Content inspection separately determines whether
    # that authorized chunk is safe to expose to the
    # LLM.
    # -------------------------------------------------

    security_result = (
        secure_retrieved_evidence(
            retrieved_evidence
        )
    )

    safe_evidence = (
        security_result.safe_evidence
    )

    # -------------------------------------------------
    # AUDIT QUARANTINED CONTENT
    # -------------------------------------------------

    if (
        security_result
        .quarantined_chunk_ids
    ):

        log_event(
            "TOOL_RAG_EVIDENCE_QUARANTINED",
            {
                "tool":
                    "search_knowledge",

                "username":
                    principal.username,

                "role":
                    principal.role,

                "quarantined_chunk_ids":
                    security_result
                    .quarantined_chunk_ids,

                "categories":
                    security_result
                    .categories,

                "retrieved_count":
                    len(
                        retrieved_evidence
                    ),

                "safe_count":
                    len(
                        safe_evidence
                    ),
            },
        )

    # -------------------------------------------------
    # AUDIT SUCCESSFUL TOOL EXECUTION
    # -------------------------------------------------

    log_event(
        "TOOL_EXECUTED",
        {
            "tool":
                "search_knowledge",

            "username":
                principal.username,

            "role":
                principal.role,

            "retrieved_count":
                len(
                    retrieved_evidence
                ),

            "result_count":
                len(
                    safe_evidence
                ),
        },
    )

    return safe_evidence