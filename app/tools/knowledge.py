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

from app.retrieval_authorization import (
    build_retrieval_principal,
    get_retrieval_access,
)

from app.security_context import (
    SecurityContext,
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
    security_context: SecurityContext | None = None,
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
    # RESOLVE SERVER-SIDE RETRIEVAL AUTHORIZATION
    # -------------------------------------------------
    #
    # Knowledge access is derived from the authenticated
    # Principal.
    #
    # The language model does not provide or override
    # the retrieval-access level.
    #
    # Workflow role and knowledge-access privilege are
    # deliberately independent.
    # -------------------------------------------------

    retrieval_principal = None

    if security_context is not None:

        if (
            security_context.principal_id
            != principal.username
        ):

            raise ValueError(
                "Knowledge retrieval principal "
                "does not match security context."
            )

        if (
            security_context.retrieval_access
            != principal.retrieval_access
        ):

            raise ValueError(
                "Knowledge retrieval access "
                "does not match security context."
            )

        retrieval_principal = (
            build_retrieval_principal(
                security_context
            )
        )

        retrieval_access = (
            retrieval_principal
            .retrieval_access
        )

    else:

        retrieval_access = (
            get_retrieval_access(
                principal
            )
        )

    log_event(
        "RAG_ACCESS_RESOLVED",
        {
            "tool":
                "search_knowledge",

            "username":
                principal.username,

            "role":
                principal.role,

            "retrieval_access":
                retrieval_access,
        },
    )

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
    #
    # The retriever receives authorization state derived
    # from trusted authenticated application context,
    # never from model-supplied tool arguments.
    # -------------------------------------------------

    if retrieval_principal is not None:

        retrieved_evidence = retriever.retrieve(
            query=query,
            top_k=top_k,
            min_similarity=min_similarity,
            retrieval_principal=
                retrieval_principal,
        )

    else:

        retrieved_evidence = retriever.retrieve(
            query=query,
            top_k=top_k,
            min_similarity=min_similarity,
            caller_access=
                retrieval_access,
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

                "retrieval_access":
                    retrieval_access,

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

            "retrieval_access":
                retrieval_access,

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