from pathlib import Path

from app.models import RetrievedEvidence

from app.rag_ingestion import (
    TRUSTED_KNOWLEDGE_DIR,
    build_knowledge_chunks,
)

from app.retrieval_authorization import (
    RetrievalAccess,
    is_knowledge_chunk_authorized,
)

from app.vector_index import (
    IndexedChunk,
    build_vector_index,
    search_vector_index,
)


# -------------------------------------------------
# KNOWLEDGE RETRIEVER
# -------------------------------------------------


class KnowledgeRetriever:

    def __init__(
        self,
        index: list[IndexedChunk],
    ):

        self._index = index


    # -------------------------------------------------
    # BUILD RETRIEVER FROM TRUSTED KNOWLEDGE
    # -------------------------------------------------

    @classmethod
    def from_trusted_knowledge(
        cls,
        root: Path = TRUSTED_KNOWLEDGE_DIR,
    ) -> "KnowledgeRetriever":

        chunks = build_knowledge_chunks(
            root
        )

        index = build_vector_index(
            chunks
        )

        return cls(
            index=index
        )


    # -------------------------------------------------
    # RETRIEVE AUTHORIZED EVIDENCE
    # -------------------------------------------------

    def retrieve(
        self,
        query: str,
        top_k: int = 3,
        min_similarity: float = 0.0,
        caller_access: RetrievalAccess = "standard",
    ) -> list[RetrievedEvidence]:

        cleaned_query = (
            query.strip()
        )

        if not cleaned_query:

            raise ValueError(
                "Retrieval query cannot be empty."
            )

        if top_k <= 0:

            raise ValueError(
                "top_k must be positive."
            )

        if not (
            -1.0
            <= min_similarity
            <= 1.0
        ):

            raise ValueError(
                "min_similarity must be "
                "between -1.0 and 1.0."
            )

        if caller_access not in (
            "standard",
            "restricted",
        ):

            raise ValueError(
                "caller_access must be "
                "'standard' or 'restricted'."
            )

        # -------------------------------------------------
        # AUTHORIZE RETRIEVAL CORPUS BEFORE SEARCH
        # -------------------------------------------------
        #
        # SECURITY INVARIANT:
        #
        # Unauthorized chunks must never participate in:
        #
        # - semantic similarity calculation
        # - ranking
        # - top-k selection
        #
        # Authorization therefore occurs against the
        # indexed corpus before search_vector_index().
        # -------------------------------------------------

        authorized_index = [
            indexed_chunk

            for indexed_chunk
            in self._index

            if is_knowledge_chunk_authorized(
                caller_access=caller_access,
                chunk=indexed_chunk.chunk,
            )
        ]

        # -------------------------------------------------
        # FAIL CLOSED WHEN NOTHING IS AUTHORIZED
        # -------------------------------------------------

        if not authorized_index:
            return []

        # -------------------------------------------------
        # SEMANTIC SEARCH ? AUTHORIZED CORPUS ONLY
        # -------------------------------------------------

        results = search_vector_index(
            query=cleaned_query,
            index=authorized_index,
            top_k=top_k,
        )

        evidence = []

        # -------------------------------------------------
        # VALIDATE SEARCH RESULTS
        # -------------------------------------------------

        for result in results:

            # ---------------------------------------------
            # RELEVANCE FILTER
            # ---------------------------------------------

            if (
                result.similarity
                < min_similarity
            ):
                continue

            chunk = result.chunk

            # ---------------------------------------------
            # DEFENSE-IN-DEPTH AUTHORIZATION RECHECK
            # ---------------------------------------------
            #
            # The vector search implementation should only
            # be capable of returning chunks from the
            # authorized index.
            #
            # Rechecking here protects against:
            #
            # - implementation regressions
            # - buggy retrieval backends
            # - mocked/adversarial search results
            #
            # This check is not the primary security
            # boundary. Pre-search corpus authorization is.
            # ---------------------------------------------

            if not is_knowledge_chunk_authorized(
                caller_access=caller_access,
                chunk=chunk,
            ):
                continue

            # ---------------------------------------------
            # BUILD AUTHORIZED EVIDENCE
            # ---------------------------------------------

            evidence.append(
                RetrievedEvidence(
                    source_id=
                        chunk.source_id,

                    source_name=
                        chunk.source_name,

                    chunk_id=
                        chunk.chunk_id,

                    chunk_number=
                        chunk.chunk_number,

                    content=
                        chunk.content,

                    similarity=
                        result.similarity,

                    source_sha256=
                        chunk.source_sha256,

                    trust_tier=
                        chunk.trust_tier,

                    access_level=
                        chunk.access_level,
                )
            )

        return evidence[:top_k]
