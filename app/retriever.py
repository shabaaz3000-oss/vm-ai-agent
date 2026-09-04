from pathlib import Path
from typing import Literal

from app.models import RetrievedEvidence

from app.rag_ingestion import (
    TRUSTED_KNOWLEDGE_DIR,
    build_knowledge_chunks,
)

from app.vector_index import (
    IndexedChunk,
    build_vector_index,
    search_vector_index,
)


# -------------------------------------------------
# RETRIEVAL ACCESS LEVEL
# -------------------------------------------------


RetrievalAccess = Literal[
    "standard",
    "restricted"
]


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
        # SEARCH CANDIDATE CHUNKS
        # -------------------------------------------------
        #
        # Search across all available indexed chunks
        # before applying authorization.
        #
        # This prevents unauthorized high-ranking
        # results from crowding authorized results
        # out of the requested top_k.
        #
        # max(..., top_k) also ensures the search
        # function never receives top_k=0 when the
        # index is empty.
        # -------------------------------------------------

        candidate_limit = max(
            len(self._index),
            top_k,
        )

        results = search_vector_index(
            query=cleaned_query,
            index=self._index,
            top_k=candidate_limit,
        )

        evidence = []

        # -------------------------------------------------
        # FILTER AND AUTHORIZE RESULTS
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
            # AUTHORIZATION FILTER
            # ---------------------------------------------
            #
            # Semantic similarity does not grant access.
            #
            # A standard caller cannot retrieve a
            # restricted chunk even if that chunk is
            # the highest-scoring semantic match.
            # ---------------------------------------------

            if (
                chunk.access_level
                == "restricted"
                and caller_access
                != "restricted"
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

        # -------------------------------------------------
        # RETURN TOP AUTHORIZED RESULTS
        # -------------------------------------------------

        return evidence[:top_k]