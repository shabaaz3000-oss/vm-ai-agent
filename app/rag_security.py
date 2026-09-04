from dataclasses import dataclass

from app.input_security import (
    aggregate_prompt_injection_matches,
    inspect_retrieved_evidence,
)

from app.models import RetrievedEvidence


# -------------------------------------------------
# RAG SECURITY RESULT
# -------------------------------------------------


@dataclass(frozen=True)
class RAGSecurityResult:

    safe_evidence: list[RetrievedEvidence]

    quarantined_chunk_ids: list[str]

    chunk_matches: dict[str, list[str]]

    categories: list[str]


# -------------------------------------------------
# INSPECT AND QUARANTINE RETRIEVED EVIDENCE
# -------------------------------------------------


def secure_retrieved_evidence(
    evidence: list[RetrievedEvidence],
) -> RAGSecurityResult:

    """
    Inspect retrieved RAG evidence for prompt-injection
    indicators and quarantine suspicious chunks.

    Suspicious content is preserved in the original
    RetrievedEvidence objects for forensic/audit use,
    but quarantined evidence is not returned in
    safe_evidence and therefore should not be sent
    to the language model.
    """

    chunk_matches = (
        inspect_retrieved_evidence(
            evidence
        )
    )

    quarantined_chunk_ids = list(
        chunk_matches.keys()
    )

    safe_evidence = [
        item
        for item in evidence
        if item.chunk_id
        not in chunk_matches
    ]

    categories = (
        aggregate_prompt_injection_matches(
            chunk_matches
        )
    )

    return RAGSecurityResult(
        safe_evidence=
            safe_evidence,

        quarantined_chunk_ids=
            quarantined_chunk_ids,

        chunk_matches=
            chunk_matches,

        categories=
            categories,
    )