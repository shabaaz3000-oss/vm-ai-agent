import inspect

from unittest.mock import patch

from app.auth import Principal

from app.models import (
    AssetContext,
    KnowledgeChunk,
    RiskResult,
    VulnerabilityFinding,
)

from app.retriever import (
    KnowledgeRetriever,
)

from app.tools.knowledge import (
    search_knowledge,
)

from app.vector_index import (
    IndexedChunk,
    SearchResult,
)


# -------------------------------------------------
# SYNTHETIC RESTRICTED CANARY
# -------------------------------------------------


RESTRICTED_CANARY = (
    "VM_AI_IDENTITY_RAG_CANARY_NOT_REAL"
)


# -------------------------------------------------
# TEST DATA HELPERS
# -------------------------------------------------


def build_restricted_chunk(
) -> KnowledgeChunk:

    return KnowledgeChunk(
        chunk_id=(
            "restricted:0:identity-aware"
        ),

        source_id=(
            "restricted-identity-test"
        ),

        source_name=(
            "restricted-identity-test.md"
        ),

        chunk_number=0,

        content=(
            "Restricted internal security "
            "architecture reference. "
            "Synthetic canary: "
            f"{RESTRICTED_CANARY}"
        ),

        source_sha256="a" * 64,

        trust_tier=
            "trusted_reference",

        access_level=
            "restricted",
    )


def build_standard_chunk(
) -> KnowledgeChunk:

    return KnowledgeChunk(
        chunk_id=(
            "standard:0:identity-aware"
        ),

        source_id=(
            "standard-identity-test"
        ),

        source_name=(
            "standard-identity-test.md"
        ),

        chunk_number=0,

        content=(
            "Apply the approved vendor patch "
            "and validate remediation with an "
            "authenticated vulnerability scan."
        ),

        source_sha256="b" * 64,

        trust_tier=
            "trusted_reference",

        access_level=
            "standard",
    )


def build_finding(
) -> VulnerabilityFinding:

    return VulnerabilityFinding(
        finding_id=
            "VULN-IDENTITY-RAG-001",

        asset_name=
            "identity-rag-app-01",

        cve=
            "CVE-2026-0001",

        title=
            "Identity-aware RAG test finding",

        description=(
            "Controlled security test for "
            "identity-aware knowledge retrieval."
        ),

        cvss=9.8,

        patch_available=True,
    )


def build_asset(
) -> AssetContext:

    return AssetContext(
        asset_name=
            "identity-rag-app-01",

        owner=
            "Security Engineering",

        application=
            "Identity RAG Test",

        environment=
            "production",

        business_criticality=
            "critical",

        internet_exposed=True,

        data_classification=
            "confidential",

        current_controls=[
            "WAF",
        ],
    )


def build_risk(
) -> RiskResult:

    return RiskResult(
        score=100,

        rating=
            "CRITICAL",

        sla_hours=24,

        factors=[
            "identity-aware-rag-test",
        ],
    )


def build_retriever(
):

    restricted_chunk = (
        build_restricted_chunk()
    )

    standard_chunk = (
        build_standard_chunk()
    )

    retriever = KnowledgeRetriever(
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
                    0.8,
                    0.2,
                ],
            ),
        ]
    )

    ranked_results = [
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

    return (
        retriever,
        ranked_results,
        restricted_chunk,
        standard_chunk,
    )


# -------------------------------------------------
# STANDARD ANALYST
# -------------------------------------------------


def test_standard_analyst_cannot_receive_restricted_evidence():

    (
        retriever,
        ranked_results,
        restricted_chunk,
        standard_chunk,
    ) = build_retriever()

    principal = Principal(
        username=
            "api-analyst",

        role=
            "ANALYST",

        retrieval_access=
            "standard",
    )

    with patch(
        "app.retriever.search_vector_index",
        return_value=ranked_results,
    ), patch(
        "app.tools.knowledge.log_event",
    ), patch.object(
        retriever,
        "retrieve",
        wraps=retriever.retrieve,
    ) as retrieve_spy:

        evidence = search_knowledge(
            principal=principal,

            finding=
                build_finding(),

            asset=
                build_asset(),

            risk=
                build_risk(),

            retriever=
                retriever,

            top_k=1,
        )

    assert (
        retrieve_spy
        .call_args
        .kwargs[
            "caller_access"
        ]
        == "standard"
    )

    assert len(evidence) == 1

    assert (
        evidence[0].chunk_id
        == standard_chunk.chunk_id
    )

    assert (
        restricted_chunk.chunk_id
        not in {
            item.chunk_id
            for item in evidence
        }
    )

    assert not any(
        RESTRICTED_CANARY
        in item.content
        for item in evidence
    )


# -------------------------------------------------
# APPROVER DOES NOT GAIN RESTRICTED DATA
# -------------------------------------------------


def test_approver_does_not_automatically_receive_restricted_evidence():

    (
        retriever,
        ranked_results,
        restricted_chunk,
        standard_chunk,
    ) = build_retriever()

    principal = Principal(
        username=
            "api-approver",

        role=
            "APPROVER",

        retrieval_access=
            "standard",
    )

    with patch(
        "app.retriever.search_vector_index",
        return_value=ranked_results,
    ), patch(
        "app.tools.knowledge.log_event",
    ), patch.object(
        retriever,
        "retrieve",
        wraps=retriever.retrieve,
    ) as retrieve_spy:

        evidence = search_knowledge(
            principal=principal,

            finding=
                build_finding(),

            asset=
                build_asset(),

            risk=
                build_risk(),

            retriever=
                retriever,

            top_k=1,
        )

    assert (
        retrieve_spy
        .call_args
        .kwargs[
            "caller_access"
        ]
        == "standard"
    )

    assert len(evidence) == 1

    assert (
        evidence[0].chunk_id
        == standard_chunk.chunk_id
    )

    assert (
        restricted_chunk.chunk_id
        not in {
            item.chunk_id
            for item in evidence
        }
    )

    assert not any(
        RESTRICTED_CANARY
        in item.content
        for item in evidence
    )


# -------------------------------------------------
# EXPLICIT RESTRICTED IDENTITY
# -------------------------------------------------


def test_restricted_analyst_can_receive_restricted_evidence():

    (
        retriever,
        ranked_results,
        restricted_chunk,
        _standard_chunk,
    ) = build_retriever()

    principal = Principal(
        username=
            "api-restricted-analyst",

        role=
            "ANALYST",

        retrieval_access=
            "restricted",
    )

    with patch(
        "app.retriever.search_vector_index",
        return_value=ranked_results,
    ), patch(
        "app.tools.knowledge.log_event",
    ), patch.object(
        retriever,
        "retrieve",
        wraps=retriever.retrieve,
    ) as retrieve_spy:

        evidence = search_knowledge(
            principal=principal,

            finding=
                build_finding(),

            asset=
                build_asset(),

            risk=
                build_risk(),

            retriever=
                retriever,

            top_k=1,
        )

    assert (
        retrieve_spy
        .call_args
        .kwargs[
            "caller_access"
        ]
        == "restricted"
    )

    assert len(evidence) == 1

    assert (
        evidence[0].chunk_id
        == restricted_chunk.chunk_id
    )

    assert (
        evidence[0].access_level
        == "restricted"
    )

    assert (
        RESTRICTED_CANARY
        in evidence[0].content
    )


# -------------------------------------------------
# HIGHER SEMANTIC SCORE DOES NOT OVERRIDE IDENTITY
# -------------------------------------------------


def test_restricted_similarity_does_not_override_standard_identity():

    (
        retriever,
        ranked_results,
        restricted_chunk,
        standard_chunk,
    ) = build_retriever()

    assert (
        ranked_results[0].similarity
        > ranked_results[1].similarity
    )

    principal = Principal(
        username=
            "api-analyst",

        role=
            "ANALYST",
    )

    with patch(
        "app.retriever.search_vector_index",
        return_value=ranked_results,
    ), patch(
        "app.tools.knowledge.log_event",
    ):

        evidence = search_knowledge(
            principal=principal,

            finding=
                build_finding(),

            asset=
                build_asset(),

            risk=
                build_risk(),

            retriever=
                retriever,

            top_k=1,
        )

    assert len(evidence) == 1

    assert (
        evidence[0].chunk_id
        == standard_chunk.chunk_id
    )

    assert (
        evidence[0].chunk_id
        != restricted_chunk.chunk_id
    )


# -------------------------------------------------
# LLM / CALLER CANNOT SUPPLY RETRIEVAL ACCESS
# -------------------------------------------------


def test_search_knowledge_does_not_accept_caller_access_argument():

    signature = inspect.signature(
        search_knowledge
    )

    assert (
        "caller_access"
        not in signature.parameters
    )

    assert (
        "retrieval_access"
        not in signature.parameters
    )


# -------------------------------------------------
# AUDIT RECORDS RESOLVED ACCESS
# -------------------------------------------------


def test_search_knowledge_audits_resolved_retrieval_access():

    (
        retriever,
        ranked_results,
        _restricted_chunk,
        _standard_chunk,
    ) = build_retriever()

    principal = Principal(
        username=
            "api-restricted-analyst",

        role=
            "ANALYST",

        retrieval_access=
            "restricted",
    )

    with patch(
        "app.retriever.search_vector_index",
        return_value=ranked_results,
    ), patch(
        "app.tools.knowledge.log_event",
    ) as log_spy:

        search_knowledge(
            principal=principal,

            finding=
                build_finding(),

            asset=
                build_asset(),

            risk=
                build_risk(),

            retriever=
                retriever,

            top_k=1,
        )

    matching_events = [
        call
        for call in log_spy.call_args_list
        if (
            call.args
            and call.args[0]
            == "RAG_ACCESS_RESOLVED"
        )
    ]

    assert len(
        matching_events
    ) == 1

    event_data = (
        matching_events[0]
        .args[1]
    )

    assert (
        event_data[
            "username"
        ]
        == "api-restricted-analyst"
    )

    assert (
        event_data[
            "role"
        ]
        == "ANALYST"
    )

    assert (
        event_data[
            "retrieval_access"
        ]
        == "restricted"
    )