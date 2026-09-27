import pytest

from app import mcp_rag_context

from app.auth import Principal
from app.security_context import SecurityContext

from app.tools.dispatcher import ToolExecutionContext

from app.models import (
    AssetContext,
    RiskResult,
    ThreatIntel,
    VulnerabilityFinding,
)

from app.retriever import (
    KnowledgeRetriever,
)


# -------------------------------------------------
# TEST DATA
# -------------------------------------------------


def make_principal():

    return Principal(
        username="mcp-rag-test",
        role="ANALYST",
        retrieval_access="standard",
    )



def make_base_context(
    principal: Principal,
) -> ToolExecutionContext:

    security_context = SecurityContext(
        principal_id=principal.username,
        role=principal.role,
        retrieval_access=
            principal.retrieval_access,
        tenant_id="tenant-a",
        session_id="session-rag-123",
    )

    return ToolExecutionContext(
        principal=principal,
        security_context=security_context,
    )


def make_finding():

    return VulnerabilityFinding(
        finding_id="FIND-RAG-001",
        asset_name="host-01",
        cve="CVE-2099-1000",
        title="Test vulnerability",
        description="Test description",
        cvss=9.8,
        patch_available=True,
    )


def make_asset():

    return AssetContext(
        asset_name="host-01",
        owner="Security Team",
        application="Payments",
        environment="production",
        business_criticality="critical",
        internet_exposed=True,
        data_classification="confidential",
        current_controls=[
            "EDR",
            "MFA",
        ],
    )


def make_threat():

    return ThreatIntel(
        cve="CVE-2099-1000",
        epss=0.99,
        kev=True,
        data_source="test-feed",
    )


def make_risk():

    return RiskResult(
        score=100,
        rating="CRITICAL",
        sla_hours=24,
        factors=[
            "security-test",
        ],
    )


# -------------------------------------------------
# SERVER-CONTROLLED CONTEXT
# -------------------------------------------------


def test_build_mcp_rag_execution_context(
    monkeypatch,
):

    principal = make_principal()

    base_context = make_base_context(
        principal
    )

    finding = make_finding()
    asset = make_asset()
    threat = make_threat()
    risk = make_risk()

    retriever = KnowledgeRetriever(
        index=[],
    )

    dispatch_calls = []

    def fake_dispatch_llm_tool(
        *,
        tool_name,
        context,
    ):

        dispatch_calls.append(
            (
                tool_name,
                context,
            )
        )

        mapping = {
            "get_finding":
                finding,

            "get_asset_details":
                asset,

            "get_threat_intel":
                threat,
        }

        return mapping[
            tool_name
        ]

    relationship_inputs = {}

    def fake_validate_relationships(
        *,
        finding,
        asset,
        threat,
    ):

        relationship_inputs[
            "finding"
        ] = finding

        relationship_inputs[
            "asset"
        ] = asset

        relationship_inputs[
            "threat"
        ] = threat

    risk_inputs = {}

    def fake_calculate_risk(
        *,
        finding,
        asset,
        threat,
    ):

        risk_inputs[
            "finding"
        ] = finding

        risk_inputs[
            "asset"
        ] = asset

        risk_inputs[
            "threat"
        ] = threat

        return risk

    monkeypatch.setattr(
        mcp_rag_context,
        "dispatch_llm_tool",
        fake_dispatch_llm_tool,
    )

    monkeypatch.setattr(
        mcp_rag_context,
        "validate_provider_relationships",
        fake_validate_relationships,
    )

    monkeypatch.setattr(
        mcp_rag_context,
        "calculate_risk",
        fake_calculate_risk,
    )

    monkeypatch.setattr(
        mcp_rag_context.KnowledgeRetriever,
        "from_trusted_knowledge",
        classmethod(
            lambda cls:
                retriever
        ),
    )

    context = (
        mcp_rag_context
        .build_mcp_rag_execution_context(
            base_context
        )
    )

    # -------------------------------------------------
    # CORE READS ARE SERVER CONTROLLED
    # -------------------------------------------------

    assert [
        call[0]
        for call in dispatch_calls
    ] == [
        "get_finding",
        "get_asset_details",
        "get_threat_intel",
    ]

    assert all(
        call_context.principal
        is principal

        for _, call_context
        in dispatch_calls
    )

    # -------------------------------------------------
    # RELATIONSHIPS VALIDATED
    # -------------------------------------------------

    assert (
        relationship_inputs["finding"]
        is finding
    )

    assert (
        relationship_inputs["asset"]
        is asset
    )

    assert (
        relationship_inputs["threat"]
        is threat
    )

    # -------------------------------------------------
    # RISK CALCULATED FROM AUTHORITATIVE DATA
    # -------------------------------------------------

    assert (
        risk_inputs["finding"]
        is finding
    )

    assert (
        risk_inputs["asset"]
        is asset
    )

    assert (
        risk_inputs["threat"]
        is threat
    )

    # -------------------------------------------------
    # COMPLETE TRUSTED CONTEXT RETURNED
    # -------------------------------------------------

    assert context.principal is principal

    assert (
        context.security_context
        is base_context.security_context
    )

    assert all(
        call_context.security_context
        is base_context.security_context
        for _, call_context
        in dispatch_calls
    )

    assert context.finding is finding
    assert context.asset is asset
    assert context.risk is risk
    assert context.retriever is retriever


# -------------------------------------------------
# RELATIONSHIP FAILURE FAILS CLOSED
# -------------------------------------------------


def test_mcp_rag_context_rejects_relationship_mismatch(
    monkeypatch,
):

    principal = make_principal()

    base_context = make_base_context(
        principal
    )

    mapping = {
        "get_finding":
            make_finding(),

        "get_asset_details":
            make_asset(),

        "get_threat_intel":
            make_threat(),
    }

    def fake_dispatch_llm_tool(
        *,
        tool_name,
        context,
    ):

        return mapping[
            tool_name
        ]

    downstream_calls = {
        "risk": 0,
        "retriever": 0,
    }

    def reject_relationships(
        **kwargs,
    ):

        raise ValueError(
            "Authoritative security "
            "relationships do not match."
        )

    def fake_calculate_risk(
        **kwargs,
    ):

        downstream_calls[
            "risk"
        ] += 1

        return make_risk()

    def fake_retriever(
        cls,
    ):

        downstream_calls[
            "retriever"
        ] += 1

        return KnowledgeRetriever(
            index=[],
        )

    monkeypatch.setattr(
        mcp_rag_context,
        "dispatch_llm_tool",
        fake_dispatch_llm_tool,
    )

    monkeypatch.setattr(
        mcp_rag_context,
        "validate_provider_relationships",
        reject_relationships,
    )

    monkeypatch.setattr(
        mcp_rag_context,
        "calculate_risk",
        fake_calculate_risk,
    )

    monkeypatch.setattr(
        mcp_rag_context.KnowledgeRetriever,
        "from_trusted_knowledge",
        classmethod(
            fake_retriever
        ),
    )

    with pytest.raises(
        ValueError,
    ):

        (
            mcp_rag_context
            .build_mcp_rag_execution_context(
                base_context
            )
        )

    # Relationship failure must stop the pipeline
    # before risk calculation or retrieval.
    assert (
        downstream_calls["risk"]
        == 0
    )

    assert (
        downstream_calls["retriever"]
        == 0
    )


def test_mcp_rag_context_requires_security_context():

    principal = make_principal()

    legacy_context = ToolExecutionContext(
        principal=principal,
    )

    with pytest.raises(
        ValueError,
        match="trusted security context",
    ):

        (
            mcp_rag_context
            .build_mcp_rag_execution_context(
                legacy_context
            )
        )
