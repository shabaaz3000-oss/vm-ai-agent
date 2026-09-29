from app.auth import Principal

from app.models import (
    AssetContext,
    RiskResult,
    ThreatIntel,
    VulnerabilityFinding,
)

from app.retriever import (
    KnowledgeRetriever,
)

from app.risk_engine import (
    calculate_risk,
)

from app.tools.dispatcher import (
    ToolExecutionContext,
    dispatch_llm_tool,
)

from app.workflow import (
    validate_provider_relationships,
)


# -------------------------------------------------
# SERVER-CONTROLLED MCP RAG CONTEXT
# -------------------------------------------------


def build_mcp_rag_execution_context(
    base_context: ToolExecutionContext,
) -> ToolExecutionContext:

    # -------------------------------------------------
    # REQUIRE TRUSTED MCP SECURITY CONTEXT
    # -------------------------------------------------

    security_context = (
        base_context.security_context
    )

    if security_context is None:

        raise ValueError(
            "MCP RAG execution requires "
            "trusted security context."
        )

    # Fail closed if mutable Principal state has drifted
    # from the immutable session-bound context.
    base_context.validate_security_binding()

    principal = (
        base_context.principal
    )

    # -------------------------------------------------
    # RETRIEVE AUTHORITATIVE CORE SECURITY DATA
    # -------------------------------------------------

    finding = dispatch_llm_tool(
        tool_name="get_finding",
        context=base_context,
    )

    if not isinstance(
        finding,
        VulnerabilityFinding,
    ):

        raise TypeError(
            "get_finding returned an "
            "unexpected result type."
        )

    asset = dispatch_llm_tool(
        tool_name="get_asset_details",
        context=base_context,
    )

    if not isinstance(
        asset,
        AssetContext,
    ):

        raise TypeError(
            "get_asset_details returned an "
            "unexpected result type."
        )

    threat = dispatch_llm_tool(
        tool_name="get_threat_intel",
        context=base_context,
    )

    if not isinstance(
        threat,
        ThreatIntel,
    ):

        raise TypeError(
            "get_threat_intel returned an "
            "unexpected result type."
        )

    # -------------------------------------------------
    # VALIDATE AUTHORITATIVE RELATIONSHIPS
    # -------------------------------------------------

    validate_provider_relationships(
        finding=finding,
        asset=asset,
        threat=threat,
    )

    # -------------------------------------------------
    # CALCULATE AUTHORITATIVE RISK
    # -------------------------------------------------

    risk = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat,
    )

    if not isinstance(
        risk,
        RiskResult,
    ):

        raise TypeError(
            "Risk calculation returned an "
            "unexpected result type."
        )

    # -------------------------------------------------
    # BUILD SERVER-CONTROLLED RETRIEVER
    # -------------------------------------------------

    retriever = (
        KnowledgeRetriever
        .from_trusted_knowledge(
            tenant_id=
                security_context.tenant_id,
        )
    )

    if not isinstance(
        retriever,
        KnowledgeRetriever,
    ):

        raise TypeError(
            "Knowledge retriever returned an "
            "unexpected result type."
        )

    # -------------------------------------------------
    # RETURN COMPLETE TRUSTED TOOL CONTEXT
    # -------------------------------------------------

    return ToolExecutionContext(
        principal=principal,
        security_context=security_context,
        finding=finding,
        asset=asset,
        risk=risk,
        retriever=retriever,
    )