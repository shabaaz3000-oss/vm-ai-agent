from collections.abc import Callable
from uuid import uuid4

from app.ai_analyzer import analyze_vulnerability
from app.audit import log_event
from app.input_security import (
    aggregate_prompt_injection_matches,
    inspect_prompt_injection_data,
)

from app.models import AIAnalysis
from app.models import AssetContext
from app.models import RiskResult
from app.models import ThreatIntel
from app.models import VulnerabilityFinding
from app.models import WorkflowResult
from app.models import WorkflowSecurity

from app.providers.base import VulnerabilityProvider
from app.providers.local_json import LocalJsonProvider

from app.rag_security import secure_retrieved_evidence
from app.retrieval_query import build_retrieval_query
from app.retriever import KnowledgeRetriever
from app.risk_engine import calculate_risk
from app.ticketing import build_ticket


# -------------------------------------------------
# DEFAULT DEMO FINDING
# -------------------------------------------------


DEFAULT_FINDING_ID = "FIND-0001"


# -------------------------------------------------
# RAG CONFIGURATION
# -------------------------------------------------


RAG_TOP_K = 2

RAG_MIN_SIMILARITY = 0.20


# -------------------------------------------------
# ANALYZER CONTRACT
# -------------------------------------------------


VulnerabilityAnalyzer = Callable[
    [
        VulnerabilityFinding,
        AssetContext,
        ThreatIntel,
        RiskResult,
    ],
    AIAnalysis,
]


# -------------------------------------------------
# WORKFLOW ID
# -------------------------------------------------


def generate_workflow_id() -> str:

    return (
        "WF-"
        + uuid4().hex[:8].upper()
    )


# -------------------------------------------------
# PROVIDER RELATIONSHIP VALIDATION
# -------------------------------------------------


def validate_provider_relationships(
    finding,
    asset,
    threat
) -> None:

    """
    Validate relationships between provider records.

    Provider data is treated as untrusted input.

    The workflow refuses to continue if the asset
    or CVE returned by the provider does not match
    the authoritative finding being processed.
    """

    if (
        asset.asset_name
        != finding.asset_name
    ):

        raise ValueError(
            "Provider asset context does not match "
            "the vulnerability finding."
        )

    if (
        threat.cve
        != finding.cve
    ):

        raise ValueError(
            "Provider threat intelligence does not "
            "match the vulnerability finding CVE."
        )


# -------------------------------------------------
# PREPARE WORKFLOW
# -------------------------------------------------


def prepare_workflow(
    provider: VulnerabilityProvider | None = None,
    finding_id: str = DEFAULT_FINDING_ID,
    analyzer: VulnerabilityAnalyzer | None = None,
) -> WorkflowResult:

    """
    Prepare a vulnerability-management workflow up to
    the human approval boundary.

    Security data is retrieved through a vulnerability
    provider and normalized into validated Pydantic
    models.

    The AI analyzer is injectable so deterministic
    local/demo analyzers can be used without external
    AI credentials.

    If no analyzer is supplied, the normal OpenAI
    vulnerability analyzer is used together with
    authorized and security-inspected RAG evidence.

    This function:

    1. Retrieves and validates provider security data
    2. Validates relationships between provider records
    3. Detects suspicious prompt-injection content
    4. Calculates authoritative deterministic risk
    5. Builds a constrained RAG retrieval query
    6. Retrieves authorized security reference evidence
    7. Inspects retrieved evidence for prompt injection
    8. Quarantines suspicious retrieved evidence
    9. Generates AI-assisted security analysis
    10. Builds a validated ticket draft
    11. Returns one structured WorkflowResult

    It does NOT:

    - approve workflows
    - create approval records
    - create tickets
    - perform external remediation actions
    """

    if provider is None:

        provider = LocalJsonProvider()

    if not finding_id.strip():

        raise ValueError(
            "finding_id cannot be blank."
        )

    workflow_id = (
        generate_workflow_id()
    )

    # -------------------------------------------------
    # 1. START WORKFLOW
    # -------------------------------------------------

    log_event(
        "WORKFLOW_STARTED",
        {
            "workflow_id":
                workflow_id,

            "provider":
                type(provider).__name__,

            "finding_id":
                finding_id,
        }
    )

    # -------------------------------------------------
    # 2. RETRIEVE AND NORMALIZE PROVIDER DATA
    # -------------------------------------------------

    finding = provider.get_finding(
        finding_id
    )

    asset = (
        provider.get_asset_context(
            finding.asset_name
        )
    )

    threat = (
        provider.get_threat_intel(
            finding.cve
        )
    )

    # -------------------------------------------------
    # 3. VALIDATE PROVIDER RELATIONSHIPS
    # -------------------------------------------------

    validate_provider_relationships(
        finding=finding,
        asset=asset,
        threat=threat
    )

    # -------------------------------------------------
    # 4. INSPECT UNTRUSTED PROVIDER DATA
    # -------------------------------------------------

    provider_security_data = {
        "finding":
            finding.model_dump(),

        "asset":
            asset.model_dump(),

        "threat":
            threat.model_dump(),
    }

    injection_field_matches = (
        inspect_prompt_injection_data(
            provider_security_data
        )
    )

    injection_matches = (
        aggregate_prompt_injection_matches(
            injection_field_matches
        )
    )

    if injection_matches:

        log_event(
            "PROMPT_INJECTION_SUSPECTED",
            {
                "workflow_id":
                    workflow_id,

                "finding_id":
                    finding.finding_id,

                "fields":
                    list(
                        injection_field_matches
                        .keys()
                    ),

                "field_matches":
                    injection_field_matches,

                "matches":
                    injection_matches,
            }
        )

    # -------------------------------------------------
    # 5. RECORD SUCCESSFUL INPUT VALIDATION
    # -------------------------------------------------

    log_event(
        "SECURITY_DATA_VALIDATED",
        {
            "workflow_id":
                workflow_id,

            "provider":
                type(provider).__name__,

            "finding_id":
                finding.finding_id,

            "asset_name":
                finding.asset_name,

            "cve":
                finding.cve,
        }
    )

    # -------------------------------------------------
    # 6. CALCULATE AUTHORITATIVE RISK
    # -------------------------------------------------

    risk = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    log_event(
        "RISK_CALCULATED",
        {
            "workflow_id":
                workflow_id,

            "score":
                risk.score,

            "rating":
                risk.rating,

            "sla_hours":
                risk.sla_hours,

            "factors":
                risk.factors,
        }
    )

    # -------------------------------------------------
    # 7. RETRIEVE SECURITY REFERENCE EVIDENCE
    # -------------------------------------------------

    retrieved_evidence = []

    safe_retrieved_evidence = []

    if analyzer is None:

        retrieval_query = (
            build_retrieval_query(
                finding=finding,
                asset=asset,
                risk=risk,
            )
        )

        try:

            knowledge_retriever = (
                KnowledgeRetriever
                .from_trusted_knowledge()
            )

            retrieved_evidence = (
                knowledge_retriever.retrieve(
                    query=
                        retrieval_query,

                    top_k=
                        RAG_TOP_K,

                    min_similarity=
                        RAG_MIN_SIMILARITY,

                    caller_access=
                        "standard",
                )
            )

            log_event(
                "RAG_EVIDENCE_RETRIEVED",
                {
                    "workflow_id":
                        workflow_id,

                    "finding_id":
                        finding.finding_id,

                    "evidence_count":
                        len(
                            retrieved_evidence
                        ),

                    "sources":
                        [
                            {
                                "source_id":
                                    item.source_id,

                                "source_name":
                                    item.source_name,

                                "chunk_id":
                                    item.chunk_id,

                                "similarity":
                                    round(
                                        item.similarity,
                                        4
                                    ),

                                "trust_tier":
                                    item.trust_tier,

                                "access_level":
                                    item.access_level,
                            }

                            for item in
                            retrieved_evidence
                        ],
                }
            )

            # -------------------------------------------------
            # 8. INSPECT AND QUARANTINE RAG EVIDENCE
            # -------------------------------------------------

            rag_security_result = (
                secure_retrieved_evidence(
                    retrieved_evidence
                )
            )

            safe_retrieved_evidence = (
                rag_security_result
                .safe_evidence
            )

            if (
                rag_security_result
                .quarantined_chunk_ids
            ):

                log_event(
                    "RAG_PROMPT_INJECTION_QUARANTINED",
                    {
                        "workflow_id":
                            workflow_id,

                        "finding_id":
                            finding.finding_id,

                        "quarantined_chunk_ids":
                            rag_security_result
                            .quarantined_chunk_ids,

                        "categories":
                            rag_security_result
                            .categories,

                        "retrieved_count":
                            len(
                                retrieved_evidence
                            ),

                        "safe_count":
                            len(
                                safe_retrieved_evidence
                            ),
                    }
                )

        except Exception as error:

            log_event(
                "RAG_RETRIEVAL_FAILED",
                {
                    "workflow_id":
                        workflow_id,

                    "finding_id":
                        finding.finding_id,

                    "error_type":
                        type(error).__name__,
                }
            )

            retrieved_evidence = []

            safe_retrieved_evidence = []

    # -------------------------------------------------
    # 9. GENERATE AI / ADVISORY ANALYSIS
    # -------------------------------------------------

    if analyzer is None:

        analysis = analyze_vulnerability(
            finding=finding,
            asset=asset,
            threat=threat,
            risk=risk,

            # Only evidence that passed the
            # deterministic RAG security gate
            # is allowed to reach the LLM.
            evidence=
                safe_retrieved_evidence,
        )

    else:

        analysis = analyzer(
            finding=finding,
            asset=asset,
            threat=threat,
            risk=risk,
        )

    log_event(
        "AI_ANALYSIS_GENERATED",
        {
            "workflow_id":
                workflow_id,

            "confidence":
                analysis.confidence,

            "requires_human_review":
                analysis.requires_human_review,

            "rag_evidence_count":
                len(
                    safe_retrieved_evidence
                ),
        }
    )

    # -------------------------------------------------
    # 10. BUILD DETERMINISTIC TICKET DRAFT
    # -------------------------------------------------

    ticket = build_ticket(
        finding=finding,
        asset=asset,
        risk=risk,
        analysis=analysis
    )

    log_event(
        "TICKET_DRAFTED",
        {
            "workflow_id":
                workflow_id,

            "priority":
                ticket.priority,

            "asset_name":
                ticket.asset_name,

            "cve":
                ticket.cve,

            "risk_rating":
                ticket.risk_rating,
        }
    )

    # -------------------------------------------------
    # 11. BUILD SECURITY METADATA
    # -------------------------------------------------

    security = WorkflowSecurity(
        prompt_injection_detected=bool(
            injection_matches
        ),

        prompt_injection_matches=
            injection_matches,

        # Human review is authoritative workflow
        # policy. An AI analyzer cannot disable it.
        human_review_required=
            True
    )

    # -------------------------------------------------
    # 12. RETURN STRUCTURED RESULT
    # -------------------------------------------------

    return WorkflowResult(
        workflow_id=
            workflow_id,

        status=
            "AWAITING_APPROVAL",

        finding_id=
            finding.finding_id,

        asset_name=
            finding.asset_name,

        cve=
            finding.cve,

        risk=
            risk,

        security=
            security,

        analysis=
            analysis,

        # Only evidence that was actually permitted
        # to reach the AI is exposed as source
        # attribution in the workflow result.
        retrieved_evidence=
            safe_retrieved_evidence,

        ticket=
            ticket
    )