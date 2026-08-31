from collections.abc import Callable
from uuid import uuid4

from app.ai_analyzer import analyze_vulnerability
from app.audit import log_event
from app.input_security import aggregate_prompt_injection_matches
from app.input_security import inspect_prompt_injection_data

from app.models import AIAnalysis
from app.models import AssetContext
from app.models import RiskResult
from app.models import ThreatIntel
from app.models import VulnerabilityFinding
from app.models import WorkflowResult
from app.models import WorkflowSecurity

from app.providers.base import VulnerabilityProvider
from app.providers.local_json import LocalJsonProvider

from app.risk_engine import calculate_risk
from app.ticketing import build_ticket


# -------------------------------------------------
# DEFAULT DEMO FINDING
# -------------------------------------------------


DEFAULT_FINDING_ID = "FIND-0001"


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
    vulnerability analyzer is used.

    This function:

    1. Retrieves and validates provider security data
    2. Validates relationships between provider records
    3. Detects suspicious prompt-injection content
    4. Calculates authoritative deterministic risk
    5. Generates AI-assisted security analysis
    6. Builds a validated ticket draft
    7. Returns one structured WorkflowResult

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
    # 7. SELECT ANALYZER
    # -------------------------------------------------

    analysis_function = (
        analyzer
        if analyzer is not None
        else analyze_vulnerability
    )

    # -------------------------------------------------
    # 8. GENERATE AI / ADVISORY ANALYSIS
    # -------------------------------------------------

    analysis = analysis_function(
        finding=finding,
        asset=asset,
        threat=threat,
        risk=risk
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
        }
    )

    # -------------------------------------------------
    # 9. BUILD DETERMINISTIC TICKET DRAFT
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
    # 10. BUILD SECURITY METADATA
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
    # 11. RETURN STRUCTURED RESULT
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

        ticket=
            ticket
    )
