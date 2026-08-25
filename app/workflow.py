from uuid import uuid4

from app.ai_analyzer import analyze_vulnerability
from app.audit import log_event
from app.input_security import detect_prompt_injection

from app.loaders import load_asset
from app.loaders import load_finding
from app.loaders import load_threat_intel

from app.models import WorkflowResult
from app.models import WorkflowSecurity

from app.risk_engine import calculate_risk
from app.ticketing import build_ticket


def generate_workflow_id() -> str:

    return "WF-" + uuid4().hex[:8].upper()


def prepare_workflow() -> WorkflowResult:
    """
    Prepare a vulnerability-management workflow up to
    the human approval boundary.

    This function:

    1. Loads and validates security data
    2. Detects suspicious prompt-injection content
    3. Calculates authoritative deterministic risk
    4. Generates AI-assisted security analysis
    5. Builds a validated ticket draft
    6. Returns one structured WorkflowResult

    It does NOT:

    - ask the user for approval
    - create an approval record
    - create a ticket
    - perform an external action
    """

    workflow_id = generate_workflow_id()

    # -------------------------------------------------
    # 1. START WORKFLOW
    # -------------------------------------------------

    log_event(
        "WORKFLOW_STARTED",
        {
            "workflow_id": workflow_id
        }
    )

    # -------------------------------------------------
    # 2. LOAD AND VALIDATE INPUT
    # -------------------------------------------------

    finding = load_finding()
    asset = load_asset()
    threat = load_threat_intel()

    # -------------------------------------------------
    # 3. INSPECT UNTRUSTED TEXT
    # -------------------------------------------------

    injection_matches = detect_prompt_injection(
        finding.description
    )

    if injection_matches:

        log_event(
            "PROMPT_INJECTION_SUSPECTED",
            {
                "workflow_id": workflow_id,
                "finding_id": finding.finding_id,
                "field": "description",
                "matches": injection_matches
            }
        )

    # -------------------------------------------------
    # 4. RECORD SUCCESSFUL INPUT VALIDATION
    # -------------------------------------------------

    log_event(
        "SECURITY_DATA_VALIDATED",
        {
            "workflow_id": workflow_id,
            "finding_id": finding.finding_id,
            "asset_name": finding.asset_name,
            "cve": finding.cve
        }
    )

    # -------------------------------------------------
    # 5. CALCULATE AUTHORITATIVE RISK
    # -------------------------------------------------

    risk = calculate_risk(
        finding=finding,
        asset=asset,
        threat=threat
    )

    log_event(
        "RISK_CALCULATED",
        {
            "workflow_id": workflow_id,
            "score": risk.score,
            "rating": risk.rating,
            "sla_hours": risk.sla_hours,
            "factors": risk.factors
        }
    )

    # -------------------------------------------------
    # 6. GENERATE AI ANALYSIS
    # -------------------------------------------------

    analysis = analyze_vulnerability(
        finding=finding,
        asset=asset,
        threat=threat,
        risk=risk
    )

    log_event(
        "AI_ANALYSIS_GENERATED",
        {
            "workflow_id": workflow_id,
            "confidence": analysis.confidence,
            "requires_human_review":
                analysis.requires_human_review
        }
    )

    # -------------------------------------------------
    # 7. BUILD DETERMINISTIC TICKET DRAFT
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
            "workflow_id": workflow_id,
            "priority": ticket.priority,
            "asset_name": ticket.asset_name,
            "cve": ticket.cve,
            "risk_rating": ticket.risk_rating
        }
    )

    # -------------------------------------------------
    # 8. BUILD SECURITY METADATA
    # -------------------------------------------------

    security = WorkflowSecurity(
        prompt_injection_detected=bool(
            injection_matches
        ),

        prompt_injection_matches=
            injection_matches,

        human_review_required=
            analysis.requires_human_review
    )

    # -------------------------------------------------
    # 9. RETURN STRUCTURED RESULT
    # -------------------------------------------------

    return WorkflowResult(
        workflow_id=workflow_id,

        status="AWAITING_APPROVAL",

        finding_id=finding.finding_id,

        asset_name=finding.asset_name,

        cve=finding.cve,

        risk=risk,

        security=security,

        ticket=ticket
    )