import pytest

from pydantic import ValidationError

from app.models import AIAnalysis
from app.models import RiskResult
from app.models import TicketDraft
from app.models import WorkflowResult
from app.models import WorkflowSecurity


# -------------------------------------------------
# TEST DATA HELPERS
# -------------------------------------------------


def make_risk():

    return RiskResult(
        score=100,
        rating="CRITICAL",
        sla_hours=24,
        factors=[
            "Listed in CISA KEV",
            "Asset is internet exposed"
        ]
    )


def make_security():

    return WorkflowSecurity(
        prompt_injection_detected=False,
        human_review_required=True
    )


def make_analysis():

    return AIAnalysis(
        executive_summary=(
            "Critical vulnerability requiring "
            "expedited remediation."
        ),

        rationale=[
            "Internet exposed.",
            "Listed in CISA KEV."
        ],

        remediation=(
            "Deploy the approved vendor patch."
        ),

        compensating_controls=[
            "Maintain WAF protection."
        ],

        validation_steps=[
            "Verify fixed version.",
            "Run authenticated rescan."
        ],

        confidence="HIGH",

        requires_human_review=True,

        ticket_summary=(
            "CRITICAL: Remediate CVE-2026-12345"
        ),

        ticket_description=(
            "Validated vulnerability ticket."
        )
    )


def make_ticket():

    return TicketDraft(
        short_description=(
            "CRITICAL: Remediate CVE-2026-12345"
        ),

        priority="P1",

        asset_name="internet-web-01",

        cve="CVE-2026-12345",

        assignment_group=(
            "Web Platform Team"
        ),

        risk_rating="CRITICAL",

        risk_score=100,

        sla_hours=24,

        description=(
            "Validated vulnerability ticket."
        ),

        remediation=(
            "Deploy the approved vendor patch."
        ),

        validation_steps=[
            "Confirm fixed version.",
            "Run authenticated rescan."
        ]
    )


# -------------------------------------------------
# WORKFLOW SECURITY MODEL
# -------------------------------------------------


def test_workflow_security_defaults_to_empty_matches():

    security = make_security()

    assert (
        security.prompt_injection_detected
        is False
    )

    assert (
        security.prompt_injection_matches
        == []
    )

    assert (
        security.human_review_required
        is True
    )


# -------------------------------------------------
# AWAITING APPROVAL STATE
# -------------------------------------------------


def test_awaiting_approval_result_is_valid():

    result = WorkflowResult(
        workflow_id="WF-12345678",

        status="AWAITING_APPROVAL",

        finding_id="FIND-0001",

        asset_name="internet-web-01",

        cve="CVE-2026-12345",

        risk=make_risk(),

        security=make_security(),

        analysis=make_analysis(),

        ticket=make_ticket()
    )

    assert (
        result.status
        == "AWAITING_APPROVAL"
    )

    assert result.approval_id is None

    assert result.ticket_id is None

    assert result.risk.score == 100

    assert (
        result.risk.rating
        == "CRITICAL"
    )

    assert (
        result.ticket.priority
        == "P1"
    )


# -------------------------------------------------
# COMPLETED TICKET STATE
# -------------------------------------------------


def test_ticket_created_result_tracks_identifiers():

    result = WorkflowResult(
        workflow_id="WF-12345678",

        status="TICKET_CREATED",

        finding_id="FIND-0001",

        asset_name="internet-web-01",

        cve="CVE-2026-12345",

        risk=make_risk(),

        security=make_security(),

        analysis=make_analysis(),

        ticket=make_ticket(),

        approval_id="APR-12345678",

        ticket_id="VM-87654321"
    )

    assert (
        result.approval_id
        == "APR-12345678"
    )

    assert (
        result.ticket_id
        == "VM-87654321"
    )


# -------------------------------------------------
# INVALID WORKFLOW STATUS
# -------------------------------------------------


def test_invalid_workflow_status_rejected():

    with pytest.raises(
        ValidationError
    ):

        WorkflowResult(
            workflow_id="WF-12345678",

            status="BANANA",

            finding_id="FIND-0001",

            asset_name="internet-web-01",

            cve="CVE-2026-12345",

            risk=make_risk(),

            security=make_security(),

            analysis=make_analysis(),

            ticket=make_ticket()
        )


# -------------------------------------------------
# NESTED RISK VALIDATION
# -------------------------------------------------


def test_nested_risk_validation_still_applies():

    with pytest.raises(
        ValidationError
    ):

        WorkflowResult(
            workflow_id="WF-12345678",

            status="AWAITING_APPROVAL",

            finding_id="FIND-0001",

            asset_name="internet-web-01",

            cve="CVE-2026-12345",

            risk={
                "score": 100,
                "rating": "SUPER_CRITICAL",
                "sla_hours": 24,
                "factors": []
            },

            security=make_security(),

            analysis=make_analysis(),

            ticket=make_ticket()
        )


# -------------------------------------------------
# STRUCTURED AI ANALYSIS
# -------------------------------------------------


def test_workflow_result_contains_ai_analysis():

    result = WorkflowResult(
        workflow_id="WF-12345678",

        status="AWAITING_APPROVAL",

        finding_id="FIND-0001",

        asset_name="internet-web-01",

        cve="CVE-2026-12345",

        risk=make_risk(),

        security=make_security(),

        analysis=make_analysis(),

        ticket=make_ticket()
    )

    assert (
        result.analysis.confidence
        == "HIGH"
    )

    assert (
        result.analysis.requires_human_review
        is True
    )

    assert (
        "Critical vulnerability"
        in result.analysis.executive_summary
    )



def test_processing_workflow_status_is_valid():

    result = WorkflowResult(
        workflow_id="WF-12345678",

        status="PROCESSING",

        finding_id="FIND-0001",

        asset_name="internet-web-01",

        cve="CVE-2026-12345",

        risk=make_risk(),

        security=make_security(),

        analysis=make_analysis(),

        ticket=make_ticket()
    )

    assert (
        result.status
        == "PROCESSING"
    )

def test_processing_workflow_status_is_valid():

    result = WorkflowResult(
        workflow_id="WF-12345678",

        status="PROCESSING",

        finding_id="FIND-0001",

        asset_name="internet-web-01",

        cve="CVE-2026-12345",

        risk=make_risk(),

        security=make_security(),

        analysis=make_analysis(),

        ticket=make_ticket()
    )

    assert (
        result.status
        == "PROCESSING"
    )