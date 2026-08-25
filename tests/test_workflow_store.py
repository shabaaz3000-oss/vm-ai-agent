import pytest

from app.models import AIAnalysis
from app.models import RiskResult
from app.models import TicketDraft
from app.models import WorkflowResult
from app.models import WorkflowSecurity

from app.workflow_store import clear_workflows
from app.workflow_store import get_workflow
from app.workflow_store import save_workflow
from app.workflow_store import update_workflow


def make_result(
    status="AWAITING_APPROVAL"
):

    return WorkflowResult(
        workflow_id="WF-TEST0001",

        status=status,

        finding_id="FIND-0001",

        asset_name="internet-web-01",

        cve="CVE-2026-12345",

        risk=RiskResult(
            score=100,
            rating="CRITICAL",
            sla_hours=24,
            factors=[
                "Listed in CISA KEV",
                "Internet exposed"
            ]
        ),

        security=WorkflowSecurity(
            prompt_injection_detected=False,
            human_review_required=True
        ),

        analysis=AIAnalysis(
            executive_summary=(
                "Critical vulnerability."
            ),

            rationale=[
                "Critical risk."
            ],

            remediation=(
                "Deploy approved patch."
            ),

            compensating_controls=[
                "Maintain WAF."
            ],

            validation_steps=[
                "Run authenticated rescan."
            ],

            confidence="HIGH",

            requires_human_review=True,

            ticket_summary=(
                "Remediate vulnerability."
            ),

            ticket_description=(
                "Validated ticket draft."
            )
        ),

        ticket=TicketDraft(
            short_description=(
                "CRITICAL vulnerability"
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
                "Validated ticket."
            ),

            remediation=(
                "Deploy approved patch."
            ),

            validation_steps=[
                "Run authenticated rescan."
            ]
        )
    )


def setup_function():

    clear_workflows()


def test_save_and_get_workflow():

    original = make_result()

    save_workflow(
        original
    )

    retrieved = get_workflow(
        "WF-TEST0001"
    )

    assert retrieved == original


def test_unknown_workflow_is_rejected():

    with pytest.raises(
        KeyError
    ):

        get_workflow(
            "WF-DOESNOTEXIST"
        )


def test_update_existing_workflow():

    save_workflow(
        make_result()
    )

    updated = make_result(
        status="REJECTED"
    )

    update_workflow(
        updated
    )

    retrieved = get_workflow(
        "WF-TEST0001"
    )

    assert (
        retrieved.status
        == "REJECTED"
    )


def test_update_unknown_workflow_is_rejected():

    with pytest.raises(
        KeyError
    ):

        update_workflow(
            make_result()
        )


def test_store_preserves_authoritative_ticket():

    original = make_result()

    save_workflow(
        original
    )

    retrieved = get_workflow(
        original.workflow_id
    )

    assert (
        retrieved.ticket.risk_rating
        == "CRITICAL"
    )

    assert (
        retrieved.ticket.risk_score
        == 100
    )

    assert (
        retrieved.ticket.sla_hours
        == 24
    )

    assert (
        retrieved.ticket.priority
        == "P1"
    )