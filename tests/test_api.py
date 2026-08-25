from fastapi.testclient import TestClient

import app.api as api_module

from app.api import app

from app.models import AIAnalysis
from app.models import RiskResult
from app.models import TicketDraft
from app.models import WorkflowResult
from app.models import WorkflowSecurity

from app.workflow_store import (
    clear_workflows,
    get_workflow,
    save_workflow,
)


client = TestClient(
    app
)


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
            "Asset is internet exposed",
        ],
    )


def make_analysis():

    return AIAnalysis(
        executive_summary=(
            "Critical vulnerability requiring "
            "expedited remediation."
        ),

        rationale=[
            "Internet exposed.",
            "Listed in CISA KEV.",
        ],

        remediation=(
            "Deploy the approved vendor patch."
        ),

        compensating_controls=[
            "Maintain WAF protection.",
        ],

        validation_steps=[
            "Verify fixed version.",
            "Run authenticated rescan.",
        ],

        confidence="HIGH",

        requires_human_review=True,

        ticket_summary=(
            "CRITICAL: Remediate CVE-2026-12345"
        ),

        ticket_description=(
            "Validated vulnerability ticket."
        ),
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
            "Verify fixed version.",
            "Run authenticated rescan.",
        ],
    )


def make_result(
    status="AWAITING_APPROVAL",
    approval_id=None,
    ticket_id=None,
):

    return WorkflowResult(
        workflow_id="WF-TEST0001",

        status=status,

        finding_id="FIND-0001",

        asset_name="internet-web-01",

        cve="CVE-2026-12345",

        risk=make_risk(),

        security=WorkflowSecurity(
            prompt_injection_detected=False,
            human_review_required=True,
        ),

        analysis=make_analysis(),

        ticket=make_ticket(),

        approval_id=approval_id,

        ticket_id=ticket_id,
    )


def setup_function():

    clear_workflows()


# -------------------------------------------------
# HEALTH ENDPOINT
# -------------------------------------------------


def test_health_endpoint():

    response = client.get(
        "/health"
    )

    assert response.status_code == 200

    assert response.json() == {
        "status": "ok"
    }


# -------------------------------------------------
# CREATE WORKFLOW
# -------------------------------------------------


def test_create_workflow_saves_server_side_state(
    monkeypatch
):

    prepared = make_result()

    monkeypatch.setattr(
        api_module,
        "prepare_workflow",
        lambda: prepared,
    )

    response = client.post(
        "/workflows"
    )

    assert response.status_code == 201

    body = response.json()

    assert (
        body["workflow_id"]
        == "WF-TEST0001"
    )

    assert (
        body["status"]
        == "AWAITING_APPROVAL"
    )

    stored = get_workflow(
        "WF-TEST0001"
    )

    assert stored == prepared


# -------------------------------------------------
# GET WORKFLOW
# -------------------------------------------------


def test_get_existing_workflow():

    save_workflow(
        make_result()
    )

    response = client.get(
        "/workflows/WF-TEST0001"
    )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["workflow_id"]
        == "WF-TEST0001"
    )

    assert (
        body["risk"]["rating"]
        == "CRITICAL"
    )

    assert (
        body["ticket"]["priority"]
        == "P1"
    )


# -------------------------------------------------
# UNKNOWN WORKFLOW
# -------------------------------------------------


def test_unknown_workflow_returns_404():

    response = client.get(
        "/workflows/WF-DOESNOTEXIST"
    )

    assert response.status_code == 404

    assert (
        response.json()["detail"]
        == "Workflow not found."
    )


# -------------------------------------------------
# APPROVAL USES TRUSTED SERVER STATE
# -------------------------------------------------


def test_approve_uses_server_side_workflow_not_client_ticket(
    monkeypatch
):

    trusted_result = make_result()

    save_workflow(
        trusted_result
    )

    captured = {}

    def fake_execute(
        result,
        approved_by,
    ):

        captured["result"] = result

        captured[
            "approved_by"
        ] = approved_by

        updated = result.model_dump()

        updated.update(
            {
                "status":
                    "TICKET_CREATED",

                "approval_id":
                    "APR-TEST0001",

                "ticket_id":
                    "VM-TEST0001",
            }
        )

        return WorkflowResult.model_validate(
            updated
        )

    monkeypatch.setattr(
        api_module,
        "approve_and_execute_workflow",
        fake_execute,
    )

    # Deliberately malicious client body.
    #
    # The API endpoint does not accept a client
    # supplied ticket. This data must therefore
    # have no influence on execution.

    response = client.post(
        "/workflows/WF-TEST0001/approve",

        json={
            "ticket": {
                "priority": "P4",
                "risk_rating": "LOW",
                "risk_score": 0,
                "sla_hours": 9999,
            }
        },
    )

    assert response.status_code == 200

    authoritative = captured[
        "result"
    ]

    assert (
        authoritative.ticket.priority
        == "P1"
    )

    assert (
        authoritative.ticket.risk_rating
        == "CRITICAL"
    )

    assert (
        authoritative.ticket.risk_score
        == 100
    )

    assert (
        authoritative.ticket.sla_hours
        == 24
    )

    assert (
        captured["approved_by"]
        == api_module.DEMO_APPROVER
    )

    body = response.json()

    assert (
        body["status"]
        == "TICKET_CREATED"
    )

    assert (
        body["approval_id"]
        == "APR-TEST0001"
    )

    assert (
        body["ticket_id"]
        == "VM-TEST0001"
    )

    stored = get_workflow(
        "WF-TEST0001"
    )

    assert (
        stored.status
        == "TICKET_CREATED"
    )


# -------------------------------------------------
# REJECTION
# -------------------------------------------------


def test_reject_updates_server_side_workflow(
    monkeypatch
):

    save_workflow(
        make_result()
    )

    def fake_reject(
        result
    ):

        updated = result.model_dump()

        updated.update(
            {
                "status": "REJECTED",
                "approval_id": None,
                "ticket_id": None,
            }
        )

        return WorkflowResult.model_validate(
            updated
        )

    monkeypatch.setattr(
        api_module,
        "reject_workflow",
        fake_reject,
    )

    response = client.post(
        "/workflows/WF-TEST0001/reject"
    )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["status"]
        == "REJECTED"
    )

    stored = get_workflow(
        "WF-TEST0001"
    )

    assert (
        stored.status
        == "REJECTED"
    )


# -------------------------------------------------
# INVALID STATE TRANSITION
# -------------------------------------------------


def test_invalid_state_transition_returns_409():

    save_workflow(
        make_result(
            status="REJECTED"
        )
    )

    response = client.post(
        "/workflows/WF-TEST0001/approve"
    )

    assert response.status_code == 409

    assert (
        "awaiting approval"
        in response.json()[
            "detail"
        ].lower()
    )