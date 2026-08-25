from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from fastapi.testclient import TestClient

import app.api as api_module
import app.ticketing as ticketing

from app.api import app

from app.models import AIAnalysis
from app.models import RiskResult
from app.models import TicketDraft
from app.models import WorkflowResult
from app.models import WorkflowSecurity

from app.workflow_store import (
    get_workflow,
    save_workflow,
)


# -------------------------------------------------
# TEST CLIENT
# -------------------------------------------------


client = TestClient(
    app
)


# -------------------------------------------------
# TEST AUTHENTICATION
# -------------------------------------------------


ANALYST_TOKEN = (
    "analyst-secret-token"
)

APPROVER_TOKEN = (
    "approver-secret-token"
)


def analyst_headers():

    return {
        "Authorization":
            f"Bearer {ANALYST_TOKEN}"
    }


def approver_headers():

    return {
        "Authorization":
            f"Bearer {APPROVER_TOKEN}"
    }


# -------------------------------------------------
# ISOLATED TEST ENVIRONMENT
# -------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_test_environment(
    tmp_path,
    monkeypatch
):

    database_path = (
        tmp_path / "workflows.db"
    )

    monkeypatch.setenv(
        "VM_AI_DB_PATH",
        str(database_path)
    )

    monkeypatch.setenv(
        "VM_AI_ANALYST_TOKEN",
        ANALYST_TOKEN
    )

    monkeypatch.setenv(
        "VM_AI_APPROVER_TOKEN",
        APPROVER_TOKEN
    )

    yield


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


# -------------------------------------------------
# PUBLIC HEALTH ENDPOINT
# -------------------------------------------------


def test_health_endpoint_is_public():

    response = client.get(
        "/health"
    )

    assert response.status_code == 200

    assert response.json() == {
        "status": "ok"
    }


# -------------------------------------------------
# CREATE REQUIRES AUTHENTICATION
# -------------------------------------------------


def test_create_workflow_requires_authentication():

    response = client.post(
        "/workflows"
    )

    assert (
        response.status_code
        == 401
    )


# -------------------------------------------------
# INVALID TOKEN
# -------------------------------------------------


def test_invalid_token_is_rejected():

    response = client.post(
        "/workflows",

        headers={
            "Authorization":
                "Bearer wrong-token"
        },
    )

    assert (
        response.status_code
        == 401
    )


# -------------------------------------------------
# ANALYST CAN CREATE
# -------------------------------------------------


def test_analyst_can_create_workflow(
    monkeypatch
):

    prepared = make_result()

    monkeypatch.setattr(
        api_module,
        "prepare_workflow",
        lambda: prepared,
    )

    response = client.post(
        "/workflows",

        headers=analyst_headers(),
    )

    assert (
        response.status_code
        == 201
    )

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
# GET REQUIRES AUTHENTICATION
# -------------------------------------------------


def test_get_workflow_requires_authentication():

    save_workflow(
        make_result()
    )

    response = client.get(
        "/workflows/WF-TEST0001"
    )

    assert (
        response.status_code
        == 401
    )


# -------------------------------------------------
# ANALYST CAN READ
# -------------------------------------------------


def test_analyst_can_read_workflow():

    save_workflow(
        make_result()
    )

    response = client.get(
        "/workflows/WF-TEST0001",

        headers=analyst_headers(),
    )

    assert (
        response.status_code
        == 200
    )

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
        "/workflows/WF-DOESNOTEXIST",

        headers=analyst_headers(),
    )

    assert (
        response.status_code
        == 404
    )

    assert (
        response.json()["detail"]
        == "Workflow not found."
    )


# -------------------------------------------------
# ANALYST CANNOT APPROVE
# -------------------------------------------------


def test_analyst_cannot_approve():

    save_workflow(
        make_result()
    )

    response = client.post(
        "/workflows/WF-TEST0001/approve",

        headers=analyst_headers(),
    )

    assert (
        response.status_code
        == 403
    )

    assert (
        "approver role"
        in response.json()[
            "detail"
        ].lower()
    )


# -------------------------------------------------
# ANALYST CANNOT REJECT
# -------------------------------------------------


def test_analyst_cannot_reject():

    save_workflow(
        make_result()
    )

    response = client.post(
        "/workflows/WF-TEST0001/reject",

        headers=analyst_headers(),
    )

    assert (
        response.status_code
        == 403
    )


# -------------------------------------------------
# APPROVAL USES AUTHENTICATED IDENTITY
# AND TRUSTED SERVER-SIDE STATE
# -------------------------------------------------


def test_approver_identity_and_server_state_are_used(
    monkeypatch
):

    trusted_result = make_result()

    save_workflow(
        trusted_result
    )

    captured = {}

    def fake_execute(
        workflow_id,
        approved_by,
    ):

        captured[
            "workflow_id"
        ] = workflow_id

        captured[
            "approved_by"
        ] = approved_by

        authoritative = (
            get_workflow(
                workflow_id
            )
        )

        captured[
            "result"
        ] = authoritative

        updated = (
            authoritative.model_dump()
        )

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

        return (
            WorkflowResult
            .model_validate(
                updated
            )
        )

    monkeypatch.setattr(
        api_module,
        "claim_and_execute_workflow",
        fake_execute,
    )

    # Malicious client attempts to submit
    # different authoritative ticket values.
    #
    # The API does not trust this request body.
    # Execution uses workflow_id to retrieve
    # trusted server-side workflow state.

    response = client.post(
        "/workflows/WF-TEST0001/approve",

        headers=approver_headers(),

        json={
            "ticket": {
                "priority": "P4",
                "risk_rating": "LOW",
                "risk_score": 0,
                "sla_hours": 9999,
            }
        },
    )

    assert (
        response.status_code
        == 200
    )

    authoritative = captured[
        "result"
    ]

    assert (
        captured["workflow_id"]
        == "WF-TEST0001"
    )

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
        == "api-approver"
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


# -------------------------------------------------
# APPROVER CAN REJECT
# -------------------------------------------------


def test_approver_can_reject_workflow(
    monkeypatch
):

    save_workflow(
        make_result()
    )

    def fake_reject(
        result
    ):

        updated = (
            result.model_dump()
        )

        updated.update(
            {
                "status":
                    "REJECTED",

                "approval_id":
                    None,

                "ticket_id":
                    None,
            }
        )

        return (
            WorkflowResult
            .model_validate(
                updated
            )
        )

    monkeypatch.setattr(
        api_module,
        "reject_workflow",
        fake_reject,
    )

    response = client.post(
        "/workflows/WF-TEST0001/reject",

        headers=approver_headers(),
    )

    assert (
        response.status_code
        == 200
    )

    assert (
        response.json()["status"]
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
# REJECTED WORKFLOW CANNOT BE APPROVED
# -------------------------------------------------


def test_rejected_workflow_cannot_be_approved():

    save_workflow(
        make_result(
            status="REJECTED"
        )
    )

    response = client.post(
        "/workflows/WF-TEST0001/approve",

        headers=approver_headers(),
    )

    assert (
        response.status_code
        == 409
    )

    assert (
        "awaiting approval"
        in response.json()[
            "detail"
        ].lower()
    )


# -------------------------------------------------
# APPROVER CAN ALSO CREATE WORKFLOW
# -------------------------------------------------


def test_approver_can_create_workflow(
    monkeypatch
):

    prepared = make_result()

    monkeypatch.setattr(
        api_module,
        "prepare_workflow",
        lambda: prepared,
    )

    response = client.post(
        "/workflows",

        headers=approver_headers(),
    )

    assert (
        response.status_code
        == 201
    )


# -------------------------------------------------
# SECOND APPROVAL IS BLOCKED
# -------------------------------------------------


def test_second_approval_is_blocked_and_creates_one_ticket(
    tmp_path,
    monkeypatch
):

    ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        ticket_file
    )

    save_workflow(
        make_result()
    )

    first_response = client.post(
        "/workflows/WF-TEST0001/approve",

        headers=approver_headers(),
    )

    second_response = client.post(
        "/workflows/WF-TEST0001/approve",

        headers=approver_headers(),
    )

    assert (
        first_response.status_code
        == 200
    )

    assert (
        second_response.status_code
        == 409
    )

    assert ticket_file.exists()

    lines = (
        ticket_file
        .read_text(
            encoding="utf-8"
        )
        .splitlines()
    )

    assert (
        len(lines)
        == 1
    )

    stored = get_workflow(
        "WF-TEST0001"
    )

    assert (
        stored.status
        == "TICKET_CREATED"
    )


# -------------------------------------------------
# CONCURRENT APPROVAL REQUESTS
# -------------------------------------------------


def test_concurrent_api_approval_creates_exactly_one_ticket(
    tmp_path,
    monkeypatch
):

    ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        ticket_file
    )

    save_workflow(
        make_result()
    )

    barrier = Barrier(
        2
    )

    def approve():

        barrier.wait()

        with TestClient(
            app
        ) as concurrent_client:

            return (
                concurrent_client.post(
                    (
                        "/workflows/"
                        "WF-TEST0001/"
                        "approve"
                    ),

                    headers=
                        approver_headers(),
                )
            )

    with ThreadPoolExecutor(
        max_workers=2
    ) as executor:

        responses = list(
            executor.map(
                lambda _: approve(),
                range(2)
            )
        )

    status_codes = sorted(
        response.status_code
        for response in responses
    )

    assert status_codes == [
        200,
        409
    ]

    assert ticket_file.exists()

    lines = (
        ticket_file
        .read_text(
            encoding="utf-8"
        )
        .splitlines()
    )

    assert (
        len(lines)
        == 1
    )

    stored = get_workflow(
        "WF-TEST0001"
    )

    assert (
        stored.status
        == "TICKET_CREATED"
    )

    successful_response = next(
        response
        for response in responses
        if response.status_code
        == 200
    )

    blocked_response = next(
        response
        for response in responses
        if response.status_code
        == 409
    )

    assert (
        successful_response
        .json()["status"]
        == "TICKET_CREATED"
    )

    assert (
        "awaiting approval"
        in blocked_response
        .json()["detail"]
        .lower()
    )