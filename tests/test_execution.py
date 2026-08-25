import json

import pytest

import app.execution as execution
import app.ticketing as ticketing

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
            "Verify fixed version.",
            "Run authenticated rescan."
        ]
    )


def make_result():

    return WorkflowResult(
        workflow_id="WF-TEST0001",

        status="AWAITING_APPROVAL",

        finding_id="FIND-0001",

        asset_name="internet-web-01",

        cve="CVE-2026-12345",

        risk=make_risk(),

        security=WorkflowSecurity(
            prompt_injection_detected=False,
            human_review_required=True
        ),

        analysis=make_analysis(),

        ticket=make_ticket()
    )


def capture_events(
    monkeypatch
):

    events = []

    monkeypatch.setattr(
        execution,
        "log_event",
        lambda event_type, details=None:
            events.append(
                {
                    "event_type":
                        event_type,

                    "details":
                        details or {}
                }
            )
    )

    return events


# -------------------------------------------------
# SUCCESSFUL APPROVAL + EXECUTION
# -------------------------------------------------


def test_approved_workflow_returns_ticket_created(
    tmp_path,
    monkeypatch
):

    events = capture_events(
        monkeypatch
    )

    temporary_ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        temporary_ticket_file
    )

    result = (
        execution
        .approve_and_execute_workflow(
            result=make_result(),
            approved_by="demo-analyst"
        )
    )

    assert (
        result.status
        == "TICKET_CREATED"
    )

    assert (
        result.approval_id
        is not None
    )

    assert (
        result.ticket_id
        is not None
    )

    assert temporary_ticket_file.exists()

    record = json.loads(
        temporary_ticket_file
        .read_text(
            encoding="utf-8"
        )
        .splitlines()[0]
    )

    assert (
        record["approval_id"]
        == result.approval_id
    )

    assert (
        record["ticket_id"]
        == result.ticket_id
    )

    event_types = [
        event["event_type"]
        for event in events
    ]

    assert (
        "TICKET_APPROVED"
        in event_types
    )

    assert (
        "MOCK_TICKET_CREATED"
        in event_types
    )


# -------------------------------------------------
# HUMAN REJECTION
# -------------------------------------------------


def test_rejected_workflow_returns_rejected_state(
    tmp_path,
    monkeypatch
):

    events = capture_events(
        monkeypatch
    )

    temporary_ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        temporary_ticket_file
    )

    result = execution.reject_workflow(
        make_result()
    )

    assert (
        result.status
        == "REJECTED"
    )

    assert result.approval_id is None

    assert result.ticket_id is None

    assert (
        temporary_ticket_file.exists()
        is False
    )

    rejected_event = next(
        event
        for event in events
        if event["event_type"]
        == "TICKET_REJECTED"
    )

    assert (
        rejected_event["details"][
            "workflow_id"
        ]
        == "WF-TEST0001"
    )


# -------------------------------------------------
# REJECTED WORKFLOW CANNOT LATER EXECUTE
# -------------------------------------------------


def test_rejected_workflow_cannot_be_executed(
    tmp_path,
    monkeypatch
):

    events = capture_events(
        monkeypatch
    )

    temporary_ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        temporary_ticket_file
    )

    rejected = execution.reject_workflow(
        make_result()
    )

    with pytest.raises(
        PermissionError
    ):

        execution.approve_and_execute_workflow(
            result=rejected,
            approved_by="demo-analyst"
        )

    assert (
        temporary_ticket_file.exists()
        is False
    )

    event_types = [
        event["event_type"]
        for event in events
    ]

    assert (
        "TICKET_APPROVED"
        not in event_types
    )

    assert (
        "MOCK_TICKET_CREATED"
        not in event_types
    )


# -------------------------------------------------
# BLANK APPROVER FAILS BEFORE EXECUTION
# -------------------------------------------------


def test_blank_approver_cannot_execute_ticket(
    tmp_path,
    monkeypatch
):

    events = capture_events(
        monkeypatch
    )

    temporary_ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        temporary_ticket_file
    )

    with pytest.raises(
        ValueError
    ):

        execution.approve_and_execute_workflow(
            result=make_result(),
            approved_by="   "
        )

    assert (
        temporary_ticket_file.exists()
        is False
    )

    event_types = [
        event["event_type"]
        for event in events
    ]

    assert (
        "TICKET_APPROVED"
        not in event_types
    )

    assert (
        "MOCK_TICKET_CREATED"
        not in event_types
    )


# -------------------------------------------------
# EXECUTION AUTHORIZATION FAILURE FAILS CLOSED
# -------------------------------------------------


def test_execution_authorization_failure_is_logged_and_blocked(
    monkeypatch
):

    events = capture_events(
        monkeypatch
    )

    def blocked_ticket_creation(
        ticket,
        approval
    ):

        raise PermissionError(
            "Approval validation failed."
        )

    monkeypatch.setattr(
        execution,
        "create_mock_ticket",
        blocked_ticket_creation
    )

    with pytest.raises(
        PermissionError
    ):

        execution.approve_and_execute_workflow(
            result=make_result(),
            approved_by="demo-analyst"
        )

    event_types = [
        event["event_type"]
        for event in events
    ]

    assert (
        "TICKET_APPROVED"
        in event_types
    )

    assert (
        "TICKET_EXECUTION_BLOCKED"
        in event_types
    )

    assert (
        "MOCK_TICKET_CREATED"
        not in event_types
    )

    blocked_event = next(
        event
        for event in events
        if event["event_type"]
        == "TICKET_EXECUTION_BLOCKED"
    )

    assert (
        blocked_event["details"][
            "workflow_id"
        ]
        == "WF-TEST0001"
    )

    assert (
        blocked_event["details"][
            "error_type"
        ]
        == "PermissionError"
    )