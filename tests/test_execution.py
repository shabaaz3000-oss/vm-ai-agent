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

# -------------------------------------------------
# ATOMIC API EXECUTION CLAIM
# -------------------------------------------------


def test_claim_and_execute_uses_atomic_workflow_claim(
    monkeypatch
):

    events = capture_events(
        monkeypatch
    )

    claimed_data = (
        make_result().model_dump()
    )

    claimed_data[
        "status"
    ] = "PROCESSING"

    claimed_result = (
        WorkflowResult.model_validate(
            claimed_data
        )
    )

    claim_calls = []

    def fake_claim(
        workflow_id
    ):

        claim_calls.append(
            workflow_id
        )

        return claimed_result

    monkeypatch.setattr(
        execution,
        "claim_workflow_for_execution",
        fake_claim
    )

    def fake_ticket_creation(
        ticket,
        approval
    ):

        return {
            "ticket_id":
                "VM-TEST0001",

            "approval_id":
                approval["approval_id"],

            "approved_by":
                approval["approved_by"],

            "approved_at":
                approval["approved_at"],

            "status":
                "OPEN",

            "priority":
                ticket.priority,

            "risk_rating":
                ticket.risk_rating
        }

    monkeypatch.setattr(
        execution,
        "create_mock_ticket",
        fake_ticket_creation
    )

    result = (
        execution
        .claim_and_execute_workflow(
            workflow_id="WF-TEST0001",

            approved_by=
                "api-approver"
        )
    )

    assert (
        claim_calls
        == ["WF-TEST0001"]
    )

    assert (
        result.status
        == "TICKET_CREATED"
    )

    assert (
        result.ticket_id
        == "VM-TEST0001"
    )

    assert (
        result.approval_id
        is not None
    )

    event_types = [
        event["event_type"]
        for event in events
    ]

    assert (
        "WORKFLOW_EXECUTION_CLAIMED"
        in event_types
    )

    assert (
        "TICKET_APPROVED"
        in event_types
    )

    assert (
        "MOCK_TICKET_CREATED"
        in event_types
    )


def test_failed_atomic_claim_prevents_ticket_execution(
    monkeypatch
):

    events = capture_events(
        monkeypatch
    )

    ticket_creation_called = False

    def blocked_claim(
        workflow_id
    ):

        raise PermissionError(
            "Workflow execution has already "
            "been claimed."
        )

    monkeypatch.setattr(
        execution,
        "claim_workflow_for_execution",
        blocked_claim
    )

    def fake_ticket_creation(
        ticket,
        approval
    ):

        nonlocal ticket_creation_called

        ticket_creation_called = True

    monkeypatch.setattr(
        execution,
        "create_mock_ticket",
        fake_ticket_creation
    )

    with pytest.raises(
        PermissionError
    ):

        execution.claim_and_execute_workflow(
            workflow_id="WF-TEST0001",

            approved_by=
                "api-approver"
        )

    assert (
        ticket_creation_called
        is False
    )

    event_types = [
        event["event_type"]
        for event in events
    ]

    assert (
        "WORKFLOW_EXECUTION_CLAIM_BLOCKED"
        in event_types
    )

    assert (
        "TICKET_APPROVED"
        not in event_types
    )

    assert (
        "MOCK_TICKET_CREATED"
        not in event_types
    )

# -------------------------------------------------
# EXECUTION RECOVERY
# -------------------------------------------------


def test_successful_atomic_execution_preserves_attempt_metadata(
    monkeypatch
):

    events = capture_events(
        monkeypatch
    )

    claimed_data = (
        make_result()
        .model_dump()
    )

    claimed_data.update(
        {
            "status":
                "PROCESSING",

            "execution_attempt_id":
                "EXEC-TEST0001",
        }
    )

    claimed_result = (
        WorkflowResult
        .model_validate(
            claimed_data
        )
    )

    monkeypatch.setattr(
        execution,
        "claim_workflow_for_execution",
        lambda workflow_id:
            claimed_result,
    )

    def fake_ticket_creation(
        ticket,
        approval
    ):

        return {
            "ticket_id":
                "VM-TEST0001",

            "approval_id":
                approval[
                    "approval_id"
                ],

            "approved_by":
                approval[
                    "approved_by"
                ],

            "approved_at":
                approval[
                    "approved_at"
                ],

            "status":
                "OPEN",

            "priority":
                ticket.priority,

            "risk_rating":
                ticket.risk_rating,
        }

    monkeypatch.setattr(
        execution,
        "create_mock_ticket",
        fake_ticket_creation,
    )

    result = (
        execution
        .claim_and_execute_workflow(
            workflow_id=
                "WF-TEST0001",

            approved_by=
                "api-approver",
        )
    )

    assert (
        result.status
        == "TICKET_CREATED"
    )

    assert (
        result.execution_attempt_id
        == "EXEC-TEST0001"
    )


def test_execution_failure_moves_workflow_to_needs_review(
    monkeypatch
):

    events = capture_events(
        monkeypatch
    )

    claimed_data = (
        make_result()
        .model_dump()
    )

    claimed_data.update(
        {
            "status":
                "PROCESSING",

            "execution_attempt_id":
                "EXEC-TEST0001",
        }
    )

    claimed_result = (
        WorkflowResult
        .model_validate(
            claimed_data
        )
    )

    monkeypatch.setattr(
        execution,
        "claim_workflow_for_execution",
        lambda workflow_id:
            claimed_result,
    )

    def failed_ticket_creation(
        ticket,
        approval
    ):

        raise RuntimeError(
            "Simulated ticket provider failure."
        )

    monkeypatch.setattr(
        execution,
        "create_mock_ticket",
        failed_ticket_creation,
    )

    review_calls = []

    def fake_mark_review(
        workflow_id,
        reason
    ):

        review_calls.append(
            (
                workflow_id,
                reason,
            )
        )

        updated_data = (
            claimed_result
            .model_dump()
        )

        updated_data.update(
            {
                "status":
                    "NEEDS_REVIEW",

                "recovery_reason":
                    reason,
            }
        )

        return (
            WorkflowResult
            .model_validate(
                updated_data
            )
        )

    monkeypatch.setattr(
        execution,
        "mark_workflow_needs_review",
        fake_mark_review,
    )

    with pytest.raises(
        RuntimeError
    ):

        execution \
            .claim_and_execute_workflow(
                workflow_id=
                    "WF-TEST0001",

                approved_by=
                    "api-approver",
            )

    assert (
        len(review_calls)
        == 1
    )

    assert (
        review_calls[0][0]
        == "WF-TEST0001"
    )

    event_types = [
        event["event_type"]
        for event in events
    ]

    assert (
        "WORKFLOW_EXECUTION_NEEDS_REVIEW"
        in event_types
    )


def test_stale_reconciliation_never_executes_ticket(
    monkeypatch
):

    ticket_creation_called = False

    review_data = (
        make_result()
        .model_dump()
    )

    review_data.update(
        {
            "status":
                "NEEDS_REVIEW",

            "execution_attempt_id":
                "EXEC-TEST0001",

            "recovery_reason":
                (
                    "Execution remained PROCESSING "
                    "too long."
                ),
        }
    )

    review_result = (
        WorkflowResult
        .model_validate(
            review_data
        )
    )

    monkeypatch.setattr(
        execution,
        "mark_stale_processing_for_review",
        lambda workflow_id,
        stale_after_seconds:
            review_result,
    )

    def fake_ticket_creation(
        ticket,
        approval
    ):

        nonlocal ticket_creation_called

        ticket_creation_called = True

    monkeypatch.setattr(
        execution,
        "create_mock_ticket",
        fake_ticket_creation,
    )

    result = (
        execution
        .reconcile_stale_workflow(
            workflow_id=
                "WF-TEST0001",

            stale_after_seconds=
                300,
        )
    )

    assert (
        result.status
        == "NEEDS_REVIEW"
    )

    assert (
        ticket_creation_called
        is False
    )