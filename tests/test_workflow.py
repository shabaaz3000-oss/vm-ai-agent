import json

import app.ticketing as ticketing
import ai_demo

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
            "Asset is internet exposed",
            "Business critical asset",
            "High EPSS",
            "Critical CVSS"
        ]
    )


def make_analysis():

    return AIAnalysis(
        executive_summary=(
            "Critical vulnerability requiring "
            "expedited remediation."
        ),

        rationale=[
            "The asset is internet exposed.",
            "The vulnerability is listed in KEV."
        ],

        remediation=(
            "Deploy the approved vendor patch "
            "within the authoritative SLA."
        ),

        compensating_controls=[
            "Maintain WAF protection.",
            "Increase EDR monitoring."
        ],

        validation_steps=[
            "Verify the fixed version.",
            "Run an authenticated rescan."
        ],

        confidence="HIGH",

        requires_human_review=True,

        ticket_summary=(
            "CRITICAL: Remediate CVE-2026-12345 "
            "on internet-web-01 within 24 hours"
        ),

        ticket_description=(
            "Validated vulnerability ticket draft."
        )
    )


def make_ticket():

    return TicketDraft(
        short_description=(
            "CRITICAL: Remediate CVE-2026-12345 "
            "on internet-web-01 within 24 hours"
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
            "Validated vulnerability ticket draft."
        ),

        remediation=(
            "Deploy the approved vendor patch "
            "within the authoritative SLA."
        ),

        validation_steps=[
            "Verify the fixed version.",
            "Run an authenticated rescan."
        ]
    )


def make_workflow_result(
    prompt_injection_detected=False,
    prompt_injection_matches=None
):

    if prompt_injection_matches is None:
        prompt_injection_matches = []

    return WorkflowResult(
        workflow_id="WF-TEST0001",

        status="AWAITING_APPROVAL",

        finding_id="FIND-0001",

        asset_name="internet-web-01",

        cve="CVE-2026-12345",

        risk=make_risk(),

        security=WorkflowSecurity(
            prompt_injection_detected=
                prompt_injection_detected,

            prompt_injection_matches=
                prompt_injection_matches,

            human_review_required=True
        ),

        analysis=make_analysis(),

        ticket=make_ticket()
    )


def configure_cli(
    monkeypatch,
    events,
    result,
    approval_input=""
):

    monkeypatch.setattr(
        ai_demo,
        "prepare_workflow",
        lambda: result
    )

    monkeypatch.setattr(
        ai_demo,
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

    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: approval_input
    )


# -------------------------------------------------
# REJECTION PATH
# -------------------------------------------------


def test_rejected_workflow_does_not_create_ticket(
    tmp_path,
    monkeypatch
):

    events = []

    result = make_workflow_result()

    configure_cli(
        monkeypatch=monkeypatch,
        events=events,
        result=result,
        approval_input=""
    )

    temporary_ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        temporary_ticket_file
    )

    ai_demo.run_workflow()

    event_types = [
        event["event_type"]
        for event in events
    ]

    assert (
        "TICKET_REJECTED"
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

    assert (
        temporary_ticket_file.exists()
        is False
    )


# -------------------------------------------------
# APPROVED PATH
# -------------------------------------------------


def test_approved_workflow_creates_ticket_with_matching_approval(
    tmp_path,
    monkeypatch
):

    events = []

    result = make_workflow_result()

    configure_cli(
        monkeypatch=monkeypatch,
        events=events,
        result=result,
        approval_input="APPROVE"
    )

    temporary_ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        temporary_ticket_file
    )

    ai_demo.run_workflow()

    assert temporary_ticket_file.exists()

    lines = (
        temporary_ticket_file
        .read_text(
            encoding="utf-8"
        )
        .splitlines()
    )

    assert len(lines) == 1

    ticket_record = json.loads(
        lines[0]
    )

    approved_event = next(
        event
        for event in events
        if event["event_type"]
        == "TICKET_APPROVED"
    )

    created_event = next(
        event
        for event in events
        if event["event_type"]
        == "MOCK_TICKET_CREATED"
    )

    approval_id = (
        approved_event["details"][
            "approval_id"
        ]
    )

    assert (
        approved_event["details"][
            "workflow_id"
        ]
        == "WF-TEST0001"
    )

    assert (
        created_event["details"][
            "workflow_id"
        ]
        == "WF-TEST0001"
    )

    assert (
        ticket_record["approval_id"]
        == approval_id
    )

    assert (
        created_event["details"][
            "approval_id"
        ]
        == approval_id
    )

    assert (
        ticket_record["approved_by"]
        == "demo-analyst"
    )

    assert (
        ticket_record["priority"]
        == "P1"
    )

    assert (
        ticket_record["risk_rating"]
        == "CRITICAL"
    )

    assert (
        ticket_record["risk_score"]
        == 100
    )

    assert (
        ticket_record["sla_hours"]
        == 24
    )


# -------------------------------------------------
# SECURITY METADATA DISPLAY
# -------------------------------------------------


def test_prompt_injection_metadata_is_displayed_without_changing_risk(
    tmp_path,
    monkeypatch,
    capsys
):

    events = []

    result = make_workflow_result(
        prompt_injection_detected=True,

        prompt_injection_matches=[
            "instruction_override",
            "risk_manipulation"
        ]
    )

    configure_cli(
        monkeypatch=monkeypatch,
        events=events,
        result=result,
        approval_input=""
    )

    temporary_ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        temporary_ticket_file
    )

    ai_demo.run_workflow()

    output = capsys.readouterr().out

    assert (
        "SECURITY WARNING"
        in output
    )

    assert (
        "instruction_override"
        in output
    )

    assert (
        "risk_manipulation"
        in output
    )

    assert (
        "Risk Rating: CRITICAL"
        in output
    )

    assert (
        "Risk Score: 100"
        in output
    )

    assert (
        result.risk.rating
        == "CRITICAL"
    )

    assert (
        result.risk.score
        == 100
    )

    assert (
        temporary_ticket_file.exists()
        is False
    )


# -------------------------------------------------
# MALFORMED INPUT FAILS SAFELY
# -------------------------------------------------


def test_invalid_json_fails_workflow_safely(
    monkeypatch,
    capsys
):

    events = []

    malformed_json_error = (
        json.JSONDecodeError(
            "Invalid JSON",
            "{bad",
            1
        )
    )

    def raise_invalid_json():

        raise malformed_json_error

    monkeypatch.setattr(
        ai_demo,
        "prepare_workflow",
        raise_invalid_json
    )

    monkeypatch.setattr(
        ai_demo,
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

    ai_demo.main()

    output = capsys.readouterr().out

    assert (
        "WORKFLOW FAILED"
        in output
    )

    failure_event = next(
        event
        for event in events
        if event["event_type"]
        == "WORKFLOW_FAILED"
    )

    assert (
        failure_event["details"][
            "error_type"
        ]
        == "JSONDecodeError"
    )

    assert (
        failure_event["details"][
            "stage"
        ]
        == "input_loading"
    )


# -------------------------------------------------
# EXECUTION AUTHORIZATION FAILURE FAILS CLOSED
# -------------------------------------------------


def test_ticket_authorization_failure_fails_closed(
    monkeypatch,
    capsys
):

    events = []

    result = make_workflow_result()

    configure_cli(
        monkeypatch=monkeypatch,
        events=events,
        result=result,
        approval_input="APPROVE"
    )

    def blocked_ticket_creation(
        ticket,
        approval
    ):

        raise PermissionError(
            "Approval validation failed."
        )

    monkeypatch.setattr(
        ai_demo,
        "create_mock_ticket",
        blocked_ticket_creation
    )

    ai_demo.main()

    output = capsys.readouterr().out

    assert (
        "WORKFLOW FAILED"
        in output
    )

    assert (
        "approval security control"
        in output
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
        not in event_types
    )

    failure_event = next(
        event
        for event in events
        if event["event_type"]
        == "WORKFLOW_FAILED"
    )

    assert (
        failure_event["details"][
            "error_type"
        ]
        == "PermissionError"
    )

    assert (
        failure_event["details"][
            "stage"
        ]
        == "ticket_execution_authorization"
    )