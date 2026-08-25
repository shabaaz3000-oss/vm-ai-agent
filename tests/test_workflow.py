import json

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


def make_result(
    status="AWAITING_APPROVAL",
    approval_id=None,
    ticket_id=None,
    prompt_injection_detected=False,
    prompt_injection_matches=None
):

    if prompt_injection_matches is None:
        prompt_injection_matches = []

    return WorkflowResult(
        workflow_id="WF-TEST0001",

        status=status,

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

        ticket=make_ticket(),

        approval_id=approval_id,

        ticket_id=ticket_id
    )


def configure_cli(
    monkeypatch,
    approval_input=""
):

    prepared_result = make_result()

    monkeypatch.setattr(
        ai_demo,
        "prepare_workflow",
        lambda: prepared_result
    )

    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: approval_input
    )

    return prepared_result


# -------------------------------------------------
# REJECTION PATH
# -------------------------------------------------


def test_rejected_workflow_calls_rejection_service(
    monkeypatch,
    capsys
):

    prepared_result = configure_cli(
        monkeypatch,
        approval_input=""
    )

    calls = []

    def fake_reject_workflow(
        result
    ):

        calls.append(result)

        return make_result(
            status="REJECTED"
        )

    monkeypatch.setattr(
        ai_demo,
        "reject_workflow",
        fake_reject_workflow
    )

    ai_demo.run_workflow()

    output = capsys.readouterr().out

    assert len(calls) == 1

    assert (
        calls[0]
        is prepared_result
    )

    assert (
        "TICKET REJECTED"
        in output
    )

    assert (
        "Workflow Status: REJECTED"
        in output
    )

    assert (
        "No ticket was created."
        in output
    )


# -------------------------------------------------
# APPROVAL PATH
# -------------------------------------------------


def test_approved_workflow_calls_execution_service(
    monkeypatch,
    capsys
):

    prepared_result = configure_cli(
        monkeypatch,
        approval_input="APPROVE"
    )

    calls = []

    def fake_execute(
        result,
        approved_by
    ):

        calls.append(
            {
                "result": result,
                "approved_by": approved_by
            }
        )

        return make_result(
            status="TICKET_CREATED",
            approval_id="APR-TEST0001",
            ticket_id="VM-TEST0001"
        )

    monkeypatch.setattr(
        ai_demo,
        "approve_and_execute_workflow",
        fake_execute
    )

    ai_demo.run_workflow()

    output = capsys.readouterr().out

    assert len(calls) == 1

    assert (
        calls[0]["result"]
        is prepared_result
    )

    assert (
        calls[0]["approved_by"]
        == "demo-analyst"
    )

    assert (
        "MOCK TICKET CREATED"
        in output
    )

    assert (
        "VM-TEST0001"
        in output
    )

    assert (
        "APR-TEST0001"
        in output
    )

    assert (
        "TICKET_CREATED"
        in output
    )


# -------------------------------------------------
# PROMPT-INJECTION DISPLAY
# -------------------------------------------------


def test_prompt_injection_metadata_is_displayed_without_changing_risk(
    monkeypatch,
    capsys
):

    result = make_result(
        prompt_injection_detected=True,

        prompt_injection_matches=[
            "instruction_override",
            "risk_manipulation"
        ]
    )

    monkeypatch.setattr(
        ai_demo,
        "prepare_workflow",
        lambda: result
    )

    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: ""
    )

    monkeypatch.setattr(
        ai_demo,
        "reject_workflow",
        lambda result:
            make_result(
                status="REJECTED"
            )
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


def test_execution_service_permission_error_fails_closed(
    monkeypatch,
    capsys
):

    events = []

    configure_cli(
        monkeypatch,
        approval_input="APPROVE"
    )

    def blocked_execution(
        result,
        approved_by
    ):

        raise PermissionError(
            "Approval validation failed."
        )

    monkeypatch.setattr(
        ai_demo,
        "approve_and_execute_workflow",
        blocked_execution
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

    assert (
        "approval security control"
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
        == "PermissionError"
    )

    assert (
        failure_event["details"][
            "stage"
        ]
        == "ticket_execution_authorization"
    )