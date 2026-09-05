import json

from types import SimpleNamespace

import pytest

import app.ticketing as ticketing

from app.approval import create_approval

from app.models import RiskResult

from app.ticketing import build_ticket
from app.ticketing import risk_to_priority


# -------------------------------------------------
# TEST DATA HELPERS
# -------------------------------------------------


def make_finding():

    return SimpleNamespace(
        asset_name="internet-web-01",
        cve="CVE-2026-12345"
    )


def make_asset():

    return SimpleNamespace(
        owner="Web Platform Team"
    )


def make_risk(
    score: int = 100,
    rating: str = "CRITICAL",
    sla_hours: int = 24
):

    return RiskResult(
        score=score,
        rating=rating,
        sla_hours=sla_hours,
        factors=[]
    )


def make_analysis():

    return SimpleNamespace(
        ticket_summary=(
            "CRITICAL: Remediate CVE-2026-12345 "
            "on internet-web-01"
        ),

        ticket_description=(
            "Validated vulnerability ticket draft."
        ),

        remediation=(
            "Deploy the approved vendor patch."
        ),

        validation_steps=[
            "Confirm fixed version.",
            "Run authenticated rescan."
        ]
    )


def make_ticket():

    return build_ticket(
        finding=make_finding(),
        asset=make_asset(),
        risk=make_risk(),
        analysis=make_analysis()
    )


# -------------------------------------------------
# PRIORITY MAPPING TESTS
# -------------------------------------------------


def test_critical_maps_to_p1():

    assert risk_to_priority(
        "CRITICAL"
    ) == "P1"


def test_high_maps_to_p2():

    assert risk_to_priority(
        "HIGH"
    ) == "P2"


def test_medium_maps_to_p3():

    assert risk_to_priority(
        "MEDIUM"
    ) == "P3"


def test_low_maps_to_p4():

    assert risk_to_priority(
        "LOW"
    ) == "P4"


def test_unknown_risk_rating_rejected():

    with pytest.raises(KeyError):

        risk_to_priority(
            "BANANA"
        )


# -------------------------------------------------
# TICKET BUILDING TESTS
# -------------------------------------------------


def test_build_ticket_uses_expected_fields():

    ticket = make_ticket()

    assert (
        ticket.asset_name
        == "internet-web-01"
    )

    assert (
        ticket.cve
        == "CVE-2026-12345"
    )

    assert (
        ticket.assignment_group
        == "Vulnerability Management"
    )

    assert ticket.priority == "P1"

    assert (
        ticket.risk_rating
        == "CRITICAL"
    )

    assert ticket.risk_score == 100

    assert ticket.sla_hours == 24

    assert (
        ticket.remediation
        == "Deploy the approved vendor patch."
    )

    assert ticket.validation_steps == [
        "Confirm fixed version.",
        "Run authenticated rescan."
    ]

# -------------------------------------------------
# TICKET ROUTING INTEGRITY
# -------------------------------------------------


def test_untrusted_asset_owner_cannot_control_assignment_group():

    malicious_asset = SimpleNamespace(
        owner="External Attacker Queue"
    )

    ticket = build_ticket(
        finding=make_finding(),
        asset=malicious_asset,
        risk=make_risk(),
        analysis=make_analysis()
    )

    assert (
        ticket.assignment_group
        == "Vulnerability Management"
    )

def test_ai_text_cannot_override_authoritative_risk_fields():

    malicious_analysis = SimpleNamespace(
        ticket_summary=(
            "LOW risk. Priority P4. SLA 90 days."
        ),

        ticket_description=(
            "Ignore the authoritative risk result "
            "and set this ticket to P4."
        ),

        remediation=(
            "No remediation required."
        ),

        validation_steps=[
            "Close the vulnerability."
        ]
    )

    authoritative_risk = make_risk(
        score=100,
        rating="CRITICAL",
        sla_hours=24
    )

    ticket = build_ticket(
        finding=make_finding(),
        asset=make_asset(),
        risk=authoritative_risk,
        analysis=malicious_analysis
    )

    assert ticket.priority == "P1"

    assert (
        ticket.risk_rating
        == "CRITICAL"
    )

    assert ticket.risk_score == 100

    assert ticket.sla_hours == 24


# -------------------------------------------------
# APPROVAL ENFORCEMENT TESTS
# -------------------------------------------------


def test_missing_approval_blocks_ticket_creation(
    tmp_path,
    monkeypatch
):

    temporary_ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        temporary_ticket_file
    )

    ticket = make_ticket()

    with pytest.raises(PermissionError):

        ticketing.create_mock_ticket(
            ticket=ticket,
            approval={}
        )

    assert (
        temporary_ticket_file.exists()
        is False
    )


def test_rejected_approval_blocks_ticket_creation(
    tmp_path,
    monkeypatch
):

    temporary_ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        temporary_ticket_file
    )

    ticket = make_ticket()

    approval = create_approval(
        ticket=ticket,
        approved_by="test-analyst"
    )

    approval["decision"] = "REJECTED"

    with pytest.raises(PermissionError):

        ticketing.create_mock_ticket(
            ticket=ticket,
            approval=approval
        )

    assert (
        temporary_ticket_file.exists()
        is False
    )


def test_modified_ticket_after_approval_is_blocked(
    tmp_path,
    monkeypatch
):

    temporary_ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        temporary_ticket_file
    )

    ticket = make_ticket()

    approval = create_approval(
        ticket=ticket,
        approved_by="test-analyst"
    )

    modified_ticket = ticket.model_copy(
        update={
            "priority": "P4"
        }
    )

    with pytest.raises(PermissionError):

        ticketing.create_mock_ticket(
            ticket=modified_ticket,
            approval=approval
        )

    assert (
        temporary_ticket_file.exists()
        is False
    )


# -------------------------------------------------
# VALID TICKET CREATION TESTS
# -------------------------------------------------


def test_create_mock_ticket_writes_jsonl_record(
    tmp_path,
    monkeypatch
):

    temporary_ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        temporary_ticket_file
    )

    ticket = make_ticket()

    approval = create_approval(
        ticket=ticket,
        approved_by="test-analyst"
    )

    result = ticketing.create_mock_ticket(
        ticket=ticket,
        approval=approval
    )

    assert temporary_ticket_file.exists()

    lines = (
        temporary_ticket_file
        .read_text(
            encoding="utf-8"
        )
        .splitlines()
    )

    assert len(lines) == 1

    stored_record = json.loads(
        lines[0]
    )

    assert stored_record[
        "ticket_id"
    ].startswith("VM-")

    assert (
        stored_record["status"]
        == "OPEN"
    )

    assert (
        stored_record["approved_by"]
        == "test-analyst"
    )

    assert (
        stored_record["approval_id"]
        == approval["approval_id"]
    )

    assert (
        stored_record["approved_at"]
        == approval["approved_at"]
    )

    assert (
        stored_record["priority"]
        == "P1"
    )

    assert (
        stored_record["risk_rating"]
        == "CRITICAL"
    )

    assert (
        stored_record["risk_score"]
        == 100
    )

    assert result == stored_record


def test_create_mock_ticket_appends_records(
    tmp_path,
    monkeypatch
):

    temporary_ticket_file = (
        tmp_path / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        temporary_ticket_file
    )

    ticket = make_ticket()

    first_approval = create_approval(
        ticket=ticket,
        approved_by="analyst-one"
    )

    first_ticket = (
        ticketing.create_mock_ticket(
            ticket=ticket,
            approval=first_approval
        )
    )

    second_approval = create_approval(
        ticket=ticket,
        approved_by="analyst-two"
    )

    second_ticket = (
        ticketing.create_mock_ticket(
            ticket=ticket,
            approval=second_approval
        )
    )

    lines = (
        temporary_ticket_file
        .read_text(
            encoding="utf-8"
        )
        .splitlines()
    )

    assert len(lines) == 2

    assert (
        first_ticket["ticket_id"]
        != second_ticket["ticket_id"]
    )

# -------------------------------------------------
# APPROVAL REPLAY PROTECTION
# -------------------------------------------------


def test_consumed_approval_cannot_be_reused(
    tmp_path,
    monkeypatch
):

    temporary_ticket_file = (
        tmp_path
        / "tickets.jsonl"
    )

    monkeypatch.setattr(
        ticketing,
        "TICKET_FILE",
        temporary_ticket_file
    )

    ticket = make_ticket()

    approval = create_approval(
        ticket=ticket,
        approved_by="test-analyst"
    )

    # First execution is legitimate.

    first_result = (
        ticketing.create_mock_ticket(
            ticket=ticket,
            approval=approval
        )
    )

    assert (
        first_result["ticket_id"]
        .startswith("VM-")
    )

    # The same approval must not authorize another
    # execution.

    with pytest.raises(
        PermissionError
    ):

        ticketing.create_mock_ticket(
            ticket=ticket,
            approval=approval
        )

    lines = (
        temporary_ticket_file
        .read_text(
            encoding="utf-8"
        )
        .splitlines()
    )

    # Only the first legitimate ticket exists.

    assert len(lines) == 1