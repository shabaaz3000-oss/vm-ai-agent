import pytest

from types import SimpleNamespace

from app.approval import (
    calculate_ticket_fingerprint,
    create_approval,
    validate_approval
)

from app.models import RiskResult

from app.ticketing import build_ticket


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


def make_risk():

    return RiskResult(
        score=100,
        rating="CRITICAL",
        sla_hours=24,
        factors=[]
    )


def make_analysis():

    return SimpleNamespace(
        ticket_summary=(
            "CRITICAL: Remediate "
            "CVE-2026-12345"
        ),

        ticket_description=(
            "Validated vulnerability "
            "ticket draft."
        ),

        remediation=(
            "Deploy approved vendor patch."
        ),

        validation_steps=[
            "Verify fixed version.",
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
# FINGERPRINT TESTS
# -------------------------------------------------


def test_same_ticket_produces_same_fingerprint():

    ticket = make_ticket()

    fingerprint_one = (
        calculate_ticket_fingerprint(
            ticket
        )
    )

    fingerprint_two = (
        calculate_ticket_fingerprint(
            ticket
        )
    )

    assert (
        fingerprint_one
        == fingerprint_two
    )


def test_modified_ticket_changes_fingerprint():

    ticket = make_ticket()

    original_fingerprint = (
        calculate_ticket_fingerprint(
            ticket
        )
    )

    modified_ticket = ticket.model_copy(
        update={
            "priority": "P4"
        }
    )

    modified_fingerprint = (
        calculate_ticket_fingerprint(
            modified_ticket
        )
    )

    assert (
        original_fingerprint
        != modified_fingerprint
    )


# -------------------------------------------------
# APPROVAL CREATION TESTS
# -------------------------------------------------


def test_valid_approval_created():

    ticket = make_ticket()

    approval = create_approval(
        ticket=ticket,
        approved_by="test-analyst"
    )

    assert (
        approval["decision"]
        == "APPROVED"
    )

    assert (
        approval["approved_by"]
        == "test-analyst"
    )

    assert approval[
        "approval_id"
    ].startswith("APR-")

    assert (
        approval["ticket_fingerprint"]
        == calculate_ticket_fingerprint(
            ticket
        )
    )


def test_blank_approver_rejected():

    ticket = make_ticket()

    with pytest.raises(ValueError):

        create_approval(
            ticket=ticket,
            approved_by=""
        )


def test_whitespace_only_approver_rejected():

    ticket = make_ticket()

    with pytest.raises(ValueError):

        create_approval(
            ticket=ticket,
            approved_by="   "
        )


# -------------------------------------------------
# APPROVAL VALIDATION TESTS
# -------------------------------------------------


def test_valid_approval_is_accepted():

    ticket = make_ticket()

    approval = create_approval(
        ticket=ticket,
        approved_by="test-analyst"
    )

    assert validate_approval(
        ticket=ticket,
        approval=approval
    ) is True


def test_rejected_decision_is_not_valid():

    ticket = make_ticket()

    approval = create_approval(
        ticket=ticket,
        approved_by="test-analyst"
    )

    approval["decision"] = "REJECTED"

    assert validate_approval(
        ticket=ticket,
        approval=approval
    ) is False


def test_approval_for_modified_ticket_is_rejected():

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

    assert validate_approval(
        ticket=modified_ticket,
        approval=approval
    ) is False


def test_missing_fingerprint_is_rejected():

    ticket = make_ticket()

    approval = create_approval(
        ticket=ticket,
        approved_by="test-analyst"
    )

    del approval[
        "ticket_fingerprint"
    ]

    assert validate_approval(
        ticket=ticket,
        approval=approval
    ) is False


def test_fake_approval_dictionary_is_rejected():

    ticket = make_ticket()

    fake_approval = {
        "decision": "APPROVED",
        "approved_by": "attacker",
        "ticket_fingerprint": "fake"
    }

    assert validate_approval(
        ticket=ticket,
        approval=fake_approval
    ) is False

# -------------------------------------------------
# FORGED APPROVAL REGRESSION TEST
# -------------------------------------------------


def test_forged_approval_with_correct_fingerprint_is_rejected():

    ticket = make_ticket()

    forged_approval = {
        "approval_id":
            "APR-FORGED",

        "decision":
            "APPROVED",

        "approved_by":
            "attacker",

        "approved_at":
            "2026-01-01T00:00:00+00:00",

        "ticket_fingerprint":
            calculate_ticket_fingerprint(
                ticket
            )
    }

    assert validate_approval(
        ticket=ticket,
        approval=forged_approval
    ) is False