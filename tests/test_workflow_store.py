import importlib

import pytest

import app.workflow_store as workflow_store

from app.models import AIAnalysis
from app.models import RiskResult
from app.models import TicketDraft
from app.models import WorkflowResult
from app.models import WorkflowSecurity


# -------------------------------------------------
# TEST DATABASE
# -------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_database(
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

    yield database_path


# -------------------------------------------------
# TEST DATA
# -------------------------------------------------


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


# -------------------------------------------------
# SAVE + GET
# -------------------------------------------------


def test_save_and_get_workflow():

    original = make_result()

    workflow_store.save_workflow(
        original
    )

    retrieved = (
        workflow_store.get_workflow(
            "WF-TEST0001"
        )
    )

    assert retrieved == original


# -------------------------------------------------
# DATABASE FILE CREATED
# -------------------------------------------------


def test_database_file_is_created(
    isolated_database
):

    assert (
        isolated_database.exists()
        is False
    )

    workflow_store.save_workflow(
        make_result()
    )

    assert (
        isolated_database.exists()
        is True
    )


# -------------------------------------------------
# UNKNOWN WORKFLOW
# -------------------------------------------------


def test_unknown_workflow_is_rejected():

    with pytest.raises(
        KeyError
    ):

        workflow_store.get_workflow(
            "WF-DOESNOTEXIST"
        )


# -------------------------------------------------
# UPDATE
# -------------------------------------------------


def test_update_existing_workflow():

    workflow_store.save_workflow(
        make_result()
    )

    updated = make_result(
        status="REJECTED"
    )

    workflow_store.update_workflow(
        updated
    )

    retrieved = (
        workflow_store.get_workflow(
            "WF-TEST0001"
        )
    )

    assert (
        retrieved.status
        == "REJECTED"
    )


# -------------------------------------------------
# UPDATE UNKNOWN
# -------------------------------------------------


def test_update_unknown_workflow_is_rejected():

    with pytest.raises(
        KeyError
    ):

        workflow_store.update_workflow(
            make_result()
        )


# -------------------------------------------------
# AUTHORITATIVE TICKET PRESERVED
# -------------------------------------------------


def test_store_preserves_authoritative_ticket():

    original = make_result()

    workflow_store.save_workflow(
        original
    )

    retrieved = (
        workflow_store.get_workflow(
            original.workflow_id
        )
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


# -------------------------------------------------
# STATE SURVIVES MODULE RELOAD
# -------------------------------------------------


def test_workflow_survives_module_reload():

    original = make_result()

    workflow_store.save_workflow(
        original
    )

    reloaded_store = (
        importlib.reload(
            workflow_store
        )
    )

    retrieved = (
        reloaded_store.get_workflow(
            "WF-TEST0001"
        )
    )

    assert retrieved == original