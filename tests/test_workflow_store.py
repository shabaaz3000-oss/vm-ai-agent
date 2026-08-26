from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import importlib

import pytest

import app.workflow_store as workflow_store

from app.models import AIAnalysis
from app.models import RiskResult
from app.models import TicketDraft
from app.models import WorkflowResult
from app.models import WorkflowSecurity


# -------------------------------------------------
# ISOLATED SQLITE DATABASE
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
# PERSISTENCE THROUGH MODULE RELOAD
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


# -------------------------------------------------
# ATOMIC EXECUTION CLAIM
# -------------------------------------------------


def test_awaiting_workflow_can_be_claimed():

    workflow_store.save_workflow(
        make_result()
    )

    claimed = (
        workflow_store
        .claim_workflow_for_execution(
            "WF-TEST0001"
        )
    )

    assert (
        claimed.status
        == "PROCESSING"
    )

    stored = (
        workflow_store.get_workflow(
            "WF-TEST0001"
        )
    )

    assert (
        stored.status
        == "PROCESSING"
    )


# -------------------------------------------------
# SECOND CLAIM IS BLOCKED
# -------------------------------------------------


def test_second_execution_claim_is_rejected():

    workflow_store.save_workflow(
        make_result()
    )

    workflow_store.claim_workflow_for_execution(
        "WF-TEST0001"
    )

    with pytest.raises(
        PermissionError
    ):

        workflow_store.claim_workflow_for_execution(
            "WF-TEST0001"
        )

    stored = (
        workflow_store.get_workflow(
            "WF-TEST0001"
        )
    )

    assert (
        stored.status
        == "PROCESSING"
    )


# -------------------------------------------------
# UNKNOWN WORKFLOW CANNOT BE CLAIMED
# -------------------------------------------------


def test_unknown_workflow_cannot_be_claimed():

    with pytest.raises(
        KeyError
    ):

        workflow_store.claim_workflow_for_execution(
            "WF-DOESNOTEXIST"
        )


# -------------------------------------------------
# CONCURRENT CLAIM
# -------------------------------------------------


def test_concurrent_execution_claim_allows_one_winner():

    workflow_store.save_workflow(
        make_result()
    )

    def attempt_claim():

        try:

            result = (
                workflow_store
                .claim_workflow_for_execution(
                    "WF-TEST0001"
                )
            )

            return (
                "CLAIMED",
                result.status
            )

        except PermissionError:

            return (
                "BLOCKED",
                None
            )

    with ThreadPoolExecutor(
        max_workers=2
    ) as executor:

        results = list(
            executor.map(
                lambda _: attempt_claim(),
                range(2)
            )
        )

    outcomes = [
        result[0]
        for result in results
    ]

    assert (
        outcomes.count("CLAIMED")
        == 1
    )

    assert (
        outcomes.count("BLOCKED")
        == 1
    )

    stored = (
        workflow_store.get_workflow(
            "WF-TEST0001"
        )
    )

    assert (
        stored.status
        == "PROCESSING"
    )

# -------------------------------------------------
# EXECUTION RECOVERY METADATA
# -------------------------------------------------


def test_execution_claim_records_recovery_metadata():

    workflow_store.save_workflow(
        make_result()
    )

    claimed = (
        workflow_store
        .claim_workflow_for_execution(
            "WF-TEST0001"
        )
    )

    assert (
        claimed.status
        == "PROCESSING"
    )

    assert (
        claimed.execution_attempt_id
        is not None
    )

    assert (
        claimed.execution_attempt_id
        .startswith("EXEC-")
    )

    assert (
        claimed.processing_started_at
        is not None
    )

    assert (
        claimed.recovery_reason
        is None
    )


def test_processing_workflow_can_be_marked_needs_review():

    workflow_store.save_workflow(
        make_result()
    )

    claimed = (
        workflow_store
        .claim_workflow_for_execution(
            "WF-TEST0001"
        )
    )

    reviewed = (
        workflow_store
        .mark_workflow_needs_review(
            workflow_id=
                "WF-TEST0001",

            reason=
                "Execution result is uncertain."
        )
    )

    assert (
        reviewed.status
        == "NEEDS_REVIEW"
    )

    assert (
        reviewed.execution_attempt_id
        == claimed.execution_attempt_id
    )

    assert (
        reviewed.processing_started_at
        == claimed.processing_started_at
    )

    assert (
        reviewed.recovery_reason
        == "Execution result is uncertain."
    )


def test_fresh_processing_workflow_is_not_marked_stale():

    workflow_store.save_workflow(
        make_result()
    )

    claimed = (
        workflow_store
        .claim_workflow_for_execution(
            "WF-TEST0001"
        )
    )

    now = (
        claimed.processing_started_at
        + timedelta(
            seconds=60
        )
    )

    with pytest.raises(
        PermissionError
    ):

        workflow_store \
            .mark_stale_processing_for_review(
                workflow_id=
                    "WF-TEST0001",

                stale_after_seconds=
                    300,

                now=
                    now,
            )

    stored = (
        workflow_store.get_workflow(
            "WF-TEST0001"
        )
    )

    assert (
        stored.status
        == "PROCESSING"
    )


def test_stale_processing_moves_to_needs_review():

    workflow_store.save_workflow(
        make_result()
    )

    claimed = (
        workflow_store
        .claim_workflow_for_execution(
            "WF-TEST0001"
        )
    )

    now = (
        claimed.processing_started_at
        + timedelta(
            seconds=301
        )
    )

    reviewed = (
        workflow_store
        .mark_stale_processing_for_review(
            workflow_id=
                "WF-TEST0001",

            stale_after_seconds=
                300,

            now=
                now,
        )
    )

    assert (
        reviewed.status
        == "NEEDS_REVIEW"
    )

    assert (
        reviewed.execution_attempt_id
        == claimed.execution_attempt_id
    )

    assert (
        reviewed.recovery_reason
        is not None
    )

    assert (
        "reconciled"
        in reviewed
        .recovery_reason
        .lower()
    )