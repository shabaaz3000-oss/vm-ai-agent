import os

from app import execution

from app.workflow_authority_security_evaluator import (
    run_workflow_authority_security_evaluation,
)


EXPECTED_CASE_IDS = {
    "insert_only_creation_blocks_overwrite",
    "generic_mutation_authority_absent",
    "tenant_bound_claim_requires_trusted_context",
    "stale_completion_attempt_rejected",
    "cross_tenant_reconciliation_rejected",
    "ambiguous_completion_requires_review",
    "trusted_reconciliation_confirms_ticket",
    "authorized_retry_rotates_attempt",
    "stale_review_attempt_rejected",
    "cross_tenant_review_rejected",
}


def test_workflow_authority_security_evaluation_passes():

    result = (
        run_workflow_authority_security_evaluation()
    )

    assert result.total_cases == 10

    assert (
        result.authority_protection_cases
        == 7
    )

    assert result.transition_cases == 3

    assert result.passed_cases == 10
    assert result.failed_cases == 0

    assert result.authority_failures == 0
    assert result.execution_errors == 0

    assert result.passed is True


def test_workflow_authority_security_case_inventory_is_stable():

    result = (
        run_workflow_authority_security_evaluation()
    )

    assert {
        case.case_id
        for case in result.cases
    } == EXPECTED_CASE_IDS

    assert all(
        case.observed_achieved
        for case in result.cases
    )

    assert all(
        case.execution_error is None
        for case in result.cases
    )


def test_workflow_authority_evaluator_restores_database_environment(
    monkeypatch,
):

    sentinel = (
        "sentinel-workflow-authority.db"
    )

    monkeypatch.setenv(
        "VM_AI_DB_PATH",
        sentinel,
    )

    result = (
        run_workflow_authority_security_evaluation()
    )

    assert result.passed is True

    assert (
        os.environ[
            "VM_AI_DB_PATH"
        ]
        == sentinel
    )


def test_workflow_authority_evaluator_never_reaches_ticket_provider(
    monkeypatch,
):

    provider_called = False

    def fail_provider(
        *args,
        **kwargs,
    ):

        nonlocal provider_called

        provider_called = True

        raise AssertionError(
            "Security evaluation must not "
            "reach an external ticket provider."
        )

    monkeypatch.setattr(
        execution,
        "_create_ticket_with_selected_provider",
        fail_provider,
    )

    result = (
        run_workflow_authority_security_evaluation()
    )

    assert result.passed is True

    assert provider_called is False
