from __future__ import annotations

import inspect

import pytest

import app.servicenow_reconciliation as reconciliation
import app.workflow_store as workflow_store

from app.models import (
    AIAnalysis,
    RiskResult,
    TicketDraft,
    WorkflowResult,
    WorkflowSecurity,
)

from app.security_context import SecurityContext

from app.servicenow_reconciliation import (
    ServiceNowReconciliationError,
    ServiceNowReconciliationResult,
)


WORKFLOW_ID = "WF-RESOLVE0001"
OLD_ATTEMPT = "EXEC-OLD00001"
NEW_ATTEMPT = "EXEC-NEW00001"
TICKET_ID = "INC0012345"

SYS_ID = (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

CORRELATION_ID = (
    "VMAI-"
    + (
        "b"
        * 64
    )
)


@pytest.fixture(autouse=True)
def isolated_database(
    tmp_path,
    monkeypatch,
):

    monkeypatch.setenv(
        "VM_AI_DB_PATH",
        str(
            tmp_path
            / "resolution.db"
        ),
    )


def context(
    *,
    tenant_id="tenant-alpha",
    role="APPROVER",
):

    return SecurityContext(
        principal_id=
            "approver-alpha",

        role=
            role,

        retrieval_access=
            "standard",

        tenant_id=
            tenant_id,

        session_id=
            (
                "session-"
                + tenant_id
                + "-"
                + role.lower()
            ),
    )


def workflow(
    *,
    status="NEEDS_REVIEW",
    tenant_id="tenant-alpha",
    execution_attempt_id=OLD_ATTEMPT,
):

    return WorkflowResult(
        workflow_id=
            WORKFLOW_ID,

        tenant_id=
            tenant_id,

        status=
            status,

        finding_id=
            "FIND-0001",

        asset_name=
            "internet-web-01",

        cve=
            "CVE-2026-12345",

        risk=
            RiskResult(
                score=100,
                rating="CRITICAL",
                sla_hours=24,
                factors=[
                    "Listed in CISA KEV",
                ],
            ),

        security=
            WorkflowSecurity(
                prompt_injection_detected=
                    False,

                human_review_required=
                    True,
            ),

        analysis=
            AIAnalysis(
                executive_summary=
                    "Critical vulnerability.",

                rationale=[
                    "Critical risk.",
                ],

                remediation=
                    "Deploy approved patch.",

                compensating_controls=[
                    "Maintain WAF.",
                ],

                validation_steps=[
                    "Run authenticated rescan.",
                ],

                confidence=
                    "HIGH",

                requires_human_review=
                    True,

                ticket_summary=
                    "Remediate vulnerability.",

                ticket_description=
                    "Validated ticket draft.",
            ),

        ticket=
            TicketDraft(
                short_description=
                    "CRITICAL vulnerability",

                priority="P1",

                asset_name=
                    "internet-web-01",

                cve=
                    "CVE-2026-12345",

                assignment_group=
                    "Vulnerability Management",

                risk_rating=
                    "CRITICAL",

                risk_score=100,

                sla_hours=24,

                description=
                    "Validated ticket.",

                remediation=
                    "Deploy approved patch.",

                validation_steps=[
                    "Run authenticated rescan.",
                ],
            ),

        execution_attempt_id=
            execution_attempt_id,

        recovery_reason=
            (
                "Execution failed after claim. "
                "External action requires reconciliation."
            ),
    )


def save_target(
    **kwargs,
):

    candidate = workflow(
        **kwargs
    )

    workflow_store.save_workflow(
        candidate
    )

    return candidate


def evidence(
    *,
    outcome,
    attempt=OLD_ATTEMPT,
    match_count=None,
    ticket_number=None,
    external_sys_id=None,
):

    if match_count is None:

        match_count = {
            "NOT_FOUND": 0,
            "CONFIRMED": 1,
            "CONFLICT": 2,
        }[
            outcome
        ]

    return ServiceNowReconciliationResult(
        workflow_id=
            WORKFLOW_ID,

        execution_attempt_id=
            attempt,

        outcome=
            outcome,

        correlation_id=
            CORRELATION_ID,

        match_count=
            match_count,

        ticket_number=
            ticket_number,

        external_sys_id=
            external_sys_id,
    )


def test_confirmed_resolution_persists_observed_ticket(
    monkeypatch,
):

    save_target()

    monkeypatch.setattr(
        reconciliation,
        "reconcile_servicenow_workflow",
        lambda *args, **kwargs:
            evidence(
                outcome=
                    "CONFIRMED",

                ticket_number=
                    TICKET_ID,

                external_sys_id=
                    SYS_ID,
            ),
    )

    result = (
        reconciliation
        .resolve_servicenow_workflow(
            WORKFLOW_ID,
            security_context=
                context(),
        )
    )

    assert result.status == "TICKET_CREATED"
    assert result.ticket_id == TICKET_ID

    assert (
        result.execution_attempt_id
        == OLD_ATTEMPT
    )

    assert (
        workflow_store
        .get_workflow(
            WORKFLOW_ID
        )
        == result
    )


def test_cross_tenant_store_resolution_fails_closed(
    monkeypatch,
):

    save_target()

    monkeypatch.setattr(
        reconciliation,
        "reconcile_servicenow_workflow",
        lambda *args, **kwargs:
            evidence(
                outcome=
                    "CONFIRMED",

                ticket_number=
                    TICKET_ID,

                external_sys_id=
                    SYS_ID,
            ),
    )

    with pytest.raises(
        PermissionError
    ):

        reconciliation \
            .resolve_servicenow_workflow(
                WORKFLOW_ID,
                security_context=
                    context(
                        tenant_id=
                            "tenant-bravo",
                    ),
            )

    stored = (
        workflow_store
        .get_workflow(
            WORKFLOW_ID
        )
    )

    assert stored.status == "NEEDS_REVIEW"
    assert stored.ticket_id is None


def test_stale_attempt_evidence_cannot_mutate(
    monkeypatch,
):

    save_target(
        execution_attempt_id=
            NEW_ATTEMPT,
    )

    monkeypatch.setattr(
        reconciliation,
        "reconcile_servicenow_workflow",
        lambda *args, **kwargs:
            evidence(
                outcome=
                    "CONFIRMED",

                attempt=
                    OLD_ATTEMPT,

                ticket_number=
                    TICKET_ID,

                external_sys_id=
                    SYS_ID,
            ),
    )

    with pytest.raises(
        PermissionError,
        match="attempt changed",
    ):

        reconciliation \
            .resolve_servicenow_workflow(
                WORKFLOW_ID,
                security_context=
                    context(),
            )

    stored = (
        workflow_store
        .get_workflow(
            WORKFLOW_ID
        )
    )

    assert stored.status == "NEEDS_REVIEW"

    assert (
        stored.execution_attempt_id
        == NEW_ATTEMPT
    )


def test_not_found_authorizes_retry_preserving_attempt(
    monkeypatch,
):

    original = save_target()

    monkeypatch.setattr(
        reconciliation,
        "reconcile_servicenow_workflow",
        lambda *args, **kwargs:
            evidence(
                outcome=
                    "NOT_FOUND",
            ),
    )

    result = (
        reconciliation
        .resolve_servicenow_workflow(
            WORKFLOW_ID,
            security_context=
                context(),
        )
    )

    assert result.status == "AWAITING_APPROVAL"

    assert (
        result.execution_attempt_id
        == OLD_ATTEMPT
    )

    assert (
        result.recovery_reason
        == original.recovery_reason
    )

    assert result.approval_id is None
    assert result.ticket_id is None


def test_next_claim_generates_new_attempt(
    monkeypatch,
):

    save_target()

    monkeypatch.setattr(
        reconciliation,
        "reconcile_servicenow_workflow",
        lambda *args, **kwargs:
            evidence(
                outcome=
                    "NOT_FOUND",
            ),
    )

    reconciliation \
        .resolve_servicenow_workflow(
            WORKFLOW_ID,
            security_context=
                context(),
        )

    monkeypatch.setattr(
        workflow_store,
        "generate_execution_attempt_id",
        lambda:
            NEW_ATTEMPT,
    )

    claimed = (
        workflow_store
        .claim_workflow_for_execution(
            WORKFLOW_ID,
            security_context=
                context(),
        )
    )

    assert claimed.status == "PROCESSING"

    assert (
        claimed.execution_attempt_id
        == NEW_ATTEMPT
    )

    assert (
        claimed.execution_attempt_id
        != OLD_ATTEMPT
    )


def test_conflict_leaves_workflow_unchanged(
    monkeypatch,
):

    original = save_target()

    monkeypatch.setattr(
        reconciliation,
        "reconcile_servicenow_workflow",
        lambda *args, **kwargs:
            evidence(
                outcome=
                    "CONFLICT",
            ),
    )

    with pytest.raises(
        ServiceNowReconciliationError,
        match="multiple matching",
    ):

        reconciliation \
            .resolve_servicenow_workflow(
                WORKFLOW_ID,
                security_context=
                    context(),
            )

    assert (
        workflow_store
        .get_workflow(
            WORKFLOW_ID
        )
        == original
    )


def test_confirm_transition_is_single_use():

    save_target()

    result = (
        workflow_store
        .confirm_reconciled_ticket_creation(
            WORKFLOW_ID,

            expected_execution_attempt_id=
                OLD_ATTEMPT,

            ticket_id=
                TICKET_ID,

            security_context=
                context(),
        )
    )

    assert result.status == "TICKET_CREATED"

    with pytest.raises(
        PermissionError,
        match="NEEDS_REVIEW",
    ):

        workflow_store \
            .confirm_reconciled_ticket_creation(
                WORKFLOW_ID,

                expected_execution_attempt_id=
                    OLD_ATTEMPT,

                ticket_id=
                    TICKET_ID,

                security_context=
                    context(),
            )


def test_retry_transition_is_single_use():

    save_target()

    result = (
        workflow_store
        .authorize_reconciled_retry(
            WORKFLOW_ID,

            expected_execution_attempt_id=
                OLD_ATTEMPT,

            security_context=
                context(),
        )
    )

    assert result.status == "AWAITING_APPROVAL"

    with pytest.raises(
        PermissionError,
        match="NEEDS_REVIEW",
    ):

        workflow_store \
            .authorize_reconciled_retry(
                WORKFLOW_ID,

                expected_execution_attempt_id=
                    OLD_ATTEMPT,

                security_context=
                    context(),
            )


def test_inconsistent_confirmed_fails_closed(
    monkeypatch,
):

    original = save_target()

    monkeypatch.setattr(
        reconciliation,
        "reconcile_servicenow_workflow",
        lambda *args, **kwargs:
            evidence(
                outcome=
                    "CONFIRMED",

                ticket_number=None,

                external_sys_id=
                    SYS_ID,
            ),
    )

    with pytest.raises(
        ServiceNowReconciliationError,
        match="incomplete",
    ):

        reconciliation \
            .resolve_servicenow_workflow(
                WORKFLOW_ID,
                security_context=
                    context(),
            )

    assert (
        workflow_store
        .get_workflow(
            WORKFLOW_ID
        )
        == original
    )


def test_inconsistent_not_found_fails_closed(
    monkeypatch,
):

    original = save_target()

    monkeypatch.setattr(
        reconciliation,
        "reconcile_servicenow_workflow",
        lambda *args, **kwargs:
            evidence(
                outcome=
                    "NOT_FOUND",

                match_count=1,

                ticket_number=
                    TICKET_ID,
            ),
    )

    with pytest.raises(
        ServiceNowReconciliationError,
        match="inconsistent",
    ):

        reconciliation \
            .resolve_servicenow_workflow(
                WORKFLOW_ID,
                security_context=
                    context(),
            )

    assert (
        workflow_store
        .get_workflow(
            WORKFLOW_ID
        )
        == original
    )


def test_wrong_workflow_identity_fails_closed(
    monkeypatch,
):

    original = save_target()

    bad_evidence = (
        ServiceNowReconciliationResult(
            workflow_id=
                "WF-OTHER0001",

            execution_attempt_id=
                OLD_ATTEMPT,

            outcome=
                "NOT_FOUND",

            correlation_id=
                CORRELATION_ID,

            match_count=0,
        )
    )

    monkeypatch.setattr(
        reconciliation,
        "reconcile_servicenow_workflow",
        lambda *args, **kwargs:
            bad_evidence,
    )

    with pytest.raises(
        ServiceNowReconciliationError,
        match="identity",
    ):

        reconciliation \
            .resolve_servicenow_workflow(
                WORKFLOW_ID,
                security_context=
                    context(),
            )

    assert (
        workflow_store
        .get_workflow(
            WORKFLOW_ID
        )
        == original
    )


def test_direct_store_retry_requires_approver():

    save_target()

    with pytest.raises(
        PermissionError,
        match="APPROVER",
    ):

        workflow_store \
            .authorize_reconciled_retry(
                WORKFLOW_ID,

                expected_execution_attempt_id=
                    OLD_ATTEMPT,

                security_context=
                    context(
                        role=
                            "ANALYST",
                    ),
            )


def test_resolution_surface_has_no_external_truth_inputs():

    signature = inspect.signature(
        reconciliation
        .resolve_servicenow_workflow
    )

    assert set(
        signature.parameters
    ) == {
        "workflow_id",
        "security_context",
    }

    for forbidden in (
        "outcome",
        "correlation_id",
        "ticket_id",
        "ticket_number",
        "sys_id",
        "tenant_id",
        "retry",
        "assignment_group",
        "provider",
        "url",
        "table",
    ):

        assert (
            forbidden
            not in signature.parameters
        )


def test_store_surfaces_have_no_raw_tenant_or_outcome():

    confirmed = inspect.signature(
        workflow_store
        .confirm_reconciled_ticket_creation
    )

    retry = inspect.signature(
        workflow_store
        .authorize_reconciled_retry
    )

    assert set(
        confirmed.parameters
    ) == {
        "workflow_id",
        "expected_execution_attempt_id",
        "ticket_id",
        "security_context",
    }

    assert set(
        retry.parameters
    ) == {
        "workflow_id",
        "expected_execution_attempt_id",
        "security_context",
    }

    for signature in (
        confirmed,
        retry,
    ):

        assert (
            "tenant_id"
            not in signature.parameters
        )

        assert (
            "outcome"
            not in signature.parameters
        )
