from __future__ import annotations

import os

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app import execution
from app import workflow_store

from app.models import WorkflowResult
from app.security_context import SecurityContext
from app.workflow_postgresql_store import (
    PostgreSQLWorkflowStore,
)
from app.workflow_store_contract import WorkflowStore


_BASE_WORKFLOW_FIXTURE = {'analysis': {'compensating_controls': ['Maintain WAF.'],
              'confidence': 'HIGH',
              'executive_summary': 'Critical vulnerability.',
              'rationale': ['Critical risk.'],
              'remediation': 'Deploy approved patch.',
              'requires_human_review': True,
              'ticket_description': 'Validated ticket draft.',
              'ticket_summary': 'Remediate vulnerability.',
              'validation_steps': ['Run authenticated rescan.']},
 'approval_id': None,
 'asset_name': 'internet-web-01',
 'cve': 'CVE-2026-12345',
 'execution_attempt_id': None,
 'finding_id': 'FIND-0001',
 'processing_started_at': None,
 'recovery_reason': None,
 'retrieved_evidence': [],
 'risk': {'factors': ['Listed in CISA KEV', 'Internet exposed'],
          'rating': 'CRITICAL',
          'score': 100,
          'sla_hours': 24},
 'security': {'human_review_required': True,
              'prompt_injection_detected': False,
              'prompt_injection_matches': []},
 'status': 'AWAITING_APPROVAL',
 'tenant_id': None,
 'ticket': {'asset_name': 'internet-web-01',
            'assignment_group': 'Web Platform Team',
            'cve': 'CVE-2026-12345',
            'description': 'Validated ticket.',
            'priority': 'P1',
            'remediation': 'Deploy approved patch.',
            'risk_rating': 'CRITICAL',
            'risk_score': 100,
            'short_description': 'CRITICAL vulnerability',
            'sla_hours': 24,
            'validation_steps': ['Run authenticated rescan.']},
 'ticket_id': None,
 'workflow_id': 'WF-EVAL-BASE0001'}

_ALPHA_CONTEXT_FIXTURE = {'principal_id': 'approver-alpha',
 'retrieval_access': 'standard',
 'role': 'APPROVER',
 'session_id': 'session-approver-alpha-tenant-alpha',
 'session_revocation_access': 'self',
 'tenant_id': 'tenant-alpha'}

_BRAVO_CONTEXT_FIXTURE = {'principal_id': 'approver-bravo',
 'retrieval_access': 'standard',
 'role': 'APPROVER',
 'session_id': 'session-approver-bravo-tenant-bravo',
 'session_revocation_access': 'self',
 'tenant_id': 'tenant-bravo'}


@dataclass(
    frozen=True
)
class WorkflowAuthorityCaseResult:

    case_id: str
    category: str
    expected_behavior: str

    observed_achieved: bool
    execution_error: str | None

    passed: bool


@dataclass(
    frozen=True
)
class WorkflowAuthoritySecurityEvaluationResult:

    total_cases: int

    authority_protection_cases: int
    transition_cases: int

    passed_cases: int
    failed_cases: int

    authority_failures: int
    execution_errors: int

    passed: bool

    cases: tuple[
        WorkflowAuthorityCaseResult,
        ...
    ]


def _security_context(
    payload: dict,
) -> SecurityContext:

    return SecurityContext(
        **payload
    )


def _workflow(
    workflow_id: str,
    *,
    tenant_id: str | None = None,
    status: str = "AWAITING_APPROVAL",
) -> WorkflowResult:

    data = dict(
        _BASE_WORKFLOW_FIXTURE
    )

    data.update(
        {
            "workflow_id":
                workflow_id,

            "tenant_id":
                tenant_id,

            "status":
                status,

            "approval_id":
                None,

            "ticket_id":
                None,

            "execution_attempt_id":
                None,

            "processing_started_at":
                None,

            "recovery_reason":
                None,
        }
    )

    return (
        WorkflowResult.model_validate(
            data
        )
    )


@contextmanager
def _isolated_sqlite_store():

    """
    Provide deterministic evaluator-local SQLite authority.

    sqlite3.Connection.__exit__ commits or rolls back, but it
    does not close the connection. Windows will not delete a
    SQLite file while any connection still owns a file handle.

    The evaluator therefore replaces workflow_store's connection
    factory only inside this context with a wrapper that preserves
    transaction behavior and explicitly closes every connection
    before TemporaryDirectory cleanup runs.
    """

    previous_path = os.environ.get(
        "VM_AI_DB_PATH"
    )

    original_connect_database = (
        workflow_store.connect_database
    )

    with TemporaryDirectory(
        prefix=(
            "vm-ai-workflow-"
            "authority-eval-"
        )
    ) as directory:

        database_path = (
            Path(
                directory
            )
            / "workflows.db"
        )

        os.environ[
            "VM_AI_DB_PATH"
        ] = str(
            database_path
        )


        @contextmanager
        def closing_connect_database():

            connection = (
                original_connect_database()
            )

            try:

                yield connection

            except BaseException:

                connection.rollback()

                raise

            else:

                connection.commit()

            finally:

                connection.close()


        try:

            with patch.object(
                workflow_store,
                "connect_database",
                closing_connect_database,
            ):

                yield (
                    workflow_store
                    .SQLiteWorkflowStore()
                )

        finally:

            if previous_path is None:

                os.environ.pop(
                    "VM_AI_DB_PATH",
                    None,
                )

            else:

                os.environ[
                    "VM_AI_DB_PATH"
                ] = previous_path


def _mark_review(
    store,
    workflow_id: str,
    reason: str,
    *,
    execution_attempt_id: str,
    security_context: SecurityContext | None = None,
):

    return (
        store.mark_workflow_needs_review(
            workflow_id,
            reason,
            expected_execution_attempt_id=
                execution_attempt_id,
            security_context=
                security_context,
        )
    )


# ============================================================
# AUTHORITY-PROTECTION CASES
# ============================================================

def _case_insert_only_creation(
    store,
) -> bool:

    original = _workflow(
        "WF-EVAL-CREATE0001"
    )

    store.save_workflow(
        original
    )

    hostile_data = (
        original.model_dump()
    )

    hostile_data.update(
        {
            "status":
                "TICKET_CREATED",

            "ticket_id":
                "VM-EVAL-UNTRUSTED",
        }
    )

    hostile = (
        WorkflowResult.model_validate(
            hostile_data
        )
    )

    blocked = False

    try:

        store.save_workflow(
            hostile
        )

    except PermissionError:

        blocked = True

    authoritative = (
        store.get_workflow(
            original.workflow_id
        )
    )

    return (
        blocked
        and authoritative
        == original
    )


def _case_generic_mutation_absent(
    _store,
) -> bool:

    return all(
        (
            not hasattr(
                workflow_store,
                "update_workflow",
            ),

            not hasattr(
                workflow_store,
                "_sqlite_update_workflow",
            ),

            not hasattr(
                workflow_store
                .SQLiteWorkflowStore,
                "update_workflow",
            ),

            not hasattr(
                PostgreSQLWorkflowStore,
                "update_workflow",
            ),

            not hasattr(
                WorkflowStore,
                "update_workflow",
            ),
        )
    )


def _case_tenant_bound_claim_requires_context(
    store,
) -> bool:

    context = (
        _security_context(
            _ALPHA_CONTEXT_FIXTURE
        )
    )

    original = _workflow(
        "WF-EVAL-TENANT0001",
        tenant_id=
            context.tenant_id,
    )

    store.save_workflow(
        original
    )

    blocked = False

    try:

        store \
            .claim_workflow_for_execution(
                original.workflow_id
            )

    except PermissionError:

        blocked = True

    authoritative = (
        store.get_workflow(
            original.workflow_id
        )
    )

    return (
        blocked
        and authoritative.status
        == "AWAITING_APPROVAL"
        and authoritative
        .execution_attempt_id
        is None
        and authoritative.tenant_id
        == context.tenant_id
    )


def _case_stale_completion_attempt_rejected(
    store,
) -> bool:

    original = _workflow(
        "WF-EVAL-ATTEMPT0001"
    )

    store.save_workflow(
        original
    )

    claimed = (
        store
        .claim_workflow_for_execution(
            original.workflow_id
        )
    )

    if (
        claimed.execution_attempt_id
        is None
    ):

        return False

    blocked = False

    try:

        store.complete_workflow_execution(
            original.workflow_id,

            expected_execution_attempt_id=
                "EXEC-EVAL-STALE0001",

            approval_id=
                "APR-EVAL-STALE0001",

            ticket_id=
                "VM-EVAL-STALE0001",
        )

    except PermissionError:

        blocked = True

    authoritative = (
        store.get_workflow(
            original.workflow_id
        )
    )

    return (
        blocked
        and authoritative
        == claimed
        and authoritative.status
        == "PROCESSING"
    )


def _case_cross_tenant_reconciliation_rejected(
    store,
) -> bool:

    alpha = (
        _security_context(
            _ALPHA_CONTEXT_FIXTURE
        )
    )

    bravo = (
        _security_context(
            _BRAVO_CONTEXT_FIXTURE
        )
    )

    original = _workflow(
        "WF-EVAL-RECON-TENANT0001",
        tenant_id=
            alpha.tenant_id,
    )

    store.save_workflow(
        original
    )

    claimed = (
        store
        .claim_workflow_for_execution(
            original.workflow_id,
            security_context=
                alpha,
        )
    )

    review = (
        _mark_review(
            store,
            original.workflow_id,
            (
                "Synthetic external outcome "
                "requires reconciliation."
            ),
            execution_attempt_id=
                claimed.execution_attempt_id,
            security_context=
                alpha,
        )
    )

    blocked = False

    try:

        store \
            .confirm_reconciled_ticket_creation(
                original.workflow_id,

                expected_execution_attempt_id=
                    review.execution_attempt_id,

                ticket_id=
                    "VM-EVAL-CROSS-TENANT",

                security_context=
                    bravo,
            )

    except PermissionError:

        blocked = True

    authoritative = (
        store.get_workflow(
            original.workflow_id
        )
    )

    return (
        blocked
        and authoritative.status
        == "NEEDS_REVIEW"
        and authoritative.tenant_id
        == alpha.tenant_id
        and authoritative
        .execution_attempt_id
        == claimed.execution_attempt_id
    )


# ============================================================
# TRANSITION / RECOVERY CASES
# ============================================================

def _case_ambiguous_completion_requires_review(
    _store,
) -> bool:

    claimed_data = (
        _workflow(
            "WF-EVAL-AMBIGUOUS0001"
        )
        .model_dump()
    )

    claimed_data.update(
        {
            "status":
                "PROCESSING",

            "execution_attempt_id":
                "EXEC-EVAL-AMBIG0001",
        }
    )

    claimed = (
        WorkflowResult.model_validate(
            claimed_data
        )
    )

    completed_data = (
        claimed.model_dump()
    )

    completed_data.update(
        {
            "status":
                "TICKET_CREATED",

            "approval_id":
                "APR-EVAL-AMBIG0001",

            "ticket_id":
                "VM-EVAL-AMBIG0001",
        }
    )

    completion_candidate = (
        WorkflowResult.model_validate(
            completed_data
        )
    )

    review_calls = []


    def fake_mark_review(
        *args,
        **kwargs,
    ):

        workflow_id = (
            args[0]
            if args
            else kwargs.get(
                "workflow_id"
            )
        )

        reason = (
            args[1]
            if len(args) > 1
            else kwargs.get(
                "reason"
            )
        )

        review_calls.append(
            (
                workflow_id,
                reason,
            )
        )

        review_data = (
            claimed.model_dump()
        )

        review_data.update(
            {
                "status":
                    "NEEDS_REVIEW",

                "recovery_reason":
                    reason,
            }
        )

        return (
            WorkflowResult.model_validate(
                review_data
            )
        )


    raised = False

    with (
        patch.object(
            execution,
            "claim_workflow_for_execution",
            return_value=
                claimed,
        ),
        patch.object(
            execution,
            "_execute_ticket_bound_workflow",
            return_value=
                completion_candidate,
        ),
        patch.object(
            execution,
            "complete_workflow_execution",
            side_effect=
                RuntimeError(
                    "Synthetic authoritative "
                    "completion failure."
                ),
        ),
        patch.object(
            execution,
            "mark_workflow_needs_review",
            side_effect=
                fake_mark_review,
        ),
    ):

        try:

            execution \
                .claim_and_execute_workflow(
                    workflow_id=
                        claimed.workflow_id,

                    approved_by=
                        "evaluation-approver",
                )

        except RuntimeError:

            raised = True

    return (
        raised
        and len(
            review_calls
        ) == 1
        and review_calls[
            0
        ][
            0
        ]
        == claimed.workflow_id
    )


def _case_trusted_reconciliation_confirmation(
    store,
) -> bool:

    context = (
        _security_context(
            _ALPHA_CONTEXT_FIXTURE
        )
    )

    original = _workflow(
        "WF-EVAL-RECON-CONFIRM0001",
        tenant_id=
            context.tenant_id,
    )

    store.save_workflow(
        original
    )

    claimed = (
        store
        .claim_workflow_for_execution(
            original.workflow_id,
            security_context=
                context,
        )
    )

    review = (
        _mark_review(
            store,
            original.workflow_id,
            (
                "Synthetic external outcome "
                "requires reconciliation."
            ),
            execution_attempt_id=
                claimed.execution_attempt_id,
            security_context=
                context,
        )
    )

    resolved = (
        store
        .confirm_reconciled_ticket_creation(
            original.workflow_id,

            expected_execution_attempt_id=
                review.execution_attempt_id,

            ticket_id=
                "VM-EVAL-RECON0001",

            security_context=
                context,
        )
    )

    return (
        resolved.status
        == "TICKET_CREATED"
        and resolved.ticket_id
        == "VM-EVAL-RECON0001"
        and resolved
        .execution_attempt_id
        == claimed.execution_attempt_id
        and resolved.tenant_id
        == context.tenant_id
    )


def _case_authorized_retry_rotates_attempt(
    store,
) -> bool:

    context = (
        _security_context(
            _ALPHA_CONTEXT_FIXTURE
        )
    )

    original = _workflow(
        "WF-EVAL-RETRY0001",
        tenant_id=
            context.tenant_id,
    )

    store.save_workflow(
        original
    )

    first_claim = (
        store
        .claim_workflow_for_execution(
            original.workflow_id,
            security_context=
                context,
        )
    )

    review = (
        _mark_review(
            store,
            original.workflow_id,
            (
                "Synthetic ambiguous "
                "execution result."
            ),
            execution_attempt_id=
                first_claim.execution_attempt_id,
            security_context=
                context,
        )
    )

    retriable = (
        store
        .authorize_reconciled_retry(
            original.workflow_id,

            expected_execution_attempt_id=
                review.execution_attempt_id,

            security_context=
                context,
        )
    )

    if (
        retriable.status
        != "AWAITING_APPROVAL"
        or retriable
        .execution_attempt_id
        != first_claim
        .execution_attempt_id
    ):

        return False

    second_claim = (
        store
        .claim_workflow_for_execution(
            original.workflow_id,
            security_context=
                context,
        )
    )

    return (
        second_claim.status
        == "PROCESSING"
        and second_claim
        .execution_attempt_id
        is not None
        and second_claim
        .execution_attempt_id
        != first_claim
        .execution_attempt_id
        and second_claim.tenant_id
        == context.tenant_id
    )


def _case_stale_review_attempt_rejected(
    store,
) -> bool:

    original = _workflow(
        "WF-EVAL-REVIEW-STALE0001"
    )

    store.save_workflow(
        original
    )

    claimed = (
        store
        .claim_workflow_for_execution(
            original.workflow_id
        )
    )

    blocked = False

    try:

        _mark_review(
            store,
            original.workflow_id,
            "Synthetic ambiguous outcome.",
            execution_attempt_id=
                "EXEC-EVAL-REVIEW-STALE",
        )

    except PermissionError:

        blocked = True

    authoritative = (
        store.get_workflow(
            original.workflow_id
        )
    )

    return (
        blocked
        and authoritative == claimed
        and authoritative.status
        == "PROCESSING"
    )


def _case_cross_tenant_review_rejected(
    store,
) -> bool:

    alpha = (
        _security_context(
            _ALPHA_CONTEXT_FIXTURE
        )
    )

    bravo = (
        _security_context(
            _BRAVO_CONTEXT_FIXTURE
        )
    )

    original = _workflow(
        "WF-EVAL-REVIEW-TENANT0001",
        tenant_id=
            alpha.tenant_id,
    )

    store.save_workflow(
        original
    )

    claimed = (
        store
        .claim_workflow_for_execution(
            original.workflow_id,
            security_context=
                alpha,
        )
    )

    blocked = False

    try:

        _mark_review(
            store,
            original.workflow_id,
            "Synthetic ambiguous outcome.",
            execution_attempt_id=
                claimed.execution_attempt_id,
            security_context=
                bravo,
        )

    except PermissionError:

        blocked = True

    authoritative = (
        store.get_workflow(
            original.workflow_id
        )
    )

    return (
        blocked
        and authoritative == claimed
        and authoritative.status
        == "PROCESSING"
        and authoritative.tenant_id
        == alpha.tenant_id
    )

_CASES = (
    (
        "stale_review_attempt_rejected",
        "AUTHORITY_PROTECTION",
        (
            "Ambiguity recovery cannot mutate "
            "a different execution attempt."
        ),
        _case_stale_review_attempt_rejected,
    ),
    (
        "cross_tenant_review_rejected",
        "AUTHORITY_PROTECTION",
        (
            "Ambiguity recovery cannot cross "
            "the trusted workflow tenant boundary."
        ),
        _case_cross_tenant_review_rejected,
    ),
    (
        "insert_only_creation_blocks_overwrite",
        "AUTHORITY_PROTECTION",
        (
            "Existing authoritative workflow state "
            "cannot be replaced through creation."
        ),
        _case_insert_only_creation,
    ),
    (
        "generic_mutation_authority_absent",
        "AUTHORITY_PROTECTION",
        (
            "No generic update_workflow authority "
            "is publicly exposed."
        ),
        _case_generic_mutation_absent,
    ),
    (
        "tenant_bound_claim_requires_trusted_context",
        "AUTHORITY_PROTECTION",
        (
            "Tenant-bound execution fails closed "
            "without trusted SecurityContext."
        ),
        _case_tenant_bound_claim_requires_context,
    ),
    (
        "stale_completion_attempt_rejected",
        "AUTHORITY_PROTECTION",
        (
            "Completion cannot mutate a different "
            "execution attempt."
        ),
        _case_stale_completion_attempt_rejected,
    ),
    (
        "cross_tenant_reconciliation_rejected",
        "AUTHORITY_PROTECTION",
        (
            "Reconciliation cannot cross the trusted "
            "workflow tenant boundary."
        ),
        _case_cross_tenant_reconciliation_rejected,
    ),
    (
        "ambiguous_completion_requires_review",
        "STATE_TRANSITION",
        (
            "Uncertain completion persistence moves "
            "execution into manual review."
        ),
        _case_ambiguous_completion_requires_review,
    ),
    (
        "trusted_reconciliation_confirms_ticket",
        "STATE_TRANSITION",
        (
            "Trusted exact-attempt reconciliation "
            "may confirm ticket creation."
        ),
        _case_trusted_reconciliation_confirmation,
    ),
    (
        "authorized_retry_rotates_attempt",
        "STATE_TRANSITION",
        (
            "Human-authorized retry preserves the "
            "old attempt until a fresh claim rotates it."
        ),
        _case_authorized_retry_rotates_attempt,
    ),
)


def _evaluate_case(
    store,
    *,
    case_id: str,
    category: str,
    expected_behavior: str,
    evaluation,
) -> WorkflowAuthorityCaseResult:

    try:

        achieved = bool(
            evaluation(
                store
            )
        )

        execution_error = None

    except Exception as error:

        achieved = False

        execution_error = (
            type(
                error
            ).__name__
        )

    return (
        WorkflowAuthorityCaseResult(
            case_id=
                case_id,

            category=
                category,

            expected_behavior=
                expected_behavior,

            observed_achieved=
                achieved,

            execution_error=
                execution_error,

            passed=
                (
                    achieved
                    and execution_error
                    is None
                ),
        )
    )


def run_workflow_authority_security_evaluation(
) -> WorkflowAuthoritySecurityEvaluationResult:

    """
    Run deterministic, credential-free workflow authority checks.

    The evaluator uses synthetic identifiers and an isolated
    SQLite database. It performs no external ticket-provider or
    network execution.
    """

    with _isolated_sqlite_store() as store:

        cases = tuple(
            _evaluate_case(
                store,

                case_id=
                    case_id,

                category=
                    category,

                expected_behavior=
                    expected_behavior,

                evaluation=
                    evaluation,
            )
            for (
                case_id,
                category,
                expected_behavior,
                evaluation,
            )
            in _CASES
        )

    passed_cases = sum(
        case.passed
        for case in cases
    )

    failed_cases = (
        len(
            cases
        )
        - passed_cases
    )

    authority_protection_cases = sum(
        case.category
        == "AUTHORITY_PROTECTION"
        for case in cases
    )

    transition_cases = sum(
        case.category
        == "STATE_TRANSITION"
        for case in cases
    )

    authority_failures = sum(
        (
            case.category
            == "AUTHORITY_PROTECTION"
        )
        and not case.passed
        for case in cases
    )

    execution_errors = sum(
        case.execution_error
        is not None
        for case in cases
    )

    return (
        WorkflowAuthoritySecurityEvaluationResult(
            total_cases=
                len(
                    cases
                ),

            authority_protection_cases=
                authority_protection_cases,

            transition_cases=
                transition_cases,

            passed_cases=
                passed_cases,

            failed_cases=
                failed_cases,

            authority_failures=
                authority_failures,

            execution_errors=
                execution_errors,

            passed=
                (
                    failed_cases
                    == 0
                ),

            cases=
                cases,
        )
    )
