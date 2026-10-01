from app.approval import create_approval
from app.audit import log_event

from app.models import WorkflowResult
from app.ticket_execution_context import (
    TicketExecutionContext,
)
from app.security_context import SecurityContext
from app.workflow_tenant import require_workflow_tenant

from app.providers.ticket_provider_factory import build_ticket_provider

from app.workflow_store import (
    claim_workflow_for_execution,
    mark_stale_processing_for_review,
    mark_workflow_needs_review,
    complete_workflow_execution,
)


# -------------------------------------------------
# WORKFLOW STATE VALIDATION
# -------------------------------------------------



def _create_ticket_with_selected_provider(
    *,
    ticket,
    approval,
    execution_context:
        TicketExecutionContext | None = None,
):
    """
    Execute a ticket through the server-selected provider.

    Provider selection remains derived exclusively from trusted
    server configuration.

    A trusted TicketExecutionContext may carry already-validated
    workflow tenant metadata to a tenant-sensitive provider,
    but it cannot select the backend itself.

    Provider cleanup is guaranteed even when the external
    action raises.
    """

    provider = build_ticket_provider()

    try:

        if execution_context is None:

            # Preserve compatibility for providers and local
            # workflows that do not require external
            # tenant-specific routing.

            return provider.create_ticket(
                ticket=ticket,
                approval=approval,
            )

        return provider.create_ticket(
            ticket=ticket,
            approval=approval,
            execution_context=
                execution_context,
        )

    finally:

        provider.close()



def _validate_execution_security_identity(
    *,
    approved_by: str,
    security_context: SecurityContext | None,
) -> None:
    """
    Validate immutable server-side execution identity
    before any workflow claim can occur.
    """

    if security_context is None:
        return

    if (
        security_context.principal_id
        != approved_by
    ):
        raise PermissionError(
            "Workflow execution security context "
            "principal mismatch."
        )

    if security_context.role != "APPROVER":
        raise PermissionError(
            "Workflow execution requires "
            "APPROVER security context."
        )


def _require_bound_workflow_execution_context(
    *,
    result: WorkflowResult,
    approved_by: str,
    security_context: SecurityContext | None,
) -> None:
    """
    Revalidate tenant authority immediately before
    ticket-bound approval creation and provider execution.
    """

    if result.tenant_id is None:
        return

    if security_context is None:
        raise PermissionError(
            "Tenant-bound workflow execution "
            "requires trusted security context."
        )

    _validate_execution_security_identity(
        approved_by=approved_by,
        security_context=security_context,
    )

    require_workflow_tenant(
        result,
        security_context=security_context,
    )


def require_awaiting_approval(
    result: WorkflowResult
) -> None:

    if result.status != "AWAITING_APPROVAL":

        raise PermissionError(
            "Workflow must be awaiting approval "
            "before an execution decision can occur."
        )


# -------------------------------------------------
# HUMAN REJECTION
# -------------------------------------------------


def reject_workflow(
    result: WorkflowResult
) -> WorkflowResult:

    require_awaiting_approval(
        result
    )

    log_event(
        "TICKET_REJECTED",
        {
            "workflow_id":
                result.workflow_id,

            "asset_name":
                result.ticket.asset_name,

            "cve":
                result.ticket.cve
        }
    )

    updated_data = result.model_dump()

    updated_data.update(
        {
            "status":
                "REJECTED",

            "approval_id":
                None,

            "ticket_id":
                None,
        }
    )

    return (
        WorkflowResult
        .model_validate(
            updated_data
        )
    )


# -------------------------------------------------
# INTERNAL AUTHORIZED EXECUTION
# -------------------------------------------------


def _execute_ticket_bound_workflow(
    result: WorkflowResult,
    approved_by: str,
    *,
    security_context: SecurityContext | None = None,
) -> WorkflowResult:

    # Revalidate trusted tenant authority before
    # create_approval() or any provider side effect.

    _require_bound_workflow_execution_context(
        result=result,
        approved_by=approved_by,
        security_context=security_context,
    )

    execution_context = None

    if result.tenant_id is not None:

        execution_context = (
            TicketExecutionContext(
                tenant_id=
                    result.tenant_id,

                workflow_id=
                    result.workflow_id,

                execution_attempt_id=
                    result.execution_attempt_id,
            )
        )

    ticket = result.ticket

    # -------------------------------------------------
    # 1. CREATE TICKET-BOUND APPROVAL
    # -------------------------------------------------

    approval_record = create_approval(
        ticket=ticket,
        approved_by=approved_by
    )

    log_event(
        "TICKET_APPROVED",
        {
            "workflow_id":
                result.workflow_id,

            "execution_attempt_id":
                result.execution_attempt_id,

            "approval_id":
                approval_record[
                    "approval_id"
                ],

            "approved_by":
                approval_record[
                    "approved_by"
                ],

            "approved_at":
                approval_record[
                    "approved_at"
                ],

            "ticket_fingerprint":
                approval_record[
                    "ticket_fingerprint"
                ],

            "asset_name":
                ticket.asset_name,

            "cve":
                ticket.cve,
        }
    )

    # -------------------------------------------------
    # 2. EXECUTE ONLY WITH VALID APPROVAL
    # -------------------------------------------------

    try:

        if execution_context is None:

            created_ticket = (
                _create_ticket_with_selected_provider(
                    ticket=ticket,
                    approval=approval_record,
                )
            )

        else:

            created_ticket = (
                _create_ticket_with_selected_provider(
                    ticket=ticket,
                    approval=approval_record,
                    execution_context=
                        execution_context,
                )
            )

    except PermissionError as error:

        log_event(
            "TICKET_EXECUTION_BLOCKED",
            {
                "workflow_id":
                    result.workflow_id,

                "execution_attempt_id":
                    result.execution_attempt_id,

                "approval_id":
                    approval_record[
                        "approval_id"
                    ],

                "error_type":
                    "PermissionError",

                "message":
                    str(error),
            }
        )

        raise

    # -------------------------------------------------
    # 3. AUDIT SUCCESSFUL EXECUTION
    # -------------------------------------------------

    log_event(
        "MOCK_TICKET_CREATED",
        {
            "workflow_id":
                result.workflow_id,

            "execution_attempt_id":
                result.execution_attempt_id,

            "ticket_id":
                created_ticket[
                    "ticket_id"
                ],

            "approval_id":
                created_ticket[
                    "approval_id"
                ],

            "priority":
                created_ticket[
                    "priority"
                ],

            "risk_rating":
                created_ticket[
                    "risk_rating"
                ],
        }
    )

    # -------------------------------------------------
    # 4. RETURN COMPLETED WORKFLOW
    # -------------------------------------------------

    updated_data = result.model_dump()

    updated_data.update(
        {
            "status":
                "TICKET_CREATED",

            "approval_id":
                created_ticket[
                    "approval_id"
                ],

            "ticket_id":
                created_ticket[
                    "ticket_id"
                ],

            "recovery_reason":
                None,
        }
    )

    return (
        WorkflowResult
        .model_validate(
            updated_data
        )
    )


# -------------------------------------------------
# DIRECT APPROVAL
# -------------------------------------------------


def approve_and_execute_workflow(
    result: WorkflowResult,
    approved_by: str,
    *,
    security_context: SecurityContext | None = None,
) -> WorkflowResult:

    require_awaiting_approval(
        result
    )

    if security_context is None:

        return _execute_ticket_bound_workflow(
            result=result,
            approved_by=approved_by,
        )

    return _execute_ticket_bound_workflow(
        result=result,
        approved_by=approved_by,
        security_context=security_context,
    )


# -------------------------------------------------
# ATOMIC SERVER-SIDE APPROVAL
# -------------------------------------------------


def claim_and_execute_workflow(
    workflow_id: str,
    approved_by: str,
    *,
    security_context: SecurityContext | None = None,
) -> WorkflowResult:

    # Validate immutable caller identity before any
    # authoritative workflow state transition.

    _validate_execution_security_identity(
        approved_by=approved_by,
        security_context=security_context,
    )

    try:

        if security_context is None:

            # Legacy/local compatibility.
            #
            # Tenant-bound workflows still fail closed
            # inside the authoritative claim.

            claimed_result = (
                claim_workflow_for_execution(
                    workflow_id
                )
            )

        else:

            claimed_result = (
                claim_workflow_for_execution(
                    workflow_id,
                    security_context=
                        security_context,
                )
            )

    except PermissionError as error:

        log_event(
            "WORKFLOW_EXECUTION_CLAIM_BLOCKED",
            {
                "workflow_id":
                    workflow_id,

                "error_type":
                    "PermissionError",

                "message":
                    str(error),
            }
        )

        raise


    log_event(
        "WORKFLOW_EXECUTION_CLAIMED",
        {
            "workflow_id":
                claimed_result.workflow_id,

            "status":
                claimed_result.status,

            "execution_attempt_id":
                claimed_result
                .execution_attempt_id,

            "processing_started_at":
                (
                    claimed_result
                    .processing_started_at
                    .isoformat()
                    if claimed_result
                    .processing_started_at
                    else None
                ),

            "approved_by":
                approved_by,
        }
    )


    try:

        # -------------------------------------------------
        # EXTERNAL SIDE EFFECT
        # -------------------------------------------------
        #
        # This returns candidate completion metadata only.
        # It is not authoritative workflow persistence.

        if security_context is None:

            execution_result = (
                _execute_ticket_bound_workflow(
                    result=
                        claimed_result,

                    approved_by=
                        approved_by,
                )
            )

        else:

            execution_result = (
                _execute_ticket_bound_workflow(
                    result=
                        claimed_result,

                    approved_by=
                        approved_by,

                    security_context=
                        security_context,
                )
            )


        # -------------------------------------------------
        # SIDE-EFFECT PROVENANCE CHECK
        # -------------------------------------------------

        if (
            execution_result.workflow_id
            != claimed_result.workflow_id
        ):

            raise RuntimeError(
                "Ticket execution result changed "
                "workflow identity."
            )

        if (
            execution_result.execution_attempt_id
            != claimed_result.execution_attempt_id
        ):

            raise RuntimeError(
                "Ticket execution result changed "
                "execution-attempt identity."
            )

        if (
            execution_result.status
            != "TICKET_CREATED"
        ):

            raise RuntimeError(
                "Ticket execution did not produce "
                "a completion candidate."
            )

        if (
            claimed_result.execution_attempt_id
            is None
        ):

            raise RuntimeError(
                "Claimed workflow is missing "
                "execution-attempt authority."
            )


        # -------------------------------------------------
        # AUTHORITATIVE COMPLETION
        # -------------------------------------------------
        #
        # The store re-reads and locks authoritative
        # PROCESSING state, validates the exact execution
        # attempt and tenant authority, and applies only
        # the approved completion fields.
        #
        # Any failure here occurs AFTER the external
        # side effect, therefore the existing recovery
        # boundary below must treat it as ambiguous.

        if security_context is None:

            return (
                complete_workflow_execution(
                    workflow_id=
                        workflow_id,

                    expected_execution_attempt_id=
                        claimed_result
                        .execution_attempt_id,

                    approval_id=
                        execution_result
                        .approval_id,

                    ticket_id=
                        execution_result
                        .ticket_id,
                )
            )

        return (
            complete_workflow_execution(
                workflow_id=
                    workflow_id,

                expected_execution_attempt_id=
                    claimed_result
                    .execution_attempt_id,

                approval_id=
                    execution_result
                    .approval_id,

                ticket_id=
                    execution_result
                    .ticket_id,

                security_context=
                    security_context,
            )
        )


    except Exception as error:

        recovery_reason = (
            "Execution failed after the workflow "
            "was claimed. External action outcome "
            "requires manual reconciliation."
        )

        try:

            review_result = (
                mark_workflow_needs_review(
                    workflow_id=
                        workflow_id,

                    reason=
                        recovery_reason,
                )
            )

        except Exception as recovery_error:

            log_event(
                "WORKFLOW_RECOVERY_MARK_FAILED",
                {
                    "workflow_id":
                        workflow_id,

                    "execution_attempt_id":
                        claimed_result
                        .execution_attempt_id,

                    "original_error_type":
                        type(error).__name__,

                    "recovery_error_type":
                        type(
                            recovery_error
                        ).__name__,
                }
            )

        else:

            log_event(
                "WORKFLOW_EXECUTION_NEEDS_REVIEW",
                {
                    "workflow_id":
                        workflow_id,

                    "execution_attempt_id":
                        review_result
                        .execution_attempt_id,

                    "status":
                        review_result.status,

                    "error_type":
                        type(error).__name__,

                    "recovery_reason":
                        review_result
                        .recovery_reason,
                }
            )

        raise


# -------------------------------------------------
# STALE EXECUTION RECONCILIATION
# -------------------------------------------------


def reconcile_stale_workflow(
    workflow_id: str,
    stale_after_seconds: int = 300
) -> WorkflowResult:

    """
    Detect a stale PROCESSING workflow and move it
    to NEEDS_REVIEW.

    This does NOT retry ticket creation.
    """

    result = (
        mark_stale_processing_for_review(
            workflow_id=
                workflow_id,

            stale_after_seconds=
                stale_after_seconds,
        )
    )

    log_event(
        "STALE_WORKFLOW_NEEDS_REVIEW",
        {
            "workflow_id":
                result.workflow_id,

            "execution_attempt_id":
                result.execution_attempt_id,

            "status":
                result.status,

            "recovery_reason":
                result.recovery_reason,
        }
    )

    return result
