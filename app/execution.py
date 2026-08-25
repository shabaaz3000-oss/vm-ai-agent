from app.approval import create_approval
from app.audit import log_event

from app.models import WorkflowResult

from app.ticketing import create_mock_ticket

from app.workflow_store import (
    claim_workflow_for_execution,
)


# -------------------------------------------------
# WORKFLOW STATE VALIDATION
# -------------------------------------------------


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
            "status": "REJECTED",
            "approval_id": None,
            "ticket_id": None
        }
    )

    return WorkflowResult.model_validate(
        updated_data
    )


# -------------------------------------------------
# INTERNAL AUTHORIZED EXECUTION
# -------------------------------------------------


def _execute_ticket_bound_workflow(
    result: WorkflowResult,
    approved_by: str
) -> WorkflowResult:

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
                ticket.cve
        }
    )

    # -------------------------------------------------
    # 2. EXECUTE ONLY WITH VALID APPROVAL
    # -------------------------------------------------

    try:

        created_ticket = create_mock_ticket(
            ticket=ticket,
            approval=approval_record
        )

    except PermissionError as error:

        log_event(
            "TICKET_EXECUTION_BLOCKED",
            {
                "workflow_id":
                    result.workflow_id,

                "approval_id":
                    approval_record[
                        "approval_id"
                    ],

                "error_type":
                    "PermissionError",

                "message":
                    str(error)
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
                ]
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
                ]
        }
    )

    return WorkflowResult.model_validate(
        updated_data
    )


# -------------------------------------------------
# DIRECT APPROVAL
# -------------------------------------------------
#
# Used by the CLI, where the WorkflowResult already
# exists locally and there is no shared HTTP race.
# -------------------------------------------------


def approve_and_execute_workflow(
    result: WorkflowResult,
    approved_by: str
) -> WorkflowResult:

    require_awaiting_approval(
        result
    )

    return _execute_ticket_bound_workflow(
        result=result,
        approved_by=approved_by
    )


# -------------------------------------------------
# ATOMIC SERVER-SIDE APPROVAL
# -------------------------------------------------
#
# Used by the API.
#
# The trusted SQLite workflow is atomically claimed
# BEFORE any ticket or external action can occur.
# -------------------------------------------------


def claim_and_execute_workflow(
    workflow_id: str,
    approved_by: str
) -> WorkflowResult:

    try:

        claimed_result = (
            claim_workflow_for_execution(
                workflow_id
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
                    str(error)
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

            "approved_by":
                approved_by
        }
    )

    return _execute_ticket_bound_workflow(
        result=claimed_result,
        approved_by=approved_by
    )