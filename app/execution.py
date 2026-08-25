from app.approval import create_approval
from app.audit import log_event

from app.models import WorkflowResult

from app.ticketing import create_mock_ticket


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
# HUMAN APPROVAL + AUTHORIZED EXECUTION
# -------------------------------------------------


def approve_and_execute_workflow(
    result: WorkflowResult,
    approved_by: str
) -> WorkflowResult:

    # -------------------------------------------------
    # 1. VERIFY WORKFLOW STATE
    # -------------------------------------------------

    require_awaiting_approval(
        result
    )

    ticket = result.ticket

    # -------------------------------------------------
    # 2. CREATE TICKET-BOUND APPROVAL
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
    # 3. EXECUTE ONLY WITH VALID APPROVAL
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
    # 4. AUDIT SUCCESSFUL EXECUTION
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
    # 5. RETURN UPDATED STRUCTURED RESULT
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