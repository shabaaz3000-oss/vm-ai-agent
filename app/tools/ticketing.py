from fastapi import HTTPException

from app.auth import Principal
from app.audit import log_event
from app.execution import claim_and_execute_workflow
from app.models import WorkflowResult

from app.tools.authorization import (
    require_tool_permission,
)

from app.workflow_store import (
    update_workflow,
)


# -------------------------------------------------
# EXECUTE TICKET-BOUND WORKFLOW TOOL
# -------------------------------------------------


def execute_ticket_workflow(
    principal: Principal,
    workflow_id: str,
) -> WorkflowResult:

    log_event(
        "TOOL_REQUESTED",
        {
            "tool":
                "execute_ticket_workflow",

            "username":
                principal.username,

            "role":
                principal.role,

            "workflow_id":
                workflow_id,
        },
    )

    # -------------------------------------------------
    # 1. AUTHORIZE TOOL USE
    # -------------------------------------------------

    try:

        require_tool_permission(
            principal=principal,
            tool_name=
                "execute_ticket_workflow",
        )

    except HTTPException:

        log_event(
            "TOOL_ACCESS_DENIED",
            {
                "tool":
                    "execute_ticket_workflow",

                "username":
                    principal.username,

                "role":
                    principal.role,

                "workflow_id":
                    workflow_id,
            },
        )

        raise

    # -------------------------------------------------
    # 2. VALIDATE TOOL ARGUMENT
    # -------------------------------------------------

    if not workflow_id.strip():

        raise ValueError(
            "workflow_id cannot be blank."
        )

    # -------------------------------------------------
    # 3. CLAIM AND EXECUTE EXISTING WORKFLOW
    # -------------------------------------------------

    try:

        result = (
            claim_and_execute_workflow(
                workflow_id=
                    workflow_id,

                approved_by=
                    principal.username,
            )
        )

        # -------------------------------------------------
        # 4. PERSIST SUCCESSFUL FINAL STATE
        # -------------------------------------------------

        persisted_result = (
            update_workflow(
                result
            )
        )

    except Exception as error:

        log_event(
            "TOOL_EXECUTION_FAILED",
            {
                "tool":
                    "execute_ticket_workflow",

                "username":
                    principal.username,

                "role":
                    principal.role,

                "workflow_id":
                    workflow_id,

                "error_type":
                    type(error).__name__,
            },
        )

        raise

    # -------------------------------------------------
    # 5. AUDIT SUCCESS
    # -------------------------------------------------

    log_event(
        "TOOL_EXECUTED",
        {
            "tool":
                "execute_ticket_workflow",

            "username":
                principal.username,

            "role":
                principal.role,

            "workflow_id":
                persisted_result.workflow_id,

            "status":
                persisted_result.status,

            "ticket_id":
                persisted_result.ticket_id,
        },
    )

    return persisted_result