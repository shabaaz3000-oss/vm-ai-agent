from fastapi import HTTPException

from app.auth import Principal
from app.audit import log_event
from app.execution import claim_and_execute_workflow
from app.models import WorkflowResult
from app.security_context import SecurityContext

from app.tools.authorization import (
    require_tool_permission,
)



# -------------------------------------------------
# EXECUTE TICKET-BOUND WORKFLOW TOOL
# -------------------------------------------------


def execute_ticket_workflow(
    principal: Principal,
    workflow_id: str,
    *,
    security_context: SecurityContext | None = None,
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

    try:

        require_tool_permission(
            principal=
                principal,

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


    if not workflow_id.strip():

        raise ValueError(
            "workflow_id cannot be blank."
        )


    try:

        if security_context is None:

            result = (
                claim_and_execute_workflow(
                    workflow_id=
                        workflow_id,

                    approved_by=
                        principal.username,
                )
            )

        else:

            result = (
                claim_and_execute_workflow(
                    workflow_id=
                        workflow_id,

                    approved_by=
                        principal.username,

                    security_context=
                        security_context,
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
                result.workflow_id,

            "status":
                result.status,

            "ticket_id":
                result.ticket_id,
        },
    )

    return result
