from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import status

from app.execution import (
    approve_and_execute_workflow,
    reject_workflow,
)

from app.models import WorkflowResult

from app.workflow import prepare_workflow

from app.workflow_store import (
    get_workflow,
    save_workflow,
    update_workflow,
)


# -------------------------------------------------
# APPLICATION
# -------------------------------------------------


app = FastAPI(
    title="VM AI Agent API",
    version="0.1.0",
    description=(
        "Secure AI-assisted vulnerability management "
        "workflow API."
    ),
)


# -------------------------------------------------
# DEMO IDENTITY
# -------------------------------------------------

# This is intentionally a fixed demo identity.
#
# It does NOT represent authenticated production
# user identity. Authentication and RBAC will be
# added in a later security phase.

DEMO_APPROVER = "api-demo-analyst"


# -------------------------------------------------
# HEALTH
# -------------------------------------------------


@app.get(
    "/health"
)
def health():

    return {
        "status": "ok"
    }


# -------------------------------------------------
# CREATE / PREPARE WORKFLOW
# -------------------------------------------------


@app.post(
    "/workflows",
    response_model=WorkflowResult,
    status_code=status.HTTP_201_CREATED,
)
def create_workflow():

    result = prepare_workflow()

    save_workflow(
        result
    )

    return result


# -------------------------------------------------
# GET WORKFLOW
# -------------------------------------------------


@app.get(
    "/workflows/{workflow_id}",
    response_model=WorkflowResult,
)
def read_workflow(
    workflow_id: str
):

    try:

        return get_workflow(
            workflow_id
        )

    except KeyError:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workflow not found.",
        )


# -------------------------------------------------
# APPROVE + EXECUTE WORKFLOW
# -------------------------------------------------


@app.post(
    "/workflows/{workflow_id}/approve",
    response_model=WorkflowResult,
)
def approve_workflow(
    workflow_id: str
):

    try:

        result = get_workflow(
            workflow_id
        )

    except KeyError:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workflow not found.",
        )

    try:

        completed_result = (
            approve_and_execute_workflow(
                result=result,
                approved_by=DEMO_APPROVER,
            )
        )

    except PermissionError as error:

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        )

    update_workflow(
        completed_result
    )

    return completed_result


# -------------------------------------------------
# REJECT WORKFLOW
# -------------------------------------------------


@app.post(
    "/workflows/{workflow_id}/reject",
    response_model=WorkflowResult,
)
def reject_workflow_endpoint(
    workflow_id: str
):

    try:

        result = get_workflow(
            workflow_id
        )

    except KeyError:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workflow not found.",
        )

    try:

        rejected_result = (
            reject_workflow(
                result=result
            )
        )

    except PermissionError as error:

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        )

    update_workflow(
        rejected_result
    )

    return rejected_result