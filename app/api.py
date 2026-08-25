from fastapi import Depends
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import status

from app.auth import Principal
from app.auth import require_approver
from app.auth import require_authenticated_user

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
    version="0.2.0",
    description=(
        "Secure AI-assisted vulnerability management "
        "workflow API with authentication and RBAC."
    ),
)


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
def create_workflow(
    principal: Principal = Depends(
        require_authenticated_user
    )
):

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
    workflow_id: str,

    principal: Principal = Depends(
        require_authenticated_user
    )
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
    workflow_id: str,

    principal: Principal = Depends(
        require_approver
    )
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

                approved_by=
                    principal.username,
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
    workflow_id: str,

    principal: Principal = Depends(
        require_approver
    )
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