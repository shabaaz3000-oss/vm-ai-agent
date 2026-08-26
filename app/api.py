from fastapi import Depends
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import status

from app.auth import Principal
from app.auth import require_approver
from app.auth import require_authenticated_user

from app.execution import (
    claim_and_execute_workflow,
    reconcile_stale_workflow,
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
    version="0.3.0",
    description=(
        "Secure AI-assisted vulnerability management "
        "workflow API with authentication, RBAC, "
        "persistent state, and atomic execution claims."
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

        completed_result = (
            claim_and_execute_workflow(
                workflow_id=workflow_id,

                approved_by=
                    principal.username,
            )
        )

    except KeyError:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workflow not found.",
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


# -------------------------------------------------
# RECONCILE STALE PROCESSING WORKFLOW
# -------------------------------------------------


@app.post(
    "/workflows/{workflow_id}/reconcile",
    response_model=WorkflowResult,
)
def reconcile_workflow(
    workflow_id: str,

    principal: Principal = Depends(
        require_approver
    )
):

    try:

        result = (
            reconcile_stale_workflow(
                workflow_id=workflow_id
            )
        )

    except KeyError:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workflow not found.",
        )

    except PermissionError as error:

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        )

    except ValueError as error:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )

    return result