from app.models import WorkflowResult


# -------------------------------------------------
# DEMO WORKFLOW STORE
# -------------------------------------------------

_workflows: dict[str, WorkflowResult] = {}


# -------------------------------------------------
# SAVE WORKFLOW
# -------------------------------------------------


def save_workflow(
    result: WorkflowResult
) -> WorkflowResult:

    _workflows[
        result.workflow_id
    ] = result

    return result


# -------------------------------------------------
# GET WORKFLOW
# -------------------------------------------------


def get_workflow(
    workflow_id: str
) -> WorkflowResult:

    result = _workflows.get(
        workflow_id
    )

    if result is None:

        raise KeyError(
            f"Workflow not found: {workflow_id}"
        )

    return result


# -------------------------------------------------
# UPDATE WORKFLOW
# -------------------------------------------------


def update_workflow(
    result: WorkflowResult
) -> WorkflowResult:

    if (
        result.workflow_id
        not in _workflows
    ):

        raise KeyError(
            "Cannot update a workflow "
            "that does not exist."
        )

    _workflows[
        result.workflow_id
    ] = result

    return result


# -------------------------------------------------
# CLEAR STORE
# -------------------------------------------------


def clear_workflows() -> None:

    _workflows.clear()