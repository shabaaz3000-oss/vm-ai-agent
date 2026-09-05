import pytest

from fastapi import HTTPException

from app.auth import Principal
from app.tools.authorization import require_tool_permission


# -------------------------------------------------
# ANALYST CAN USE READ TOOL
# -------------------------------------------------


def test_analyst_can_get_finding():

    principal = Principal(
        username="test-analyst",
        role="ANALYST",
    )

    require_tool_permission(
        principal=principal,
        tool_name="get_finding",
    )


# -------------------------------------------------
# ANALYST CANNOT EXECUTE TICKET WORKFLOW
# -------------------------------------------------


def test_analyst_cannot_execute_ticket_workflow():

    principal = Principal(
        username="test-analyst",
        role="ANALYST",
    )

    with pytest.raises(
        HTTPException
    ) as exc_info:

        require_tool_permission(
            principal=principal,
            tool_name="execute_ticket_workflow",
        )

    assert (
        exc_info.value.status_code
        == 403
    )


# -------------------------------------------------
# APPROVER CAN EXECUTE TICKET WORKFLOW
# -------------------------------------------------


def test_approver_can_execute_ticket_workflow():

    principal = Principal(
        username="test-approver",
        role="APPROVER",
    )

    require_tool_permission(
        principal=principal,
        tool_name="execute_ticket_workflow",
    )