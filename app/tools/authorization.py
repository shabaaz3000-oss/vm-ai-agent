from fastapi import HTTPException
from fastapi import status

from app.auth import Principal


# -------------------------------------------------
# TOOL PERMISSIONS
# -------------------------------------------------


TOOL_PERMISSIONS = {
    "ANALYST": {
        "get_finding",
        "get_asset_details",
        "get_threat_intel",
        "search_knowledge",
    },

    "APPROVER": {
        "get_finding",
        "get_asset_details",
        "get_threat_intel",
        "search_knowledge",
        "execute_ticket_workflow",
    },
}


# -------------------------------------------------
# REQUIRE TOOL PERMISSION
# -------------------------------------------------


def require_tool_permission(
    principal: Principal,
    tool_name: str,
) -> None:

    allowed_tools = TOOL_PERMISSIONS.get(
        principal.role,
        set(),
    )

    if tool_name not in allowed_tools:

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,

            detail=(
                f"Principal is not authorized "
                f"to use tool '{tool_name}'."
            ),
        )