from fastapi import HTTPException

from app.auth import Principal
from app.audit import log_event
from app.loaders import load_finding
from app.models import VulnerabilityFinding

from app.tools.authorization import require_tool_permission


# -------------------------------------------------
# GET VULNERABILITY FINDING TOOL
# -------------------------------------------------


def get_finding(
    principal: Principal,
) -> VulnerabilityFinding:

    log_event(
        "TOOL_REQUESTED",
        {
            "tool": "get_finding",
            "username": principal.username,
            "role": principal.role,
        },
    )

    try:

        require_tool_permission(
            principal=principal,
            tool_name="get_finding",
        )

    except HTTPException:

        log_event(
            "TOOL_ACCESS_DENIED",
            {
                "tool": "get_finding",
                "username": principal.username,
                "role": principal.role,
            },
        )

        raise

    finding = load_finding()

    log_event(
        "TOOL_EXECUTED",
        {
            "tool": "get_finding",
            "username": principal.username,
            "role": principal.role,
        },
    )

    return finding