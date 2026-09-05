from fastapi import HTTPException

from app.auth import Principal
from app.audit import log_event
from app.loaders import load_threat_intel
from app.models import ThreatIntel

from app.tools.authorization import require_tool_permission


# -------------------------------------------------
# GET THREAT INTELLIGENCE TOOL
# -------------------------------------------------


def get_threat_intel(
    principal: Principal,
) -> ThreatIntel:

    log_event(
        "TOOL_REQUESTED",
        {
            "tool": "get_threat_intel",
            "username": principal.username,
            "role": principal.role,
        },
    )

    try:

        require_tool_permission(
            principal=principal,
            tool_name="get_threat_intel",
        )

    except HTTPException:

        log_event(
            "TOOL_ACCESS_DENIED",
            {
                "tool": "get_threat_intel",
                "username": principal.username,
                "role": principal.role,
            },
        )

        raise

    threat_intel = load_threat_intel()

    log_event(
        "TOOL_EXECUTED",
        {
            "tool": "get_threat_intel",
            "username": principal.username,
            "role": principal.role,
        },
    )

    return threat_intel