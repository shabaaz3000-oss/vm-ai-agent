from fastapi import HTTPException

from app.auth import Principal
from app.audit import log_event
from app.loaders import load_asset
from app.models import AssetContext

from app.tools.authorization import require_tool_permission


# -------------------------------------------------
# GET ASSET DETAILS TOOL
# -------------------------------------------------


def get_asset_details(
    principal: Principal,
) -> AssetContext:

    log_event(
        "TOOL_REQUESTED",
        {
            "tool": "get_asset_details",
            "username": principal.username,
            "role": principal.role,
        },
    )

    try:

        require_tool_permission(
            principal=principal,
            tool_name="get_asset_details",
        )

    except HTTPException:

        log_event(
            "TOOL_ACCESS_DENIED",
            {
                "tool": "get_asset_details",
                "username": principal.username,
                "role": principal.role,
            },
        )

        raise

    asset = load_asset()

    log_event(
        "TOOL_EXECUTED",
        {
            "tool": "get_asset_details",
            "username": principal.username,
            "role": principal.role,
        },
    )

    return asset