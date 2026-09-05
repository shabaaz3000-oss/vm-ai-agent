import pytest

from fastapi import HTTPException
from fastapi import status

from app.auth import Principal

from app.tools import assets


# -------------------------------------------------
# ANALYST CAN USE GET ASSET DETAILS TOOL
# -------------------------------------------------


def test_analyst_can_get_asset_details(
    monkeypatch,
):

    principal = Principal(
        username="test-analyst",
        role="ANALYST",
    )

    expected_asset = object()

    monkeypatch.setattr(
        assets,
        "load_asset",
        lambda: expected_asset,
    )

    monkeypatch.setattr(
        assets,
        "log_event",
        lambda *args, **kwargs: None,
    )

    result = assets.get_asset_details(
        principal=principal,
    )

    assert result is expected_asset


# -------------------------------------------------
# APPROVER CAN USE GET ASSET DETAILS TOOL
# -------------------------------------------------


def test_approver_can_get_asset_details(
    monkeypatch,
):

    principal = Principal(
        username="test-approver",
        role="APPROVER",
    )

    expected_asset = object()

    monkeypatch.setattr(
        assets,
        "load_asset",
        lambda: expected_asset,
    )

    monkeypatch.setattr(
        assets,
        "log_event",
        lambda *args, **kwargs: None,
    )

    result = assets.get_asset_details(
        principal=principal,
    )

    assert result is expected_asset


# -------------------------------------------------
# DENIED TOOL DOES NOT LOAD ASSET
# -------------------------------------------------


def test_denied_tool_does_not_load_asset(
    monkeypatch,
):

    principal = Principal(
        username="test-analyst",
        role="ANALYST",
    )

    loader_called = False

    def deny_tool(
        principal,
        tool_name,
    ):

        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            detail="Denied",
        )

    def fake_load_asset():

        nonlocal loader_called

        loader_called = True

        return object()

    monkeypatch.setattr(
        assets,
        "require_tool_permission",
        deny_tool,
    )

    monkeypatch.setattr(
        assets,
        "load_asset",
        fake_load_asset,
    )

    monkeypatch.setattr(
        assets,
        "log_event",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(
        HTTPException
    ) as exc_info:

        assets.get_asset_details(
            principal=principal,
        )

    assert (
        exc_info.value.status_code
        == 403
    )

    assert loader_called is False


# -------------------------------------------------
# SUCCESSFUL TOOL CALL IS AUDITED
# -------------------------------------------------


def test_get_asset_details_is_audited(
    monkeypatch,
):

    principal = Principal(
        username="test-analyst",
        role="ANALYST",
    )

    events = []

    monkeypatch.setattr(
        assets,
        "load_asset",
        lambda: object(),
    )

    def fake_log_event(
        event,
        data=None,
    ):

        events.append(
            (
                event,
                data,
            )
        )

    monkeypatch.setattr(
        assets,
        "log_event",
        fake_log_event,
    )

    assets.get_asset_details(
        principal=principal,
    )

    event_names = [
        event[0]
        for event in events
    ]

    assert "TOOL_REQUESTED" in event_names

    assert "TOOL_EXECUTED" in event_names