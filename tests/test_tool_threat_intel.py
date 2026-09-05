import pytest

from fastapi import HTTPException
from fastapi import status

from app.auth import Principal

from app.tools import threat_intel


# -------------------------------------------------
# ANALYST CAN USE GET THREAT INTEL TOOL
# -------------------------------------------------


def test_analyst_can_get_threat_intel(
    monkeypatch,
):

    principal = Principal(
        username="test-analyst",
        role="ANALYST",
    )

    expected_threat_intel = object()

    monkeypatch.setattr(
        threat_intel,
        "load_threat_intel",
        lambda: expected_threat_intel,
    )

    monkeypatch.setattr(
        threat_intel,
        "log_event",
        lambda *args, **kwargs: None,
    )

    result = threat_intel.get_threat_intel(
        principal=principal,
    )

    assert result is expected_threat_intel


# -------------------------------------------------
# APPROVER CAN USE GET THREAT INTEL TOOL
# -------------------------------------------------


def test_approver_can_get_threat_intel(
    monkeypatch,
):

    principal = Principal(
        username="test-approver",
        role="APPROVER",
    )

    expected_threat_intel = object()

    monkeypatch.setattr(
        threat_intel,
        "load_threat_intel",
        lambda: expected_threat_intel,
    )

    monkeypatch.setattr(
        threat_intel,
        "log_event",
        lambda *args, **kwargs: None,
    )

    result = threat_intel.get_threat_intel(
        principal=principal,
    )

    assert result is expected_threat_intel


# -------------------------------------------------
# DENIED TOOL DOES NOT LOAD THREAT INTEL
# -------------------------------------------------


def test_denied_tool_does_not_load_threat_intel(
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

    def fake_load_threat_intel():

        nonlocal loader_called

        loader_called = True

        return object()

    monkeypatch.setattr(
        threat_intel,
        "require_tool_permission",
        deny_tool,
    )

    monkeypatch.setattr(
        threat_intel,
        "load_threat_intel",
        fake_load_threat_intel,
    )

    monkeypatch.setattr(
        threat_intel,
        "log_event",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(
        HTTPException
    ) as exc_info:

        threat_intel.get_threat_intel(
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


def test_get_threat_intel_is_audited(
    monkeypatch,
):

    principal = Principal(
        username="test-analyst",
        role="ANALYST",
    )

    events = []

    monkeypatch.setattr(
        threat_intel,
        "load_threat_intel",
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
        threat_intel,
        "log_event",
        fake_log_event,
    )

    threat_intel.get_threat_intel(
        principal=principal,
    )

    event_names = [
        event[0]
        for event in events
    ]

    assert "TOOL_REQUESTED" in event_names

    assert "TOOL_EXECUTED" in event_names