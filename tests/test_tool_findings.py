import pytest

from fastapi import HTTPException
from fastapi import status

from app.auth import Principal

from app.tools import findings


# -------------------------------------------------
# ANALYST CAN USE GET FINDING TOOL
# -------------------------------------------------


def test_analyst_can_get_finding(
    monkeypatch,
):

    principal = Principal(
        username="test-analyst",
        role="ANALYST",
    )

    expected_finding = object()

    monkeypatch.setattr(
        findings,
        "load_finding",
        lambda: expected_finding,
    )

    monkeypatch.setattr(
        findings,
        "log_event",
        lambda *args, **kwargs: None,
    )

    result = findings.get_finding(
        principal=principal,
    )

    assert result is expected_finding


# -------------------------------------------------
# APPROVER CAN USE GET FINDING TOOL
# -------------------------------------------------


def test_approver_can_get_finding(
    monkeypatch,
):

    principal = Principal(
        username="test-approver",
        role="APPROVER",
    )

    expected_finding = object()

    monkeypatch.setattr(
        findings,
        "load_finding",
        lambda: expected_finding,
    )

    monkeypatch.setattr(
        findings,
        "log_event",
        lambda *args, **kwargs: None,
    )

    result = findings.get_finding(
        principal=principal,
    )

    assert result is expected_finding


# -------------------------------------------------
# DENIED TOOL DOES NOT LOAD FINDING
# -------------------------------------------------


def test_denied_tool_does_not_load_finding(
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

    def fake_load_finding():

        nonlocal loader_called

        loader_called = True

        return object()

    monkeypatch.setattr(
        findings,
        "require_tool_permission",
        deny_tool,
    )

    monkeypatch.setattr(
        findings,
        "load_finding",
        fake_load_finding,
    )

    monkeypatch.setattr(
        findings,
        "log_event",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(
        HTTPException
    ) as exc_info:

        findings.get_finding(
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


def test_get_finding_is_audited(
    monkeypatch,
):

    principal = Principal(
        username="test-analyst",
        role="ANALYST",
    )

    events = []

    monkeypatch.setattr(
        findings,
        "load_finding",
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
        findings,
        "log_event",
        fake_log_event,
    )

    findings.get_finding(
        principal=principal,
    )

    event_names = [
        event[0]
        for event in events
    ]

    assert "TOOL_REQUESTED" in event_names

    assert "TOOL_EXECUTED" in event_names