import inspect

import pytest

from fastapi import HTTPException
from fastapi import status

from app.auth import Principal

from app.tools import ticketing


# -------------------------------------------------
# ANALYST CANNOT EXECUTE WORKFLOW
# -------------------------------------------------


def test_analyst_cannot_execute_ticket_workflow(
    monkeypatch,
):

    principal = Principal(
        username="test-analyst",
        role="ANALYST",
    )

    execution_called = False

    def fake_execute(
        workflow_id,
        approved_by,
    ):

        nonlocal execution_called

        execution_called = True

        return object()

    monkeypatch.setattr(
        ticketing,
        "claim_and_execute_workflow",
        fake_execute,
    )

    monkeypatch.setattr(
        ticketing,
        "log_event",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(
        HTTPException
    ) as exc_info:

        ticketing.execute_ticket_workflow(
            principal=principal,
            workflow_id="WF-TEST1234",
        )

    assert (
        exc_info.value.status_code
        == status.HTTP_403_FORBIDDEN
    )

    assert execution_called is False


# -------------------------------------------------
# APPROVER IDENTITY IS BOUND TO EXECUTION
# -------------------------------------------------


def test_approver_identity_is_used_for_execution(
    monkeypatch,
):

    principal = Principal(
        username="test-approver",
        role="APPROVER",
    )

    received = {}

    class FakeResult:

        workflow_id = "WF-TEST1234"
        status = "TICKET_CREATED"
        ticket_id = "VM-12345678"

    result = FakeResult()

    def fake_execute(
        workflow_id,
        approved_by,
    ):

        received[
            "workflow_id"
        ] = workflow_id

        received[
            "approved_by"
        ] = approved_by

        return result

    monkeypatch.setattr(
        ticketing,
        "claim_and_execute_workflow",
        fake_execute,
    )

    monkeypatch.setattr(
        ticketing,
        "update_workflow",
        lambda result: result,
    )

    monkeypatch.setattr(
        ticketing,
        "log_event",
        lambda *args, **kwargs: None,
    )

    ticketing.execute_ticket_workflow(
        principal=principal,
        workflow_id="WF-TEST1234",
    )

    assert (
        received["workflow_id"]
        == "WF-TEST1234"
    )

    assert (
        received["approved_by"]
        == "test-approver"
    )


# -------------------------------------------------
# SUCCESSFUL EXECUTION IS PERSISTED
# -------------------------------------------------


def test_successful_execution_is_persisted(
    monkeypatch,
):

    principal = Principal(
        username="test-approver",
        role="APPROVER",
    )

    persisted = []

    class FakeResult:

        workflow_id = "WF-TEST1234"
        status = "TICKET_CREATED"
        ticket_id = "VM-12345678"

    result = FakeResult()

    monkeypatch.setattr(
        ticketing,
        "claim_and_execute_workflow",
        lambda **kwargs: result,
    )

    def fake_update_workflow(
        workflow_result,
    ):

        persisted.append(
            workflow_result
        )

        return workflow_result

    monkeypatch.setattr(
        ticketing,
        "update_workflow",
        fake_update_workflow,
    )

    monkeypatch.setattr(
        ticketing,
        "log_event",
        lambda *args, **kwargs: None,
    )

    returned = (
        ticketing
        .execute_ticket_workflow(
            principal=principal,
            workflow_id="WF-TEST1234",
        )
    )

    assert persisted == [
        result
    ]

    assert returned is result


# -------------------------------------------------
# BLANK WORKFLOW ID DOES NOT EXECUTE
# -------------------------------------------------


def test_blank_workflow_id_does_not_execute(
    monkeypatch,
):

    principal = Principal(
        username="test-approver",
        role="APPROVER",
    )

    execution_called = False

    def fake_execute(
        **kwargs,
    ):

        nonlocal execution_called

        execution_called = True

        return object()

    monkeypatch.setattr(
        ticketing,
        "claim_and_execute_workflow",
        fake_execute,
    )

    monkeypatch.setattr(
        ticketing,
        "log_event",
        lambda *args, **kwargs: None,
    )

    with pytest.raises(
        ValueError
    ):

        ticketing.execute_ticket_workflow(
            principal=principal,
            workflow_id="   ",
        )

    assert execution_called is False


# -------------------------------------------------
# FAILED EXECUTION IS AUDITED
# -------------------------------------------------


def test_failed_execution_is_audited(
    monkeypatch,
):

    principal = Principal(
        username="test-approver",
        role="APPROVER",
    )

    events = []

    def fake_execute(
        **kwargs,
    ):

        raise PermissionError(
            "Execution blocked."
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
        ticketing,
        "claim_and_execute_workflow",
        fake_execute,
    )

    monkeypatch.setattr(
        ticketing,
        "log_event",
        fake_log_event,
    )

    with pytest.raises(
        PermissionError
    ):

        ticketing.execute_ticket_workflow(
            principal=principal,
            workflow_id="WF-TEST1234",
        )

    event_names = [
        event
        for event, data in events
    ]

    assert (
        "TOOL_EXECUTION_FAILED"
        in event_names
    )


# -------------------------------------------------
# TOOL CANNOT ACCEPT ARBITRARY TICKET FIELDS
# -------------------------------------------------


def test_execution_tool_accepts_only_identity_and_workflow():

    signature = inspect.signature(
        ticketing.execute_ticket_workflow
    )

    assert list(
        signature.parameters
    ) == [
        "principal",
        "workflow_id",
    ]