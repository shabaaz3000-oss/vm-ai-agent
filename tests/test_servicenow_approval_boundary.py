from __future__ import annotations

import pytest

from app.approval import create_approval
from app.models import TicketDraft
from app.providers.servicenow_ticket_provider import (
    ServiceNowTicketProvider,
)


class RecordingClient:

    def __init__(self):
        self.calls = []

    def create_record(
        self,
        payload,
    ):
        self.calls.append(
            dict(payload)
        )

        return {
            "sys_id":
                "0123456789abcdef0123456789abcdef",

            "number":
                "INC0012345",
        }

    def close(
        self,
    ):
        return None


def ticket() -> TicketDraft:

    return TicketDraft(
        short_description=
            "Patch critical vulnerability",

        priority=
            "P1",

        asset_name=
            "server01",

        cve=
            "CVE-2026-12345",

        assignment_group=
            "Vulnerability Management",

        risk_rating=
            "CRITICAL",

        risk_score=
            98,

        sla_hours=
            24,

        description=
            "Critical vulnerability requires remediation.",

        remediation=
            "Apply the vendor security update.",

        validation_steps=[
            "Confirm package version.",
            "Run authenticated vulnerability scan.",
        ],
    )


def test_real_application_approval_is_consumed_before_servicenow_post():

    candidate = ticket()

    approval = create_approval(
        ticket=candidate,
        approved_by=
            "security.approver",
    )

    client = RecordingClient()

    provider = ServiceNowTicketProvider(
        client
    )

    result = provider.create_ticket(
        ticket=candidate,
        approval=approval,
    )

    assert (
        result["ticket_id"]
        == "INC0012345"
    )

    assert len(
        client.calls
    ) == 1

    # The same one-time application approval cannot be
    # replayed for a second external action.
    with pytest.raises(
        PermissionError,
        match="application-issued approval",
    ):

        provider.create_ticket(
            ticket=candidate,
            approval=approval,
        )

    assert len(
        client.calls
    ) == 1


def test_forged_nonblank_approval_id_cannot_reach_http_client():

    client = RecordingClient()

    provider = ServiceNowTicketProvider(
        client
    )

    with pytest.raises(
        PermissionError,
        match="application-issued approval",
    ):

        provider.create_ticket(
            ticket=ticket(),
            approval={
                "approval_id":
                    "APR-FORGED123",
            },
        )

    assert (
        client.calls
        == []
    )


def test_approval_bound_to_different_ticket_cannot_reach_http_client():

    approved_ticket = ticket()

    approval = create_approval(
        ticket=approved_ticket,
        approved_by=
            "security.approver",
    )

    modified_ticket = (
        TicketDraft.model_validate(
            {
                **approved_ticket.model_dump(),

                "short_description":
                    "Attacker-modified ticket",
            }
        )
    )

    client = RecordingClient()

    provider = ServiceNowTicketProvider(
        client
    )

    with pytest.raises(
        PermissionError,
        match="application-issued approval",
    ):

        provider.create_ticket(
            ticket=modified_ticket,
            approval=approval,
        )

    assert (
        client.calls
        == []
    )


def test_provider_cleanup_closes_http_client():

    class ClosableClient(
        RecordingClient
    ):

        def __init__(self):
            super().__init__()
            self.closed = False

        def close(self):
            self.closed = True

    client = ClosableClient()

    provider = ServiceNowTicketProvider(
        client
    )

    provider.close()

    assert client.closed is True
