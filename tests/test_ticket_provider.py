from __future__ import annotations

from typing import Any

import app.providers.mock_ticket_provider as mock_module

from app.providers.mock_ticket_provider import (
    MockTicketProvider,
)
from app.providers.ticket_provider import TicketProvider


def test_mock_ticket_provider_satisfies_contract():

    provider = MockTicketProvider()

    assert isinstance(
        provider,
        TicketProvider,
    )


def test_mock_ticket_provider_has_stable_provider_name():

    provider = MockTicketProvider()

    assert provider.provider_name == "mock"


def test_mock_ticket_provider_delegates_to_existing_secure_path(
    monkeypatch,
):

    provider = MockTicketProvider()

    ticket = object()

    approval = {
        "approval_id": "APR-TEST",
        "decision": "APPROVED",
        "approved_by": "security.approver",
        "approved_at": "2026-09-30T00:00:00+00:00",
        "ticket_fingerprint": "test-fingerprint",
    }

    expected_result = {
        "ticket_id": "VM-TEST",
        "status": "OPEN",
    }

    calls: list[
        tuple[
            object,
            dict[str, Any],
        ]
    ] = []

    def fake_create_mock_ticket(
        *,
        ticket,
        approval,
    ):

        calls.append(
            (
                ticket,
                approval,
            )
        )

        return expected_result

    monkeypatch.setattr(
        mock_module,
        "create_mock_ticket",
        fake_create_mock_ticket,
    )

    result = provider.create_ticket(
        ticket=ticket,
        approval=approval,
    )

    assert result == expected_result

    assert calls == [
        (
            ticket,
            approval,
        )
    ]


def test_mock_adapter_does_not_modify_ticket_or_approval(
    monkeypatch,
):

    provider = MockTicketProvider()

    ticket = object()

    approval = {
        "approval_id": "APR-IMMUTABLE-TEST",
        "decision": "APPROVED",
        "approved_by": "security.approver",
    }

    approval_before = dict(
        approval
    )

    observed = {}

    def fake_create_mock_ticket(
        *,
        ticket,
        approval,
    ):

        observed["ticket"] = ticket
        observed["approval"] = dict(
            approval
        )

        return {
            "ticket_id": "VM-NO-MUTATION",
            "status": "OPEN",
        }

    monkeypatch.setattr(
        mock_module,
        "create_mock_ticket",
        fake_create_mock_ticket,
    )

    provider.create_ticket(
        ticket=ticket,
        approval=approval,
    )

    assert approval == approval_before

    assert observed["ticket"] is ticket

    assert observed["approval"] == approval_before
