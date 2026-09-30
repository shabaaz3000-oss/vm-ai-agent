from __future__ import annotations

from typing import Any

from app.models import TicketDraft
from app.ticketing import create_mock_ticket


class MockTicketProvider:
    """
    Compatibility adapter for the existing portfolio/demo
    ticket implementation.

    This adapter intentionally delegates to create_mock_ticket
    instead of duplicating its security checks.

    As a result, the existing trusted approval validation,
    one-time approval consumption, JSONL persistence behavior,
    and ticket-record shape remain unchanged.
    """

    provider_name = "mock"

    def create_ticket(
        self,
        *,
        ticket: TicketDraft,
        approval: dict[str, Any],
    ) -> dict[str, Any]:

        return create_mock_ticket(
            ticket=ticket,
            approval=approval,
        )
