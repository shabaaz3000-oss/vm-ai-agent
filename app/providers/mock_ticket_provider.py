from __future__ import annotations

from typing import Any

from app.models import TicketDraft
from app.ticket_execution_context import (
    TicketExecutionContext,
)
from app.ticketing import create_mock_ticket


class MockTicketProvider:
    """
    Compatibility adapter for the existing portfolio/demo
    ticket implementation.

    The mock side effect has no tenant-specific external
    routing destination. A trusted execution context may be
    supplied by the common provider boundary, but it is not
    used to derive mock ticket authority.
    """

    provider_name = "mock"

    def create_ticket(
        self,
        *,
        ticket: TicketDraft,
        approval: dict[str, Any],
        execution_context:
            TicketExecutionContext | None = None,
    ) -> dict[str, Any]:

        del execution_context

        return create_mock_ticket(
            ticket=ticket,
            approval=approval,
        )

    def close(
        self,
    ) -> None:
        """
        The JSONL-backed mock provider owns no persistent
        network resources.
        """

        return None
