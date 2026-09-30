from __future__ import annotations

from typing import Any
from typing import Protocol
from typing import runtime_checkable

from app.models import TicketDraft
from app.ticket_execution_context import (
    TicketExecutionContext,
)


@runtime_checkable
class TicketProvider(Protocol):
    """
    Contract for controlled external ticket providers.

    Implementations operate below workflow authorization,
    human approval issuance, identity authority, tenant
    authority, deterministic risk calculation, and ticket
    construction.

    A provider may enforce application-issued approval before
    its side effect, but it must never establish approval or
    derive security authority from caller-controlled input.

    Tenant-sensitive production providers may additionally
    require trusted TicketExecutionContext supplied by the
    authoritative workflow execution boundary.
    """

    provider_name: str

    def create_ticket(
        self,
        *,
        ticket: TicketDraft,
        approval: dict[str, Any],
        execution_context:
            TicketExecutionContext | None = None,
    ) -> dict[str, Any]:
        """
        Execute the provider-specific ticket side effect.
        """

        ...

    def close(
        self,
    ) -> None:
        """
        Release provider-owned resources.

        Implementations without persistent resources should
        provide a no-op implementation.
        """

        ...
