from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from app.models import TicketDraft


@runtime_checkable
class TicketProvider(Protocol):
    """
    Contract for controlled external ticket creation.

    A TicketProvider is deliberately below the authoritative
    workflow, authorization, approval, and execution-claim
    boundaries.

    Implementations MUST NOT be treated as sources of:

    - workflow authorization
    - approval authority
    - ticket priority authority
    - assignment-routing authority
    - tenant authority
    - principal authority

    Those decisions remain application-controlled.

    The current approval argument is retained because the
    existing mock ticket path validates and consumes the
    application-issued approval immediately before its side
    effect.

    Production providers must eventually be invoked only
    through the same trusted execution boundary.
    """

    provider_name: str

    def create_ticket(
        self,
        *,
        ticket: TicketDraft,
        approval: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Create one external ticket for an already-authorized
        workflow execution.

        Implementations return a normalized ticket record.
        """
        ...
