from __future__ import annotations

from dataclasses import dataclass


@dataclass(
    frozen=True,
    slots=True,
)
class TicketExecutionContext:
    """
    Immutable execution metadata produced only after the
    authoritative workflow tenant boundary has been validated.

    This object transfers trusted application state to an
    external provider. It is not itself an authentication
    mechanism and must never be populated from model, MCP,
    ticket, approval, or HTTP request data.
    """

    tenant_id: str
    workflow_id: str
    execution_attempt_id: str | None = None

    def __post_init__(
        self,
    ) -> None:

        for (
            field_name,
            value,
        ) in (
            (
                "tenant_id",
                self.tenant_id,
            ),
            (
                "workflow_id",
                self.workflow_id,
            ),
        ):

            if (
                not isinstance(
                    value,
                    str,
                )
                or not value.strip()
                or value
                != value.strip()
            ):

                raise ValueError(
                    f"{field_name} must be "
                    "a non-blank normalized string."
                )

        if (
            self.execution_attempt_id
            is not None
        ):

            value = (
                self.execution_attempt_id
            )

            if (
                not isinstance(
                    value,
                    str,
                )
                or not value.strip()
                or value
                != value.strip()
            ):

                raise ValueError(
                    "execution_attempt_id must be "
                    "None or a non-blank "
                    "normalized string."
                )
