from __future__ import annotations

from typing import Any

from app.models import TicketDraft
from app.providers.servicenow_client import (
    ServiceNowClient,
)


class ServiceNowTicketProvider:
    """
    Production ServiceNow ticket provider.

    This provider is intentionally responsible only for mapping
    an already-authorized TicketDraft to a tightly controlled
    ServiceNow payload and submitting it through the hardened
    ServiceNow client.

    It does NOT establish approval, workflow, identity, tenant,
    priority, assignment-group, or execution authority.
    """

    provider_name = "servicenow"

    _ALLOWED_PAYLOAD_FIELDS = frozenset(
        {
            "short_description",
            "description",
            "priority",
            "assignment_group",
            "correlation_id",
        }
    )

    def __init__(
        self,
        client: ServiceNowClient,
    ) -> None:

        self._client = client

    @staticmethod
    def _build_description(
        ticket: TicketDraft,
    ) -> str:

        validation_steps = "\n".join(
            f"- {step}"
            for step in ticket.validation_steps
        )

        return (
            f"{ticket.description}\n\n"
            "Security Context\n"
            f"Asset: {ticket.asset_name}\n"
            f"CVE: {ticket.cve}\n"
            f"Risk Rating: {ticket.risk_rating}\n"
            f"Risk Score: {ticket.risk_score}\n"
            f"SLA Hours: {ticket.sla_hours}\n\n"
            "Remediation\n"
            f"{ticket.remediation}\n\n"
            "Validation Steps\n"
            f"{validation_steps}"
        )

    @classmethod
    def build_payload(
        cls,
        *,
        ticket: TicketDraft,
        correlation_id: str,
    ) -> dict[str, Any]:

        normalized_correlation_id = (
            correlation_id.strip()
        )

        if not normalized_correlation_id:
            raise ValueError(
                "ServiceNow correlation_id cannot be blank."
            )

        payload = {
            "short_description":
                ticket.short_description,

            "description":
                cls._build_description(
                    ticket
                ),

            "priority":
                {
                    "P1": "1",
                    "P2": "2",
                    "P3": "3",
                    "P4": "4",
                }[
                    ticket.priority
                ],

            "assignment_group":
                ticket.assignment_group,

            "correlation_id":
                normalized_correlation_id,
        }

        unexpected_fields = (
            set(payload)
            - cls._ALLOWED_PAYLOAD_FIELDS
        )

        if unexpected_fields:
            raise ValueError(
                "ServiceNow payload contains "
                "non-allowlisted fields."
            )

        return payload

    def create_ticket(
        self,
        *,
        ticket: TicketDraft,
        approval: dict[str, Any],
    ) -> dict[str, Any]:

        if not isinstance(
            approval,
            dict,
        ):
            raise TypeError(
                "approval must be a dictionary."
            )

        approval_id = approval.get(
            "approval_id"
        )

        if (
            not isinstance(
                approval_id,
                str,
            )
            or not approval_id.strip()
        ):
            raise ValueError(
                "A trusted approval_id is required."
            )

        payload = self.build_payload(
            ticket=ticket,
            correlation_id=
                approval_id,
        )

        result = self._client.create_record(
            payload
        )

        return {
            "ticket_id":
                result["number"],

            "external_sys_id":
                result["sys_id"],

            "status":
                "OPEN",

            "provider":
                self.provider_name,

            "approval_id":
                approval_id,

            **ticket.model_dump(),
        }
