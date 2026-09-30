from __future__ import annotations

from typing import Any

from app.approval import consume_approval
from app.models import TicketDraft

from app.providers.servicenow_client import (
    ServiceNowClient,
)

from app.providers.servicenow_routing import (
    ServiceNowRoutingPolicy,
    normalize_assignment_group_sys_id,
)

from app.ticket_execution_context import (
    TicketExecutionContext,
)


class ServiceNowTicketProvider:
    """
    Production ServiceNow ticket provider.

    This provider maps an already-authorized TicketDraft and
    trusted TicketExecutionContext to a tightly controlled
    ServiceNow payload.

    It does NOT establish workflow, approval, identity, tenant,
    priority, or provider-selection authority.

    ServiceNow assignment routing is resolved exclusively from
    the server-owned ServiceNowRoutingPolicy using the trusted
    execution tenant. TicketDraft.assignment_group is never a
    production routing authority.
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
        routing_policy:
            ServiceNowRoutingPolicy,
    ) -> None:

        if not isinstance(
            routing_policy,
            ServiceNowRoutingPolicy,
        ):

            raise TypeError(
                "ServiceNowRoutingPolicy is required."
            )

        self._client = client

        self._routing_policy = (
            routing_policy
        )

    @staticmethod
    def _build_description(
        ticket: TicketDraft,
    ) -> str:

        validation_steps = "\n".join(
            f"- {step}"
            for step
            in ticket.validation_steps
        )

        return (
            f"{ticket.description}\n\n"
            "Security Context\n"
            f"Asset: {ticket.asset_name}\n"
            f"CVE: {ticket.cve}\n"
            f"Risk Rating: "
            f"{ticket.risk_rating}\n"
            f"Risk Score: "
            f"{ticket.risk_score}\n"
            f"SLA Hours: "
            f"{ticket.sla_hours}\n\n"
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
        assignment_group_sys_id: str,
        correlation_id: str,
    ) -> dict[str, Any]:

        normalized_correlation_id = (
            correlation_id.strip()
        )

        if not normalized_correlation_id:

            raise ValueError(
                "ServiceNow correlation_id "
                "cannot be blank."
            )

        trusted_assignment_group = (
            normalize_assignment_group_sys_id(
                assignment_group_sys_id
            )
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
                trusted_assignment_group,

            "correlation_id":
                normalized_correlation_id,
        }

        unexpected_fields = (
            set(
                payload
            )
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
        execution_context:
            TicketExecutionContext | None = None,
    ) -> dict[str, Any]:

        if not isinstance(
            execution_context,
            TicketExecutionContext,
        ):

            raise PermissionError(
                "Trusted ticket execution context "
                "is required for ServiceNow routing."
            )

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

        # Resolve trusted tenant routing before consuming the
        # one-time approval. Configuration/routing failures
        # therefore cannot burn an approval without an
        # attempted external side effect.

        assignment_group_sys_id = (
            self._routing_policy
            .resolve_assignment_group(
                execution_context
                .tenant_id
            )
        )

        payload = self.build_payload(
            ticket=ticket,
            assignment_group_sys_id=
                assignment_group_sys_id,
            correlation_id=
                approval_id,
        )

        # Consume the exact-ticket approval immediately before
        # the external ServiceNow side effect.

        if not consume_approval(
            ticket=ticket,
            approval=approval,
        ):

            raise PermissionError(
                "Valid application-issued approval "
                "is required before ServiceNow "
                "ticket creation."
            )

        result = self._client.create_record(
            payload
        )

        return {
            **ticket.model_dump(),

            # Authoritative external routing metadata is
            # written after model_dump() so the generic
            # TicketDraft display value cannot overwrite it.

            "assignment_group":
                assignment_group_sys_id,

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
        }

    def close(
        self,
    ) -> None:
        """
        Release the underlying HTTP client.
        """

        self._client.close()
