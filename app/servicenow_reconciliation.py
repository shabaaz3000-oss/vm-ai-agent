from __future__ import annotations

import os

from dataclasses import dataclass
from typing import Literal

from app.providers.servicenow_client import (
    ServiceNowClient,
)

from app.providers.servicenow_config import (
    ServiceNowSettings,
)

from app.providers.servicenow_correlation import (
    build_servicenow_correlation_id,
)

from app.security_context import (
    SecurityContext,
)

from app.ticket_execution_context import (
    TicketExecutionContext,
)

from app.workflow_store import (
    authorize_reconciled_retry,
    confirm_reconciled_ticket_creation,
    get_workflow,
)

from app.workflow_tenant import (
    require_workflow_tenant,
)


class ServiceNowReconciliationError(
    PermissionError
):
    """
    Raised when a workflow is not eligible for trusted
    ServiceNow reconciliation.
    """


@dataclass(
    frozen=True,
    slots=True,
)
class ServiceNowReconciliationResult:

    workflow_id: str

    execution_attempt_id: str

    outcome: Literal[
        "NOT_FOUND",
        "CONFIRMED",
        "CONFLICT",
    ]

    correlation_id: str

    match_count: int

    ticket_number: str | None = None

    external_sys_id: str | None = None


def _build_servicenow_reconciliation_client(
) -> ServiceNowClient:
    """
    Construct the read-only reconciliation client exclusively
    from server-owned process configuration.
    """

    provider_name = (
        os.environ.get(
            "TICKET_PROVIDER",
            "mock",
        )
        .strip()
        .lower()
    )

    if provider_name != "servicenow":

        raise ServiceNowReconciliationError(
            "ServiceNow reconciliation is available "
            "only when the server-selected ticket "
            "provider is servicenow."
        )

    settings = (
        ServiceNowSettings
        .from_environment()
    )

    return ServiceNowClient(
        settings
    )


def reconcile_servicenow_workflow(
    workflow_id: str,
    *,
    security_context: SecurityContext,
) -> ServiceNowReconciliationResult:
    """
    Perform a read-only external reconciliation for one
    NEEDS_REVIEW workflow.

    This function does NOT retry ticket creation and does NOT
    mutate workflow state.

    A later explicit recovery decision must determine whether a
    confirmed external ticket should close the workflow or
    whether a NOT_FOUND result permits a controlled retry.
    """

    if (
        not isinstance(
            workflow_id,
            str,
        )
        or not workflow_id.strip()
        or workflow_id
        != workflow_id.strip()
    ):

        raise ValueError(
            "workflow_id must be a non-blank "
            "normalized string."
        )

    if not isinstance(
        security_context,
        SecurityContext,
    ):

        raise ServiceNowReconciliationError(
            "Trusted SecurityContext is required."
        )

    if security_context.role != "APPROVER":

        raise ServiceNowReconciliationError(
            "ServiceNow reconciliation requires "
            "APPROVER security context."
        )

    workflow = get_workflow(
        workflow_id
    )

    if workflow.status != "NEEDS_REVIEW":

        raise ServiceNowReconciliationError(
            "Only a NEEDS_REVIEW workflow can be "
            "reconciled with ServiceNow."
        )

    require_workflow_tenant(
        workflow,
        security_context=
            security_context,
    )

    if workflow.tenant_id is None:

        # require_workflow_tenant() already rejects this.
        # Retain an explicit guard for type narrowing and
        # defense in depth.

        raise ServiceNowReconciliationError(
            "Tenant-bound workflow is required."
        )

    execution_context = (
        TicketExecutionContext(
            tenant_id=
                workflow.tenant_id,

            workflow_id=
                workflow.workflow_id,

            execution_attempt_id=
                workflow.execution_attempt_id,
        )
    )

    correlation_id = (
        build_servicenow_correlation_id(
            execution_context
        )
    )

    client = (
        _build_servicenow_reconciliation_client()
    )

    try:

        records = (
            client
            .find_records_by_correlation_id(
                correlation_id
            )
        )

    finally:

        client.close()

    match_count = len(
        records
    )

    if match_count == 0:

        return ServiceNowReconciliationResult(
            workflow_id=
                workflow.workflow_id,

            execution_attempt_id=
                workflow.execution_attempt_id,

            outcome=
                "NOT_FOUND",

            correlation_id=
                correlation_id,

            match_count=
                0,
        )

    if match_count == 1:

        record = records[
            0
        ]

        return ServiceNowReconciliationResult(
            workflow_id=
                workflow.workflow_id,

            execution_attempt_id=
                workflow.execution_attempt_id,

            outcome=
                "CONFIRMED",

            correlation_id=
                correlation_id,

            match_count=
                1,

            ticket_number=
                record[
                    "number"
                ],

            external_sys_id=
                record[
                    "sys_id"
                ],
        )

    return ServiceNowReconciliationResult(
        workflow_id=
            workflow.workflow_id,

        execution_attempt_id=
            workflow.execution_attempt_id,

        outcome=
            "CONFLICT",

        correlation_id=
            correlation_id,

        match_count=
            match_count,
    )

def resolve_servicenow_workflow(
    workflow_id: str,
    *,
    security_context: SecurityContext,
):
    """
    Resolve one NEEDS_REVIEW workflow from fresh ServiceNow
    external truth.

    The caller controls only workflow identity and supplies the
    trusted SecurityContext. Outcome, correlation ID, ticket
    identifiers, tenant identity, and retry decision are never
    accepted as caller authority.
    """

    evidence = (
        reconcile_servicenow_workflow(
            workflow_id,
            security_context=
                security_context,
        )
    )

    if (
        evidence.workflow_id
        != workflow_id
    ):

        raise ServiceNowReconciliationError(
            "Reconciliation workflow identity "
            "does not match the requested workflow."
        )

    if (
        not isinstance(
            evidence.execution_attempt_id,
            str,
        )
        or not evidence.execution_attempt_id.strip()
        or evidence.execution_attempt_id
        != evidence.execution_attempt_id.strip()
    ):

        raise ServiceNowReconciliationError(
            "Reconciliation evidence does not "
            "contain a trusted execution attempt."
        )

    if (
        evidence.outcome
        == "CONFIRMED"
    ):

        if (
            evidence.match_count
            != 1
            or not isinstance(
                evidence.ticket_number,
                str,
            )
            or not evidence.ticket_number.strip()
            or evidence.ticket_number
            != evidence.ticket_number.strip()
            or not isinstance(
                evidence.external_sys_id,
                str,
            )
            or not evidence.external_sys_id.strip()
        ):

            raise ServiceNowReconciliationError(
                "Confirmed reconciliation evidence "
                "is incomplete or inconsistent."
            )

        return (
            confirm_reconciled_ticket_creation(
                workflow_id,
                expected_execution_attempt_id=
                    evidence.execution_attempt_id,
                ticket_id=
                    evidence.ticket_number,
                security_context=
                    security_context,
            )
        )

    if (
        evidence.outcome
        == "NOT_FOUND"
    ):

        if (
            evidence.match_count
            != 0
            or evidence.ticket_number
            is not None
            or evidence.external_sys_id
            is not None
        ):

            raise ServiceNowReconciliationError(
                "NOT_FOUND reconciliation evidence "
                "is inconsistent."
            )

        return (
            authorize_reconciled_retry(
                workflow_id,
                expected_execution_attempt_id=
                    evidence.execution_attempt_id,
                security_context=
                    security_context,
            )
        )

    if (
        evidence.outcome
        == "CONFLICT"
    ):

        if (
            evidence.match_count
            < 2
        ):

            raise ServiceNowReconciliationError(
                "CONFLICT reconciliation evidence "
                "is inconsistent."
            )

        raise ServiceNowReconciliationError(
            "ServiceNow reconciliation found "
            "multiple matching records. "
            "Workflow remains NEEDS_REVIEW "
            "and retry is forbidden."
        )

    raise ServiceNowReconciliationError(
        "Unknown ServiceNow reconciliation outcome."
    )
