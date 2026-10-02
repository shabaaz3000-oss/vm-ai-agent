from datetime import datetime
from typing import Protocol

from app.models import WorkflowResult
from app.security_context import SecurityContext


class WorkflowStore(Protocol):
    """
    Persistence authority required by workflow execution.

    Implementations must preserve the workflow state machine,
    atomic claim semantics, tenant authorization checks, execution
    attempt provenance, and fail-closed reconciliation behavior.
    """

    def save_workflow(
        self,
        result: WorkflowResult,
    ) -> WorkflowResult:
        ...

    def get_workflow(
        self,
        workflow_id: str,
    ) -> WorkflowResult:
        ...


    def claim_workflow_for_execution(
        self,
        workflow_id: str,
        *,
        security_context: SecurityContext | None = None,
    ) -> WorkflowResult:
        ...

    def complete_workflow_execution(
        self,
        workflow_id: str,
        *,
        expected_execution_attempt_id: str,
        approval_id: str,
        ticket_id: str,
        security_context: SecurityContext | None = None,
    ) -> WorkflowResult:
        ...

    def reject_workflow_authoritatively(
        self,
        workflow_id: str,
        *,
        security_context: SecurityContext | None = None,
    ) -> WorkflowResult:
        ...

    def mark_workflow_needs_review(self, workflow_id: str, reason: str, *, expected_execution_attempt_id: str, security_context: SecurityContext | None=None) -> WorkflowResult:
        ...

    def mark_stale_processing_for_review(
        self,
        workflow_id: str,
        stale_after_seconds: int = 300,
        now: datetime | None = None,
    ) -> WorkflowResult:
        ...

    def clear_workflows(
        self,
    ) -> None:
        ...

    def confirm_reconciled_ticket_creation(
        self,
        workflow_id: str,
        *,
        expected_execution_attempt_id: str,
        ticket_id: str,
        security_context: SecurityContext,
    ) -> WorkflowResult:
        ...

    def authorize_reconciled_retry(
        self,
        workflow_id: str,
        *,
        expected_execution_attempt_id: str,
        security_context: SecurityContext,
    ) -> WorkflowResult:
        ...
