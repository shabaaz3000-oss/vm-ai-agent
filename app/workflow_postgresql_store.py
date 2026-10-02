from __future__ import annotations

from datetime import datetime
from datetime import timezone

from uuid import uuid4

import psycopg

from app.models import WorkflowResult
from app.security_context import SecurityContext
from app.workflow_tenant import (
    require_workflow_tenant,
)
from app.security_observability_integrations import emit_postgresql_workflow_execution_claim_denied_security_event
from app.workflow_tenant import WorkflowTenantBindingError

from app.security_observability_integrations import emit_workflow_store_reconciliation_denied_security_event



class PostgreSQLWorkflowStore:
    """
    Shared PostgreSQL-backed workflow authority.

    Security-sensitive transitions lock the authoritative row
    with SELECT ... FOR UPDATE and then perform a conditional
    UPDATE before the transaction commits.

    This makes execution claims and reconciliation transitions
    authoritative across independent application instances.
    """

    def __init__(
        self,
        *,
        database_url: str,
        connect_timeout_seconds: int = 10,
    ) -> None:

        if (
            not isinstance(
                database_url,
                str,
            )
            or not database_url.strip()
            or database_url
            != database_url.strip()
        ):
            raise ValueError(
                "database_url must be a non-blank "
                "normalized string."
            )

        if not database_url.startswith(
            (
                "postgresql://",
                "postgres://",
            )
        ):
            raise ValueError(
                "database_url must use a PostgreSQL URL."
            )

        if connect_timeout_seconds <= 0:
            raise ValueError(
                "connect_timeout_seconds must be "
                "greater than zero."
            )

        self._database_url = (
            database_url
        )

        self._connect_timeout_seconds = (
            connect_timeout_seconds
        )

    @property
    def database_url(
        self,
    ) -> str:
        return self._database_url

    def _connect(
        self,
    ) -> psycopg.Connection:
        """
        Open one PostgreSQL connection for one authoritative
        workflow-store operation.
        """

        return psycopg.connect(
            self._database_url,
            connect_timeout=
                self._connect_timeout_seconds,
        )

    @staticmethod
    def _generate_execution_attempt_id(
    ) -> str:

        return (
            "EXEC-"
            + uuid4().hex[:8].upper()
        )

    @staticmethod
    def _utc_now(
    ) -> datetime:

        return datetime.now(
            timezone.utc
        )

    @staticmethod
    def _validate_reconciliation_transition_target(
        current: WorkflowResult,
        *,
        expected_execution_attempt_id: str,
        security_context: SecurityContext,
    ) -> None:

        if not isinstance(
            security_context,
            SecurityContext,
        ):
            emit_workflow_store_reconciliation_denied_security_event(
                source_component="workflow_postgresql_store",
                reason_code="security_binding_mismatch",
                workflow_id=current.workflow_id,
                tenant_id=current.tenant_id,
                execution_attempt_id=
                    current.execution_attempt_id,
            )

            raise PermissionError(
                "Trusted SecurityContext is required "
                "for reconciliation resolution."
            )

        if (
            security_context.role
            != "APPROVER"
        ):
            emit_workflow_store_reconciliation_denied_security_event(
                source_component="workflow_postgresql_store",
                reason_code="reconciliation_denied",
                workflow_id=current.workflow_id,
                tenant_id=current.tenant_id,
                execution_attempt_id=
                    current.execution_attempt_id,
            )

            raise PermissionError(
                "Reconciliation resolution requires "
                "APPROVER security context."
            )

        try:
            require_workflow_tenant(
                current,
                security_context=
                    security_context,
            )

        except WorkflowTenantBindingError:

            trusted_current_tenant = (
                current.tenant_id
                if (
                    isinstance(
                        current.tenant_id,
                        str,
                    )
                    and current.tenant_id.strip()
                    and current.tenant_id
                    == current.tenant_id.strip()
                )
                else None
            )

            trusted_context_tenant = (
                security_context.tenant_id
                if (
                    isinstance(
                        security_context.tenant_id,
                        str,
                    )
                    and security_context.tenant_id.strip()
                    and security_context.tenant_id
                    == security_context.tenant_id.strip()
                )
                else None
            )

            tenant_reason = (
                "cross_tenant"
                if (
                    trusted_current_tenant
                    is not None
                    and trusted_context_tenant
                    is not None
                    and trusted_current_tenant
                    != trusted_context_tenant
                )
                else "security_binding_mismatch"
            )

            emit_workflow_store_reconciliation_denied_security_event(
                source_component="workflow_postgresql_store",
                reason_code=tenant_reason,
                workflow_id=current.workflow_id,
                tenant_id=current.tenant_id,
                execution_attempt_id=
                    current.execution_attempt_id,
            )

            raise

        if (
            not isinstance(
                expected_execution_attempt_id,
                str,
            )
            or not
                expected_execution_attempt_id.strip()
            or expected_execution_attempt_id
            != expected_execution_attempt_id.strip()
        ):
            emit_workflow_store_reconciliation_denied_security_event(
                source_component="workflow_postgresql_store",
                reason_code="reconciliation_denied",
                workflow_id=current.workflow_id,
                tenant_id=current.tenant_id,
            )

            raise ValueError(
                "expected_execution_attempt_id must be "
                "a non-blank normalized string."
            )

        if (
            current.execution_attempt_id
            != expected_execution_attempt_id
        ):
            emit_workflow_store_reconciliation_denied_security_event(
                source_component="workflow_postgresql_store",
                reason_code="execution_attempt_mismatch",
                workflow_id=current.workflow_id,
                tenant_id=current.tenant_id,
                execution_attempt_id=
                    current.execution_attempt_id,
            )

            raise PermissionError(
                "Workflow execution attempt changed "
                "after reconciliation."
            )

    @staticmethod
    def _parse_workflow(
        payload: str,
    ) -> WorkflowResult:

        return (
            WorkflowResult
            .model_validate_json(
                payload
            )
        )

    @staticmethod
    def _require_workflow_id(
        workflow_id: str,
    ) -> None:

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

    def _select_for_update(
        self,
        connection: psycopg.Connection,
        workflow_id: str,
    ) -> tuple[str, str]:

        row = connection.execute(
            """
            SELECT
                status,
                payload

            FROM workflows

            WHERE workflow_id = %s

            FOR UPDATE
            """,
            (
                workflow_id,
            ),
        ).fetchone()

        if row is None:
            raise KeyError(
                f"Workflow not found: "
                f"{workflow_id}"
            )

        return (
            row[0],
            row[1],
        )

    # --------------------------------------------------------
    # BASIC PERSISTENCE
    # --------------------------------------------------------

    def save_workflow(
        self,
        result: WorkflowResult,
    ) -> WorkflowResult:
        """
        Create a new authoritative workflow row.

        Creation authority is insert-only. An existing workflow_id
        must never be overwritten through save_workflow().
        """

        payload = (
            result.model_dump_json()
        )

        with self._connect() as connection:

            cursor = connection.execute(
                """
                INSERT INTO workflows (
                    workflow_id,
                    status,
                    payload
                )
                VALUES (%s, %s, %s)

                ON CONFLICT(workflow_id)
                DO NOTHING
                """,
                (
                    result.workflow_id,
                    result.status,
                    payload,
                ),
            )

            if cursor.rowcount != 1:

                raise PermissionError(
                    "Workflow already exists; creation "
                    "authority cannot overwrite "
                    "authoritative state."
                )

        return result

    def get_workflow(
        self,
        workflow_id: str,
    ) -> WorkflowResult:

        with self._connect() as connection:

            row = connection.execute(
                """
                SELECT payload
                FROM workflows
                WHERE workflow_id = %s
                """,
                (
                    workflow_id,
                ),
            ).fetchone()

        if row is None:
            raise KeyError(
                f"Workflow not found: "
                f"{workflow_id}"
            )

        return self._parse_workflow(
            row[0]
        )


    # --------------------------------------------------------
    # DISTRIBUTED EXECUTION CLAIM
    # --------------------------------------------------------

    def claim_workflow_for_execution(
        self,
        workflow_id: str,
        *,
        security_context: SecurityContext | None = None,
    ) -> WorkflowResult:
        """
        Atomically claim an AWAITING_APPROVAL workflow.

        SELECT ... FOR UPDATE serializes competing application
        instances around the authoritative workflow row.

        Tenant authorization is evaluated after the lock is held
        and before the state transition is committed.
        """

        with self._connect() as connection:

            status, original_payload = (
                self._select_for_update(
                    connection,
                    workflow_id,
                )
            )

            if (
                status
                != "AWAITING_APPROVAL"
            ):
                emit_postgresql_workflow_execution_claim_denied_security_event(
                    reason=(
                        "execution_already_claimed"
                        if status == "PROCESSING"
                        else "workflow_transition_not_allowed"
                    ),
                )

                raise PermissionError(
                    "Workflow must be awaiting approval "
                    "before execution can be claimed."
                )

            current = (
                self._parse_workflow(
                    original_payload
                )
            )

            if current.tenant_id is not None:

                if security_context is None:
                    emit_postgresql_workflow_execution_claim_denied_security_event(
                        reason="security_binding_mismatch",
                        tenant_id=current.tenant_id,
                        workflow_id=current.workflow_id,
                    )

                    raise PermissionError(
                        "Tenant-bound workflow execution "
                        "requires trusted security context."
                    )

                try:
                    require_workflow_tenant(
                        current,
                        security_context=
                            security_context,
                    )
                except WorkflowTenantBindingError:
                    canonical_tenant_id = (
                        current.tenant_id
                        if (
                            isinstance(
                                current.tenant_id,
                                str,
                            )
                            and current.tenant_id.strip()
                            and current.tenant_id
                            == current.tenant_id.strip()
                        )
                        else None
                    )

                    emit_postgresql_workflow_execution_claim_denied_security_event(
                        reason=(
                            "cross_tenant"
                            if (
                                canonical_tenant_id
                                is not None
                                and canonical_tenant_id
                                != security_context.tenant_id
                            )
                            else "security_binding_mismatch"
                        ),
                        tenant_id=canonical_tenant_id,
                        workflow_id=current.workflow_id,
                    )

                    raise

            updated_data = (
                current.model_dump()
            )

            updated_data.update(
                {
                    "status":
                        "PROCESSING",

                    "execution_attempt_id":
                        self
                        ._generate_execution_attempt_id(),

                    "processing_started_at":
                        self._utc_now(),

                    "recovery_reason":
                        None,
                }
            )

            claimed = (
                WorkflowResult
                .model_validate(
                    updated_data
                )
            )

            cursor = connection.execute(
                """
                UPDATE workflows

                SET
                    status = %s,
                    payload = %s,
                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE
                    workflow_id = %s
                    AND status =
                        'AWAITING_APPROVAL'
                    AND payload = %s
                """,
                (
                    claimed.status,
                    claimed.model_dump_json(),
                    workflow_id,
                    original_payload,
                ),
            )

            if cursor.rowcount != 1:
                emit_postgresql_workflow_execution_claim_denied_security_event(
                    reason="execution_already_claimed",
                    tenant_id=current.tenant_id,
                    workflow_id=current.workflow_id,
                )

                raise PermissionError(
                    "Workflow execution has already "
                    "been claimed."
                )

        return claimed

    # --------------------------------------------------------
    # FAILURE / AMBIGUOUS-WRITE RECOVERY
    # --------------------------------------------------------

    def complete_workflow_execution(
        self,
        workflow_id: str,
        *,
        expected_execution_attempt_id: str,
        approval_id: str,
        ticket_id: str,
        security_context: SecurityContext | None = None,
    ) -> WorkflowResult:
        """
        Atomically complete the exact PROCESSING execution attempt.

        The authoritative row is locked before state, tenant, and
        execution-attempt authority are validated.
        """

        for field_name, value in (
            (
                "expected_execution_attempt_id",
                expected_execution_attempt_id,
            ),
            (
                "approval_id",
                approval_id,
            ),
            (
                "ticket_id",
                ticket_id,
            ),
        ):

            if (
                not isinstance(
                    value,
                    str,
                )
                or not value.strip()
                or value != value.strip()
            ):

                raise ValueError(
                    f"{field_name} must be a non-blank "
                    "normalized string."
                )

        with self._connect() as connection:

            status, original_payload = (
                self._select_for_update(
                    connection,
                    workflow_id,
                )
            )

            if status != "PROCESSING":

                raise PermissionError(
                    "Only a PROCESSING workflow can "
                    "be completed."
                )

            current = (
                self._parse_workflow(
                    original_payload
                )
            )

            if current.tenant_id is not None:

                if security_context is None:

                    raise PermissionError(
                        "Tenant-bound workflow completion "
                        "requires trusted security context."
                    )

                require_workflow_tenant(
                    current,
                    security_context=
                        security_context,
                )

            if (
                current.execution_attempt_id
                != expected_execution_attempt_id
            ):

                raise PermissionError(
                    "Workflow execution attempt changed."
                )

            updated_data = (
                current.model_dump()
            )

            updated_data.update(
                {
                    "status":
                        "TICKET_CREATED",

                    "approval_id":
                        approval_id,

                    "ticket_id":
                        ticket_id,

                    "recovery_reason":
                        None,
                }
            )

            completed = (
                WorkflowResult
                .model_validate(
                    updated_data
                )
            )

            cursor = connection.execute(
                """
                UPDATE workflows

                SET
                    status = %s,
                    payload = %s,
                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE
                    workflow_id = %s
                    AND status = 'PROCESSING'
                    AND payload = %s
                """,
                (
                    completed.status,
                    completed.model_dump_json(),
                    workflow_id,
                    original_payload,
                ),
            )

            if cursor.rowcount != 1:

                raise PermissionError(
                    "Workflow completion authority changed."
                )

        return completed

    def reject_workflow_authoritatively(
        self,
        workflow_id: str,
        *,
        security_context: SecurityContext | None = None,
    ) -> WorkflowResult:
        """
        Atomically reject an AWAITING_APPROVAL workflow.
        """

        with self._connect() as connection:

            status, original_payload = (
                self._select_for_update(
                    connection,
                    workflow_id,
                )
            )

            if status != "AWAITING_APPROVAL":

                raise PermissionError(
                    "Workflow must be awaiting approval "
                    "before it can be rejected."
                )

            current = (
                self._parse_workflow(
                    original_payload
                )
            )

            if current.tenant_id is not None:

                if security_context is None:

                    raise PermissionError(
                        "Tenant-bound workflow rejection "
                        "requires trusted security context."
                    )

                require_workflow_tenant(
                    current,
                    security_context=
                        security_context,
                )

            updated_data = (
                current.model_dump()
            )

            updated_data.update(
                {
                    "status":
                        "REJECTED",

                    "approval_id":
                        None,

                    "ticket_id":
                        None,
                }
            )

            rejected = (
                WorkflowResult
                .model_validate(
                    updated_data
                )
            )

            cursor = connection.execute(
                """
                UPDATE workflows

                SET
                    status = %s,
                    payload = %s,
                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE
                    workflow_id = %s
                    AND status =
                        'AWAITING_APPROVAL'
                    AND payload = %s
                """,
                (
                    rejected.status,
                    rejected.model_dump_json(),
                    workflow_id,
                    original_payload,
                ),
            )

            if cursor.rowcount != 1:

                raise PermissionError(
                    "Workflow rejection authority changed."
                )

        return rejected

    def mark_workflow_needs_review(
        self,
        workflow_id: str,
        reason: str,
        *,
        expected_execution_attempt_id: str,
        security_context: SecurityContext | None = None,
    ) -> WorkflowResult:

        if (
            not isinstance(
                reason,
                str,
            )
            or not reason.strip()
        ):

            raise ValueError(
                "Recovery reason cannot be blank."
            )

        if (
            not isinstance(
                expected_execution_attempt_id,
                str,
            )
            or not expected_execution_attempt_id.strip()
            or expected_execution_attempt_id
            != expected_execution_attempt_id.strip()
        ):

            raise ValueError(
                "expected_execution_attempt_id "
                "must be a non-blank normalized string."
            )

        with self._connect() as connection:

            status, original_payload = (
                self._select_for_update(
                    connection,
                    workflow_id,
                )
            )

            if status != "PROCESSING":

                raise PermissionError(
                    "Only a PROCESSING workflow can "
                    "be moved to NEEDS_REVIEW."
                )

            current = (
                self._parse_workflow(
                    original_payload
                )
            )

            if current.tenant_id is not None:

                if security_context is None:

                    raise PermissionError(
                        "Tenant-bound workflow recovery "
                        "requires trusted security context."
                    )

                require_workflow_tenant(
                    current,
                    security_context=
                        security_context,
                )

            if (
                current.execution_attempt_id
                != expected_execution_attempt_id
            ):

                raise PermissionError(
                    "Workflow execution attempt changed."
                )

            updated_data = (
                current.model_dump()
            )

            updated_data.update(
                {
                    "status":
                        "NEEDS_REVIEW",

                    "recovery_reason":
                        reason,
                }
            )

            review_result = (
                WorkflowResult
                .model_validate(
                    updated_data
                )
            )

            cursor = connection.execute(
                """
                UPDATE workflows
                SET
                    status = %s,
                    payload = %s,
                    updated_at =
                        CURRENT_TIMESTAMP
                WHERE
                    workflow_id = %s
                    AND status = 'PROCESSING'
                    AND payload = %s
                """,
                (
                    review_result.status,
                    review_result.model_dump_json(),
                    workflow_id,
                    original_payload,
                ),
            )

            if cursor.rowcount != 1:

                raise PermissionError(
                    "Workflow recovery authority changed."
                )

        return review_result

    def mark_stale_processing_for_review(
        self,
        workflow_id: str,
        stale_after_seconds: int = 300,
        now: datetime | None = None,
    ) -> WorkflowResult:

        if stale_after_seconds <= 0:
            raise ValueError(
                "stale_after_seconds must be greater "
                "than zero."
            )

        effective_now = (
            now
            if now is not None
            else self._utc_now()
        )

        if effective_now.tzinfo is None:
            effective_now = (
                effective_now.replace(
                    tzinfo=timezone.utc
                )
            )

        with self._connect() as connection:

            status, original_payload = (
                self._select_for_update(
                    connection,
                    workflow_id,
                )
            )

            if status != "PROCESSING":
                raise PermissionError(
                    "Workflow is not currently "
                    "PROCESSING."
                )

            current = (
                self._parse_workflow(
                    original_payload
                )
            )

            started_at = (
                current.processing_started_at
            )

            if started_at is None:
                raise PermissionError(
                    "PROCESSING workflow does not "
                    "contain a processing start time."
                )

            if started_at.tzinfo is None:
                started_at = (
                    started_at.replace(
                        tzinfo=timezone.utc
                    )
                )

            processing_age_seconds = (
                effective_now
                - started_at
            ).total_seconds()

            if (
                processing_age_seconds
                < stale_after_seconds
            ):
                raise PermissionError(
                    "Workflow is still within the "
                    "allowed processing window."
                )

            recovery_reason = (
                "Execution remained PROCESSING beyond "
                f"{stale_after_seconds} seconds. "
                "External action outcome must be "
                "reconciled before any retry."
            )

            updated_data = (
                current.model_dump()
            )

            updated_data.update(
                {
                    "status":
                        "NEEDS_REVIEW",

                    "recovery_reason":
                        recovery_reason,
                }
            )

            review_result = (
                WorkflowResult
                .model_validate(
                    updated_data
                )
            )

            cursor = connection.execute(
                """
                UPDATE workflows

                SET
                    status = %s,
                    payload = %s,
                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE
                    workflow_id = %s
                    AND status =
                        'PROCESSING'
                    AND payload = %s
                """,
                (
                    review_result.status,
                    review_result.model_dump_json(),
                    workflow_id,
                    original_payload,
                ),
            )

            if cursor.rowcount != 1:
                raise PermissionError(
                    "Workflow state changed before "
                    "stale recovery could complete."
                )

        return review_result

    # --------------------------------------------------------
    # PRODUCTION BULK DELETION BOUNDARY
    # --------------------------------------------------------

    def clear_workflows(
        self,
    ) -> None:
        """
        Runtime PostgreSQL identities deliberately do not receive
        DELETE authority. Destructive cleanup is a deployment /
        administrative responsibility, not an application-runtime
        capability.
        """

        raise PermissionError(
            "PostgreSQL runtime workflow authority "
            "does not permit bulk workflow deletion."
        )

    # --------------------------------------------------------
    # HUMAN RECONCILIATION ? CONFIRMED TICKET
    # --------------------------------------------------------

    def confirm_reconciled_ticket_creation(
        self,
        workflow_id: str,
        *,
        expected_execution_attempt_id: str,
        ticket_id: str,
        security_context: SecurityContext,
    ) -> WorkflowResult:

        self._require_workflow_id(
            workflow_id
        )

        if (
            not isinstance(
                ticket_id,
                str,
            )
            or not ticket_id.strip()
            or ticket_id
            != ticket_id.strip()
        ):
            raise ValueError(
                "ticket_id must be a non-blank "
                "normalized string."
            )

        with self._connect() as connection:

            status, original_payload = (
                self._select_for_update(
                    connection,
                    workflow_id,
                )
            )

            if status != "NEEDS_REVIEW":
                emit_workflow_store_reconciliation_denied_security_event(
                    source_component="workflow_postgresql_store",
                    reason_code="workflow_transition_not_allowed",
                )

                raise PermissionError(
                    "Only a NEEDS_REVIEW workflow can "
                    "be confirmed after reconciliation."
                )

            current = (
                self._parse_workflow(
                    original_payload
                )
            )

            self \
                ._validate_reconciliation_transition_target(
                    current,
                    expected_execution_attempt_id=
                        expected_execution_attempt_id,
                    security_context=
                        security_context,
                )

            if current.ticket_id is not None:
                emit_workflow_store_reconciliation_denied_security_event(
                    source_component="workflow_postgresql_store",
                    reason_code="reconciliation_denied",
                    workflow_id=current.workflow_id,
                    tenant_id=current.tenant_id,
                    execution_attempt_id=
                        current.execution_attempt_id,
                )

                raise PermissionError(
                    "NEEDS_REVIEW workflow already "
                    "contains a ticket identifier."
                )

            updated_data = (
                current.model_dump()
            )

            updated_data.update(
                {
                    "status":
                        "TICKET_CREATED",

                    "ticket_id":
                        ticket_id,
                }
            )

            resolved = (
                WorkflowResult
                .model_validate(
                    updated_data
                )
            )

            cursor = connection.execute(
                """
                UPDATE workflows

                SET
                    status = %s,
                    payload = %s,
                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE
                    workflow_id = %s
                    AND status =
                        'NEEDS_REVIEW'
                    AND payload = %s
                """,
                (
                    resolved.status,
                    resolved.model_dump_json(),
                    workflow_id,
                    original_payload,
                ),
            )

            if cursor.rowcount != 1:
                emit_workflow_store_reconciliation_denied_security_event(
                    source_component="workflow_postgresql_store",
                    reason_code="reconciliation_denied",
                    workflow_id=current.workflow_id,
                    tenant_id=current.tenant_id,
                    execution_attempt_id=
                        current.execution_attempt_id,
                )

                raise PermissionError(
                    "Workflow state changed before "
                    "confirmed reconciliation could "
                    "be committed."
                )

        return resolved

    # --------------------------------------------------------
    # HUMAN RECONCILIATION ? AUTHORIZED RETRY
    # --------------------------------------------------------

    def authorize_reconciled_retry(
        self,
        workflow_id: str,
        *,
        expected_execution_attempt_id: str,
        security_context: SecurityContext,
    ) -> WorkflowResult:

        self._require_workflow_id(
            workflow_id
        )

        with self._connect() as connection:

            status, original_payload = (
                self._select_for_update(
                    connection,
                    workflow_id,
                )
            )

            if status != "NEEDS_REVIEW":
                emit_workflow_store_reconciliation_denied_security_event(
                    source_component="workflow_postgresql_store",
                    reason_code="workflow_transition_not_allowed",
                )

                raise PermissionError(
                    "Only a NEEDS_REVIEW workflow can "
                    "be authorized for reconciled retry."
                )

            current = (
                self._parse_workflow(
                    original_payload
                )
            )

            self \
                ._validate_reconciliation_transition_target(
                    current,
                    expected_execution_attempt_id=
                        expected_execution_attempt_id,
                    security_context=
                        security_context,
                )

            updated_data = (
                current.model_dump()
            )

            updated_data.update(
                {
                    "status":
                        "AWAITING_APPROVAL",

                    "approval_id":
                        None,

                    "ticket_id":
                        None,
                }
            )

            authorized = (
                WorkflowResult
                .model_validate(
                    updated_data
                )
            )

            cursor = connection.execute(
                """
                UPDATE workflows

                SET
                    status = %s,
                    payload = %s,
                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE
                    workflow_id = %s
                    AND status =
                        'NEEDS_REVIEW'
                    AND payload = %s
                """,
                (
                    authorized.status,
                    authorized.model_dump_json(),
                    workflow_id,
                    original_payload,
                ),
            )

            if cursor.rowcount != 1:
                emit_workflow_store_reconciliation_denied_security_event(
                    source_component="workflow_postgresql_store",
                    reason_code="reconciliation_denied",
                    workflow_id=current.workflow_id,
                    tenant_id=current.tenant_id,
                    execution_attempt_id=
                        current.execution_attempt_id,
                )

                raise PermissionError(
                    "Workflow state changed before "
                    "retry authorization could "
                    "be committed."
                )

        return authorized
