import os
import sqlite3

from datetime import datetime
from datetime import timezone
from pathlib import Path
from uuid import uuid4

from app.models import WorkflowResult
from app.security_context import SecurityContext
from app.workflow_tenant import require_workflow_tenant


# -------------------------------------------------
# DATABASE LOCATION
# -------------------------------------------------


def get_database_path() -> Path:

    configured_path = os.getenv(
        "VM_AI_DB_PATH",
        "data/workflows.db"
    )

    return Path(
        configured_path
    )


# -------------------------------------------------
# EXECUTION METADATA
# -------------------------------------------------


def generate_execution_attempt_id() -> str:

    return (
        "EXEC-"
        + uuid4().hex[:8].upper()
    )


def utc_now() -> datetime:

    return datetime.now(
        timezone.utc
    )


# -------------------------------------------------
# DATABASE CONNECTION
# -------------------------------------------------


def connect_database():

    database_path = get_database_path()

    database_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        database_path,
        timeout=10
    )

    connection.row_factory = (
        sqlite3.Row
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS workflows (
            workflow_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL
                DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    connection.commit()

    return connection


# -------------------------------------------------
# SAVE WORKFLOW
# -------------------------------------------------


def _sqlite_save_workflow(
    result: WorkflowResult
) -> WorkflowResult:
    """
    Create a new authoritative workflow row.

    Creation authority is insert-only. An existing workflow_id
    must never be overwritten through save_workflow().
    """

    payload = (
        result.model_dump_json()
    )

    with connect_database() as connection:

        cursor = connection.execute(
            """
            INSERT INTO workflows (
                workflow_id,
                status,
                payload
            )
            VALUES (?, ?, ?)

            ON CONFLICT(workflow_id)
            DO NOTHING
            """,
            (
                result.workflow_id,
                result.status,
                payload,
            )
        )

        if cursor.rowcount != 1:

            raise PermissionError(
                "Workflow already exists; creation "
                "authority cannot overwrite "
                "authoritative state."
            )

    return result


# -------------------------------------------------
# GET WORKFLOW
# -------------------------------------------------


def _sqlite_get_workflow(
    workflow_id: str
) -> WorkflowResult:

    with connect_database() as connection:

        row = connection.execute(
            """
            SELECT payload
            FROM workflows
            WHERE workflow_id = ?
            """,
            (
                workflow_id,
            )
        ).fetchone()

    if row is None:

        raise KeyError(
            f"Workflow not found: {workflow_id}"
        )

    return (
        WorkflowResult
        .model_validate_json(
            row["payload"]
        )
    )


# -------------------------------------------------
# UPDATE WORKFLOW
# -------------------------------------------------




# -------------------------------------------------
# ATOMIC EXECUTION CLAIM
# -------------------------------------------------


def _sqlite_claim_workflow_for_execution(
    workflow_id: str,
    *,
    security_context: SecurityContext | None = None,
) -> WorkflowResult:

    """
    Atomically claim an AWAITING_APPROVAL workflow.

    Only one caller may transition a workflow from
    AWAITING_APPROVAL to PROCESSING.

    The claim also creates execution metadata used
    for recovery and reconciliation.
    """

    with connect_database() as connection:

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        row = connection.execute(
            """
            SELECT
                status,
                payload

            FROM workflows

            WHERE workflow_id = ?
            """,
            (
                workflow_id,
            )
        ).fetchone()

        if row is None:

            raise KeyError(
                f"Workflow not found: {workflow_id}"
            )

        if (
            row["status"]
            != "AWAITING_APPROVAL"
        ):

            raise PermissionError(
                "Workflow must be awaiting approval "
                "before execution can be claimed."
            )

        current = (
            WorkflowResult
            .model_validate_json(
                row["payload"]
            )
        )

        # -------------------------------------------------
        # TENANT AUTHORITY GATE
        # -------------------------------------------------
        #
        # A tenant-bound workflow may only be claimed by a
        # trusted SecurityContext for that exact tenant.
        #
        # This check executes while BEGIN IMMEDIATE holds
        # the write lock and BEFORE AWAITING_APPROVAL is
        # changed to PROCESSING.
        #
        # Therefore a cross-tenant caller cannot consume or
        # poison the execution claim.
        # -------------------------------------------------

        if current.tenant_id is not None:

            if security_context is None:

                raise PermissionError(
                    "Tenant-bound workflow execution "
                    "requires trusted security context."
                )

            require_workflow_tenant(
                current,
                security_context=security_context,
            )

        updated_data = (
            current.model_dump()
        )

        updated_data.update(
            {
                "status":
                    "PROCESSING",

                "execution_attempt_id":
                    generate_execution_attempt_id(),

                "processing_started_at":
                    utc_now(),

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
                status = ?,
                payload = ?,
                updated_at = CURRENT_TIMESTAMP

            WHERE
                workflow_id = ?
                AND status = 'AWAITING_APPROVAL'
            """,
            (
                claimed.status,
                claimed.model_dump_json(),
                workflow_id,
            )
        )

        if cursor.rowcount != 1:

            raise PermissionError(
                "Workflow execution has already "
                "been claimed."
            )

    return claimed


# -------------------------------------------------
# MARK EXECUTION FOR HUMAN REVIEW
# -------------------------------------------------


def _sqlite_complete_workflow_execution(
    workflow_id: str,
    *,
    expected_execution_attempt_id: str,
    approval_id: str,
    ticket_id: str,
    security_context: SecurityContext | None = None,
) -> WorkflowResult:
    """
    Atomically complete the exact PROCESSING execution attempt.

    Caller-supplied workflow payloads are never authoritative here.
    The current row is read under the SQLite write lock and only the
    approved completion fields are applied.
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

    with connect_database() as connection:

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        row = connection.execute(
            """
            SELECT
                status,
                payload

            FROM workflows

            WHERE workflow_id = ?
            """,
            (
                workflow_id,
            )
        ).fetchone()

        if row is None:

            raise KeyError(
                f"Workflow not found: "
                f"{workflow_id}"
            )

        if (
            row["status"]
            != "PROCESSING"
        ):

            raise PermissionError(
                "Only a PROCESSING workflow can "
                "be completed."
            )

        current = (
            WorkflowResult
            .model_validate_json(
                row["payload"]
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
                status = ?,
                payload = ?,
                updated_at = CURRENT_TIMESTAMP

            WHERE
                workflow_id = ?
                AND status = 'PROCESSING'
                AND payload = ?
            """,
            (
                completed.status,
                completed.model_dump_json(),
                workflow_id,
                row["payload"],
            )
        )

        if cursor.rowcount != 1:

            raise PermissionError(
                "Workflow completion authority changed."
            )

    return completed


def _sqlite_reject_workflow_authoritatively(
    workflow_id: str,
    *,
    security_context: SecurityContext | None = None,
) -> WorkflowResult:
    """
    Atomically reject an AWAITING_APPROVAL workflow.

    Rejection derives the new state from the authoritative row and
    cannot accept arbitrary caller-supplied workflow state.
    """

    with connect_database() as connection:

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        row = connection.execute(
            """
            SELECT
                status,
                payload

            FROM workflows

            WHERE workflow_id = ?
            """,
            (
                workflow_id,
            )
        ).fetchone()

        if row is None:

            raise KeyError(
                f"Workflow not found: "
                f"{workflow_id}"
            )

        if (
            row["status"]
            != "AWAITING_APPROVAL"
        ):

            raise PermissionError(
                "Workflow must be awaiting approval "
                "before it can be rejected."
            )

        current = (
            WorkflowResult
            .model_validate_json(
                row["payload"]
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
                status = ?,
                payload = ?,
                updated_at = CURRENT_TIMESTAMP

            WHERE
                workflow_id = ?
                AND status = 'AWAITING_APPROVAL'
                AND payload = ?
            """,
            (
                rejected.status,
                rejected.model_dump_json(),
                workflow_id,
                row["payload"],
            )
        )

        if cursor.rowcount != 1:

            raise PermissionError(
                "Workflow rejection authority changed."
            )

    return rejected

def _sqlite_mark_workflow_needs_review(
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

    with connect_database() as connection:

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        row = connection.execute(
            """
            SELECT
                status,
                payload
            FROM workflows
            WHERE workflow_id = ?
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

        if (
            row["status"]
            != "PROCESSING"
        ):

            raise PermissionError(
                "Only a PROCESSING workflow can "
                "be moved to NEEDS_REVIEW."
            )

        current = (
            WorkflowResult
            .model_validate_json(
                row["payload"]
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
                status = ?,
                payload = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE
                workflow_id = ?
                AND status = 'PROCESSING'
                AND payload = ?
            """,
            (
                review_result.status,
                review_result.model_dump_json(),
                workflow_id,
                row["payload"],
            ),
        )

        if cursor.rowcount != 1:

            raise PermissionError(
                "Workflow recovery authority changed."
            )

    return review_result


# -------------------------------------------------
# STALE PROCESSING DETECTION
# -------------------------------------------------


def _sqlite_mark_stale_processing_for_review(
    workflow_id: str,
    stale_after_seconds: int = 300,
    now: datetime | None = None
) -> WorkflowResult:

    """
    Move a stale PROCESSING workflow to NEEDS_REVIEW.

    This function deliberately does NOT retry ticket
    execution. An uncertain external action requires
    reconciliation instead of automatic re-execution.
    """

    if stale_after_seconds <= 0:

        raise ValueError(
            "stale_after_seconds must be greater "
            "than zero."
        )

    effective_now = (
        now
        if now is not None
        else utc_now()
    )

    if effective_now.tzinfo is None:

        effective_now = (
            effective_now.replace(
                tzinfo=timezone.utc
            )
        )

    with connect_database() as connection:

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        row = connection.execute(
            """
            SELECT
                status,
                payload

            FROM workflows

            WHERE workflow_id = ?
            """,
            (
                workflow_id,
            )
        ).fetchone()

        if row is None:

            raise KeyError(
                f"Workflow not found: {workflow_id}"
            )

        if (
            row["status"]
            != "PROCESSING"
        ):

            raise PermissionError(
                "Workflow is not currently "
                "PROCESSING."
            )

        current = (
            WorkflowResult
            .model_validate_json(
                row["payload"]
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
                status = ?,
                payload = ?,
                updated_at = CURRENT_TIMESTAMP

            WHERE
                workflow_id = ?
                AND status = 'PROCESSING'
            """,
            (
                review_result.status,
                review_result.model_dump_json(),
                workflow_id,
            )
        )

        if cursor.rowcount != 1:

            raise PermissionError(
                "Workflow state changed before "
                "stale recovery could complete."
            )

    return review_result


# -------------------------------------------------
# CLEAR STORE
# -------------------------------------------------


def _sqlite_clear_workflows() -> None:

    with connect_database() as connection:

        connection.execute(
            """
            DELETE FROM workflows
            """
        )

# -------------------------------------------------
# RECONCILIATION RESOLUTION
# -------------------------------------------------


def _validate_reconciliation_transition_target(
    current: WorkflowResult,
    *,
    expected_execution_attempt_id: str,
    security_context: SecurityContext,
) -> None:
    """
    Validate the authoritative state required before applying a
    ServiceNow reconciliation result.

    This helper is called only while the workflow database is
    protected by BEGIN IMMEDIATE.
    """

    if not isinstance(
        security_context,
        SecurityContext,
    ):

        raise PermissionError(
            "Trusted SecurityContext is required "
            "for reconciliation resolution."
        )

    if (
        security_context.role
        != "APPROVER"
    ):

        raise PermissionError(
            "Reconciliation resolution requires "
            "APPROVER security context."
        )

    require_workflow_tenant(
        current,
        security_context=
            security_context,
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
            "expected_execution_attempt_id must be "
            "a non-blank normalized string."
        )

    if (
        current.execution_attempt_id
        != expected_execution_attempt_id
    ):

        raise PermissionError(
            "Workflow execution attempt changed "
            "after reconciliation."
        )


def _sqlite_confirm_reconciled_ticket_creation(
    workflow_id: str,
    *,
    expected_execution_attempt_id: str,
    ticket_id: str,
    security_context: SecurityContext,
) -> WorkflowResult:
    """
    Atomically resolve a confirmed external ServiceNow ticket.

    Only NEEDS_REVIEW may transition to TICKET_CREATED.

    The transition re-checks tenant authority and the exact
    execution attempt under the same database write lock used
    for the state change.
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

    with connect_database() as connection:

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        row = connection.execute(
            """
            SELECT
                status,
                payload

            FROM workflows

            WHERE workflow_id = ?
            """,
            (
                workflow_id,
            )
        ).fetchone()

        if row is None:

            raise KeyError(
                f"Workflow not found: {workflow_id}"
            )

        if (
            row["status"]
            != "NEEDS_REVIEW"
        ):

            raise PermissionError(
                "Only a NEEDS_REVIEW workflow can "
                "be confirmed after reconciliation."
            )

        original_payload = (
            row[
                "payload"
            ]
        )

        current = (
            WorkflowResult
            .model_validate_json(
                original_payload
            )
        )

        _validate_reconciliation_transition_target(
            current,
            expected_execution_attempt_id=
                expected_execution_attempt_id,
            security_context=
                security_context,
        )

        if (
            current.ticket_id
            is not None
        ):

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
                status = ?,
                payload = ?,
                updated_at = CURRENT_TIMESTAMP

            WHERE
                workflow_id = ?
                AND status = 'NEEDS_REVIEW'
                AND payload = ?
            """,
            (
                resolved.status,
                resolved.model_dump_json(),
                workflow_id,
                original_payload,
            )
        )

        if cursor.rowcount != 1:

            raise PermissionError(
                "Workflow state changed before "
                "confirmed reconciliation could "
                "be committed."
            )

    return resolved


def _sqlite_authorize_reconciled_retry(
    workflow_id: str,
    *,
    expected_execution_attempt_id: str,
    security_context: SecurityContext,
) -> WorkflowResult:
    """
    Atomically authorize a new human-triggered execution after
    ServiceNow reconciliation proves the ambiguous attempt was
    NOT_FOUND.

    The old execution_attempt_id is intentionally preserved in
    AWAITING_APPROVAL for audit provenance. The next atomic
    claim must overwrite it with a freshly generated attempt.
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

    with connect_database() as connection:

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        row = connection.execute(
            """
            SELECT
                status,
                payload

            FROM workflows

            WHERE workflow_id = ?
            """,
            (
                workflow_id,
            )
        ).fetchone()

        if row is None:

            raise KeyError(
                f"Workflow not found: {workflow_id}"
            )

        if (
            row["status"]
            != "NEEDS_REVIEW"
        ):

            raise PermissionError(
                "Only a NEEDS_REVIEW workflow can "
                "be authorized for reconciled retry."
            )

        original_payload = (
            row[
                "payload"
            ]
        )

        current = (
            WorkflowResult
            .model_validate_json(
                original_payload
            )
        )

        _validate_reconciliation_transition_target(
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
                status = ?,
                payload = ?,
                updated_at = CURRENT_TIMESTAMP

            WHERE
                workflow_id = ?
                AND status = 'NEEDS_REVIEW'
                AND payload = ?
            """,
            (
                authorized.status,
                authorized.model_dump_json(),
                workflow_id,
                original_payload,
            )
        )

        if cursor.rowcount != 1:

            raise PermissionError(
                "Workflow state changed before "
                "retry authorization could "
                "be committed."
            )

    return authorized
# ============================================================
# WORKFLOW STORE BACKEND ABSTRACTION
# ============================================================
#
# The functions above implement the original SQLite authority
# semantics. They are intentionally retained in this module so
# existing local/test behavior and security-sensitive monkeypatch
# points remain stable.
#
# Public callers below resolve a WorkflowStore backend and dispatch
# through the common contract.
#
# PostgreSQL selection deliberately fails closed until the
# production implementation is introduced.
# ============================================================

import os as _workflow_store_os

from app.workflow_store_contract import WorkflowStore


WORKFLOW_STORE_BACKEND_ENV = (
    "VM_AI_WORKFLOW_STORE_BACKEND"
)

WORKFLOW_STORE_DATABASE_URL_ENV = (
    "VM_AI_WORKFLOW_DATABASE_URL"
)


class SQLiteWorkflowStore:
    """
    Adapter exposing the existing SQLite workflow authority
    through the shared WorkflowStore contract.
    """

    def save_workflow(
        self,
        result: WorkflowResult,
    ) -> WorkflowResult:
        return _sqlite_save_workflow(
            result
        )

    def get_workflow(
        self,
        workflow_id: str,
    ) -> WorkflowResult:
        return _sqlite_get_workflow(
            workflow_id
        )


    def claim_workflow_for_execution(
        self,
        workflow_id: str,
        *,
        security_context: SecurityContext | None = None,
    ) -> WorkflowResult:
        return (
            _sqlite_claim_workflow_for_execution(
                workflow_id,
                security_context=
                    security_context,
            )
        )

    def complete_workflow_execution(
        self,
        workflow_id: str,
        *,
        expected_execution_attempt_id: str,
        approval_id: str,
        ticket_id: str,
        security_context: SecurityContext | None = None,
    ) -> WorkflowResult:
        return _sqlite_complete_workflow_execution(
            workflow_id,
            expected_execution_attempt_id=
                expected_execution_attempt_id,
            approval_id=
                approval_id,
            ticket_id=
                ticket_id,
            security_context=
                security_context,
        )

    def reject_workflow_authoritatively(
        self,
        workflow_id: str,
        *,
        security_context: SecurityContext | None = None,
    ) -> WorkflowResult:
        return _sqlite_reject_workflow_authoritatively(
            workflow_id,
            security_context=
                security_context,
        )

    def mark_workflow_needs_review(self, workflow_id: str, reason: str, *, expected_execution_attempt_id: str, security_context: SecurityContext | None=None) -> WorkflowResult:
        return _sqlite_mark_workflow_needs_review(workflow_id, reason, expected_execution_attempt_id=expected_execution_attempt_id, security_context=security_context)

    def mark_stale_processing_for_review(
        self,
        workflow_id: str,
        stale_after_seconds: int = 300,
        now: datetime | None = None,
    ) -> WorkflowResult:
        return (
            _sqlite_mark_stale_processing_for_review(
                workflow_id,
                stale_after_seconds=
                    stale_after_seconds,
                now=now,
            )
        )

    def clear_workflows(
        self,
    ) -> None:
        _sqlite_clear_workflows()

    def confirm_reconciled_ticket_creation(
        self,
        workflow_id: str,
        *,
        expected_execution_attempt_id: str,
        ticket_id: str,
        security_context: SecurityContext,
    ) -> WorkflowResult:
        return (
            _sqlite_confirm_reconciled_ticket_creation(
                workflow_id,
                expected_execution_attempt_id=
                    expected_execution_attempt_id,
                ticket_id=
                    ticket_id,
                security_context=
                    security_context,
            )
        )

    def authorize_reconciled_retry(
        self,
        workflow_id: str,
        *,
        expected_execution_attempt_id: str,
        security_context: SecurityContext,
    ) -> WorkflowResult:
        return (
            _sqlite_authorize_reconciled_retry(
                workflow_id,
                expected_execution_attempt_id=
                    expected_execution_attempt_id,
                security_context=
                    security_context,
            )
        )


def get_workflow_store_backend_name() -> str:
    """
    Resolve the configured workflow persistence backend.

    SQLite remains the backward-compatible local/test default.
    Production deployments may explicitly select PostgreSQL
    using a separately configured database URL.
    """

    configured = (
        _workflow_store_os.getenv(
            WORKFLOW_STORE_BACKEND_ENV,
            "sqlite",
        )
    )

    backend = configured.strip().lower()

    if not backend:
        raise RuntimeError(
            "VM_AI_WORKFLOW_STORE_BACKEND "
            "cannot be blank."
        )

    return backend



def _get_postgresql_workflow_database_url() -> str:
    """
    Resolve and validate the PostgreSQL workflow database URL.

    The value is never included in configuration error messages
    so database credentials cannot leak through exception text.
    """

    from urllib.parse import parse_qs
    from urllib.parse import urlsplit

    configured = (
        _workflow_store_os.getenv(
            WORKFLOW_STORE_DATABASE_URL_ENV
        )
    )

    if (
        configured is None
        or not configured.strip()
    ):
        raise RuntimeError(
            "PostgreSQL workflow store requires "
            "VM_AI_WORKFLOW_DATABASE_URL."
        )

    if configured != configured.strip():
        raise RuntimeError(
            "VM_AI_WORKFLOW_DATABASE_URL must be "
            "a normalized PostgreSQL URL."
        )

    parsed = urlsplit(
        configured
    )

    if (
        parsed.scheme
        not in {
            "postgres",
            "postgresql",
        }
        or not parsed.netloc
    ):
        raise RuntimeError(
            "VM_AI_WORKFLOW_DATABASE_URL must use "
            "a PostgreSQL URL."
        )

    environment = (
        _workflow_store_os.getenv(
            "VM_AI_ENV",
            "local",
        )
        .strip()
        .lower()
    )

    if environment == "production":

        sslmode_values = (
            parse_qs(
                parsed.query
            )
            .get(
                "sslmode",
                [],
            )
        )

        if (
            len(sslmode_values) != 1
            or sslmode_values[0].lower()
            not in {
                "require",
                "verify-ca",
                "verify-full",
            }
        ):
            raise RuntimeError(
                "Production PostgreSQL workflow "
                "authority requires TLS."
            )

    return configured


def validate_workflow_store_readiness() -> None:
    """
    Validate configured workflow persistence before serving API
    requests.

    SQLite remains the local/test backend and requires no external
    startup validation.

    PostgreSQL runtime authority performs only read-only schema
    compatibility validation. Runtime startup never provisions,
    migrates, alters, or repairs PostgreSQL schema objects.
    """

    backend = (
        get_workflow_store_backend_name()
    )

    if backend == "sqlite":
        return

    if backend in {
        "postgres",
        "postgresql",
    }:

        from app.workflow_postgresql_schema import (
            validate_postgresql_workflow_schema,
        )

        validate_postgresql_workflow_schema(
            database_url=
                _get_postgresql_workflow_database_url()
        )

        return

    raise RuntimeError(
        "Unsupported workflow store backend: "
        f"{backend}"
    )


def get_workflow_store() -> WorkflowStore:
    """
    Return the authoritative workflow-store backend.

    Unknown or not-yet-implemented production backends fail
    closed. There is no implicit downgrade to SQLite.
    """

    backend = (
        get_workflow_store_backend_name()
    )

    if backend == "sqlite":
        return SQLiteWorkflowStore()

    if backend in {
        "postgres",
        "postgresql",
    }:
        from app.workflow_postgresql_store import (
            PostgreSQLWorkflowStore,
        )

        return PostgreSQLWorkflowStore(
            database_url=
                _get_postgresql_workflow_database_url()
        )

    raise RuntimeError(
        "Unsupported workflow store backend: "
        f"{backend}"
    )


# ============================================================
# STABLE PUBLIC WORKFLOW STORE API
# ============================================================


def save_workflow(
    result: WorkflowResult
) -> WorkflowResult:
    return (
        get_workflow_store()
        .save_workflow(
            result
        )
    )


def get_workflow(
    workflow_id: str
) -> WorkflowResult:
    return (
        get_workflow_store()
        .get_workflow(
            workflow_id
        )
    )




def claim_workflow_for_execution(
    workflow_id: str,
    *,
    security_context: SecurityContext | None = None,
) -> WorkflowResult:
    return (
        get_workflow_store()
        .claim_workflow_for_execution(
            workflow_id,
            security_context=
                security_context,
        )
    )


def complete_workflow_execution(
    workflow_id: str,
    *,
    expected_execution_attempt_id: str,
    approval_id: str,
    ticket_id: str,
    security_context: SecurityContext | None = None,
) -> WorkflowResult:
    return (
        get_workflow_store()
        .complete_workflow_execution(
            workflow_id,
            expected_execution_attempt_id=
                expected_execution_attempt_id,
            approval_id=
                approval_id,
            ticket_id=
                ticket_id,
            security_context=
                security_context,
        )
    )


def reject_workflow_authoritatively(
    workflow_id: str,
    *,
    security_context: SecurityContext | None = None,
) -> WorkflowResult:
    return (
        get_workflow_store()
        .reject_workflow_authoritatively(
            workflow_id,
            security_context=
                security_context,
        )
    )

def mark_workflow_needs_review(workflow_id: str, reason: str, *, expected_execution_attempt_id: str, security_context: SecurityContext | None=None) -> WorkflowResult:
    return get_workflow_store().mark_workflow_needs_review(workflow_id, reason, expected_execution_attempt_id=expected_execution_attempt_id, security_context=security_context)


def mark_stale_processing_for_review(
    workflow_id: str,
    stale_after_seconds: int = 300,
    now: datetime | None = None
) -> WorkflowResult:
    return (
        get_workflow_store()
        .mark_stale_processing_for_review(
            workflow_id,
            stale_after_seconds=
                stale_after_seconds,
            now=now,
        )
    )


def clear_workflows() -> None:
    get_workflow_store().clear_workflows()


def confirm_reconciled_ticket_creation(
    workflow_id: str,
    *,
    expected_execution_attempt_id: str,
    ticket_id: str,
    security_context: SecurityContext,
) -> WorkflowResult:
    return (
        get_workflow_store()
        .confirm_reconciled_ticket_creation(
            workflow_id,
            expected_execution_attempt_id=
                expected_execution_attempt_id,
            ticket_id=
                ticket_id,
            security_context=
                security_context,
        )
    )


def authorize_reconciled_retry(
    workflow_id: str,
    *,
    expected_execution_attempt_id: str,
    security_context: SecurityContext,
) -> WorkflowResult:
    return (
        get_workflow_store()
        .authorize_reconciled_retry(
            workflow_id,
            expected_execution_attempt_id=
                expected_execution_attempt_id,
            security_context=
                security_context,
        )
    )
