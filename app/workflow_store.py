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


def save_workflow(
    result: WorkflowResult
) -> WorkflowResult:

    payload = (
        result.model_dump_json()
    )

    with connect_database() as connection:

        connection.execute(
            """
            INSERT INTO workflows (
                workflow_id,
                status,
                payload
            )
            VALUES (?, ?, ?)

            ON CONFLICT(workflow_id)
            DO UPDATE SET
                status = excluded.status,
                payload = excluded.payload,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                result.workflow_id,
                result.status,
                payload,
            )
        )

    return result


# -------------------------------------------------
# GET WORKFLOW
# -------------------------------------------------


def get_workflow(
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


def update_workflow(
    result: WorkflowResult
) -> WorkflowResult:

    payload = (
        result.model_dump_json()
    )

    with connect_database() as connection:

        cursor = connection.execute(
            """
            UPDATE workflows

            SET
                status = ?,
                payload = ?,
                updated_at = CURRENT_TIMESTAMP

            WHERE workflow_id = ?
            """,
            (
                result.status,
                payload,
                result.workflow_id,
            )
        )

        if cursor.rowcount == 0:

            raise KeyError(
                "Cannot update a workflow "
                "that does not exist."
            )

    return result


# -------------------------------------------------
# ATOMIC EXECUTION CLAIM
# -------------------------------------------------


def claim_workflow_for_execution(
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


def mark_workflow_needs_review(
    workflow_id: str,
    reason: str
) -> WorkflowResult:

    if not reason.strip():

        raise ValueError(
            "Recovery reason cannot be blank."
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
                "Only a PROCESSING workflow can "
                "be moved to NEEDS_REVIEW."
            )

        current = (
            WorkflowResult
            .model_validate_json(
                row["payload"]
            )
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
                "recovery could be recorded."
            )

    return review_result


# -------------------------------------------------
# STALE PROCESSING DETECTION
# -------------------------------------------------


def mark_stale_processing_for_review(
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


def clear_workflows() -> None:

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


def confirm_reconciled_ticket_creation(
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


def authorize_reconciled_retry(
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
