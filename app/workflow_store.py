import os
import sqlite3

from datetime import datetime
from datetime import timezone
from pathlib import Path
from uuid import uuid4

from app.models import WorkflowResult


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
    workflow_id: str
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