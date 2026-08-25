import os
import sqlite3

from pathlib import Path

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

    return WorkflowResult.model_validate_json(
        row["payload"]
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

    A second caller must fail instead of executing
    the same workflow again.
    """

    with connect_database() as connection:

        # BEGIN IMMEDIATE obtains the SQLite write
        # lock before checking the workflow state.
        #
        # This prevents two writers from both seeing
        # AWAITING_APPROVAL and claiming it.

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

        updated_data[
            "status"
        ] = "PROCESSING"

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
# CLEAR STORE
# -------------------------------------------------


def clear_workflows() -> None:

    with connect_database() as connection:

        connection.execute(
            """
            DELETE FROM workflows
            """
        )