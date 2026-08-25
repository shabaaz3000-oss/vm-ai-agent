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
        database_path
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
# CLEAR STORE
# -------------------------------------------------


def clear_workflows() -> None:

    with connect_database() as connection:

        connection.execute(
            """
            DELETE FROM workflows
            """
        )