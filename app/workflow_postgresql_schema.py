from __future__ import annotations

import psycopg


def provision_postgresql_workflow_schema(
    *,
    database_url: str,
    connect_timeout_seconds: int = 10,
) -> None:
    """
    Provision PostgreSQL workflow authority using a deployment
    identity.

    Runtime application identities must not use this function.
    Schema ownership and runtime mutation authority are separate.
    """

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

    with psycopg.connect(
        database_url,
        connect_timeout=
            connect_timeout_seconds,
        autocommit=True,
    ) as connection:

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS workflows (
                workflow_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
                workflows_status_idx
            ON workflows (status)
            """
        )
