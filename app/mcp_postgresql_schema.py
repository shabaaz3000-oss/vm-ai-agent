from __future__ import annotations

import psycopg


# -------------------------------------------------
# POSTGRESQL MCP SESSION SCHEMA
# -------------------------------------------------


def provision_postgresql_session_schema(
    *,
    database_url: str,
    connect_timeout_seconds: int = 10,
) -> None:
    """
    Provision PostgreSQL objects required by the MCP
    session store.

    This function is intended for deployment/bootstrap
    identities with schema DDL privileges.

    The normal MCP application runtime does not call
    this function and therefore does not require DDL
    authority.
    """

    normalized_database_url = (
        database_url.strip()
    )

    if not normalized_database_url:

        raise ValueError(
            "database_url must not be empty"
        )

    if connect_timeout_seconds <= 0:

        raise ValueError(
            "connect_timeout_seconds must be "
            "greater than zero"
        )

    with psycopg.connect(
        normalized_database_url,
        connect_timeout=
            connect_timeout_seconds,
    ) as connection:

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS
                mcp_sessions (
                    session_id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
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
                idx_mcp_sessions_principal_tenant
            ON mcp_sessions (
                principal_id,
                tenant_id
            )
            """
        )
