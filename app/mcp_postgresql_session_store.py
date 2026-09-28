from __future__ import annotations

import psycopg

from app.mcp_session import MCPSession
from app.mcp_session_store import SessionStore


# -------------------------------------------------
# POSTGRESQL MCP SESSION STORE
# -------------------------------------------------


class PostgreSQLSessionStore(SessionStore):
    """
    Shared PostgreSQL-backed MCP session store.

    This store provides authoritative session persistence
    suitable for multiple independent application instances.

    Security policy remains in MCPSessionManager.

    The database is responsible only for durable,
    transactionally consistent session state.
    """

    def __init__(
        self,
        *,
        database_url: str,
        connect_timeout_seconds: int = 10,
    ) -> None:

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

        self._database_url = (
            normalized_database_url
        )

        self._connect_timeout_seconds = (
            connect_timeout_seconds
        )


    # -------------------------------------------------
    # DATABASE CONNECTION
    # -------------------------------------------------

    def _connect(
        self,
    ) -> psycopg.Connection:
        """
        Open one PostgreSQL connection and ensure that
        the MCP session schema exists.

        The database URL is trusted server-side
        configuration and is never emitted to logs.
        """

        connection = psycopg.connect(
            self._database_url,
            connect_timeout=
                self._connect_timeout_seconds,
        )

        try:

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

            connection.commit()

            return connection

        except Exception:

            connection.rollback()
            connection.close()

            raise


    # -------------------------------------------------
    # GET SESSION
    # -------------------------------------------------

    def get(
        self,
        session_id: str,
    ) -> MCPSession | None:

        with self._connect() as connection:

            row = connection.execute(
                """
                SELECT payload
                FROM mcp_sessions
                WHERE session_id = %s
                """,
                (
                    session_id,
                ),
            ).fetchone()

        if row is None:

            return None

        return MCPSession.model_validate_json(
            row[0]
        )


    # -------------------------------------------------
    # SAVE / REPLACE SESSION
    # -------------------------------------------------

    def save(
        self,
        session: MCPSession,
    ) -> MCPSession:

        payload = (
            session.model_dump_json()
        )

        with self._connect() as connection:

            connection.execute(
                """
                INSERT INTO mcp_sessions (
                    session_id,
                    principal_id,
                    tenant_id,
                    payload
                )
                VALUES (%s, %s, %s, %s)

                ON CONFLICT (session_id)
                DO UPDATE SET
                    principal_id =
                        EXCLUDED.principal_id,
                    tenant_id =
                        EXCLUDED.tenant_id,
                    payload =
                        EXCLUDED.payload,
                    updated_at =
                        CURRENT_TIMESTAMP
                """,
                (
                    session.session_id,
                    session.principal_id,
                    session.tenant_id,
                    payload,
                ),
            )

        return session


    # -------------------------------------------------
    # ATOMIC COMPARE-AND-SWAP
    # -------------------------------------------------

    def replace_if_current(
        self,
        *,
        expected: MCPSession,
        replacement: MCPSession,
    ) -> bool:
        """
        Atomically replace the authoritative session
        only when its persisted payload still matches
        the caller's expected state.

        PostgreSQL performs the comparison and update
        as one statement. This preserves CAS semantics
        across independent application processes and
        hosts.
        """

        if (
            expected.session_id
            != replacement.session_id
        ):

            raise ValueError(
                "replacement session_id must match expected"
            )

        expected_payload = (
            expected.model_dump_json()
        )

        replacement_payload = (
            replacement.model_dump_json()
        )

        with self._connect() as connection:

            cursor = connection.execute(
                """
                UPDATE mcp_sessions

                SET
                    principal_id = %s,
                    tenant_id = %s,
                    payload = %s,
                    updated_at = CURRENT_TIMESTAMP

                WHERE
                    session_id = %s
                    AND payload = %s
                """,
                (
                    replacement.principal_id,
                    replacement.tenant_id,
                    replacement_payload,
                    expected.session_id,
                    expected_payload,
                ),
            )

            return (
                cursor.rowcount
                == 1
            )


    # -------------------------------------------------
    # LIST PRINCIPAL SESSIONS
    # -------------------------------------------------

    def list_for_principal(
        self,
        *,
        principal_id: str,
        tenant_id: str,
    ) -> list[MCPSession]:

        with self._connect() as connection:

            rows = connection.execute(
                """
                SELECT payload
                FROM mcp_sessions
                WHERE
                    principal_id = %s
                    AND tenant_id = %s
                ORDER BY created_at, session_id
                """,
                (
                    principal_id,
                    tenant_id,
                ),
            ).fetchall()

        return [
            MCPSession.model_validate_json(
                row[0]
            )
            for row in rows
        ]
