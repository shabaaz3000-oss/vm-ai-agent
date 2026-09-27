import sqlite3

from pathlib import Path

from app.mcp_session import MCPSession
from app.mcp_session_store import SessionStore


# -------------------------------------------------
# SQLITE MCP SESSION STORE
# -------------------------------------------------


class SQLiteSessionStore(SessionStore):
    """
    Durable SQLite-backed MCP session store.

    This class is responsible only for persistence.

    Security policy remains in MCPSessionManager.
    """

    def __init__(
        self,
        *,
        database_path: str | Path,
    ) -> None:

        self._database_path = Path(
            database_path
        )


    # -------------------------------------------------
    # DATABASE CONNECTION
    # -------------------------------------------------

    def _connect(
        self,
    ) -> sqlite3.Connection:

        self._database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        connection = sqlite3.connect(
            str(
                self._database_path
            ),
            timeout=10,
        )

        connection.row_factory = (
            sqlite3.Row
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS mcp_sessions (
                session_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL
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
                WHERE session_id = ?
                """,
                (
                    session_id,
                ),
            ).fetchone()

        if row is None:

            return None

        return (
            MCPSession.model_validate_json(
                row["payload"]
            )
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
                VALUES (?, ?, ?, ?)

                ON CONFLICT(session_id)
                DO UPDATE SET
                    principal_id =
                        excluded.principal_id,
                    tenant_id =
                        excluded.tenant_id,
                    payload =
                        excluded.payload,
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
                    principal_id = ?,
                    tenant_id = ?,
                    payload = ?,
                    updated_at = CURRENT_TIMESTAMP

                WHERE
                    session_id = ?
                    AND payload = ?
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
                    principal_id = ?
                    AND tenant_id = ?
                ORDER BY created_at, session_id
                """,
                (
                    principal_id,
                    tenant_id,
                ),
            ).fetchall()

        return [
            MCPSession.model_validate_json(
                row["payload"]
            )
            for row in rows
        ]
