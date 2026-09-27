from __future__ import annotations

from abc import ABC
from abc import abstractmethod
from threading import Lock
from typing import TYPE_CHECKING


if TYPE_CHECKING:

    from app.mcp_session import MCPSession


# -------------------------------------------------
# MCP SESSION STORE CONTRACT
# -------------------------------------------------


class SessionStore(ABC):
    """
    Persistence contract for authoritative MCP session
    records.

    Session stores are responsible only for storing and
    retrieving session state.

    Session stores do NOT:
    - authenticate principals
    - authorize session use
    - enforce tenant boundaries
    - decide expiration
    - decide revocation authority
    - build SecurityContext
    - emit security-policy decisions
    """

    @abstractmethod
    def get(
        self,
        session_id: str,
    ) -> MCPSession | None:
        """
        Return one authoritative session record or None.
        """

        raise NotImplementedError

    @abstractmethod
    def save(
        self,
        session: MCPSession,
    ) -> MCPSession:
        """
        Store or replace one authoritative session record.
        """

        raise NotImplementedError

    @abstractmethod
    def replace_if_current(
        self,
        *,
        expected: MCPSession,
        replacement: MCPSession,
    ) -> bool:
        """
        Atomically replace a session only when the
        authoritative record still matches expected.

        Returns True when replacement succeeds.
        Returns False when expected is stale.
        """

        raise NotImplementedError

    @abstractmethod
    def list_for_principal(
        self,
        *,
        principal_id: str,
        tenant_id: str,
    ) -> list[MCPSession]:
        """
        Return sessions matching one principal and tenant.
        """

        raise NotImplementedError


# -------------------------------------------------
# IN-MEMORY SESSION STORE
# -------------------------------------------------


class InMemorySessionStore(SessionStore):
    """
    Process-local MCP session store used for tests, demos,
    and backward-compatible default behavior.

    Security policy remains in MCPSessionManager.
    """

    def __init__(
        self,
    ) -> None:

        self._sessions: dict[
            str,
            MCPSession,
        ] = {}

        self._lock = Lock()

    def get(
        self,
        session_id: str,
    ) -> MCPSession | None:

        with self._lock:

            return self._sessions.get(
                session_id
            )

    def save(
        self,
        session: MCPSession,
    ) -> MCPSession:

        with self._lock:

            self._sessions[
                session.session_id
            ] = session

        return session

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

        with self._lock:

            current = self._sessions.get(
                expected.session_id
            )

            if current != expected:

                return False

            self._sessions[
                expected.session_id
            ] = replacement

            return True

    def list_for_principal(
        self,
        *,
        principal_id: str,
        tenant_id: str,
    ) -> list[MCPSession]:

        with self._lock:

            return [
                session
                for session
                in self._sessions.values()
                if (
                    session.principal_id
                    == principal_id
                    and session.tenant_id
                    == tenant_id
                )
            ]
