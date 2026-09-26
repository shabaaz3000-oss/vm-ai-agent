from datetime import datetime
from datetime import timedelta
from datetime import timezone

import secrets

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from app.auth import Principal
from app.security_context import SecurityContext


# -------------------------------------------------
# SESSION ERRORS
# -------------------------------------------------


class MCPSessionError(Exception):
    """
    Base exception for MCP session failures.
    """


class MCPSessionNotFound(MCPSessionError):
    """
    Raised when a session identifier does not exist.
    """


class MCPSessionAccessDenied(MCPSessionError):
    """
    Raised when a principal attempts to use a session
    that does not belong to that identity or tenant.
    """


class MCPSessionExpired(MCPSessionError):
    """
    Raised when an MCP session has expired.
    """


# -------------------------------------------------
# MCP SESSION
# -------------------------------------------------


class MCPSession(BaseModel):
    """
    Immutable server-generated MCP session.

    A session is bound to one authenticated principal
    and one enterprise tenant.
    """

    model_config = ConfigDict(
        frozen=True
    )

    session_id: str = Field(
        min_length=1
    )

    principal_id: str = Field(
        min_length=1
    )

    tenant_id: str = Field(
        min_length=1
    )

    created_at: datetime

    expires_at: datetime


# -------------------------------------------------
# MCP SESSION MANAGER
# -------------------------------------------------


class MCPSessionManager:
    """
    In-memory MCP session manager.

    This implementation intentionally keeps persistence
    simple while security semantics are established.

    A future enterprise implementation can replace the
    backing store without changing session ownership
    rules.
    """

    def __init__(
        self,
        *,
        session_ttl: timedelta = timedelta(
            minutes=30
        ),
    ) -> None:

        if session_ttl <= timedelta(0):
            raise ValueError(
                "session_ttl must be positive"
            )

        self._session_ttl = session_ttl

        self._sessions: dict[
            str,
            MCPSession,
        ] = {}


    # -------------------------------------------------
    # CREATE SESSION
    # -------------------------------------------------

    def create_session(
        self,
        principal: Principal,
        *,
        tenant_id: str,
        now: datetime | None = None,
    ) -> MCPSession:

        if not tenant_id:
            raise ValueError(
                "tenant_id must not be empty"
            )

        current_time = (
            now
            if now is not None
            else datetime.now(
                timezone.utc
            )
        )

        session_id = secrets.token_urlsafe(
            32
        )

        session = MCPSession(
            session_id=session_id,
            principal_id=principal.username,
            tenant_id=tenant_id,
            created_at=current_time,
            expires_at=(
                current_time
                + self._session_ttl
            ),
        )

        self._sessions[
            session.session_id
        ] = session

        return session


    # -------------------------------------------------
    # VALIDATE SESSION
    # -------------------------------------------------

    def validate_session(
        self,
        principal: Principal,
        *,
        session_id: str,
        tenant_id: str,
        now: datetime | None = None,
    ) -> MCPSession:

        session = self._sessions.get(
            session_id
        )

        if session is None:
            raise MCPSessionNotFound(
                "MCP session was not found."
            )

        if (
            session.principal_id
            != principal.username
        ):
            raise MCPSessionAccessDenied(
                "MCP session principal mismatch."
            )

        if (
            session.tenant_id
            != tenant_id
        ):
            raise MCPSessionAccessDenied(
                "MCP session tenant mismatch."
            )

        current_time = (
            now
            if now is not None
            else datetime.now(
                timezone.utc
            )
        )

        if current_time >= session.expires_at:
            raise MCPSessionExpired(
                "MCP session has expired."
            )

        return session

    # -------------------------------------------------
    # BUILD TRUSTED SECURITY CONTEXT
    # -------------------------------------------------

    def build_security_context(
        self,
        principal: Principal,
        *,
        session_id: str,
        tenant_id: str,
        now: datetime | None = None,
    ) -> SecurityContext:
        """
        Validate session ownership before creating the
        immutable execution security context.

        The caller-supplied session identifier is never
        trusted merely because it exists.
        """

        session = self.validate_session(
            principal,
            session_id=session_id,
            tenant_id=tenant_id,
            now=now,
        )

        return SecurityContext.from_principal(
            principal,
            tenant_id=session.tenant_id,
            session_id=session.session_id,
        )
