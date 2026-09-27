from hashlib import sha256
from datetime import datetime
from datetime import timedelta
from datetime import timezone

import secrets

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

from app.auth import Principal
from app.audit import log_event
from app.security_context import SecurityContext

from app.mcp_session_store import InMemorySessionStore
from app.mcp_session_store import SessionStore





def _session_correlation_id(
    session_id: str,
) -> str:

    return sha256(
        session_id.encode(
            "utf-8"
        )
    ).hexdigest()[:16]


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


class MCPSessionRevoked(MCPSessionError):
    """
    Raised when an MCP session has been revoked.
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

    revoked_at: datetime | None = None


# -------------------------------------------------
# PRINCIPAL SESSION REVOCATION RESULT
# -------------------------------------------------


class PrincipalSessionRevocationResult(BaseModel):
    """
    Aggregate result for tenant-scoped principal session
    revocation.

    Raw session identifiers are deliberately excluded.
    """

    model_config = ConfigDict(
        frozen=True
    )

    principal_id: str = Field(
        min_length=1
    )

    tenant_id: str = Field(
        min_length=1
    )

    matched_sessions: int = Field(
        ge=0
    )

    newly_revoked_sessions: int = Field(
        ge=0
    )

    already_revoked_sessions: int = Field(
        ge=0
    )


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
        session_store: SessionStore | None = None,
    ) -> None:

        if session_ttl <= timedelta():

            raise ValueError(
                "session_ttl must be greater than zero."
            )

        self._session_ttl = session_ttl

        self._session_store = (
            session_store
            if session_store is not None
            else InMemorySessionStore()
        )


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

        self._session_store.save(
            session
        )

        return session


    # -------------------------------------------------
    # REVOKE SESSION
    # -------------------------------------------------

    def revoke_session(
        self,
        principal: Principal,
        *,
        session_id: str,
        tenant_id: str,
        now: datetime | None = None,
    ) -> MCPSession:
        """
        Revoke an MCP session after verifying ownership
        and tenant binding.

        Revocation replaces the authoritative immutable
        session record. There is intentionally no
        un-revoke operation.
        """

        session = self._session_store.get(
            session_id
        )

        if session is None:

            log_event(
                "MCP_SESSION_REVOCATION_BLOCKED",
                {
                    "principal_id":
                        principal.username,

                    "tenant_id":
                        tenant_id,

                    "session_correlation_id":
                        _session_correlation_id(
                            session_id
                        ),

                    "reason":
                        "session_not_found",
                },
            )

            raise MCPSessionNotFound(
                "MCP session was not found."
            )

        if (
            session.principal_id
            != principal.username
        ):

            log_event(
                "MCP_SESSION_REVOCATION_BLOCKED",
                {
                    "principal_id":
                        principal.username,

                    "tenant_id":
                        tenant_id,

                    "session_correlation_id":
                        _session_correlation_id(
                            session_id
                        ),

                    "reason":
                        "principal_mismatch",
                },
            )

            raise MCPSessionAccessDenied(
                "MCP session principal mismatch."
            )

        if (
            session.tenant_id
            != tenant_id
        ):

            log_event(
                "MCP_SESSION_REVOCATION_BLOCKED",
                {
                    "principal_id":
                        principal.username,

                    "tenant_id":
                        tenant_id,

                    "session_correlation_id":
                        _session_correlation_id(
                            session_id
                        ),

                    "reason":
                        "tenant_mismatch",
                },
            )

            raise MCPSessionAccessDenied(
                "MCP session tenant mismatch."
            )

        if session.revoked_at is not None:

            return session

        current_time = (
            now
            if now is not None
            else datetime.now(
                timezone.utc
            )
        )

        revoked_session = session.model_copy(
            update={
                "revoked_at":
                    current_time,
            }
        )

        replaced = (
            self._session_store.replace_if_current(
                expected=session,
                replacement=revoked_session,
            )
        )

        if not replaced:

            authoritative = (
                self._session_store.get(
                    session_id
                )
            )

            if authoritative is None:

                log_event(
                    "MCP_SESSION_REVOCATION_BLOCKED",
                    {
                        "principal_id":
                            principal.username,

                        "tenant_id":
                            tenant_id,

                        "session_correlation_id":
                            _session_correlation_id(
                                session_id
                            ),

                        "reason":
                            "concurrent_session_disappearance",
                    },
                )

                raise MCPSessionNotFound(
                    "Session no longer exists."
                )

            if authoritative.revoked_at is not None:

                return authoritative

            log_event(
                "MCP_SESSION_REVOCATION_BLOCKED",
                {
                    "principal_id":
                        principal.username,

                    "tenant_id":
                        tenant_id,

                    "session_correlation_id":
                        _session_correlation_id(
                            session_id
                        ),

                    "reason":
                        "concurrent_state_change",
                },
            )

            raise MCPSessionAccessDenied(
                "Session state changed during revocation."
            )

        log_event(
            "MCP_SESSION_REVOKED",
            {
                "principal_id":
                    principal.username,

                "tenant_id":
                    tenant_id,

                "session_correlation_id":
                    _session_correlation_id(
                        session_id
                    ),
            },
        )

        return revoked_session


    # -------------------------------------------------
    # REVOKE PRINCIPAL SESSIONS
    # -------------------------------------------------

    def revoke_principal_sessions(
        self,
        actor: Principal,
        *,
        actor_session_id: str,
        tenant_id: str,
        target_principal_id: str,
        now: datetime | None = None,
    ) -> PrincipalSessionRevocationResult:
        """
        Revoke all authoritative sessions for one principal
        within the actor's validated enterprise tenant.

        Administrative revocation requires both a currently
        valid actor session and explicit tenant-scoped
        session-revocation authority.
        """

        if not target_principal_id:

            raise ValueError(
                "target_principal_id must not be empty"
            )

        # -------------------------------------------------
        # REVALIDATE ACTOR SESSION
        # -------------------------------------------------
        #
        # Administrative authority must never survive a
        # revoked, expired, mismatched, or otherwise invalid
        # actor session.
        # -------------------------------------------------

        actor_session = self.validate_session(
            actor,
            session_id=actor_session_id,
            tenant_id=tenant_id,
            now=now,
        )

        # -------------------------------------------------
        # REQUIRE EXPLICIT REVOCATION AUTHORITY
        # -------------------------------------------------

        if (
            actor.session_revocation_access
            != "tenant_admin"
        ):

            log_event(
                "MCP_PRINCIPAL_SESSION_REVOCATION_BLOCKED",
                {
                    "actor_principal_id":
                        actor.username,

                    "target_principal_id":
                        target_principal_id,

                    "tenant_id":
                        actor_session.tenant_id,

                    "actor_session_correlation_id":
                        _session_correlation_id(
                            actor_session_id
                        ),

                    "reason":
                        "insufficient_revocation_authority",
                },
            )

            raise MCPSessionAccessDenied(
                "Tenant session-administration "
                "authority is required."
            )

        current_time = (
            now
            if now is not None
            else datetime.now(
                timezone.utc
            )
        )

        # -------------------------------------------------
        # AUTHORITATIVE TENANT SCOPE
        # -------------------------------------------------
        #
        # Target scope comes from the validated actor
        # session, not independently from caller-controlled
        # target parameters.
        # -------------------------------------------------

        authoritative_tenant_id = (
            actor_session.tenant_id
        )

        matched_sessions = 0
        newly_revoked_sessions = 0
        already_revoked_sessions = 0

        # Snapshot dictionary items so authoritative
        # immutable records can safely be replaced during
        # iteration without changing dictionary keys.

        target_sessions = (
            self._session_store.list_for_principal(
                principal_id=target_principal_id,
                tenant_id=authoritative_tenant_id,
            )
        )

        for session in target_sessions:

            matched_sessions += 1

            if session.revoked_at is not None:

                already_revoked_sessions += 1

                continue

            revoked_session = session.model_copy(
                update={
                    "revoked_at":
                        current_time,
                }
            )

            replaced = (
                self._session_store.replace_if_current(
                    expected=session,
                    replacement=revoked_session,
                )
            )

            if replaced:

                newly_revoked_sessions += 1

                continue

            # Another writer changed the authoritative
            # session after this operation enumerated it.
            # Reload before deciding how to count the
            # transition.

            authoritative = (
                self._session_store.get(
                    session.session_id
                )
            )

            if authoritative is None:

                log_event(
                    "MCP_PRINCIPAL_SESSION_REVOCATION_BLOCKED",
                    {
                        "actor_principal_id":
                            actor.username,

                        "target_principal_id":
                            target_principal_id,

                        "tenant_id":
                            authoritative_tenant_id,

                        "actor_session_correlation_id":
                            _session_correlation_id(
                                actor_session_id
                            ),

                        "reason":
                            "concurrent_session_disappearance",
                    },
                )

                raise MCPSessionNotFound(
                    "Target session no longer exists."
                )

            if authoritative.revoked_at is not None:

                already_revoked_sessions += 1

                continue

            log_event(
                "MCP_PRINCIPAL_SESSION_REVOCATION_BLOCKED",
                {
                    "actor_principal_id":
                        actor.username,

                    "target_principal_id":
                        target_principal_id,

                    "tenant_id":
                        authoritative_tenant_id,

                    "actor_session_correlation_id":
                        _session_correlation_id(
                            actor_session_id
                        ),

                    "reason":
                        "concurrent_state_change",
                },
            )

            raise MCPSessionAccessDenied(
                "Target session state changed during "
                "administrative revocation."
            )

        result = (
            PrincipalSessionRevocationResult(
                principal_id=target_principal_id,
                tenant_id=authoritative_tenant_id,
                matched_sessions=matched_sessions,
                newly_revoked_sessions=(
                    newly_revoked_sessions
                ),
                already_revoked_sessions=(
                    already_revoked_sessions
                ),
            )
        )

        # -------------------------------------------------
        # AGGREGATE SECURITY AUDIT
        # -------------------------------------------------
        #
        # The administrative operation is recorded without
        # exposing raw actor or target session identifiers.
        # -------------------------------------------------

        log_event(
            "MCP_PRINCIPAL_SESSIONS_REVOKED",
            {
                "actor_principal_id":
                    actor.username,

                "target_principal_id":
                    target_principal_id,

                "tenant_id":
                    authoritative_tenant_id,

                "actor_session_correlation_id":
                    _session_correlation_id(
                        actor_session_id
                    ),

                "matched_sessions":
                    matched_sessions,

                "newly_revoked_sessions":
                    newly_revoked_sessions,

                "already_revoked_sessions":
                    already_revoked_sessions,
            },
        )

        return result


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

        session = self._session_store.get(
            session_id
        )

        if session is None:

            log_event(
                "MCP_SESSION_VALIDATION_BLOCKED",
                {
                    "principal_id":
                        principal.username,

                    "tenant_id":
                        tenant_id,

                    "session_correlation_id":
                        _session_correlation_id(
                            session_id
                        ),

                    "reason":
                        "session_not_found",
                },
            )

            raise MCPSessionNotFound(
                "MCP session was not found."
            )

        if (
            session.principal_id
            != principal.username
        ):

            log_event(
                "MCP_SESSION_VALIDATION_BLOCKED",
                {
                    "principal_id":
                        principal.username,

                    "tenant_id":
                        tenant_id,

                    "session_correlation_id":
                        _session_correlation_id(
                            session_id
                        ),

                    "reason":
                        "principal_mismatch",
                },
            )

            raise MCPSessionAccessDenied(
                "MCP session principal mismatch."
            )

        if (
            session.tenant_id
            != tenant_id
        ):

            log_event(
                "MCP_SESSION_VALIDATION_BLOCKED",
                {
                    "principal_id":
                        principal.username,

                    "tenant_id":
                        tenant_id,

                    "session_correlation_id":
                        _session_correlation_id(
                            session_id
                        ),

                    "reason":
                        "tenant_mismatch",
                },
            )

            raise MCPSessionAccessDenied(
                "MCP session tenant mismatch."
            )

        if session.revoked_at is not None:

            log_event(
                "MCP_SESSION_VALIDATION_BLOCKED",
                {
                    "principal_id":
                        principal.username,

                    "tenant_id":
                        tenant_id,

                    "session_correlation_id":
                        _session_correlation_id(
                            session_id
                        ),

                    "reason":
                        "session_revoked",
                },
            )

            raise MCPSessionRevoked(
                "MCP session has been revoked."
            )

        current_time = (
            now
            if now is not None
            else datetime.now(
                timezone.utc
            )
        )

        if current_time >= session.expires_at:

            log_event(
                "MCP_SESSION_VALIDATION_BLOCKED",
                {
                    "principal_id":
                        principal.username,

                    "tenant_id":
                        tenant_id,

                    "session_correlation_id":
                        _session_correlation_id(
                            session_id
                        ),

                    "reason":
                        "session_expired",
                },
            )

            raise MCPSessionExpired(
                "MCP session has expired."
            )

        log_event(
            "MCP_SESSION_VALIDATED",
            {
                "principal_id":
                    principal.username,

                "tenant_id":
                    tenant_id,

                "session_correlation_id":
                    _session_correlation_id(
                        session_id
                    ),
            },
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
