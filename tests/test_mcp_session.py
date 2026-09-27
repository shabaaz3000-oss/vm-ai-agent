from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest

from app.auth import Principal

from app.mcp_session import (
    MCPSessionAccessDenied,
    MCPSessionExpired,
    MCPSessionManager,
    MCPSessionNotFound,
)


def make_principal(
    username: str = "alice",
) -> Principal:

    return Principal(
        username=username,
        role="ANALYST",
        retrieval_access="standard",
    )


def fixed_time() -> datetime:

    return datetime(
        2026,
        9,
        26,
        12,
        0,
        tzinfo=timezone.utc,
    )


def test_session_is_server_generated():

    manager = MCPSessionManager()

    session = manager.create_session(
        make_principal(),
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    assert session.session_id
    assert len(session.session_id) >= 32


def test_sessions_receive_unique_ids():

    manager = MCPSessionManager()

    principal = make_principal()

    first = manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    second = manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    assert first.session_id != second.session_id


def test_session_is_bound_to_principal():

    manager = MCPSessionManager()

    alice = make_principal(
        "alice"
    )

    session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    validated = manager.validate_session(
        alice,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    assert validated == session


def test_user_cannot_use_another_users_session():

    manager = MCPSessionManager()

    alice = make_principal(
        "alice"
    )

    bob = make_principal(
        "bob"
    )

    session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    with pytest.raises(
        MCPSessionAccessDenied
    ):

        manager.validate_session(
            bob,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=fixed_time(),
        )


def test_session_cannot_cross_tenant_boundary():

    manager = MCPSessionManager()

    alice = make_principal()

    session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    with pytest.raises(
        MCPSessionAccessDenied
    ):

        manager.validate_session(
            alice,
            session_id=session.session_id,
            tenant_id="tenant-b",
            now=fixed_time(),
        )


def test_unknown_session_is_rejected():

    manager = MCPSessionManager()

    with pytest.raises(
        MCPSessionNotFound
    ):

        manager.validate_session(
            make_principal(),
            session_id="does-not-exist",
            tenant_id="tenant-a",
            now=fixed_time(),
        )


def test_expired_session_is_rejected():

    manager = MCPSessionManager(
        session_ttl=timedelta(
            minutes=30
        )
    )

    start = fixed_time()

    session = manager.create_session(
        make_principal(),
        tenant_id="tenant-a",
        now=start,
    )

    with pytest.raises(
        MCPSessionExpired
    ):

        manager.validate_session(
            make_principal(),
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=(
                start
                + timedelta(
                    minutes=30
                )
            ),
        )


def test_session_manager_rejects_nonpositive_ttl():

    with pytest.raises(
        ValueError
    ):

        MCPSessionManager(
            session_ttl=timedelta(
                seconds=0
            )
        )


# -------------------------------------------------
# VALIDATED SECURITY CONTEXT
# -------------------------------------------------


def test_validated_session_builds_security_context():

    manager = MCPSessionManager()

    principal = make_principal(
        "alice"
    )

    session = manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    context = manager.build_security_context(
        principal,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    assert context.principal_id == "alice"
    assert context.role == "ANALYST"
    assert context.retrieval_access == "standard"
    assert context.tenant_id == "tenant-a"
    assert context.session_id == session.session_id


def test_security_context_cannot_be_built_for_other_user():

    manager = MCPSessionManager()

    alice = make_principal(
        "alice"
    )

    bob = make_principal(
        "bob"
    )

    session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    with pytest.raises(
        MCPSessionAccessDenied
    ):

        manager.build_security_context(
            bob,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=fixed_time(),
        )


def test_security_context_cannot_cross_tenant_boundary():

    manager = MCPSessionManager()

    principal = make_principal(
        "alice"
    )

    session = manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    with pytest.raises(
        MCPSessionAccessDenied
    ):

        manager.build_security_context(
            principal,
            session_id=session.session_id,
            tenant_id="tenant-b",
            now=fixed_time(),
        )



# -------------------------------------------------
# SESSION VALIDATION AUDIT
# -------------------------------------------------


def test_successful_session_validation_is_audited(
    monkeypatch,
):

    events = []

    monkeypatch.setattr(
        "app.mcp_session.log_event",
        lambda event_type, details=None:
            events.append(
                (
                    event_type,
                    details or {},
                )
            ),
    )

    manager = MCPSessionManager()

    principal = make_principal(
        "alice"
    )

    session = manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    manager.validate_session(
        principal,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    validated = [
        details
        for event_type, details
        in events
        if event_type
        == "MCP_SESSION_VALIDATED"
    ]

    assert len(validated) == 1

    assert (
        validated[0]["principal_id"]
        == "alice"
    )

    assert (
        validated[0]["tenant_id"]
        == "tenant-a"
    )

    assert (
        session.session_id
        not in str(validated[0])
    )


def test_cross_user_session_attempt_is_audited(
    monkeypatch,
):

    events = []

    monkeypatch.setattr(
        "app.mcp_session.log_event",
        lambda event_type, details=None:
            events.append(
                (
                    event_type,
                    details or {},
                )
            ),
    )

    manager = MCPSessionManager()

    alice = make_principal(
        "alice"
    )

    bob = make_principal(
        "bob"
    )

    session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    with pytest.raises(
        MCPSessionAccessDenied
    ):

        manager.validate_session(
            bob,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=fixed_time(),
        )

    blocked = [
        details
        for event_type, details
        in events
        if event_type
        == "MCP_SESSION_VALIDATION_BLOCKED"
    ]

    assert len(blocked) == 1

    assert (
        blocked[0]["reason"]
        == "principal_mismatch"
    )

    assert (
        blocked[0]["principal_id"]
        == "bob"
    )

    assert (
        session.session_id
        not in str(blocked[0])
    )
