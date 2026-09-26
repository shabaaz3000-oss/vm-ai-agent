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