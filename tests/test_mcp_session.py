from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest

from pydantic import ValidationError

from app.auth import Principal

from app.mcp_session import (
    MCPSessionAccessDenied,
    MCPSessionExpired,
    MCPSessionManager,
    MCPSessionNotFound,
    MCPSessionRevoked,
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



# -------------------------------------------------
# SESSION REVOCATION
# -------------------------------------------------


def test_revoked_session_is_rejected():

    manager = MCPSessionManager()

    principal = make_principal(
        "alice"
    )

    start = fixed_time()

    session = manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=start,
    )

    revoked = manager.revoke_session(
        principal,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    assert revoked.revoked_at == (
        start
        + timedelta(
            minutes=5
        )
    )

    with pytest.raises(
        MCPSessionRevoked
    ):

        manager.validate_session(
            principal,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=(
                start
                + timedelta(
                    minutes=10
                )
            ),
        )


def test_user_cannot_revoke_another_users_session():

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

        manager.revoke_session(
            bob,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=fixed_time(),
        )

    validated = manager.validate_session(
        alice,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    assert validated.session_id == session.session_id


def test_session_revocation_cannot_cross_tenant_boundary():

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

        manager.revoke_session(
            principal,
            session_id=session.session_id,
            tenant_id="tenant-b",
            now=fixed_time(),
        )

    validated = manager.validate_session(
        principal,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    assert validated.session_id == session.session_id


def test_revoked_session_cannot_build_security_context():

    manager = MCPSessionManager()

    principal = make_principal(
        "alice"
    )

    start = fixed_time()

    session = manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=start,
    )

    manager.revoke_session(
        principal,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    with pytest.raises(
        MCPSessionRevoked
    ):

        manager.build_security_context(
            principal,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=(
                start
                + timedelta(
                    minutes=10
                )
            ),
        )


def test_session_revocation_is_audited(
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

    manager.revoke_session(
        principal,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    revoked = [
        details
        for event_type, details
        in events
        if event_type
        == "MCP_SESSION_REVOKED"
    ]

    assert len(revoked) == 1

    assert (
        revoked[0]["principal_id"]
        == "alice"
    )

    assert (
        revoked[0]["tenant_id"]
        == "tenant-a"
    )

    assert (
        session.session_id
        not in str(revoked[0])
    )


def test_revoked_session_validation_is_audited(
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

    manager.revoke_session(
        principal,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    with pytest.raises(
        MCPSessionRevoked
    ):

        manager.validate_session(
            principal,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=fixed_time(),
        )

    blocked = [
        details
        for event_type, details
        in events
        if (
            event_type
            == "MCP_SESSION_VALIDATION_BLOCKED"
            and details.get("reason")
            == "session_revoked"
        )
    ]

    assert len(blocked) == 1

    assert (
        blocked[0]["principal_id"]
        == "alice"
    )

    assert (
        blocked[0]["tenant_id"]
        == "tenant-a"
    )

    assert (
        session.session_id
        not in str(blocked[0])
    )



# -------------------------------------------------
# ADVERSARIAL SESSION LIFECYCLE
# -------------------------------------------------


def test_session_revocation_state_cannot_be_mutated_by_caller():

    manager = MCPSessionManager()

    session = manager.create_session(
        make_principal(),
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    with pytest.raises(
        ValidationError
    ):

        session.revoked_at = fixed_time()


def test_repeated_revocation_is_idempotent(
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

    start = fixed_time()

    session = manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=start,
    )

    first_revocation = manager.revoke_session(
        principal,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    second_revocation = manager.revoke_session(
        principal,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=10
            )
        ),
    )

    assert (
        first_revocation.revoked_at
        == start
        + timedelta(
            minutes=5
        )
    )

    assert (
        second_revocation.revoked_at
        == first_revocation.revoked_at
    )

    revoked_events = [
        event_type
        for event_type, _details
        in events
        if event_type
        == "MCP_SESSION_REVOKED"
    ]

    assert len(revoked_events) == 1


def test_stale_session_object_cannot_bypass_revocation():

    manager = MCPSessionManager()

    principal = make_principal(
        "alice"
    )

    start = fixed_time()

    original_session = manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=start,
    )

    manager.revoke_session(
        principal,
        session_id=original_session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    # The original immutable object is merely a stale
    # snapshot. The manager's stored record is authoritative.
    assert original_session.revoked_at is None

    with pytest.raises(
        MCPSessionRevoked
    ):

        manager.validate_session(
            principal,
            session_id=original_session.session_id,
            tenant_id="tenant-a",
            now=(
                start
                + timedelta(
                    minutes=10
                )
            ),
        )


def test_revoked_session_remains_revoked_after_expiration_time():

    manager = MCPSessionManager(
        session_ttl=timedelta(
            minutes=30
        )
    )

    principal = make_principal(
        "alice"
    )

    start = fixed_time()

    session = manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=start,
    )

    manager.revoke_session(
        principal,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    with pytest.raises(
        MCPSessionRevoked
    ):

        manager.validate_session(
            principal,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=(
                start
                + timedelta(
                    minutes=31
                )
            ),
        )


def test_unknown_session_revocation_is_rejected_and_audited(
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

    unknown_session_id = (
        "attacker-controlled-session-id"
    )

    with pytest.raises(
        MCPSessionNotFound
    ):

        manager.revoke_session(
            make_principal(
                "alice"
            ),
            session_id=unknown_session_id,
            tenant_id="tenant-a",
            now=fixed_time(),
        )

    blocked = [
        details
        for event_type, details
        in events
        if event_type
        == "MCP_SESSION_REVOCATION_BLOCKED"
    ]

    assert len(blocked) == 1

    assert (
        blocked[0]["reason"]
        == "session_not_found"
    )

    assert (
        blocked[0]["principal_id"]
        == "alice"
    )

    assert (
        blocked[0]["tenant_id"]
        == "tenant-a"
    )

    assert (
        unknown_session_id
        not in str(blocked[0])
    )


# -------------------------------------------------
# PRINCIPAL-WIDE SESSION REVOCATION
# -------------------------------------------------


def make_session_admin(
    username: str = "session-admin",
) -> Principal:

    return Principal(
        username=username,
        role="ANALYST",
        retrieval_access="standard",
        session_revocation_access="tenant_admin",
    )


def test_tenant_admin_can_revoke_principal_sessions():

    manager = MCPSessionManager()

    admin = make_session_admin()

    alice = make_principal(
        "alice"
    )

    start = fixed_time()

    admin_session = manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=start,
    )

    first = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    second = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    result = manager.revoke_principal_sessions(
        admin,
        actor_session_id=admin_session.session_id,
        tenant_id="tenant-a",
        target_principal_id="alice",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    assert result.principal_id == "alice"
    assert result.tenant_id == "tenant-a"
    assert result.matched_sessions == 2
    assert result.newly_revoked_sessions == 2
    assert result.already_revoked_sessions == 0

    with pytest.raises(
        MCPSessionRevoked
    ):

        manager.validate_session(
            alice,
            session_id=first.session_id,
            tenant_id="tenant-a",
            now=(
                start
                + timedelta(
                    minutes=10
                )
            ),
        )

    with pytest.raises(
        MCPSessionRevoked
    ):

        manager.validate_session(
            alice,
            session_id=second.session_id,
            tenant_id="tenant-a",
            now=(
                start
                + timedelta(
                    minutes=10
                )
            ),
        )


def test_bulk_revocation_is_tenant_scoped():

    manager = MCPSessionManager()

    admin = make_session_admin()

    alice = make_principal(
        "alice"
    )

    start = fixed_time()

    admin_session = manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=start,
    )

    tenant_a_session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    tenant_b_session = manager.create_session(
        alice,
        tenant_id="tenant-b",
        now=start,
    )

    manager.revoke_principal_sessions(
        admin,
        actor_session_id=admin_session.session_id,
        tenant_id="tenant-a",
        target_principal_id="alice",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    with pytest.raises(
        MCPSessionRevoked
    ):

        manager.validate_session(
            alice,
            session_id=tenant_a_session.session_id,
            tenant_id="tenant-a",
            now=(
                start
                + timedelta(
                    minutes=10
                )
            ),
        )

    validated = manager.validate_session(
        alice,
        session_id=tenant_b_session.session_id,
        tenant_id="tenant-b",
        now=(
            start
            + timedelta(
                minutes=10
            )
        ),
    )

    assert (
        validated.session_id
        == tenant_b_session.session_id
    )


def test_bulk_revocation_does_not_affect_other_principals():

    manager = MCPSessionManager()

    admin = make_session_admin()

    alice = make_principal(
        "alice"
    )

    bob = make_principal(
        "bob"
    )

    start = fixed_time()

    admin_session = manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=start,
    )

    manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    bob_session = manager.create_session(
        bob,
        tenant_id="tenant-a",
        now=start,
    )

    manager.revoke_principal_sessions(
        admin,
        actor_session_id=admin_session.session_id,
        tenant_id="tenant-a",
        target_principal_id="alice",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    validated = manager.validate_session(
        bob,
        session_id=bob_session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=10
            )
        ),
    )

    assert (
        validated.session_id
        == bob_session.session_id
    )


def test_ordinary_principal_cannot_bulk_revoke_sessions():

    manager = MCPSessionManager()

    actor = make_principal(
        "ordinary-user"
    )

    alice = make_principal(
        "alice"
    )

    start = fixed_time()

    actor_session = manager.create_session(
        actor,
        tenant_id="tenant-a",
        now=start,
    )

    alice_session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    with pytest.raises(
        MCPSessionAccessDenied
    ):

        manager.revoke_principal_sessions(
            actor,
            actor_session_id=actor_session.session_id,
            tenant_id="tenant-a",
            target_principal_id="alice",
            now=(
                start
                + timedelta(
                    minutes=5
                )
            ),
        )

    validated = manager.validate_session(
        alice,
        session_id=alice_session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=10
            )
        ),
    )

    assert (
        validated.session_id
        == alice_session.session_id
    )


def test_revoked_admin_session_cannot_bulk_revoke():

    manager = MCPSessionManager()

    admin = make_session_admin()

    alice = make_principal(
        "alice"
    )

    start = fixed_time()

    admin_session = manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=start,
    )

    alice_session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    manager.revoke_session(
        admin,
        session_id=admin_session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    with pytest.raises(
        MCPSessionRevoked
    ):

        manager.revoke_principal_sessions(
            admin,
            actor_session_id=admin_session.session_id,
            tenant_id="tenant-a",
            target_principal_id="alice",
            now=(
                start
                + timedelta(
                    minutes=10
                )
            ),
        )

    validated = manager.validate_session(
        alice,
        session_id=alice_session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=10
            )
        ),
    )

    assert (
        validated.session_id
        == alice_session.session_id
    )


def test_expired_admin_session_cannot_bulk_revoke():

    manager = MCPSessionManager(
        session_ttl=timedelta(
            minutes=30
        )
    )

    admin = make_session_admin()

    alice = make_principal(
        "alice"
    )

    start = fixed_time()

    admin_session = manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=start,
    )

    alice_session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    with pytest.raises(
        MCPSessionExpired
    ):

        manager.revoke_principal_sessions(
            admin,
            actor_session_id=admin_session.session_id,
            tenant_id="tenant-a",
            target_principal_id="alice",
            now=(
                start
                + timedelta(
                    minutes=31
                )
            ),
        )

    # Use a time before Alice's own expiration to prove
    # the failed admin action did not revoke her session.
    validated = manager.validate_session(
        alice,
        session_id=alice_session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=20
            )
        ),
    )

    assert (
        validated.session_id
        == alice_session.session_id
    )


def test_bulk_revocation_is_idempotent():

    manager = MCPSessionManager()

    admin = make_session_admin()

    alice = make_principal(
        "alice"
    )

    start = fixed_time()

    admin_session = manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=start,
    )

    manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    first = manager.revoke_principal_sessions(
        admin,
        actor_session_id=admin_session.session_id,
        tenant_id="tenant-a",
        target_principal_id="alice",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    second = manager.revoke_principal_sessions(
        admin,
        actor_session_id=admin_session.session_id,
        tenant_id="tenant-a",
        target_principal_id="alice",
        now=(
            start
            + timedelta(
                minutes=10
            )
        ),
    )

    assert first.matched_sessions == 2
    assert first.newly_revoked_sessions == 2
    assert first.already_revoked_sessions == 0

    assert second.matched_sessions == 2
    assert second.newly_revoked_sessions == 0
    assert second.already_revoked_sessions == 2


# -------------------------------------------------
# PRINCIPAL-WIDE REVOCATION HARDENING
# -------------------------------------------------


def test_tenant_admin_cannot_use_wrong_tenant_scope():

    manager = MCPSessionManager()

    admin = make_session_admin()

    alice = make_principal(
        "alice"
    )

    start = fixed_time()

    admin_session = manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=start,
    )

    alice_session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    with pytest.raises(
        MCPSessionAccessDenied
    ):

        manager.revoke_principal_sessions(
            admin,
            actor_session_id=admin_session.session_id,
            tenant_id="tenant-b",
            target_principal_id="alice",
            now=(
                start
                + timedelta(
                    minutes=5
                )
            ),
        )

    validated = manager.validate_session(
        alice,
        session_id=alice_session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=10
            )
        ),
    )

    assert (
        validated.session_id
        == alice_session.session_id
    )


def test_approver_cannot_bulk_revoke_without_explicit_authority():

    manager = MCPSessionManager()

    approver = Principal(
        username="approver",
        role="APPROVER",
        retrieval_access="standard",
    )

    alice = make_principal(
        "alice"
    )

    start = fixed_time()

    approver_session = manager.create_session(
        approver,
        tenant_id="tenant-a",
        now=start,
    )

    alice_session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    with pytest.raises(
        MCPSessionAccessDenied
    ):

        manager.revoke_principal_sessions(
            approver,
            actor_session_id=(
                approver_session.session_id
            ),
            tenant_id="tenant-a",
            target_principal_id="alice",
            now=(
                start
                + timedelta(
                    minutes=5
                )
            ),
        )

    validated = manager.validate_session(
        alice,
        session_id=alice_session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=10
            )
        ),
    )

    assert (
        validated.session_id
        == alice_session.session_id
    )


def test_bulk_revocation_rejects_empty_target_principal():

    manager = MCPSessionManager()

    admin = make_session_admin()

    session = manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    with pytest.raises(
        ValueError
    ):

        manager.revoke_principal_sessions(
            admin,
            actor_session_id=session.session_id,
            tenant_id="tenant-a",
            target_principal_id="",
            now=fixed_time(),
        )


def test_bulk_revocation_of_unknown_target_returns_zero_counts():

    manager = MCPSessionManager()

    admin = make_session_admin()

    admin_session = manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    result = manager.revoke_principal_sessions(
        admin,
        actor_session_id=admin_session.session_id,
        tenant_id="tenant-a",
        target_principal_id="does-not-exist",
        now=fixed_time(),
    )

    assert result.matched_sessions == 0
    assert result.newly_revoked_sessions == 0
    assert result.already_revoked_sessions == 0


def test_principal_session_revocation_result_is_immutable():

    manager = MCPSessionManager()

    admin = make_session_admin()

    admin_session = manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    result = manager.revoke_principal_sessions(
        admin,
        actor_session_id=admin_session.session_id,
        tenant_id="tenant-a",
        target_principal_id="alice",
        now=fixed_time(),
    )

    with pytest.raises(
        ValidationError
    ):

        result.matched_sessions = 999


def test_bulk_revocation_audit_is_aggregate_and_token_safe(
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

    admin = make_session_admin()

    alice = make_principal(
        "alice"
    )

    start = fixed_time()

    admin_session = manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=start,
    )

    first = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    second = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    result = manager.revoke_principal_sessions(
        admin,
        actor_session_id=admin_session.session_id,
        tenant_id="tenant-a",
        target_principal_id="alice",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    revoked_events = [
        details
        for event_type, details
        in events
        if event_type
        == "MCP_PRINCIPAL_SESSIONS_REVOKED"
    ]

    assert len(revoked_events) == 1

    details = revoked_events[0]

    assert (
        details["actor_principal_id"]
        == admin.username
    )

    assert (
        details["target_principal_id"]
        == "alice"
    )

    assert (
        details["tenant_id"]
        == "tenant-a"
    )

    assert details["matched_sessions"] == 2

    assert (
        details["newly_revoked_sessions"]
        == 2
    )

    assert (
        details["already_revoked_sessions"]
        == 0
    )

    assert (
        admin_session.session_id
        not in str(details)
    )

    assert (
        first.session_id
        not in str(details)
    )

    assert (
        second.session_id
        not in str(details)
    )

    assert (
        first.session_id
        not in str(result)
    )

    assert (
        second.session_id
        not in str(result)
    )


def test_repeat_bulk_revocation_preserves_original_timestamp():

    store = InMemorySessionStore()

    manager = MCPSessionManager(
        session_store=store
    )

    admin = make_session_admin()

    alice = make_principal(
        "alice"
    )

    start = fixed_time()

    admin_session = manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=start,
    )

    alice_session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    first_time = (
        start
        + timedelta(
            minutes=5
        )
    )

    second_time = (
        start
        + timedelta(
            minutes=10
        )
    )

    manager.revoke_principal_sessions(
        admin,
        actor_session_id=admin_session.session_id,
        tenant_id="tenant-a",
        target_principal_id="alice",
        now=first_time,
    )

    first_revoked_at = (
        store.get(
            alice_session.session_id
        ).revoked_at
    )

    manager.revoke_principal_sessions(
        admin,
        actor_session_id=admin_session.session_id,
        tenant_id="tenant-a",
        target_principal_id="alice",
        now=second_time,
    )

    second_revoked_at = (
        store.get(
            alice_session.session_id
        ).revoked_at
    )

    assert first_revoked_at == first_time

    assert (
        second_revoked_at
        == first_revoked_at
    )


# -------------------------------------------------
# SESSION STORE INJECTION
# -------------------------------------------------

from app.mcp_session_store import InMemorySessionStore


def test_session_manager_accepts_injected_store():

    store = InMemorySessionStore()

    manager = MCPSessionManager(
        session_store=store
    )

    principal = make_principal(
        "alice"
    )

    session = manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=fixed_time(),
    )

    assert (
        store.get(
            session.session_id
        )
        == session
    )


def test_managers_sharing_store_observe_same_session():

    store = InMemorySessionStore()

    first_manager = MCPSessionManager(
        session_store=store
    )

    second_manager = MCPSessionManager(
        session_store=store
    )

    principal = make_principal(
        "alice"
    )

    start = fixed_time()

    session = first_manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=start,
    )

    validated = second_manager.validate_session(
        principal,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    assert (
        validated.session_id
        == session.session_id
    )


def test_shared_store_propagates_revocation_between_managers():

    store = InMemorySessionStore()

    first_manager = MCPSessionManager(
        session_store=store
    )

    second_manager = MCPSessionManager(
        session_store=store
    )

    principal = make_principal(
        "alice"
    )

    start = fixed_time()

    session = first_manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=start,
    )

    first_manager.revoke_session(
        principal,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    with pytest.raises(
        MCPSessionRevoked
    ):

        second_manager.validate_session(
            principal,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=(
                start
                + timedelta(
                    minutes=10
                )
            ),
        )


def test_default_session_managers_remain_isolated():

    first_manager = MCPSessionManager()

    second_manager = MCPSessionManager()

    principal = make_principal(
        "alice"
    )

    start = fixed_time()

    session = first_manager.create_session(
        principal,
        tenant_id="tenant-a",
        now=start,
    )

    with pytest.raises(
        MCPSessionNotFound
    ):

        second_manager.validate_session(
            principal,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=(
                start
                + timedelta(
                    minutes=5
                )
            ),
        )
