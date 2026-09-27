from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest

from app.auth import Principal

from app.mcp_session import (
    MCPSessionManager,
    MCPSessionRevoked,
)

from app.mcp_sqlite_session_store import (
    SQLiteSessionStore,
)


# -------------------------------------------------
# TEST HELPERS
# -------------------------------------------------


def fixed_time() -> datetime:

    return datetime(
        2026,
        9,
        27,
        12,
        0,
        tzinfo=timezone.utc,
    )


def make_principal(
    username: str,
) -> Principal:

    return Principal(
        username=username,
        role="ANALYST",
        retrieval_access="standard",
    )


def make_session_admin() -> Principal:

    return Principal(
        username="session-admin",
        role="ANALYST",
        retrieval_access="standard",
        session_revocation_access="tenant_admin",
    )


def make_managers(
    tmp_path,
):

    database_path = (
        tmp_path
        / "mcp_sessions.db"
    )

    first_store = SQLiteSessionStore(
        database_path=database_path
    )

    second_store = SQLiteSessionStore(
        database_path=database_path
    )

    first_manager = MCPSessionManager(
        session_store=first_store
    )

    second_manager = MCPSessionManager(
        session_store=second_store
    )

    return (
        first_manager,
        second_manager,
        database_path,
    )


# -------------------------------------------------
# CROSS-INSTANCE SESSION VISIBILITY
# -------------------------------------------------


def test_session_created_by_one_manager_is_valid_in_another(
    tmp_path,
):

    (
        first_manager,
        second_manager,
        _,
    ) = make_managers(
        tmp_path
    )

    alice = make_principal(
        "alice"
    )

    start = fixed_time()

    session = first_manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    validated = second_manager.validate_session(
        alice,
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


# -------------------------------------------------
# CROSS-INSTANCE SINGLE REVOCATION
# -------------------------------------------------


def test_revocation_by_one_manager_is_enforced_by_another(
    tmp_path,
):

    (
        first_manager,
        second_manager,
        _,
    ) = make_managers(
        tmp_path
    )

    alice = make_principal(
        "alice"
    )

    start = fixed_time()

    session = first_manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    first_manager.revoke_session(
        alice,
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
            alice,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=(
                start
                + timedelta(
                    minutes=10
                )
            ),
        )


# -------------------------------------------------
# CROSS-INSTANCE ADMINISTRATIVE REVOCATION
# -------------------------------------------------


def test_principal_wide_revocation_propagates_across_managers(
    tmp_path,
):

    (
        first_manager,
        second_manager,
        _,
    ) = make_managers(
        tmp_path
    )

    admin = make_session_admin()

    alice = make_principal(
        "alice"
    )

    bob = make_principal(
        "bob"
    )

    start = fixed_time()

    admin_session = first_manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=start,
    )

    alice_first = first_manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    alice_second = second_manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    alice_other_tenant = first_manager.create_session(
        alice,
        tenant_id="tenant-b",
        now=start,
    )

    bob_session = second_manager.create_session(
        bob,
        tenant_id="tenant-a",
        now=start,
    )

    result = first_manager.revoke_principal_sessions(
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

    assert result.matched_sessions == 2
    assert result.newly_revoked_sessions == 2

    for session in (
        alice_first,
        alice_second,
    ):

        with pytest.raises(
            MCPSessionRevoked
        ):

            second_manager.validate_session(
                alice,
                session_id=session.session_id,
                tenant_id="tenant-a",
                now=(
                    start
                    + timedelta(
                        minutes=10
                    )
                ),
            )

    validated_other_tenant = (
        second_manager.validate_session(
            alice,
            session_id=(
                alice_other_tenant.session_id
            ),
            tenant_id="tenant-b",
            now=(
                start
                + timedelta(
                    minutes=10
                )
            ),
        )
    )

    assert (
        validated_other_tenant.session_id
        == alice_other_tenant.session_id
    )

    validated_bob = (
        first_manager.validate_session(
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
    )

    assert (
        validated_bob.session_id
        == bob_session.session_id
    )


# -------------------------------------------------
# REVOCATION SURVIVES MANAGER / STORE RECONSTRUCTION
# -------------------------------------------------


def test_revocation_survives_new_store_and_manager_instances(
    tmp_path,
):

    (
        first_manager,
        _,
        database_path,
    ) = make_managers(
        tmp_path
    )

    alice = make_principal(
        "alice"
    )

    start = fixed_time()

    session = first_manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    first_manager.revoke_session(
        alice,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=5
            )
        ),
    )

    reconstructed_store = SQLiteSessionStore(
        database_path=database_path
    )

    reconstructed_manager = MCPSessionManager(
        session_store=reconstructed_store
    )

    with pytest.raises(
        MCPSessionRevoked
    ):

        reconstructed_manager.validate_session(
            alice,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=(
                start
                + timedelta(
                    minutes=10
                )
            ),
        )
