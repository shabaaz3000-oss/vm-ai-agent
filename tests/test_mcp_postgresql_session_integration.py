import os

from concurrent.futures import ThreadPoolExecutor

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from threading import Barrier

import pytest

import psycopg

from psycopg import sql

from app.auth import Principal

from app.mcp_session import (
    MCPSessionManager,
    MCPSessionRevoked,
)

from app.mcp_postgresql_schema import (
    provision_postgresql_session_schema,
)

from app.mcp_postgresql_session_store import (
    PostgreSQLSessionStore,
)


# -------------------------------------------------
# POSTGRES TEST CONFIGURATION
# -------------------------------------------------


def postgres_database_url() -> str:
    """
    Provision the integration schema using a deployment
    identity, then return a separate least-privileged URL
    used by PostgreSQLSessionStore.
    """

    database_url = os.environ.get(
        "TEST_POSTGRES_DATABASE_URL"
    )

    admin_database_url = os.environ.get(
        "TEST_POSTGRES_ADMIN_DATABASE_URL"
    )

    if (
        not database_url
        or not admin_database_url
    ):

        pytest.skip(
            "PostgreSQL integration-test URLs "
            "are not configured"
        )

    provision_postgresql_session_schema(
        database_url=
            admin_database_url
    )

    with psycopg.connect(
        admin_database_url,
        autocommit=True,
    ) as connection:

        role = connection.execute(
            """
            SELECT 1
            FROM pg_roles
            WHERE rolname = %s
            """,
            (
                "vm_ai_runtime",
            ),
        ).fetchone()

        if role is None:

            connection.execute(
                """
                CREATE ROLE vm_ai_runtime LOGIN
                """
            )

        database_name = (
            connection.execute(
                """
                SELECT current_database()
                """
            ).fetchone()[0]
        )

        connection.execute(
            sql.SQL(
                """
                REVOKE CREATE ON SCHEMA public
                FROM PUBLIC
                """
            )
        )

        connection.execute(
            sql.SQL(
                """
                REVOKE TEMPORARY ON DATABASE {}
                FROM PUBLIC
                """
            ).format(
                sql.Identifier(
                    database_name
                )
            )
        )

        connection.execute(
            sql.SQL(
                """
                GRANT CONNECT ON DATABASE {}
                TO vm_ai_runtime
                """
            ).format(
                sql.Identifier(
                    database_name
                )
            )
        )

        connection.execute(
            """
            GRANT USAGE ON SCHEMA public
            TO vm_ai_runtime
            """
        )

        connection.execute(
            """
            REVOKE ALL PRIVILEGES
            ON TABLE mcp_sessions
            FROM PUBLIC
            """
        )

        connection.execute(
            """
            GRANT SELECT, INSERT, UPDATE
            ON TABLE mcp_sessions
            TO vm_ai_runtime
            """
        )

    return database_url


def fixed_time() -> datetime:

    return datetime(
        2026,
        9,
        28,
        0,
        0,
        tzinfo=timezone.utc,
    )


def make_principal() -> Principal:

    return Principal(
        username="alice",
        role="ANALYST",
        retrieval_access="standard",
    )




# -------------------------------------------------
# RUNTIME DATABASE LEAST PRIVILEGE
# -------------------------------------------------


def test_runtime_identity_cannot_create_schema_objects():

    database_url = (
        postgres_database_url()
    )

    with pytest.raises(
        psycopg.errors.InsufficientPrivilege
    ):

        with psycopg.connect(
            database_url
        ) as connection:

            connection.execute(
                """
                CREATE TABLE
                    mcp_runtime_ddl_should_fail (
                        id INTEGER
                    )
                """
            )


def test_runtime_identity_cannot_delete_session_rows():

    database_url = (
        postgres_database_url()
    )

    with pytest.raises(
        psycopg.errors.InsufficientPrivilege
    ):

        with psycopg.connect(
            database_url
        ) as connection:

            connection.execute(
                """
                DELETE FROM mcp_sessions
                WHERE FALSE
                """
            )


# -------------------------------------------------
# MULTI-INSTANCE ATOMIC COMPARE-AND-SWAP
# -------------------------------------------------


def test_multi_instance_compare_and_swap_has_one_winner():

    database_url = (
        postgres_database_url()
    )

    first_store = PostgreSQLSessionStore(
        database_url=database_url
    )

    second_store = PostgreSQLSessionStore(
        database_url=database_url
    )

    authoritative_store = PostgreSQLSessionStore(
        database_url=database_url
    )

    manager = MCPSessionManager(
        session_store=first_store
    )

    alice = make_principal()

    start = fixed_time()

    session = manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    # Independent application instances obtain the same
    # authoritative active session before either mutation.

    first_expected = first_store.get(
        session.session_id
    )

    second_expected = second_store.get(
        session.session_id
    )

    assert first_expected is not None
    assert second_expected is not None

    assert first_expected == second_expected

    first_revocation_time = (
        start
        + timedelta(
            minutes=5
        )
    )

    second_revocation_time = (
        start
        + timedelta(
            minutes=10
        )
    )

    first_replacement = (
        first_expected.model_copy(
            update={
                "revoked_at":
                    first_revocation_time,
            }
        )
    )

    second_replacement = (
        second_expected.model_copy(
            update={
                "revoked_at":
                    second_revocation_time,
            }
        )
    )

    barrier = Barrier(
        2
    )

    def compete(
        store,
        expected,
        replacement,
    ):

        barrier.wait(
            timeout=10
        )

        return store.replace_if_current(
            expected=expected,
            replacement=replacement,
        )

    with ThreadPoolExecutor(
        max_workers=2
    ) as executor:

        first_future = executor.submit(
            compete,
            first_store,
            first_expected,
            first_replacement,
        )

        second_future = executor.submit(
            compete,
            second_store,
            second_expected,
            second_replacement,
        )

        results = (
            first_future.result(),
            second_future.result(),
        )

    # Exactly one independent instance may successfully
    # perform the ACTIVE -> REVOKED state transition.

    assert sorted(
        results
    ) == [
        False,
        True,
    ]

    authoritative = (
        authoritative_store.get(
            session.session_id
        )
    )

    assert authoritative is not None

    assert authoritative.revoked_at in (
        first_revocation_time,
        second_revocation_time,
    )


# -------------------------------------------------
# CROSS-INSTANCE REVOCATION AUTHORITY
# -------------------------------------------------


def test_revocation_on_one_instance_is_immediately_authoritative():

    database_url = (
        postgres_database_url()
    )

    first_store = PostgreSQLSessionStore(
        database_url=database_url
    )

    second_store = PostgreSQLSessionStore(
        database_url=database_url
    )

    third_store = PostgreSQLSessionStore(
        database_url=database_url
    )

    first_manager = MCPSessionManager(
        session_store=first_store
    )

    second_manager = MCPSessionManager(
        session_store=second_store
    )

    alice = make_principal()

    start = fixed_time()

    # Instance A creates the session.

    session = first_manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    # Instance B independently validates the session
    # using the shared PostgreSQL authority.

    validated = second_manager.validate_session(
        alice,
        session_id=session.session_id,
        tenant_id="tenant-a",
        now=(
            start
            + timedelta(
                minutes=1
            )
        ),
    )

    assert (
        validated.session_id
        == session.session_id
    )

    # Instance B revokes the session.

    revoked = second_manager.revoke_session(
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

    assert revoked.revoked_at is not None

    # A third independent store sees the same
    # authoritative revocation.

    authoritative = third_store.get(
        session.session_id
    )

    assert authoritative is not None

    assert (
        authoritative.revoked_at
        == revoked.revoked_at
    )

    # Instance A must no longer trust the session merely
    # because it originally created it.

    with pytest.raises(
        MCPSessionRevoked
    ):

        first_manager.validate_session(
            alice,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=(
                start
                + timedelta(
                    minutes=6
                )
            ),
        )
