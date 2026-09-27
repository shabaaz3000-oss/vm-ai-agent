from concurrent.futures import ThreadPoolExecutor

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from threading import Barrier

from app.auth import Principal

from app.mcp_session import (
    MCPSessionManager,
)

from app.mcp_sqlite_session_store import (
    SQLiteSessionStore,
)


# -------------------------------------------------
# COORDINATED SQLITE STORE
# -------------------------------------------------


class CoordinatedSQLiteSessionStore(
    SQLiteSessionStore
):
    """
    Test-only SQLite store that forces two revocation
    callers to read the same active session before either
    caller can proceed to save its replacement.
    """

    def __init__(
        self,
        *,
        database_path,
        barrier: Barrier,
    ) -> None:

        super().__init__(
            database_path=database_path
        )

        self._barrier = barrier

        self.coordinate_reads = False

    def get(
        self,
        session_id: str,
    ):

        session = super().get(
            session_id
        )

        if (
            self.coordinate_reads
            and session is not None
            and session.revoked_at is None
        ):

            self._barrier.wait(
                timeout=5
            )

        return session


# -------------------------------------------------
# HELPERS
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


def make_principal() -> Principal:

    return Principal(
        username="alice",
        role="ANALYST",
        retrieval_access="standard",
    )


# -------------------------------------------------
# CONCURRENT SINGLE-SESSION REVOCATION
# -------------------------------------------------


def test_concurrent_revocation_has_one_authoritative_timestamp(
    tmp_path,
):

    database_path = (
        tmp_path
        / "mcp_sessions.db"
    )

    barrier = Barrier(
        2
    )

    first_store = CoordinatedSQLiteSessionStore(
        database_path=database_path,
        barrier=barrier,
    )

    second_store = CoordinatedSQLiteSessionStore(
        database_path=database_path,
        barrier=barrier,
    )

    first_manager = MCPSessionManager(
        session_store=first_store
    )

    second_manager = MCPSessionManager(
        session_store=second_store
    )

    alice = make_principal()

    start = fixed_time()

    session = first_manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    # Coordinate only the revocation reads. Session
    # creation itself must complete normally first.

    first_store.coordinate_reads = True
    second_store.coordinate_reads = True

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

    def revoke_first():

        return first_manager.revoke_session(
            alice,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=first_revocation_time,
        )

    def revoke_second():

        return second_manager.revoke_session(
            alice,
            session_id=session.session_id,
            tenant_id="tenant-a",
            now=second_revocation_time,
        )

    with ThreadPoolExecutor(
        max_workers=2
    ) as executor:

        first_future = executor.submit(
            revoke_first
        )

        second_future = executor.submit(
            revoke_second
        )

        first_result = (
            first_future.result()
        )

        second_result = (
            second_future.result()
        )

    authoritative = SQLiteSessionStore(
        database_path=database_path
    ).get(
        session.session_id
    )

    assert authoritative is not None

    # Both callers must observe the same winning
    # authoritative revocation record. A stale caller
    # must not return its losing timestamp as though its
    # write became authoritative.

    assert (
        first_result.revoked_at
        == authoritative.revoked_at
    )

    assert (
        second_result.revoked_at
        == authoritative.revoked_at
    )


# -------------------------------------------------
# COORDINATED BULK SQLITE STORE
# -------------------------------------------------


class CoordinatedBulkSQLiteSessionStore(
    SQLiteSessionStore
):
    """
    Test-only store that forces two administrative
    revocation callers to enumerate the same active target
    sessions before either caller can persist revocation.
    """

    def __init__(
        self,
        *,
        database_path,
        barrier: Barrier,
    ) -> None:

        super().__init__(
            database_path=database_path
        )

        self._bulk_barrier = barrier

        self.coordinate_lists = False

    def list_for_principal(
        self,
        *,
        principal_id: str,
        tenant_id: str,
    ):

        sessions = super().list_for_principal(
            principal_id=principal_id,
            tenant_id=tenant_id,
        )

        if (
            self.coordinate_lists
            and principal_id == "alice"
            and tenant_id == "tenant-a"
        ):

            self._bulk_barrier.wait(
                timeout=5
            )

        return sessions


# -------------------------------------------------
# CONCURRENT PRINCIPAL-WIDE REVOCATION
# -------------------------------------------------


def test_concurrent_bulk_revocation_has_one_state_transition(
    tmp_path,
):

    database_path = (
        tmp_path
        / "mcp_sessions.db"
    )

    barrier = Barrier(
        2
    )

    first_store = CoordinatedBulkSQLiteSessionStore(
        database_path=database_path,
        barrier=barrier,
    )

    second_store = CoordinatedBulkSQLiteSessionStore(
        database_path=database_path,
        barrier=barrier,
    )

    first_manager = MCPSessionManager(
        session_store=first_store
    )

    second_manager = MCPSessionManager(
        session_store=second_store
    )

    admin = Principal(
        username="session-admin",
        role="ANALYST",
        retrieval_access="standard",
        session_revocation_access="tenant_admin",
    )

    alice = Principal(
        username="alice",
        role="ANALYST",
        retrieval_access="standard",
    )

    start = fixed_time()

    admin_session = first_manager.create_session(
        admin,
        tenant_id="tenant-a",
        now=start,
    )

    alice_session = first_manager.create_session(
        alice,
        tenant_id="tenant-a",
        now=start,
    )

    # Coordinate only target enumeration after setup.
    first_store.coordinate_lists = True
    second_store.coordinate_lists = True

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

    def revoke_first():

        return first_manager.revoke_principal_sessions(
            admin,
            actor_session_id=admin_session.session_id,
            tenant_id="tenant-a",
            target_principal_id="alice",
            now=first_revocation_time,
        )

    def revoke_second():

        return second_manager.revoke_principal_sessions(
            admin,
            actor_session_id=admin_session.session_id,
            tenant_id="tenant-a",
            target_principal_id="alice",
            now=second_revocation_time,
        )

    with ThreadPoolExecutor(
        max_workers=2
    ) as executor:

        first_future = executor.submit(
            revoke_first
        )

        second_future = executor.submit(
            revoke_second
        )

        first_result = (
            first_future.result()
        )

        second_result = (
            second_future.result()
        )

    results = (
        first_result,
        second_result,
    )

    # Exactly one administrative operation may perform
    # the ACTIVE -> REVOKED transition.

    assert (
        sum(
            result.newly_revoked_sessions
            for result in results
        )
        == 1
    )

    # The losing concurrent caller must observe that the
    # session is already authoritatively revoked.

    assert (
        sum(
            result.already_revoked_sessions
            for result in results
        )
        == 1
    )

    authoritative = SQLiteSessionStore(
        database_path=database_path
    ).get(
        alice_session.session_id
    )

    assert authoritative is not None

    assert authoritative.revoked_at in (
        first_revocation_time,
        second_revocation_time,
    )
