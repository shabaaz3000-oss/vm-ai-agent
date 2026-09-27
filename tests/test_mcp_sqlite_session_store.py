from datetime import datetime
from datetime import timedelta
from datetime import timezone

from app.mcp_session import MCPSession

from app.mcp_sqlite_session_store import (
    SQLiteSessionStore,
)


# -------------------------------------------------
# TEST SESSION
# -------------------------------------------------


def make_session(
    *,
    session_id: str = "session-1",
    principal_id: str = "alice",
    tenant_id: str = "tenant-a",
    revoked_at: datetime | None = None,
) -> MCPSession:

    created_at = datetime(
        2026,
        9,
        27,
        12,
        0,
        tzinfo=timezone.utc,
    )

    return MCPSession(
        session_id=session_id,
        principal_id=principal_id,
        tenant_id=tenant_id,
        created_at=created_at,
        expires_at=(
            created_at
            + timedelta(
                minutes=30
            )
        ),
        revoked_at=revoked_at,
    )


# -------------------------------------------------
# DATABASE CREATION
# -------------------------------------------------


def test_sqlite_store_creates_database_on_first_write(
    tmp_path,
):

    database_path = (
        tmp_path
        / "mcp_sessions.db"
    )

    store = SQLiteSessionStore(
        database_path=database_path
    )

    assert (
        database_path.exists()
        is False
    )

    store.save(
        make_session()
    )

    assert (
        database_path.exists()
        is True
    )


# -------------------------------------------------
# SAVE + GET
# -------------------------------------------------


def test_sqlite_store_saves_and_gets_session(
    tmp_path,
):

    store = SQLiteSessionStore(
        database_path=(
            tmp_path
            / "mcp_sessions.db"
        )
    )

    original = make_session()

    result = store.save(
        original
    )

    retrieved = store.get(
        original.session_id
    )

    assert result == original
    assert retrieved == original


# -------------------------------------------------
# UNKNOWN SESSION
# -------------------------------------------------


def test_sqlite_store_returns_none_for_unknown_session(
    tmp_path,
):

    store = SQLiteSessionStore(
        database_path=(
            tmp_path
            / "mcp_sessions.db"
        )
    )

    assert (
        store.get(
            "does-not-exist"
        )
        is None
    )


# -------------------------------------------------
# PRINCIPAL + TENANT QUERY
# -------------------------------------------------


def test_sqlite_store_lists_only_matching_principal_and_tenant(
    tmp_path,
):

    store = SQLiteSessionStore(
        database_path=(
            tmp_path
            / "mcp_sessions.db"
        )
    )

    sessions = (
        make_session(
            session_id="alice-a1",
            principal_id="alice",
            tenant_id="tenant-a",
        ),
        make_session(
            session_id="alice-a2",
            principal_id="alice",
            tenant_id="tenant-a",
        ),
        make_session(
            session_id="alice-b",
            principal_id="alice",
            tenant_id="tenant-b",
        ),
        make_session(
            session_id="bob-a",
            principal_id="bob",
            tenant_id="tenant-a",
        ),
    )

    for session in sessions:

        store.save(
            session
        )

    results = store.list_for_principal(
        principal_id="alice",
        tenant_id="tenant-a",
    )

    assert {
        session.session_id
        for session in results
    } == {
        "alice-a1",
        "alice-a2",
    }


# -------------------------------------------------
# AUTHORITATIVE REPLACEMENT
# -------------------------------------------------


def test_sqlite_store_persists_replaced_revocation_state(
    tmp_path,
):

    store = SQLiteSessionStore(
        database_path=(
            tmp_path
            / "mcp_sessions.db"
        )
    )

    original = make_session()

    store.save(
        original
    )

    revoked_at = datetime(
        2026,
        9,
        27,
        12,
        5,
        tzinfo=timezone.utc,
    )

    revoked = original.model_copy(
        update={
            "revoked_at":
                revoked_at,
        }
    )

    store.save(
        revoked
    )

    retrieved = store.get(
        original.session_id
    )

    assert retrieved == revoked

    assert (
        retrieved.revoked_at
        == revoked_at
    )


# -------------------------------------------------
# DURABILITY / STORE RECONSTRUCTION
# -------------------------------------------------


def test_sqlite_session_survives_store_reconstruction(
    tmp_path,
):

    database_path = (
        tmp_path
        / "mcp_sessions.db"
    )

    first_store = SQLiteSessionStore(
        database_path=database_path
    )

    session = make_session()

    first_store.save(
        session
    )

    second_store = SQLiteSessionStore(
        database_path=database_path
    )

    retrieved = second_store.get(
        session.session_id
    )

    assert retrieved == session


# -------------------------------------------------
# SHARED AUTHORITATIVE STATE
# -------------------------------------------------


def test_sqlite_store_instances_share_authoritative_state(
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

    session = make_session()

    first_store.save(
        session
    )

    assert (
        second_store.get(
            session.session_id
        )
        == session
    )


# -------------------------------------------------
# ATOMIC COMPARE-AND-SWAP
# -------------------------------------------------


def test_sqlite_store_replace_if_current_succeeds(
    tmp_path,
):

    store = SQLiteSessionStore(
        database_path=(
            tmp_path
            / "mcp_sessions.db"
        )
    )

    original = make_session()

    store.save(
        original
    )

    replacement = original.model_copy(
        update={
            "revoked_at":
                datetime(
                    2026,
                    9,
                    27,
                    12,
                    5,
                    tzinfo=timezone.utc,
                ),
        }
    )

    replaced = store.replace_if_current(
        expected=original,
        replacement=replacement,
    )

    assert replaced is True

    assert (
        store.get(
            original.session_id
        )
        == replacement
    )


def test_sqlite_store_replace_if_current_rejects_stale_expected(
    tmp_path,
):

    store = SQLiteSessionStore(
        database_path=(
            tmp_path
            / "mcp_sessions.db"
        )
    )

    original = make_session()

    first_replacement = original.model_copy(
        update={
            "revoked_at":
                datetime(
                    2026,
                    9,
                    27,
                    12,
                    5,
                    tzinfo=timezone.utc,
                ),
        }
    )

    stale_replacement = original.model_copy(
        update={
            "revoked_at":
                datetime(
                    2026,
                    9,
                    27,
                    12,
                    10,
                    tzinfo=timezone.utc,
                ),
        }
    )

    store.save(
        original
    )

    store.save(
        first_replacement
    )

    replaced = store.replace_if_current(
        expected=original,
        replacement=stale_replacement,
    )

    assert replaced is False

    assert (
        store.get(
            original.session_id
        )
        == first_replacement
    )


def test_sqlite_concurrent_replace_if_current_allows_one_winner(
    tmp_path,
):

    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

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

    original = make_session()

    first_store.save(
        original
    )

    first_replacement = original.model_copy(
        update={
            "revoked_at":
                datetime(
                    2026,
                    9,
                    27,
                    12,
                    5,
                    tzinfo=timezone.utc,
                ),
        }
    )

    second_replacement = original.model_copy(
        update={
            "revoked_at":
                datetime(
                    2026,
                    9,
                    27,
                    12,
                    10,
                    tzinfo=timezone.utc,
                ),
        }
    )

    barrier = Barrier(
        2
    )

    def attempt_replace(
        store,
        replacement,
    ):

        barrier.wait(
            timeout=5
        )

        return store.replace_if_current(
            expected=original,
            replacement=replacement,
        )

    with ThreadPoolExecutor(
        max_workers=2
    ) as executor:

        first_future = executor.submit(
            attempt_replace,
            first_store,
            first_replacement,
        )

        second_future = executor.submit(
            attempt_replace,
            second_store,
            second_replacement,
        )

        results = [
            first_future.result(),
            second_future.result(),
        ]

    assert results.count(True) == 1
    assert results.count(False) == 1

    authoritative = first_store.get(
        original.session_id
    )

    assert authoritative in (
        first_replacement,
        second_replacement,
    )
