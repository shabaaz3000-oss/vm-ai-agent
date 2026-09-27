from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest

from app.mcp_session import MCPSession

from app.mcp_session_store import (
    InMemorySessionStore,
    SessionStore,
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
# ABSTRACT STORE CONTRACT
# -------------------------------------------------


def test_session_store_is_abstract():

    with pytest.raises(
        TypeError
    ):

        SessionStore()


# -------------------------------------------------
# SAVE + GET
# -------------------------------------------------


def test_in_memory_store_saves_and_gets_session():

    store = InMemorySessionStore()

    session = make_session()

    result = store.save(
        session
    )

    assert result == session

    assert (
        store.get(
            session.session_id
        )
        == session
    )


# -------------------------------------------------
# UNKNOWN SESSION
# -------------------------------------------------


def test_in_memory_store_returns_none_for_unknown_session():

    store = InMemorySessionStore()

    assert (
        store.get(
            "does-not-exist"
        )
        is None
    )


# -------------------------------------------------
# PRINCIPAL + TENANT QUERY
# -------------------------------------------------


def test_in_memory_store_lists_only_matching_principal_and_tenant():

    store = InMemorySessionStore()

    alice_a1 = make_session(
        session_id="alice-a1",
        principal_id="alice",
        tenant_id="tenant-a",
    )

    alice_a2 = make_session(
        session_id="alice-a2",
        principal_id="alice",
        tenant_id="tenant-a",
    )

    alice_b = make_session(
        session_id="alice-b",
        principal_id="alice",
        tenant_id="tenant-b",
    )

    bob_a = make_session(
        session_id="bob-a",
        principal_id="bob",
        tenant_id="tenant-a",
    )

    for session in (
        alice_a1,
        alice_a2,
        alice_b,
        bob_a,
    ):

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


def test_in_memory_store_replaces_existing_session_record():

    store = InMemorySessionStore()

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

    stored = store.get(
        original.session_id
    )

    assert stored == revoked

    assert (
        stored.revoked_at
        == revoked_at
    )


# -------------------------------------------------
# STORE INSTANCE ISOLATION
# -------------------------------------------------


def test_in_memory_store_instances_are_isolated():

    first = InMemorySessionStore()

    second = InMemorySessionStore()

    session = make_session()

    first.save(
        session
    )

    assert (
        first.get(
            session.session_id
        )
        == session
    )

    assert (
        second.get(
            session.session_id
        )
        is None
    )


# -------------------------------------------------
# ATOMIC COMPARE-AND-SWAP
# -------------------------------------------------


def test_in_memory_store_replace_if_current_succeeds():

    store = InMemorySessionStore()

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

    replacement = original.model_copy(
        update={
            "revoked_at":
                revoked_at,
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


def test_in_memory_store_replace_if_current_rejects_stale_expected():

    store = InMemorySessionStore()

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
