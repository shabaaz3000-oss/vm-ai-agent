from pathlib import Path

import pytest

from app.auth import Principal

from app.mcp_session_runtime import (
    MCPSessionRuntimeConfigurationError,
    build_mcp_session_manager,
    build_mcp_session_store,
    load_mcp_session_runtime_settings,
)

from app.mcp_session_store import (
    InMemorySessionStore,
)

from app.mcp_sqlite_session_store import (
    SQLiteSessionStore,
)


def test_local_defaults_to_memory():

    settings = (
        load_mcp_session_runtime_settings(
            {}
        )
    )

    assert settings.environment == "local"

    assert settings.store_kind == "memory"

    store = build_mcp_session_store(
        settings
    )

    assert isinstance(
        store,
        InMemorySessionStore,
    )


def test_explicit_sqlite_store_is_built(
    tmp_path,
):

    database_path = (
        tmp_path
        / "mcp_sessions.db"
    )

    settings = (
        load_mcp_session_runtime_settings(
            {
                "VM_AI_ENV":
                    "development",

                "VM_AI_SESSION_STORE":
                    "sqlite",

                "VM_AI_SESSION_DB_PATH":
                    str(database_path),
            }
        )
    )

    store = build_mcp_session_store(
        settings
    )

    assert isinstance(
        store,
        SQLiteSessionStore,
    )

    assert (
        settings.database_path
        == database_path
    )


def test_production_requires_explicit_store():

    with pytest.raises(
        MCPSessionRuntimeConfigurationError
    ):
        load_mcp_session_runtime_settings(
            {
                "VM_AI_ENV":
                    "production",
            }
        )


def test_production_rejects_memory_store():

    with pytest.raises(
        MCPSessionRuntimeConfigurationError
    ):
        load_mcp_session_runtime_settings(
            {
                "VM_AI_ENV":
                    "production",

                "VM_AI_SESSION_STORE":
                    "memory",
            }
        )


def test_production_sqlite_requires_database_path():

    with pytest.raises(
        MCPSessionRuntimeConfigurationError
    ):
        load_mcp_session_runtime_settings(
            {
                "VM_AI_ENV":
                    "production",

                "VM_AI_SESSION_STORE":
                    "sqlite",
            }
        )


def test_invalid_store_is_rejected():

    with pytest.raises(
        MCPSessionRuntimeConfigurationError
    ):
        load_mcp_session_runtime_settings(
            {
                "VM_AI_SESSION_STORE":
                    "redis",
            }
        )


def test_invalid_ttl_is_rejected():

    with pytest.raises(
        MCPSessionRuntimeConfigurationError
    ):
        load_mcp_session_runtime_settings(
            {
                "VM_AI_SESSION_TTL_MINUTES":
                    "zero",
            }
        )


def test_non_positive_ttl_is_rejected():

    with pytest.raises(
        MCPSessionRuntimeConfigurationError
    ):
        load_mcp_session_runtime_settings(
            {
                "VM_AI_SESSION_TTL_MINUTES":
                    "0",
            }
        )


def test_runtime_factory_uses_shared_sqlite_state(
    tmp_path,
):

    database_path = (
        tmp_path
        / "shared_sessions.db"
    )

    environment = {
        "VM_AI_ENV":
            "development",

        "VM_AI_SESSION_STORE":
            "sqlite",

        "VM_AI_SESSION_DB_PATH":
            str(database_path),

        "VM_AI_SESSION_TTL_MINUTES":
            "30",
    }

    first_manager = (
        build_mcp_session_manager(
            environment
        )
    )

    principal = Principal(
        username="alice",
        role="ANALYST",
        retrieval_access="standard",
    )

    session = (
        first_manager.create_session(
            principal,
            tenant_id="tenant-a",
        )
    )

    second_manager = (
        build_mcp_session_manager(
            environment
        )
    )

    validated = (
        second_manager.validate_session(
            principal,
            session_id=
                session.session_id,
            tenant_id="tenant-a",
        )
    )

    assert (
        validated.session_id
        == session.session_id
    )