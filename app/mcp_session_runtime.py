from __future__ import annotations

import os

from dataclasses import dataclass
from dataclasses import field
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs
from urllib.parse import urlsplit
from typing import Mapping

from app.mcp_session import MCPSessionManager
from app.mcp_session_store import (
    InMemorySessionStore,
    SessionStore,
)
from app.mcp_postgresql_session_store import (
    PostgreSQLSessionStore,
)
from app.mcp_sqlite_session_store import (
    SQLiteSessionStore,
)


DEFAULT_SESSION_TTL_MINUTES = 30

DEFAULT_SQLITE_DATABASE_PATH = Path(
    "data/mcp_sessions.db"
)

SUPPORTED_ENVIRONMENTS = {
    "local",
    "development",
    "test",
    "production",
}

SUPPORTED_SESSION_STORES = {
    "memory",
    "sqlite",
    "postgresql",
}


class MCPSessionRuntimeConfigurationError(
    RuntimeError
):
    """
    Raised when MCP session runtime configuration
    is missing, invalid, or unsafe.
    """


@dataclass(frozen=True)
class MCPSessionRuntimeSettings:
    """
    Authoritative configuration used to construct
    the MCP session persistence runtime.
    """

    environment: str

    store_kind: str

    session_ttl: timedelta

    database_path: Path | None

    database_url: str | None = field(
        repr=False
    )



def _validate_postgresql_database_url(
    database_url: str,
    *,
    production: bool,
) -> str:
    """
    Validate trusted server-side PostgreSQL configuration
    without exposing credentials in configuration errors.
    """

    normalized = (
        database_url.strip()
    )

    if not normalized:

        raise MCPSessionRuntimeConfigurationError(
            "VM_AI_SESSION_DATABASE_URL must "
            "not be empty."
        )

    try:

        parsed = urlsplit(
            normalized
        )

        hostname = parsed.hostname

    except ValueError as exc:

        raise MCPSessionRuntimeConfigurationError(
            "VM_AI_SESSION_DATABASE_URL is invalid."
        ) from exc

    if parsed.scheme.lower() != "postgresql":

        raise MCPSessionRuntimeConfigurationError(
            "VM_AI_SESSION_DATABASE_URL must use "
            "the postgresql:// scheme."
        )

    if not hostname:

        raise MCPSessionRuntimeConfigurationError(
            "VM_AI_SESSION_DATABASE_URL must include "
            "a database host."
        )

    if (
        not parsed.path
        or parsed.path == "/"
    ):

        raise MCPSessionRuntimeConfigurationError(
            "VM_AI_SESSION_DATABASE_URL must include "
            "a database name."
        )

    if production:

        query = parse_qs(
            parsed.query
        )

        sslmode = (
            query.get(
                "sslmode",
                [""],
            )[-1]
            .strip()
            .lower()
        )

        if sslmode not in {
            "require",
            "verify-ca",
            "verify-full",
        }:

            raise MCPSessionRuntimeConfigurationError(
                "Production PostgreSQL session storage "
                "must require TLS with sslmode=require, "
                "verify-ca, or verify-full."
            )

    return normalized


def load_mcp_session_runtime_settings(
    environment: Mapping[str, str] | None = None,
) -> MCPSessionRuntimeSettings:
    """
    Resolve MCP session configuration from trusted
    server-side environment variables.

    Production fails closed when durable session
    configuration has not been explicitly supplied.
    """

    source = (
        os.environ
        if environment is None
        else environment
    )

    runtime_environment = (
        source.get(
            "VM_AI_ENV",
            "local",
        )
        .strip()
        .lower()
    )

    if (
        runtime_environment
        not in SUPPORTED_ENVIRONMENTS
    ):
        raise MCPSessionRuntimeConfigurationError(
            "Unsupported VM_AI_ENV value: "
            f"{runtime_environment!r}"
        )

    configured_store = source.get(
        "VM_AI_SESSION_STORE"
    )

    if configured_store is None:

        if runtime_environment == "production":
            raise (
                MCPSessionRuntimeConfigurationError(
                    "VM_AI_SESSION_STORE must be "
                    "explicitly configured in "
                    "production."
                )
            )

        store_kind = "memory"

    else:

        store_kind = (
            configured_store
            .strip()
            .lower()
        )

    if (
        store_kind
        not in SUPPORTED_SESSION_STORES
    ):
        raise MCPSessionRuntimeConfigurationError(
            "Unsupported VM_AI_SESSION_STORE value: "
            f"{store_kind!r}"
        )

    if (
        runtime_environment == "production"
        and store_kind == "memory"
    ):
        raise MCPSessionRuntimeConfigurationError(
            "In-memory MCP session storage is "
            "not permitted in production."
        )

    raw_ttl = source.get(
        "VM_AI_SESSION_TTL_MINUTES",
        str(DEFAULT_SESSION_TTL_MINUTES),
    )

    try:
        ttl_minutes = int(
            raw_ttl
        )

    except ValueError as exc:
        raise MCPSessionRuntimeConfigurationError(
            "VM_AI_SESSION_TTL_MINUTES must "
            "be an integer."
        ) from exc

    if ttl_minutes <= 0:
        raise MCPSessionRuntimeConfigurationError(
            "VM_AI_SESSION_TTL_MINUTES must "
            "be greater than zero."
        )

    database_path: Path | None = None

    database_url: str | None = None

    if store_kind == "sqlite":

        configured_database_path = (
            source.get(
                "VM_AI_SESSION_DB_PATH"
            )
        )

        if (
            configured_database_path is None
            or not configured_database_path.strip()
        ):

            if (
                runtime_environment
                == "production"
            ):

                raise (
                    MCPSessionRuntimeConfigurationError(
                        "VM_AI_SESSION_DB_PATH must "
                        "be explicitly configured "
                        "when SQLite is used in "
                        "production."
                    )
                )

            database_path = (
                DEFAULT_SQLITE_DATABASE_PATH
            )

        else:

            database_path = Path(
                configured_database_path
            )

    if store_kind == "postgresql":

        configured_database_url = (
            source.get(
                "VM_AI_SESSION_DATABASE_URL"
            )
        )

        if (
            configured_database_url is None
            or not configured_database_url.strip()
        ):

            raise MCPSessionRuntimeConfigurationError(
                "VM_AI_SESSION_DATABASE_URL must "
                "be explicitly configured when "
                "PostgreSQL session storage is used."
            )

        database_url = (
            _validate_postgresql_database_url(
                configured_database_url,
                production=(
                    runtime_environment
                    == "production"
                ),
            )
        )

    return MCPSessionRuntimeSettings(
        environment=runtime_environment,
        store_kind=store_kind,
        session_ttl=timedelta(
            minutes=ttl_minutes
        ),
        database_path=database_path,
        database_url=database_url,
    )


def build_mcp_session_store(
    settings: MCPSessionRuntimeSettings,
) -> SessionStore:
    """
    Construct the authoritative session store for
    the configured MCP runtime.
    """

    if settings.store_kind == "memory":
        return InMemorySessionStore()

    if settings.store_kind == "sqlite":

        if settings.database_path is None:
            raise MCPSessionRuntimeConfigurationError(
                "SQLite session storage requires "
                "a database path."
            )

        return SQLiteSessionStore(
            database_path=
                settings.database_path,
        )

    if settings.store_kind == "postgresql":

        if settings.database_url is None:

            raise MCPSessionRuntimeConfigurationError(
                "PostgreSQL session storage requires "
                "a database URL."
            )

        return PostgreSQLSessionStore(
            database_url=
                settings.database_url,
        )

    raise MCPSessionRuntimeConfigurationError(
        "Unsupported MCP session store."
    )


def build_mcp_session_manager(
    environment: Mapping[str, str] | None = None,
) -> MCPSessionManager:
    """
    Build the application's authoritative MCP session
    manager from trusted server-side configuration.
    """

    settings = (
        load_mcp_session_runtime_settings(
            environment
        )
    )

    session_store = (
        build_mcp_session_store(
            settings
        )
    )

    return MCPSessionManager(
        session_ttl=
            settings.session_ttl,
        session_store=
            session_store,
    )