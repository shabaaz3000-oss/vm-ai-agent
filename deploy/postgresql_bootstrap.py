from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping
from urllib.parse import parse_qsl, urlsplit

import psycopg
from psycopg import sql

from app.mcp_postgresql_schema import (
    provision_postgresql_session_schema,
)
from app.workflow_postgresql_schema import (
    provision_postgresql_workflow_schema,
)


RUNTIME_ROLE = "vm_ai_runtime"

RUNTIME_TABLES = (
    "workflows",
    "mcp_sessions",
)

_SECURE_POSTGRESQL_SSLMODES = frozenset(
    {
        "require",
        "verify-ca",
        "verify-full",
    }
)


class PostgreSQLBootstrapConfigurationError(
    RuntimeError
):
    """
    Deployment bootstrap configuration is invalid.
    """


class PostgreSQLBootstrapAuthorityError(
    RuntimeError
):
    """
    Deployment/runtime authority separation is invalid.
    """


def _read_secret(
    *,
    environment: Mapping[str, str],
    name: str,
) -> str:
    """
    Resolve a secret from either NAME or NAME_FILE.

    Supplying both sources is rejected so deployment
    configuration cannot silently choose one authority source
    over another.
    """

    direct_value = environment.get(name)

    file_setting = environment.get(
        f"{name}_FILE"
    )

    direct_present = (
        direct_value is not None
        and direct_value != ""
    )

    file_present = (
        file_setting is not None
        and file_setting.strip() != ""
    )

    if direct_present and file_present:
        raise PostgreSQLBootstrapConfigurationError(
            f"{name} and {name}_FILE must not both be set."
        )

    if direct_present:
        return direct_value

    if not file_present:
        raise PostgreSQLBootstrapConfigurationError(
            f"{name} or {name}_FILE is required."
        )

    secret_path = Path(
        file_setting.strip()
    )

    try:
        secret_value = secret_path.read_text(
            encoding="utf-8"
        )
    except (OSError, UnicodeError) as exc:
        raise PostgreSQLBootstrapConfigurationError(
            f"Unable to read {name}_FILE."
        ) from exc

    # Secret files commonly end with a single newline.
    # Do not strip other whitespace from secret material.
    secret_value = secret_value.rstrip(
        "\r\n"
    )

    if secret_value == "":
        raise PostgreSQLBootstrapConfigurationError(
            f"{name}_FILE must not be empty."
        )

    return secret_value


def _validate_deployment_database_url(
    *,
    database_url: str,
    environment: Mapping[str, str],
) -> None:
    """
    Validate deployment database configuration without
    placing the database URL into exception messages.
    """

    try:
        parsed = urlsplit(
            database_url
        )
    except ValueError as exc:
        raise PostgreSQLBootstrapConfigurationError(
            "Deployment PostgreSQL database URL is invalid."
        ) from exc

    if parsed.scheme.lower() != "postgresql":
        raise PostgreSQLBootstrapConfigurationError(
            "Deployment database URL must use the "
            "postgresql:// scheme."
        )

    if not parsed.hostname:
        raise PostgreSQLBootstrapConfigurationError(
            "Deployment PostgreSQL database URL must "
            "include a host."
        )

    if (
        not parsed.path
        or parsed.path == "/"
    ):
        raise PostgreSQLBootstrapConfigurationError(
            "Deployment PostgreSQL database URL must "
            "include a database name."
        )

    environment_name = (
        environment.get(
            "VM_AI_ENV",
            "",
        )
        .strip()
        .lower()
    )

    if environment_name != "production":
        return

    sslmode_values = [
        value.strip().lower()
        for key, value in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )
        if key.lower() == "sslmode"
    ]

    if (
        len(sslmode_values) != 1
        or sslmode_values[0]
        not in _SECURE_POSTGRESQL_SSLMODES
    ):
        raise PostgreSQLBootstrapConfigurationError(
            "Production deployment PostgreSQL authority "
            "requires exactly one sslmode set to require, "
            "verify-ca, or verify-full."
        )


def _assert_deployment_identity_separate(
    *,
    database_url: str,
) -> None:
    """
    Reject use of the runtime identity as deployment
    authority before any provisioning operation occurs.
    """

    with psycopg.connect(
        database_url,
        connect_timeout=10,
    ) as connection:
        (
            session_user,
            current_user,
        ) = connection.execute(
            """
            SELECT session_user, current_user
            """
        ).fetchone()

    if (
        session_user == RUNTIME_ROLE
        or current_user == RUNTIME_ROLE
    ):
        raise PostgreSQLBootstrapAuthorityError(
            "Deployment PostgreSQL authority must be "
            "separate from the runtime role."
        )


def _runtime_role_exists(
    *,
    connection: psycopg.Connection,
) -> bool:
    row = connection.execute(
        """
        SELECT 1
        FROM pg_roles
        WHERE rolname = %s
        """,
        (
            RUNTIME_ROLE,
        ),
    ).fetchone()

    return row is not None


def _assert_runtime_role_has_no_memberships(
    *,
    connection: psycopg.Connection,
) -> None:
    """
    A runtime role with membership in another role could
    acquire authority outside the intended direct grants.
    """

    row = connection.execute(
        """
        SELECT 1
        FROM pg_auth_members AS membership
        JOIN pg_roles AS member_role
          ON member_role.oid = membership.member
        WHERE member_role.rolname = %s
        LIMIT 1
        """,
        (
            RUNTIME_ROLE,
        ),
    ).fetchone()

    if row is not None:
        raise PostgreSQLBootstrapAuthorityError(
            "Runtime PostgreSQL role must not be a "
            "member of another role."
        )


def _assert_runtime_role_not_authority_owner(
    *,
    connection: psycopg.Connection,
) -> None:
    """
    Direct ACL revocation cannot remove object-owner
    authority. Reject ownership of the authoritative
    deployment objects rather than misrepresenting the
    runtime role as least privileged.
    """

    database_owner = connection.execute(
        """
        SELECT 1
        FROM pg_database AS database
        JOIN pg_roles AS owner
          ON owner.oid = database.datdba
        WHERE database.datname = current_database()
          AND owner.rolname = %s
        LIMIT 1
        """,
        (
            RUNTIME_ROLE,
        ),
    ).fetchone()

    if database_owner is not None:
        raise PostgreSQLBootstrapAuthorityError(
            "Runtime PostgreSQL role must not own the "
            "application database."
        )

    schema_owner = connection.execute(
        """
        SELECT 1
        FROM pg_namespace AS namespace
        JOIN pg_roles AS owner
          ON owner.oid = namespace.nspowner
        WHERE namespace.nspname = 'public'
          AND owner.rolname = %s
        LIMIT 1
        """,
        (
            RUNTIME_ROLE,
        ),
    ).fetchone()

    if schema_owner is not None:
        raise PostgreSQLBootstrapAuthorityError(
            "Runtime PostgreSQL role must not own the "
            "public schema."
        )

    table_owner = connection.execute(
        """
        SELECT class.relname
        FROM pg_class AS class
        JOIN pg_namespace AS namespace
          ON namespace.oid = class.relnamespace
        JOIN pg_roles AS owner
          ON owner.oid = class.relowner
        WHERE namespace.nspname = 'public'
          AND class.relname = ANY(%s)
          AND owner.rolname = %s
        LIMIT 1
        """,
        (
            list(RUNTIME_TABLES),
            RUNTIME_ROLE,
        ),
    ).fetchone()

    if table_owner is not None:
        raise PostgreSQLBootstrapAuthorityError(
            "Runtime PostgreSQL role must not own "
            "authoritative application tables."
        )


def _configure_runtime_role(
    *,
    database_url: str,
    runtime_password: str,
) -> None:
    """
    Normalize the runtime identity to the minimum database
    authority required by the PostgreSQL stores.
    """

    with psycopg.connect(
        database_url,
        connect_timeout=10,
    ) as connection:
        role_exists = _runtime_role_exists(
            connection=connection
        )

        if role_exists:
            _assert_runtime_role_has_no_memberships(
                connection=connection
            )

            _assert_runtime_role_not_authority_owner(
                connection=connection
            )
        else:
            connection.execute(
                """
                CREATE ROLE vm_ai_runtime
                    NOLOGIN
                    NOSUPERUSER
                    NOCREATEDB
                    NOCREATEROLE
                    NOINHERIT
                    NOREPLICATION
                    NOBYPASSRLS
                """
            )

        # Normalize dangerous role attributes even when the
        # deployment is reconciling an existing runtime role.
        connection.execute(
            """
            ALTER ROLE vm_ai_runtime
                NOLOGIN
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                NOINHERIT
                NOREPLICATION
                NOBYPASSRLS
            """
        )

        database_name = connection.execute(
            """
            SELECT current_database()
            """
        ).fetchone()[0]

        database_identifier = sql.Identifier(
            database_name
        )

        runtime_identifier = sql.Identifier(
            RUNTIME_ROLE
        )

        # PUBLIC must not remain an alternate path to schema
        # creation or database temporary-object authority.
        connection.execute(
            """
            REVOKE CREATE ON SCHEMA public
            FROM PUBLIC
            """
        )

        connection.execute(
            sql.SQL(
                """
                REVOKE TEMPORARY ON DATABASE {}
                FROM PUBLIC
                """
            ).format(
                database_identifier
            )
        )

        # Normalize direct database privileges for the runtime
        # identity before granting only CONNECT.
        connection.execute(
            sql.SQL(
                """
                REVOKE ALL PRIVILEGES ON DATABASE {}
                FROM {}
                """
            ).format(
                database_identifier,
                runtime_identifier,
            )
        )

        connection.execute(
            sql.SQL(
                """
                GRANT CONNECT ON DATABASE {}
                TO {}
                """
            ).format(
                database_identifier,
                runtime_identifier,
            )
        )

        # Normalize schema privileges before granting only
        # object-usage authority.
        connection.execute(
            sql.SQL(
                """
                REVOKE ALL PRIVILEGES ON SCHEMA public
                FROM {}
                """
            ).format(
                runtime_identifier
            )
        )

        connection.execute(
            sql.SQL(
                """
                GRANT USAGE ON SCHEMA public
                TO {}
                """
            ).format(
                runtime_identifier
            )
        )

        for table_name in RUNTIME_TABLES:
            table_identifier = sql.Identifier(
                table_name
            )

            connection.execute(
                sql.SQL(
                    """
                    REVOKE ALL PRIVILEGES ON TABLE {}
                    FROM PUBLIC
                    """
                ).format(
                    table_identifier
                )
            )

            connection.execute(
                sql.SQL(
                    """
                    REVOKE ALL PRIVILEGES ON TABLE {}
                    FROM {}
                    """
                ).format(
                    table_identifier,
                    runtime_identifier,
                )
            )

            connection.execute(
                sql.SQL(
                    """
                    GRANT SELECT, INSERT, UPDATE
                    ON TABLE {}
                    TO {}
                    """
                ).format(
                    table_identifier,
                    runtime_identifier,
                )
            )

        # LOGIN is enabled only after the role has been
        # reconciled to the intended authority boundary.
        #
        # PostgreSQL utility/DDL statements do not support
        # Psycopg 3 server-side parameter binding reliably.
        # Compose the password as a safely quoted SQL literal
        # rather than using a %s server-side placeholder.
        connection.execute(
            sql.SQL(
                """
                ALTER ROLE {}
                    LOGIN
                    PASSWORD {}
                """
            ).format(
                runtime_identifier,
                sql.Literal(
                    runtime_password
                ),
            )
        )


def bootstrap_postgresql(
    *,
    environment: Mapping[str, str],
) -> None:
    """
    Provision PostgreSQL deployment objects and reconcile
    the separate least-privileged runtime identity.

    The application runtime must never call this function.
    """

    deployment_database_url = _read_secret(
        environment=environment,
        name="VM_AI_DEPLOYMENT_DATABASE_URL",
    )

    runtime_password = _read_secret(
        environment=environment,
        name="VM_AI_RUNTIME_DATABASE_PASSWORD",
    )

    _validate_deployment_database_url(
        database_url=deployment_database_url,
        environment=environment,
    )

    _assert_deployment_identity_separate(
        database_url=deployment_database_url
    )

    # Existing schema functions remain the authoritative
    # deployment-time schema implementation.
    provision_postgresql_workflow_schema(
        database_url=deployment_database_url
    )

    provision_postgresql_session_schema(
        database_url=deployment_database_url
    )

    _configure_runtime_role(
        database_url=deployment_database_url,
        runtime_password=runtime_password,
    )


def main() -> int:
    bootstrap_postgresql(
        environment=os.environ
    )

    # Deliberately do not print connection strings, secret
    # paths, passwords, or provider/database response bodies.
    print(
        "PostgreSQL deployment bootstrap complete."
    )
    print(
        "Runtime database authority: "
        "CONNECT + USAGE + SELECT/INSERT/UPDATE."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
