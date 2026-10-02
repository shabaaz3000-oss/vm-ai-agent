from __future__ import annotations

import psycopg

from psycopg import sql


WORKFLOW_SCHEMA_VERSION = 1

WORKFLOW_SCHEMA_COMMENT_PREFIX = (
    "vm_ai_agent_workflow_schema:v"
)

WORKFLOW_SCHEMA_COMMENT = (
    f"{WORKFLOW_SCHEMA_COMMENT_PREFIX}"
    f"{WORKFLOW_SCHEMA_VERSION}"
)


def _require_postgresql_database_url(
    database_url: str,
    *,
    connect_timeout_seconds: int,
) -> None:
    """
    Validate workflow-schema connection settings.

    Database URLs are deliberately excluded from exception text so
    credentials cannot leak through configuration failures.
    """

    if (
        not isinstance(
            database_url,
            str,
        )
        or not database_url.strip()
        or database_url
        != database_url.strip()
    ):
        raise ValueError(
            "database_url must be a non-blank "
            "normalized string."
        )

    if not database_url.startswith(
        (
            "postgresql://",
            "postgres://",
        )
    ):
        raise ValueError(
            "database_url must use a PostgreSQL URL."
        )

    if connect_timeout_seconds <= 0:
        raise ValueError(
            "connect_timeout_seconds must be "
            "greater than zero."
        )


def _validate_workflow_schema_connection(
    connection,
    *,
    require_version: bool,
) -> None:
    """
    Validate workflow-table compatibility using read-only queries.

    When require_version is False, an unversioned compatible table
    is accepted so the deployment identity may stamp the initial
    version. A conflicting existing version is always rejected.
    """

    identity = connection.execute(
        """
        SELECT
            to_regclass(
                'public.workflows'
            )::text,
            obj_description(
                to_regclass(
                    'public.workflows'
                ),
                'pg_class'
            )
        """
    ).fetchone()

    if (
        identity is None
        or identity[0] is None
    ):
        raise RuntimeError(
            "PostgreSQL workflow schema "
            "is not provisioned."
        )

    schema_comment = identity[1]

    if require_version:

        if (
            schema_comment
            != WORKFLOW_SCHEMA_COMMENT
        ):
            raise RuntimeError(
                "PostgreSQL workflow schema "
                "version is incompatible."
            )

    elif (
        schema_comment is not None
        and schema_comment
        != WORKFLOW_SCHEMA_COMMENT
    ):
        # Deployment provisioning must never silently rewrite an
        # unknown/future schema version to the current version.
        raise RuntimeError(
            "PostgreSQL workflow schema "
            "version is incompatible."
        )

    columns = connection.execute(
        """
        SELECT
            column_name,
            data_type,
            is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'workflows'
        ORDER BY ordinal_position
        """
    ).fetchall()

    expected_columns = [
        (
            "workflow_id",
            "text",
            "NO",
        ),
        (
            "status",
            "text",
            "NO",
        ),
        (
            "payload",
            "text",
            "NO",
        ),
        (
            "created_at",
            "timestamp with time zone",
            "NO",
        ),
        (
            "updated_at",
            "timestamp with time zone",
            "NO",
        ),
    ]

    actual_columns = [
        tuple(
            row
        )
        for row in columns
    ]

    if (
        actual_columns
        != expected_columns
    ):
        raise RuntimeError(
            "PostgreSQL workflow schema "
            "shape is incompatible."
        )

    primary_key_rows = (
        connection.execute(
            """
            SELECT
                kcu.column_name
            FROM
                information_schema
                .table_constraints AS tc
            JOIN
                information_schema
                .key_column_usage AS kcu
              ON tc.constraint_name =
                 kcu.constraint_name
             AND tc.table_schema =
                 kcu.table_schema
            WHERE tc.table_schema = 'public'
              AND tc.table_name = 'workflows'
              AND tc.constraint_type =
                  'PRIMARY KEY'
            ORDER BY kcu.ordinal_position
            """
        ).fetchall()
    )

    primary_key = [
        row[0]
        for row
        in primary_key_rows
    ]

    if primary_key != [
        "workflow_id"
    ]:
        raise RuntimeError(
            "PostgreSQL workflow schema "
            "primary key is incompatible."
        )

    index_row = connection.execute(
        """
        SELECT indexdef
        FROM pg_indexes
        WHERE schemaname = 'public'
          AND tablename = 'workflows'
          AND indexname =
              'workflows_status_idx'
        """
    ).fetchone()

    if (
        index_row is None
        or "(status)"
        not in index_row[0]
    ):
        raise RuntimeError(
            "PostgreSQL workflow schema "
            "status index is incompatible."
        )


def provision_postgresql_workflow_schema(
    *,
    database_url: str,
    connect_timeout_seconds: int = 10,
) -> None:
    """
    Provision workflow schema using deployment/admin authority.

    Runtime application identities must not call this function.

    Provisioning may create schema objects and stamp a compatible
    unversioned workflow table with the current schema version.
    It never silently rewrites an incompatible existing version.
    """

    _require_postgresql_database_url(
        database_url,
        connect_timeout_seconds=
            connect_timeout_seconds,
    )

    with psycopg.connect(
        database_url,
        connect_timeout=
            connect_timeout_seconds,
        autocommit=True,
    ) as connection:

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS workflows (
                workflow_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMPTZ NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
                workflows_status_idx
            ON workflows (status)
            """
        )

        # Validate shape before stamping the version. This prevents
        # CREATE TABLE IF NOT EXISTS from masquerading as migration.
        _validate_workflow_schema_connection(
            connection,
            require_version=False,
        )

        connection.execute(
            sql.SQL(
                """
                COMMENT ON TABLE workflows IS {}
                """
            ).format(
                sql.Literal(
                    WORKFLOW_SCHEMA_COMMENT
                )
            )
        )

        _validate_workflow_schema_connection(
            connection,
            require_version=True,
        )


def validate_postgresql_workflow_schema(
    *,
    database_url: str,
    connect_timeout_seconds: int = 10,
) -> int:
    """
    Validate workflow schema using read-only runtime authority.

    Runtime validation never creates, alters, migrates, comments
    on, repairs, or otherwise mutates PostgreSQL schema objects.

    Return the validated workflow schema version.
    """

    _require_postgresql_database_url(
        database_url,
        connect_timeout_seconds=
            connect_timeout_seconds,
    )

    try:

        with psycopg.connect(
            database_url,
            connect_timeout=
                connect_timeout_seconds,
            autocommit=True,
        ) as connection:

            _validate_workflow_schema_connection(
                connection,
                require_version=True,
            )

    except RuntimeError:
        raise

    except psycopg.Error as error:
        raise RuntimeError(
            "PostgreSQL workflow schema "
            "validation failed."
        ) from error

    return WORKFLOW_SCHEMA_VERSION
