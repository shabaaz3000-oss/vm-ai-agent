from __future__ import annotations

from pathlib import Path

import pytest

import deploy.postgresql_bootstrap as bootstrap


class _Result:
    def __init__(
        self,
        row,
    ):
        self._row = row

    def fetchone(self):
        return self._row


class _ScriptedConnection:
    def __init__(
        self,
        rows,
    ):
        self._rows = list(rows)
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ):
        return False

    def execute(
        self,
        query,
        params=None,
    ):
        self.calls.append(
            (
                query,
                params,
            )
        )

        if not self._rows:
            raise AssertionError(
                "Unexpected database query."
            )

        return _Result(
            self._rows.pop(0)
        )


class _RuntimeConfigurationConnection:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ):
        return False

    def execute(
        self,
        query,
        params=None,
    ):
        self.calls.append(
            (
                query,
                params,
            )
        )

        if (
            isinstance(query, str)
            and "SELECT current_database()" in query
        ):
            return _Result(
                (
                    "vm_ai_agent",
                )
            )

        return _Result(
            None
        )


def test_read_secret_returns_direct_value():
    value = bootstrap._read_secret(
        environment={
            "TEST_SECRET": "direct-secret",
        },
        name="TEST_SECRET",
    )

    assert value == "direct-secret"


def test_read_secret_file_removes_only_line_endings(
    tmp_path: Path,
):
    secret_file = (
        tmp_path
        / "runtime-password"
    )

    secret_file.write_bytes(
        b"  preserved-secret  \r\n"
    )

    value = bootstrap._read_secret(
        environment={
            "TEST_SECRET_FILE":
                str(secret_file),
        },
        name="TEST_SECRET",
    )

    assert value == "  preserved-secret  "


def test_read_secret_rejects_ambiguous_sources_without_values():
    direct_secret = "direct-secret-value"

    secret_path = (
        "C:/sensitive/runtime-password"
    )

    with pytest.raises(
        bootstrap.PostgreSQLBootstrapConfigurationError
    ) as exc_info:
        bootstrap._read_secret(
            environment={
                "TEST_SECRET":
                    direct_secret,
                "TEST_SECRET_FILE":
                    secret_path,
            },
            name="TEST_SECRET",
        )

    message = str(
        exc_info.value
    )

    assert direct_secret not in message
    assert secret_path not in message


@pytest.mark.parametrize(
    "database_url",
    [
        (
            "postgresql://deployment:secret@postgres/"
            "vm_ai_agent"
        ),
        (
            "postgresql://deployment:secret@postgres/"
            "vm_ai_agent?sslmode=disable"
        ),
        (
            "postgresql://deployment:secret@postgres/"
            "vm_ai_agent?sslmode=prefer"
        ),
        (
            "postgresql://deployment:secret@postgres/"
            "vm_ai_agent?sslmode=require"
            "&sslmode=verify-full"
        ),
        (
            "postgresql://deployment:secret@postgres/"
            "vm_ai_agent?sslmode="
        ),
    ],
)
def test_production_database_url_rejects_insecure_tls(
    database_url: str,
):
    with pytest.raises(
        bootstrap.PostgreSQLBootstrapConfigurationError,
        match="requires exactly one sslmode",
    ) as exc_info:
        bootstrap._validate_deployment_database_url(
            database_url=database_url,
            environment={
                "VM_AI_ENV": "production",
            },
        )

    message = str(
        exc_info.value
    )

    assert "secret" not in message
    assert database_url not in message


@pytest.mark.parametrize(
    "sslmode",
    [
        "require",
        "verify-ca",
        "verify-full",
    ],
)
def test_production_database_url_accepts_secure_tls(
    sslmode: str,
):
    bootstrap._validate_deployment_database_url(
        database_url=(
            "postgresql://deployment@postgres/"
            f"vm_ai_agent?sslmode={sslmode}"
        ),
        environment={
            "VM_AI_ENV": "production",
        },
    )


def test_nonproduction_database_url_does_not_impose_production_tls():
    bootstrap._validate_deployment_database_url(
        database_url=(
            "postgresql://deployment@postgres/"
            "vm_ai_agent?sslmode=disable"
        ),
        environment={
            "VM_AI_ENV": "development",
        },
    )


@pytest.mark.parametrize(
    "identity_row",
    [
        (
            bootstrap.RUNTIME_ROLE,
            bootstrap.RUNTIME_ROLE,
        ),
        (
            bootstrap.RUNTIME_ROLE,
            "vm_ai_deployment",
        ),
        (
            "vm_ai_deployment",
            bootstrap.RUNTIME_ROLE,
        ),
    ],
)
def test_deployment_identity_rejects_runtime_role_without_url_disclosure(
    monkeypatch: pytest.MonkeyPatch,
    identity_row,
):
    database_url = (
        "postgresql://vm_ai_runtime:"
        "deployment-secret@postgres/"
        "vm_ai_agent?sslmode=require"
    )

    connection = _ScriptedConnection(
        [
            identity_row,
        ]
    )

    monkeypatch.setattr(
        bootstrap.psycopg,
        "connect",
        lambda *args, **kwargs:
            connection,
    )

    with pytest.raises(
        bootstrap.PostgreSQLBootstrapAuthorityError,
        match="must be separate",
    ) as exc_info:
        bootstrap._assert_deployment_identity_separate(
            database_url=database_url
        )

    message = str(
        exc_info.value
    )

    assert "deployment-secret" not in message
    assert database_url not in message


def test_deployment_identity_accepts_separate_role(
    monkeypatch: pytest.MonkeyPatch,
):
    connection = _ScriptedConnection(
        [
            (
                "vm_ai_deployment",
                "vm_ai_deployment",
            ),
        ]
    )

    monkeypatch.setattr(
        bootstrap.psycopg,
        "connect",
        lambda *args, **kwargs:
            connection,
    )

    bootstrap._assert_deployment_identity_separate(
        database_url=(
            "postgresql://vm_ai_deployment@postgres/"
            "vm_ai_agent?sslmode=require"
        )
    )


def test_runtime_role_membership_is_rejected():
    connection = _ScriptedConnection(
        [
            (
                1,
            ),
        ]
    )

    with pytest.raises(
        bootstrap.PostgreSQLBootstrapAuthorityError,
        match="member of another role",
    ):
        bootstrap._assert_runtime_role_has_no_memberships(
            connection=connection
        )


@pytest.mark.parametrize(
    (
        "rows",
        "message",
    ),
    [
        (
            [
                (
                    1,
                ),
            ],
            "application database",
        ),
        (
            [
                None,
                (
                    1,
                ),
            ],
            "public schema",
        ),
        (
            [
                None,
                None,
                (
                    "workflows",
                ),
            ],
            "authoritative application tables",
        ),
    ],
)
def test_runtime_role_ownership_is_rejected(
    rows,
    message: str,
):
    connection = _ScriptedConnection(
        rows
    )

    with pytest.raises(
        bootstrap.PostgreSQLBootstrapAuthorityError,
        match=message,
    ):
        bootstrap._assert_runtime_role_not_authority_owner(
            connection=connection
        )


def test_runtime_role_without_membership_or_ownership_passes():
    membership_connection = _ScriptedConnection(
        [
            None,
        ]
    )

    bootstrap._assert_runtime_role_has_no_memberships(
        connection=membership_connection
    )

    ownership_connection = _ScriptedConnection(
        [
            None,
            None,
            None,
        ]
    )

    bootstrap._assert_runtime_role_not_authority_owner(
        connection=ownership_connection
    )


def test_bootstrap_stops_before_provisioning_when_identity_is_invalid(
    monkeypatch: pytest.MonkeyPatch,
):
    events = []

    def reject_identity(
        *,
        database_url: str,
    ) -> None:
        events.append(
            "identity"
        )

        raise bootstrap.PostgreSQLBootstrapAuthorityError(
            "deployment authority rejected"
        )

    def unexpected_call(
        **kwargs,
    ) -> None:
        events.append(
            "unexpected"
        )

    monkeypatch.setattr(
        bootstrap,
        "_assert_deployment_identity_separate",
        reject_identity,
    )

    monkeypatch.setattr(
        bootstrap,
        "provision_postgresql_workflow_schema",
        unexpected_call,
    )

    monkeypatch.setattr(
        bootstrap,
        "provision_postgresql_session_schema",
        unexpected_call,
    )

    monkeypatch.setattr(
        bootstrap,
        "_configure_runtime_role",
        unexpected_call,
    )

    with pytest.raises(
        bootstrap.PostgreSQLBootstrapAuthorityError,
        match="deployment authority rejected",
    ):
        bootstrap.bootstrap_postgresql(
            environment={
                "VM_AI_ENV":
                    "production",
                "VM_AI_DEPLOYMENT_DATABASE_URL":
                    (
                        "postgresql://deployment@postgres/"
                        "vm_ai_agent?sslmode=require"
                    ),
                "VM_AI_RUNTIME_DATABASE_PASSWORD":
                    "runtime-secret",
            }
        )

    assert events == [
        "identity",
    ]


def test_bootstrap_preserves_deployment_then_runtime_order(
    monkeypatch: pytest.MonkeyPatch,
):
    events = []

    def record_identity(
        *,
        database_url: str,
    ) -> None:
        events.append(
            (
                "identity",
                database_url,
            )
        )

    def record_workflow(
        *,
        database_url: str,
    ) -> None:
        events.append(
            (
                "workflow",
                database_url,
            )
        )

    def record_session(
        *,
        database_url: str,
    ) -> None:
        events.append(
            (
                "session",
                database_url,
            )
        )

    def record_runtime(
        *,
        database_url: str,
        runtime_password: str,
    ) -> None:
        events.append(
            (
                "runtime",
                database_url,
                runtime_password,
            )
        )

    monkeypatch.setattr(
        bootstrap,
        "_assert_deployment_identity_separate",
        record_identity,
    )

    monkeypatch.setattr(
        bootstrap,
        "provision_postgresql_workflow_schema",
        record_workflow,
    )

    monkeypatch.setattr(
        bootstrap,
        "provision_postgresql_session_schema",
        record_session,
    )

    monkeypatch.setattr(
        bootstrap,
        "_configure_runtime_role",
        record_runtime,
    )

    database_url = (
        "postgresql://deployment@postgres/"
        "vm_ai_agent?sslmode=require"
    )

    runtime_password = (
        "runtime-secret"
    )

    bootstrap.bootstrap_postgresql(
        environment={
            "VM_AI_ENV":
                "production",
            "VM_AI_DEPLOYMENT_DATABASE_URL":
                database_url,
            "VM_AI_RUNTIME_DATABASE_PASSWORD":
                runtime_password,
        }
    )

    assert events == [
        (
            "identity",
            database_url,
        ),
        (
            "workflow",
            database_url,
        ),
        (
            "session",
            database_url,
        ),
        (
            "runtime",
            database_url,
            runtime_password,
        ),
    ]


def test_runtime_password_uses_client_side_literal_not_execute_params(
    monkeypatch: pytest.MonkeyPatch,
):
    connection = (
        _RuntimeConfigurationConnection()
    )

    monkeypatch.setattr(
        bootstrap.psycopg,
        "connect",
        lambda *args, **kwargs:
            connection,
    )

    monkeypatch.setattr(
        bootstrap,
        "_runtime_role_exists",
        lambda **kwargs:
            False,
    )

    literal_values = []

    def record_literal(
        value,
    ):
        literal_values.append(
            value
        )

        # Preserve a Composable return value without putting
        # the actual password into the fake SQL statement.
        return bootstrap.sql.SQL(
            "'__redacted_test_literal__'"
        )

    monkeypatch.setattr(
        bootstrap.sql,
        "Literal",
        record_literal,
    )

    runtime_password = (
        "runtime-password-secret"
    )

    bootstrap._configure_runtime_role(
        database_url=(
            "postgresql://deployment@postgres/"
            "vm_ai_agent?sslmode=require"
        ),
        runtime_password=runtime_password,
    )

    assert literal_values == [
        runtime_password,
    ]

    final_query, final_params = (
        connection.calls[-1]
    )

    assert final_params is None

    for _, params in connection.calls:
        if params is not None:
            assert (
                runtime_password
                not in repr(params)
            )

    assert final_query is not None
