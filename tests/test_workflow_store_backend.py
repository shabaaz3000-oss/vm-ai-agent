import inspect

import pytest

from app import workflow_store


def test_workflow_store_defaults_to_sqlite(
    monkeypatch,
):
    monkeypatch.delenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        raising=False,
    )

    assert (
        workflow_store
        .get_workflow_store_backend_name()
        == "sqlite"
    )

    assert isinstance(
        workflow_store.get_workflow_store(),
        workflow_store.SQLiteWorkflowStore,
    )


def test_explicit_sqlite_backend_is_selected(
    monkeypatch,
):
    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "sqlite",
    )

    assert isinstance(
        workflow_store.get_workflow_store(),
        workflow_store.SQLiteWorkflowStore,
    )


def test_backend_name_is_normalized(
    monkeypatch,
):
    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "  SQLITE  ",
    )

    assert (
        workflow_store
        .get_workflow_store_backend_name()
        == "sqlite"
    )


def test_blank_backend_fails_closed(
    monkeypatch,
):
    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "   ",
    )

    with pytest.raises(
        RuntimeError,
        match="cannot be blank",
    ):
        workflow_store.get_workflow_store()


def test_postgresql_requires_database_url(
    monkeypatch,
):
    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "postgresql",
    )

    monkeypatch.delenv(
        "VM_AI_WORKFLOW_DATABASE_URL",
        raising=False,
    )

    monkeypatch.delenv(
        "VM_AI_ENV",
        raising=False,
    )

    with pytest.raises(
        RuntimeError,
        match="requires "
              "VM_AI_WORKFLOW_DATABASE_URL",
    ):
        workflow_store.get_workflow_store()


def test_postgresql_rejects_non_postgresql_url(
    monkeypatch,
):
    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "postgresql",
    )

    monkeypatch.setenv(
        "VM_AI_WORKFLOW_DATABASE_URL",
        "sqlite:///workflows.db",
    )

    monkeypatch.delenv(
        "VM_AI_ENV",
        raising=False,
    )

    with pytest.raises(
        RuntimeError,
        match="must use a PostgreSQL URL",
    ):
        workflow_store.get_workflow_store()


def test_postgresql_backend_is_built(
    monkeypatch,
):
    database_url = (
        "postgresql://runtime@db.example.test/"
        "vm_ai_workflows"
    )

    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "postgresql",
    )

    monkeypatch.setenv(
        "VM_AI_WORKFLOW_DATABASE_URL",
        database_url,
    )

    monkeypatch.setenv(
        "VM_AI_ENV",
        "development",
    )

    store = (
        workflow_store
        .get_workflow_store()
    )

    assert (
        store.__class__.__name__
        == "PostgreSQLWorkflowStore"
    )

    assert (
        store.database_url
        == database_url
    )


def test_production_postgresql_requires_tls(
    monkeypatch,
):
    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "postgresql",
    )

    monkeypatch.setenv(
        "VM_AI_WORKFLOW_DATABASE_URL",
        (
            "postgresql://runtime@"
            "db.example.test/"
            "vm_ai_workflows"
        ),
    )

    monkeypatch.setenv(
        "VM_AI_ENV",
        "production",
    )

    with pytest.raises(
        RuntimeError,
        match="requires TLS",
    ):
        workflow_store.get_workflow_store()


def test_production_postgresql_secure_url_is_accepted(
    monkeypatch,
):
    database_url = (
        "postgresql://runtime@db.example.test/"
        "vm_ai_workflows?sslmode=verify-full"
    )

    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "postgresql",
    )

    monkeypatch.setenv(
        "VM_AI_WORKFLOW_DATABASE_URL",
        database_url,
    )

    monkeypatch.setenv(
        "VM_AI_ENV",
        "production",
    )

    store = (
        workflow_store
        .get_workflow_store()
    )

    assert (
        store.__class__.__name__
        == "PostgreSQLWorkflowStore"
    )

    assert (
        store.database_url
        == database_url
    )


def test_postgresql_database_secret_is_not_in_store_repr(
    monkeypatch,
):
    secret = (
        "do-not-expose-this-password"
    )

    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "postgresql",
    )

    monkeypatch.setenv(
        "VM_AI_WORKFLOW_DATABASE_URL",
        (
            "postgresql://runtime:"
            f"{secret}"
            "@db.example.test/"
            "vm_ai_workflows"
        ),
    )

    monkeypatch.setenv(
        "VM_AI_ENV",
        "development",
    )

    store = (
        workflow_store
        .get_workflow_store()
    )

    assert (
        secret
        not in repr(store)
    )


def test_unknown_backend_fails_closed(
    monkeypatch,
):
    monkeypatch.setenv(
        "VM_AI_WORKFLOW_STORE_BACKEND",
        "untrusted-backend",
    )

    with pytest.raises(
        RuntimeError,
        match="Unsupported workflow store backend",
    ):
        workflow_store.get_workflow_store()


def test_claim_public_signature_preserves_tenant_authority_boundary():
    signature = inspect.signature(
        workflow_store
        .claim_workflow_for_execution
    )

    assert set(
        signature.parameters
    ) == {
        "workflow_id",
        "security_context",
    }

    assert (
        signature.parameters[
            "security_context"
        ].kind
        is inspect.Parameter.KEYWORD_ONLY
    )

    for forbidden in (
        "tenant",
        "tenant_id",
        "principal",
        "provider",
        "assignment_group",
        "instance_url",
    ):
        assert (
            forbidden
            not in signature.parameters
        )


def test_reconciliation_public_signatures_preserve_authority_boundary():
    confirm_signature = (
        inspect.signature(
            workflow_store
            .confirm_reconciled_ticket_creation
        )
    )

    retry_signature = (
        inspect.signature(
            workflow_store
            .authorize_reconciled_retry
        )
    )

    assert set(
        confirm_signature.parameters
    ) == {
        "workflow_id",
        "expected_execution_attempt_id",
        "ticket_id",
        "security_context",
    }

    assert set(
        retry_signature.parameters
    ) == {
        "workflow_id",
        "expected_execution_attempt_id",
        "security_context",
    }

    for signature in (
        confirm_signature,
        retry_signature,
    ):
        assert (
            signature.parameters[
                "security_context"
            ].kind
            is inspect.Parameter.KEYWORD_ONLY
        )

        assert (
            signature.parameters[
                "expected_execution_attempt_id"
            ].kind
            is inspect.Parameter.KEYWORD_ONLY
        )
